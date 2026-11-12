/**
 * Double Ratchet 状态机（Signal 规范实现，FR-2.1：前向保密 + PCS）。
 *
 * - KDF_RK：root chain，随对端新 ratchet 公钥推进（DH ratchet）
 * - KDF_CK：对称链，每条消息推进一次，支持跳过丢失消息（上限 MAX_SKIP）
 * - 每条消息使用独立 message key + 随机 nonce（key 一次性，随机 nonce 安全）
 * - 消息头进入 AEAD 关联数据：密文与 (dh, pn, n) 绑定，防头替换
 * - 被跳过的 message key 保存于 skipped，供乱序消息解密；同一消息重放
 *   会因 key 已消费而失败（防重放，SR-4）
 */
import {
  AEAD_KEY_LENGTH,
  AEAD_NONCE_LENGTH,
  type KeyPair,
  aeadDecrypt,
  aeadEncrypt,
  generateX25519KeyPair,
  hkdfSha256,
  randomBytes,
  x25519SharedSecret,
} from "../crypto/index.ts";
import { base58Decode, base58Encode, concatBytes } from "../codec/index.ts";

const ROOT_INFO = "mychat:dr:rk:v1";
const CHAIN_INFO = "mychat:dr:ck:v1";
/** 单方向允许跳过的最大消息数（Signal 规范默认 2000，M0 收紧为 1000）。 */
export const MAX_SKIP = 1000;
/**
 * skipped 存储全局上限：伪造 header（随机 dh + 大 n）可借 skipMessageKeys
 * 无限膨胀 skipped 存储（存储 DoS）；达上限即拒绝，由 ratchetDecrypt 的
 * 事务回滚兜底，会话状态保持解密前原样。
 */
export const MAX_SKIPPED_TOTAL = 4000;

/** 消息头（明文传输，进入 AEAD 关联数据）。 */
export interface DrHeader {
  /** 发送方当前 ratchet 公钥（32B） */
  dh: Uint8Array;
  /** 上一条发送链长度（接收方 ratchet 跳转时用于批量跳 key） */
  pn: number;
  /** 本链内消息序号 */
  n: number;
}

export interface RatchetState {
  rootKey: Uint8Array;
  dhSelf: KeyPair;
  dhRemote: Uint8Array | null;
  sendChainKey: Uint8Array | null;
  recvChainKey: Uint8Array | null;
  sendCount: number;
  recvCount: number;
  prevSendCount: number;
  /** 被跳过的 message key；键 = base58(dh) + ":" + n */
  skipped: Map<string, Uint8Array>;
}

/** KDF_RK：root key + DH 输出 → 新 root key + 新链密钥（64B HKDF 双输出）。 */
function kdfRootKey(rootKey: Uint8Array, dhOut: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const out = hkdfSha256(concatBytes(rootKey, dhOut), rootKey, ROOT_INFO, 64);
  return { rootKey: out.slice(0, 32), chainKey: out.slice(32, 64) };
}

/** KDF_CK：链密钥 → (下一链密钥, message key)。 */
function kdfChainKey(chainKey: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
  const out = hkdfSha256(chainKey, new Uint8Array(32), CHAIN_INFO, 64);
  return { chainKey: out.slice(0, 32), messageKey: out.slice(32, 64) };
}

function skippedKey(dh: Uint8Array, n: number): string {
  return `${base58Encode(dh)}:${n}`;
}

/**
 * 解析 skipped 键 id（与 skippedKey 同格式：base58(dh) + ":" + n）。
 * 导出供持久化层反序列化时校验；格式非法（缺分隔符/序号非十进制非负整数）
 * 或 dh 非 base58 合法编码时 throw。
 */
export function parseSkippedKeyId(key: string): { dh: Uint8Array; n: number } {
  const sep = key.lastIndexOf(":");
  if (sep <= 0) throw new Error("ratchet: skipped 键 id 缺少分隔符");
  const nText = key.slice(sep + 1);
  if (!/^(0|[1-9]\d*)$/.test(nText)) throw new Error("ratchet: skipped 键 id 序号非法");
  return { dh: base58Decode(key.slice(0, sep)), n: Number(nText) };
}

/**
 * 发起方初始化：已持对方 SPK 公钥，立即生成新 ratchet 密钥并推进 root chain。
 */
export function ratchetInitInitiator(sk: Uint8Array, spkRemotePublic: Uint8Array): RatchetState {
  const dhSelf = generateX25519KeyPair();
  const step = kdfRootKey(sk, x25519SharedSecret(dhSelf.privateKey, spkRemotePublic));
  return {
    rootKey: step.rootKey,
    dhSelf,
    dhRemote: spkRemotePublic,
    sendChainKey: step.chainKey,
    recvChainKey: null,
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
    skipped: new Map(),
  };
}

/**
 * 响应方初始化：以 SPK 密钥对为首个发送 ratchet 密钥；待收到首条消息时对端链建立。
 */
export function ratchetInitResponder(sk: Uint8Array, spkSelf: KeyPair): RatchetState {
  return {
    rootKey: sk,
    dhSelf: spkSelf,
    dhRemote: null,
    sendChainKey: null,
    recvChainKey: null,
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
    skipped: new Map(),
  };
}

/**
 * 加密一条消息。会就地推进状态（sendCount/链密钥）。
 * @param ad 会话级关联数据（X3DH AD），与消息头一并绑定进 AEAD
 */
export function ratchetEncrypt(
  state: RatchetState,
  plaintext: Uint8Array,
  ad: Uint8Array,
): { header: DrHeader; nonce: Uint8Array; ciphertext: Uint8Array } {
  if (state.sendChainKey === null) {
    throw new Error("ratchet: 发送链未建立（响应方须先收到初始消息）");
  }
  const step = kdfChainKey(state.sendChainKey);
  state.sendChainKey = step.chainKey;
  const header: DrHeader = { dh: state.dhSelf.publicKey, pn: state.prevSendCount, n: state.sendCount };
  state.sendCount += 1;

  const nonce = randomBytes(AEAD_NONCE_LENGTH);
  const ciphertext = aeadEncrypt(
    step.messageKey,
    nonce,
    plaintext,
    concatBytes(ad, encodeHeader(header), nonce),
  );
  return { header, nonce, ciphertext };
}

/**
 * 解密一条消息。支持乱序（跳过的 key 存入 skipped）；同一 (dh, n) 重放会 throw。
 * 就地推进状态（可能触发 DH ratchet 与链跳转）。
 *
 * 事务式提交：链推进路径在 AEAD 验证成功前不提交任何状态——推进/跳存/DH
 * ratchet 期间任何一步 throw（AEAD 验证失败、跳存超限、DH 低阶点抛错）都会
 * 回滚到解密前状态。否则旧代消息重放会触发错误方向的 DH ratchet 使双方
 * rootKey 永久分叉（会话死亡），伪造 header 则能把 skipped/recvCount 推到
 * 伪造位置，后续真实消息全部被拒。
 */
export function ratchetDecrypt(
  state: RatchetState,
  header: DrHeader,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  ad: Uint8Array,
): Uint8Array {
  const keyId = skippedKey(header.dh, header.n);
  const reused = state.skipped.get(keyId);
  if (reused !== undefined) {
    // key 尚在 = 消息曾被显式跳过保存；先解密成功再删除：解密失败保留 key，
    // 真实乱序消息重投仍可解。同密文重复投递会重复出明文（Signal 同款语义），
    // 由应用层按 mid 去重兜底。
    const plaintext = aeadDecrypt(reused, nonce, ciphertext, concatBytes(ad, encodeHeader(header), nonce));
    state.skipped.delete(keyId);
    return plaintext;
  }

  if (state.dhRemote !== null && bytesEqualHeader(header.dh, state.dhRemote) && header.n < state.recvCount) {
    // 当前链上 n < recvCount 的消息必然已消费过（或 key 已在 skipped 中消费）。
    // 直接拒绝且不推进链：防止重放破坏链状态造成后续消息解密失败（自伤型 DoS）。
    throw new Error("ratchet: 消息重放或已消费（链内旧序号）");
  }

  // 快照将被链推进路径替换的全部状态字段；skipped 只追加不替换（Map 插入序），
  // 记录进入时的大小即可识别本轮新增键。skippedMap 引用本身从不被替换。
  const snapshot = {
    rootKey: state.rootKey,
    dhSelf: state.dhSelf,
    dhRemote: state.dhRemote,
    sendChainKey: state.sendChainKey,
    recvChainKey: state.recvChainKey,
    sendCount: state.sendCount,
    recvCount: state.recvCount,
    prevSendCount: state.prevSendCount,
  };
  const skippedSizeBefore = state.skipped.size;
  try {
    if (state.dhRemote === null || !bytesEqualHeader(header.dh, state.dhRemote)) {
      skipMessageKeys(state, header.pn); // 旧链剩余 key 全部跳存
      dhRatchet(state, header.dh);
    }
    skipMessageKeys(state, header.n);

    if (state.recvChainKey === null) {
      throw new Error("ratchet: 接收链未建立");
    }
    const step = kdfChainKey(state.recvChainKey);
    state.recvChainKey = step.chainKey;
    state.recvCount += 1;

    // AEAD 验证成功前的一切改动都属"未提交"：失败即整体回滚
    return aeadDecrypt(step.messageKey, nonce, ciphertext, concatBytes(ad, encodeHeader(header), nonce));
  } catch (err) {
    state.rootKey = snapshot.rootKey;
    state.dhSelf = snapshot.dhSelf;
    state.dhRemote = snapshot.dhRemote;
    state.sendChainKey = snapshot.sendChainKey;
    state.recvChainKey = snapshot.recvChainKey;
    state.sendCount = snapshot.sendCount;
    state.recvCount = snapshot.recvCount;
    state.prevSendCount = snapshot.prevSendCount;
    // 删除本轮新增的 skipped 键（新增键必然位于 Map 插入序尾部）
    const staleKeys = [...state.skipped.keys()].slice(skippedSizeBefore);
    for (const k of staleKeys) state.skipped.delete(k);
    throw err;
  }
}

function bytesEqualHeader(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** 把当前接收链推进 n 步，跳过的 message key 存入 skipped（上限 MAX_SKIP 与全局上限 MAX_SKIPPED_TOTAL）。 */
function skipMessageKeys(state: RatchetState, until: number): void {
  if (state.recvChainKey === null) return;
  if (state.recvCount + MAX_SKIP < until) {
    throw new Error(`ratchet: 跳过消息数超过上限 ${MAX_SKIP}（疑似异常或攻击）`);
  }
  // 全局上限（防存储 DoS）：伪造 header 每条可净增至多 MAX_SKIP 个键，
  // 达上限后直接拒绝，事务回滚保证会话状态不受影响。
  if (state.skipped.size >= MAX_SKIPPED_TOTAL) {
    throw new Error(`ratchet: skipped 存储达全局上限 ${MAX_SKIPPED_TOTAL}（疑似存储 DoS）`);
  }
  while (state.recvCount < until) {
    const step = kdfChainKey(state.recvChainKey);
    state.recvChainKey = step.chainKey;
    if (state.dhRemote !== null) {
      state.skipped.set(skippedKey(state.dhRemote, state.recvCount), step.messageKey);
    }
    state.recvCount += 1;
  }
}

/** DH ratchet：对端启用新 ratchet 公钥时推进 root chain 两次（先收链后发链）。 */
function dhRatchet(state: RatchetState, dhRemote: Uint8Array): void {
  state.prevSendCount = state.sendCount;
  state.sendCount = 0;
  state.recvCount = 0;
  state.dhRemote = dhRemote;

  const recvStep = kdfRootKey(state.rootKey, x25519SharedSecret(state.dhSelf.privateKey, dhRemote));
  state.rootKey = recvStep.rootKey;
  state.recvChainKey = recvStep.chainKey;

  state.dhSelf = generateX25519KeyPair();
  const sendStep = kdfRootKey(state.rootKey, x25519SharedSecret(state.dhSelf.privateKey, dhRemote));
  state.rootKey = sendStep.rootKey;
  state.sendChainKey = sendStep.chainKey;
}

/** 消息头定长编码：dh(32B) + pn(4B BE) + n(4B BE) = 40B。 */
export function encodeHeader(header: DrHeader): Uint8Array {
  const out = new Uint8Array(40);
  out.set(header.dh, 0);
  const view = new DataView(out.buffer);
  view.setUint32(32, header.pn, false);
  view.setUint32(36, header.n, false);
  return out;
}

export function decodeHeader(bytes: Uint8Array): DrHeader {
  if (bytes.length !== 40) throw new Error("ratchet: 消息头长度非法");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    dh: bytes.slice(0, 32),
    pn: view.getUint32(32, false),
    n: view.getUint32(36, false),
  };
}
