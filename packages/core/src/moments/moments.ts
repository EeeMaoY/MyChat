/**
 * 动态（Moments/EDS-min，FR-4.1/4.2/4.4，M3 计划 §6）—— 好友圈动态的协议原语。
 *
 * 模型（EDS-min：只做动态日志与能力包裹，完整 EDS 属后续里程碑）：
 * - 好友圈密钥 momentKey（32B，作者与好友持有，经 1:1 会话分发）派生动态信箱 ID；
 * - 动态信箱 = append-only 动态日志：条目（post/delete/like）以 momentKey AEAD 加密；
 * - 每条动态独立内容密钥（encryptAttachment 模式）：文字与图片引用一起入块，
 *   块 CID 经日志条目分发；删除 = 墓碑条目 + 物理删块（客户端语义为准）；
 * - 点赞（like）不产生内容块：cid 置空串、无内容密钥，以 targetCid 指向被赞动态的内容块 CID。
 *
 * 作者性（加固批次 ②）：日志信箱是节点公共 append（知道 feedId 即可投递），
 * 对称圈密钥无法提供作者性——**每条目带 IK 签名**（覆盖全部业务字段），读取时
 * 强制验签：持有圈密钥的好友伪造他人条目在验签处被拒（密文层过、签名层拦截）。
 *
 * 边界（如实披露）：momentKey v1 不轮换（可重置，见客户端"重置好友圈"）；已缓存
 * 的密文副本无法物理强制删除（FR-4.4 固有边界）；评论仅作者可见（v1 子集）。
 */
import { base58Decode, base58Encode, bytesToUtf8, concatBytes, utf8ToBytes } from "../codec/index.ts";
import { AEAD_KEY_LENGTH, AEAD_NONCE_LENGTH, aeadDecrypt, aeadEncrypt, hkdfSha256, randomBytes, ed25519Sign, ed25519Verify } from "../crypto/index.ts";
import { decryptAttachment, encryptAttachment } from "../attachment/index.ts";
import { didToEd25519PublicKey } from "../identity/did.ts";

const FEED_ID_PREFIX = "mychat:moments-feed-v1:";
const ENTRY_SIGNING_PREFIX = "mychat:moment-entry-v1:";
const SIGNATURE_LENGTH = 64;

export function generateMomentKey(): Uint8Array {
  return randomBytes(AEAD_KEY_LENGTH);
}

/** 动态信箱 ID（好友按此增量拉取作者的动态日志）。 */
export function momentFeedId(momentKey: Uint8Array): string {
  return base58Encode(hkdfSha256(momentKey, new Uint8Array(0), FEED_ID_PREFIX));
}

/** 动态日志条目（AEAD 明文形态；post/comment 携带内容指针，delete 携带墓碑目标，like/comment 携带目标动态）。 */
export interface FeedEntry {
  v: 1;
  type: "post" | "delete" | "like" | "comment";
  /** post/comment = 评论/动态内容块 CID；delete = 被删动态的块 CID；like = ""（点赞无内容块） */
  cid: string;
  /** like/comment 专用：被赞/被评动态的内容块 CID（进入签名域，篡改必被验签拒绝） */
  targetCid?: string;
  /** 作者 DID（验签公钥来源） */
  authorDid: string;
  /** post/comment 时为内容密钥（base58） */
  contentKey?: string;
  /** post/comment 时为 AEAD nonce（base58） */
  nonce?: string;
  at: number;
  /** 作者 IK 签名（64B，覆盖除 signature 外全部字段） */
  signature: Uint8Array;
}

export interface UnsignedFeedEntry {
  v: 1;
  type: "post" | "delete" | "like" | "comment";
  cid: string;
  /** like/comment 专用：被赞/被评动态的内容块 CID */
  targetCid?: string;
  authorDid: string;
  contentKey?: string;
  nonce?: string;
  at: number;
}

/** 被签消息（确定性编码，防拼接歧义；导出供测试与审计复核）。 */
export function feedEntryMessage(fields: UnsignedFeedEntry): Uint8Array {
  const head = concatBytes(
    utf8ToBytes(ENTRY_SIGNING_PREFIX),
    prefixed(fields.type),
    prefixed(fields.cid),
    prefixed(fields.authorDid),
    uint64(fields.at),
    // targetCid 有无标志位（1B，like 条目专用）与本体位于 contentKey 标志位之前；
    // 旧形态条目无 targetCid，标志位恒 0，编码确定不受影响。
    new Uint8Array([fields.targetCid !== undefined ? 1 : 0]),
    ...(fields.targetCid !== undefined ? [prefixed(fields.targetCid)] : []),
    new Uint8Array([fields.contentKey !== undefined ? 1 : 0]),
  );
  if (fields.contentKey === undefined || fields.nonce === undefined) return head;
  return concatBytes(head, prefixed(fields.contentKey), prefixed(fields.nonce));
}

function prefixed(text: string): Uint8Array {
  const bytes = utf8ToBytes(text);
  const out = new Uint8Array(2 + bytes.length);
  new DataView(out.buffer).setUint16(0, bytes.length, false);
  out.set(bytes, 2);
  return out;
}

function uint64(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

/** 由作者 IK 签发日志条目（签名后随圈密钥 AEAD 入日志信箱）。 */
export function makeMomentEntry(ikEdPrivateKey: Uint8Array, fields: UnsignedFeedEntry): FeedEntry {
  return { ...fields, signature: ed25519Sign(ikEdPrivateKey, feedEntryMessage(fields)) };
}

export function sealFeedEntry(momentKey: Uint8Array, entry: FeedEntry): Uint8Array {
  const nonce = randomBytes(AEAD_NONCE_LENGTH);
  const ciphertext = aeadEncrypt(momentKey, nonce, utf8ToBytes(JSON.stringify(entryToJson(entry))));
  return new Uint8Array([...nonce, ...ciphertext]);
}

/**
 * 解日志条目：AEAD（圈密钥，非好友在密文层即被拒）→ 严格解析 → **IK 验签**
 * （伪造条目在此被拒——加固批次 ②）。任一失败 throw，调用方安全丢弃。
 */
export function openFeedEntry(momentKey: Uint8Array, payload: Uint8Array): FeedEntry {
  if (payload.length < AEAD_NONCE_LENGTH + 16) throw new Error("动态日志条目过短");
  const nonce = payload.slice(0, AEAD_NONCE_LENGTH);
  const plaintext = aeadDecrypt(momentKey, nonce, payload.slice(AEAD_NONCE_LENGTH));
  const raw = JSON.parse(bytesToUtf8(plaintext)) as Record<string, unknown>;
  const entry = entryFromJson(raw);
  // 作者性验证：签名者必须与条目声明作者一致
  const signatureValid = ed25519Verify(entry.signature, feedEntryMessage(entry), didToEd25519PublicKey(entry.authorDid));
  if (!signatureValid) throw new Error("动态日志条目签名验证失败（伪造或篡改）");
  return entry;
}

function entryToJson(e: FeedEntry): Record<string, unknown> {
  return {
    v: e.v,
    type: e.type,
    cid: e.cid,
    authorDid: e.authorDid,
    at: e.at,
    ...(e.contentKey !== undefined && e.nonce !== undefined ? { contentKey: e.contentKey, nonce: e.nonce } : {}),
    ...(e.targetCid !== undefined ? { targetCid: e.targetCid } : {}),
    signature: base58Encode(e.signature),
  };
}

function entryFromJson(raw: Record<string, unknown>): FeedEntry {
  if (
    raw.v !== 1 ||
    (raw.type !== "post" && raw.type !== "delete" && raw.type !== "like" && raw.type !== "comment") ||
    typeof raw.cid !== "string" ||
    typeof raw.authorDid !== "string" ||
    typeof raw.signature !== "string"
  ) {
    throw new Error("动态日志条目字段非法");
  }
  if (typeof raw.at !== "number") throw new Error("动态日志条目时间字段非法");
  const entry: FeedEntry = {
    v: 1,
    type: raw.type,
    cid: raw.cid,
    authorDid: raw.authorDid,
    at: raw.at,
    signature: base58Decode(raw.signature),
  };
  if (typeof raw.contentKey === "string" && typeof raw.nonce === "string") {
    entry.contentKey = raw.contentKey;
    entry.nonce = raw.nonce;
  }
  // 解析层宽容：targetCid 为可选字段，post/delete 带了该字段值也照存——与 like 的一致性
  // 语义由签名域编码保证（有无标志位进入签名，篡改必被验签拒绝）。
  if (typeof raw.targetCid === "string") entry.targetCid = raw.targetCid;
  // 语义硬校验：点赞条目必须指向被赞动态（在验签前即拒绝，无需浪费验签）
  if (entry.type === "like" && entry.targetCid === undefined) throw new Error("点赞条目缺少目标动态");
  // 语义硬校验：评论条目必须指向被评动态且携带评论内容块
  if (entry.type === "comment" && (entry.targetCid === undefined || entry.contentKey === undefined || entry.nonce === undefined)) {
    throw new Error("评论条目缺少目标动态或内容指针");
  }
  // 语义硬校验：评论条目必须指向被评动态且携带评论内容块
  if (entry.type === "comment" && (entry.targetCid === undefined || entry.contentKey === undefined || entry.nonce === undefined)) {
    throw new Error("评论条目缺少目标动态或内容指针");
  }
  if (entry.signature.length !== SIGNATURE_LENGTH) throw new Error("动态日志条目签名长度非法");
  return entry;
}

/** 便捷谓词：是否为点赞条目（type 为 like 且携带被赞目标）。 */
export function isLikeEntry(entry: FeedEntry): boolean {
  return entry.type === "like" && entry.targetCid !== undefined;
}

/** 动态内容块明文（图片以引用形式与文字同块，图片本体另为独立 CAS 块）。 */
export interface MomentPayload {
  v: 1;
  text: string;
  attachment?: { cid: string; contentKey: string; nonce: string; name: string; size: number; mime: string };
}

/**
 * 创建动态内容块：独立内容密钥加密（encryptAttachment 模式）。
 * 返回可 PUT 的块与日志条目所需指针；图片块由调用方另行 encryptAttachment 上传。
 */
export function createMomentBlock(payload: MomentPayload): { block: Uint8Array; cid: string; contentKey: string; nonce: string } {
  const att = encryptAttachment(utf8ToBytes(JSON.stringify(payload)));
  return {
    block: att.ciphertext,
    cid: att.cid,
    contentKey: base58Encode(att.contentKey),
    nonce: base58Encode(att.nonce),
  };
}

/** 解动态内容块（好友侧：日志条目提供 cid/CK/nonce）。 */
export function openMomentBlock(block: Uint8Array, contentKey: string, nonce: string): MomentPayload {
  const plaintext = decryptAttachment({
    ciphertext: block,
    contentKey: base58Decode(contentKey),
    nonce: base58Decode(nonce),
  });
  const raw = JSON.parse(bytesToUtf8(plaintext)) as Record<string, unknown>;
  if (raw.v !== 1 || typeof raw.text !== "string") throw new Error("动态内容块字段非法");
  const attachment = raw.attachment as MomentPayload["attachment"] | undefined;
  return {
    v: 1,
    text: raw.text,
    ...(attachment && typeof attachment.cid === "string" ? { attachment } : {}),
  };
}
