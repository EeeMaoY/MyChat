/**
 * X3DH 预密钥束（PreKeyBundle）—— 构造 / 验证 / 确定性编解码（设计报告 §5.2）。
 *
 * bundle 经 EDS 公开区分发（存放与分发由 S2 节点负责，本模块只管构造/验证/编解码）。
 * 发起方在 X3DH 握手前必须验签：IK-ed 签名同时覆盖 IK-x（身份 DH 绑定）与 SPK（签名预密钥）。
 */
import { concatBytes, utf8ToBytes } from "../codec/index.ts";
import { type KeyPair, KEY_LENGTH, blake3Hash, ed25519Sign, ed25519Verify } from "../crypto/index.ts";
import { didToEd25519PublicKey } from "./did.ts";
import { type Identity, ikxBindingMessage } from "./identity.ts";

/** SPK 绑定签名的域分隔前缀（§5.2） */
export const SPK_BINDING_PREFIX = "mychat:spk:";

/** Ed25519 签名固定 64 字节 */
const SIGNATURE_LENGTH = 64;

export interface PreKeyBundle {
  /** 所属身份的 DID */
  did: string;
  /** 32B X25519 身份 DH 公钥 */
  ikxPublic: Uint8Array;
  /** IK-ed 签 "mychat:ikx-bind:" || ikxPublic（与 identity.ikxBindingSig 同构） */
  ikxSignature: Uint8Array;
  /** 32B 签名预密钥（X25519） */
  spkPublic: Uint8Array;
  /** IK-ed 签 "mychat:spk:" || spkPublic */
  spkSignature: Uint8Array;
  /** SPK 过期时间（ms epoch） */
  spkExpiresAt: number;
  /** 一次性预密钥编号 */
  opkId: number;
  /** 32B 一次性预密钥（X25519） */
  opkPublic: Uint8Array;
}

/**
 * OPK 编号 = OPK 公钥的 blake3 指纹前 4 字节（大端 uint32）。
 *
 * 自主设计决定：OPK 公钥不参与签名（Signal 同样如此，篡改最终由 X3DH 共享秘密
 * 失配兜底），此处将 opkId 绑定为公钥指纹，使 bundle 对 OPK 也具备即时的篡改
 * 可见性——verifyPreKeyBundle 可直接拒绝被改动的 OPK，而非等到握手时失败。
 */
export function deriveOpkId(opkPublic: Uint8Array): number {
  if (opkPublic.length !== KEY_LENGTH) {
    throw new Error(`OPK 公钥长度须为 ${KEY_LENGTH} 字节，实际 ${opkPublic.length}`);
  }
  const digest = blake3Hash(opkPublic);
  const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);
  return view.getUint32(0, false);
}

/**
 * 由身份签发预密钥束。ttlMs 从 Date.now() 起算，spkExpiresAt = now + ttlMs。
 * opk.id 必须等于 deriveOpkId(opk.publicKey)（见 deriveOpkId 的设计决定）。
 */
export function issuePreKeyBundle(
  identity: Identity,
  spk: KeyPair,
  opk: KeyPair & { id: number },
  ttlMs: number,
): PreKeyBundle {
  if (spk.publicKey.length !== KEY_LENGTH) {
    throw new Error(`SPK 公钥长度须为 ${KEY_LENGTH} 字节`);
  }
  const canonicalOpkId = deriveOpkId(opk.publicKey);
  if (opk.id !== canonicalOpkId) {
    throw new Error("opk.id 与公钥指纹不一致：OPK 编号须由 deriveOpkId 派生");
  }
  return {
    did: identity.did,
    ikxPublic: identity.ikX.publicKey,
    ikxSignature: identity.ikxBindingSig,
    spkPublic: spk.publicKey,
    spkSignature: ed25519Sign(
      identity.ikEd.privateKey,
      concatBytes(utf8ToBytes(SPK_BINDING_PREFIX), spk.publicKey),
    ),
    spkExpiresAt: Date.now() + ttlMs,
    opkId: canonicalOpkId,
    opkPublic: opk.publicKey,
  };
}

/** SPK 绑定签名的被签消息："mychat:spk:" || spkPublic */
function spkBindingMessage(spkPublic: Uint8Array): Uint8Array {
  return concatBytes(utf8ToBytes(SPK_BINDING_PREFIX), spkPublic);
}

/**
 * 验证预密钥束：
 * 1. did 格式合法；
 * 2. ikxSignature 与 spkSignature 均能被 did 对应的 IK-ed 公钥验签通过；
 * 3. 各公钥长度 32B、签名长度 64B；
 * 4. spkExpiresAt 未过期（以 Date.now() 为准）；
 * 5. opkId 与 opkPublic 指纹一致。
 */
export function verifyPreKeyBundle(bundle: PreKeyBundle): boolean {
  if (
    bundle.ikxPublic.length !== KEY_LENGTH ||
    bundle.spkPublic.length !== KEY_LENGTH ||
    bundle.opkPublic.length !== KEY_LENGTH ||
    bundle.ikxSignature.length !== SIGNATURE_LENGTH ||
    bundle.spkSignature.length !== SIGNATURE_LENGTH
  ) {
    return false;
  }
  let ikPublic: Uint8Array;
  try {
    ikPublic = didToEd25519PublicKey(bundle.did);
  } catch {
    return false;
  }
  if (!ed25519Verify(bundle.ikxSignature, ikxBindingMessage(bundle.ikxPublic), ikPublic)) {
    return false;
  }
  if (!ed25519Verify(bundle.spkSignature, spkBindingMessage(bundle.spkPublic), ikPublic)) {
    return false;
  }
  if (!(bundle.spkExpiresAt > Date.now())) {
    return false;
  }
  if (bundle.opkId !== deriveOpkId(bundle.opkPublic)) {
    return false;
  }
  return true;
}

// ---- 确定性二进制编码（字段顺序固定 + 长度前缀，供网络/存储传输） ----
//
// 布局 v1：
//   magic "MCPB"(4B) + 版本(1B)
//   长度前缀字段（2B 大端长度 + 内容）：
//     did(变长 UTF-8) | ikxPublic(32) | ikxSignature(64) | spkPublic(32) | spkSignature(64) | opkPublic(32)
//   定长数值：spkExpiresAt(8B 大端 uint64) + opkId(4B 大端 uint32)
// 解码器对 magic、版本、每个长度前缀、总长与 did 格式做严格校验，任何畸形输入 throw。

const BUNDLE_MAGIC = utf8ToBytes("MCPB");
const BUNDLE_VERSION = 1;

function writeLengthPrefixed(target: Uint8Array, offset: number, bytes: Uint8Array): number {
  const view = new DataView(target.buffer);
  view.setUint16(offset, bytes.length, false);
  target.set(bytes, offset + 2);
  return offset + 2 + bytes.length;
}

/** 确定性二进制编码：同一 bundle 编码结果逐字节一致。 */
export function encodePreKeyBundle(bundle: PreKeyBundle): Uint8Array {
  if (!Number.isSafeInteger(bundle.spkExpiresAt) || bundle.spkExpiresAt < 0) {
    throw new Error("预密钥束编码失败：spkExpiresAt 须为非负安全整数");
  }
  if (!Number.isSafeInteger(bundle.opkId) || bundle.opkId < 0 || bundle.opkId > 0xffffffff) {
    throw new Error("预密钥束编码失败：opkId 须为 uint32");
  }
  const didBytes = utf8ToBytes(bundle.did);
  const prefixed = [didBytes, bundle.ikxPublic, bundle.ikxSignature, bundle.spkPublic, bundle.spkSignature, bundle.opkPublic];
  const total =
    BUNDLE_MAGIC.length + 1 + 8 + 4 + prefixed.reduce((sum, part) => sum + 2 + part.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  out.set(BUNDLE_MAGIC, offset);
  offset += BUNDLE_MAGIC.length;
  view.setUint8(offset, BUNDLE_VERSION);
  offset += 1;
  offset = writeLengthPrefixed(out, offset, didBytes);
  offset = writeLengthPrefixed(out, offset, bundle.ikxPublic);
  offset = writeLengthPrefixed(out, offset, bundle.ikxSignature);
  offset = writeLengthPrefixed(out, offset, bundle.spkPublic);
  offset = writeLengthPrefixed(out, offset, bundle.spkSignature);
  view.setBigUint64(offset, BigInt(bundle.spkExpiresAt), false);
  offset += 8;
  view.setUint32(offset, bundle.opkId, false);
  offset += 4;
  offset = writeLengthPrefixed(out, offset, bundle.opkPublic);
  if (offset !== total) {
    throw new Error("预密钥束编码失败：内部长度计算错误");
  }
  return out;
}

function readLengthPrefixed(
  bytes: Uint8Array,
  view: DataView,
  offset: number,
  expectedLength: number | null,
  fieldName: string,
): { value: Uint8Array; next: number } {
  if (offset + 2 > bytes.length) {
    throw new Error(`预密钥束解码失败：${fieldName} 长度前缀越界`);
  }
  const length = view.getUint16(offset, false);
  if (expectedLength !== null && length !== expectedLength) {
    throw new Error(`预密钥束解码失败：${fieldName} 长度须为 ${expectedLength}，实际 ${length}`);
  }
  if (offset + 2 + length > bytes.length) {
    throw new Error(`预密钥束解码失败：${fieldName} 内容越界`);
  }
  return { value: bytes.slice(offset + 2, offset + 2 + length), next: offset + 2 + length };
}

/** 确定性二进制解码：magic/版本/长度前缀/总长/did 格式任一不符即 throw。 */
export function decodePreKeyBundle(bytes: Uint8Array): PreKeyBundle {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerLength = BUNDLE_MAGIC.length + 1;
  if (bytes.length < headerLength) {
    throw new Error("预密钥束解码失败：输入过短");
  }
  for (let i = 0; i < BUNDLE_MAGIC.length; i++) {
    if (bytes[i] !== BUNDLE_MAGIC[i]) {
      throw new Error("预密钥束解码失败：magic 不匹配");
    }
  }
  if (view.getUint8(BUNDLE_MAGIC.length) !== BUNDLE_VERSION) {
    throw new Error("预密钥束解码失败：不支持的版本");
  }
  let offset = headerLength;
  // did 为变长字段：解码后校验其格式（前缀 + base58 + 32B 公钥）
  const did = readLengthPrefixed(bytes, view, offset, null, "did");
  offset = did.next;
  const ikxPublic = readLengthPrefixed(bytes, view, offset, KEY_LENGTH, "ikxPublic");
  offset = ikxPublic.next;
  const ikxSignature = readLengthPrefixed(bytes, view, offset, SIGNATURE_LENGTH, "ikxSignature");
  offset = ikxSignature.next;
  const spkPublic = readLengthPrefixed(bytes, view, offset, KEY_LENGTH, "spkPublic");
  offset = spkPublic.next;
  const spkSignature = readLengthPrefixed(bytes, view, offset, SIGNATURE_LENGTH, "spkSignature");
  offset = spkSignature.next;
  if (offset + 8 + 4 > bytes.length) {
    throw new Error("预密钥束解码失败：数值字段越界");
  }
  const spkExpiresAt = view.getBigUint64(offset, false);
  offset += 8;
  const opkId = view.getUint32(offset, false);
  offset += 4;
  const opkPublic = readLengthPrefixed(bytes, view, offset, KEY_LENGTH, "opkPublic");
  offset = opkPublic.next;
  if (offset !== bytes.length) {
    throw new Error("预密钥束解码失败：存在尾部多余字节");
  }
  const didText = new TextDecoder().decode(did.value);
  try {
    didToEd25519PublicKey(didText);
  } catch {
    throw new Error("预密钥束解码失败：did 字段格式非法");
  }
  return {
    did: didText,
    ikxPublic: ikxPublic.value,
    ikxSignature: ikxSignature.value,
    spkPublic: spkPublic.value,
    spkSignature: spkSignature.value,
    spkExpiresAt: Number(spkExpiresAt),
    opkId,
    opkPublic: opkPublic.value,
  };
}
