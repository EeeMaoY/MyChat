/**
 * 附件端到端加密（FR-5.3 子集，M1 计划 §3.4）。
 *
 * 流程：随机 CK + XChaCha20-Poly1305 加密内容 → CID = base58(BLAKE3(密文))
 * 入公共 CAS（节点只见密文，SR-1 不变）；CK 与 nonce 放入 E2EE 会话消息体
 * （消息本身端到端加密，CK 的保密性与会话等价）。
 *
 * 注意：随机 nonce ⇒ 相同内容重复加密产生不同 CID（语义安全），CAS 幂等
 * 不适用于附件——同文件重复发送会各存一份，属预期行为。
 *
 * 元数据（文件名/大小/mime）由调用方放入消息体；它们对节点不可见。
 */
import { AEAD_KEY_LENGTH, AEAD_NONCE_LENGTH, aeadDecrypt, aeadEncrypt, blake3Hash, randomBytes } from "../crypto/index.ts";
import { base58Encode } from "../codec/index.ts";

export interface EncryptedAttachment {
  /** CAS 存取键：base58(BLAKE3(密文)) */
  cid: string;
  /** 密文（含 AEAD tag） */
  ciphertext: Uint8Array;
  /** 内容密钥（32B）——只进入 E2EE 会话消息体 */
  contentKey: Uint8Array;
  /** AEAD nonce（24B） */
  nonce: Uint8Array;
}

/** 加密附件；空内容拒绝。 */
export function encryptAttachment(data: Uint8Array): EncryptedAttachment {
  if (data.length === 0) throw new Error("附件内容为空");
  const contentKey = randomBytes(AEAD_KEY_LENGTH);
  const nonce = randomBytes(AEAD_NONCE_LENGTH);
  const ciphertext = aeadEncrypt(contentKey, nonce, data);
  return { cid: base58Encode(blake3Hash(ciphertext)), ciphertext, contentKey, nonce };
}

/** 解密附件（认证失败/密钥不匹配抛错）。 */
export function decryptAttachment(
  att: Pick<EncryptedAttachment, "ciphertext" | "contentKey" | "nonce">,
): Uint8Array {
  return aeadDecrypt(att.contentKey, att.nonce, att.ciphertext);
}

/** 校验密文与 CID 一致（取回块后的完整性自检，CAS 防替换的客户端面）。 */
export function verifyAttachmentCid(att: Pick<EncryptedAttachment, "cid" | "ciphertext">): boolean {
  return base58Encode(blake3Hash(att.ciphertext)) === att.cid;
}
