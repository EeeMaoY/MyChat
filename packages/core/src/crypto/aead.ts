/**
 * AEAD 加密：XChaCha20-Poly1305（RFC 8439 ChaCha20-Poly1305 的 XNonce 扩展）。
 *
 * 选型说明（设计报告 §13 算法基线允许 ChaCha20-Poly1305）：
 * 24B 随机 nonce 使 nonce 碰撞概率可忽略，适合去中心化场景中
 * 无状态生成 nonce 的现实约束（AES-GCM 的 12B 随机 nonce 不可安全随机化）。
 *
 * 输出格式：ciphertext || tag(16B)；认证失败时 decrypt 抛错。
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";

export const AEAD_KEY_LENGTH = 32;
export const AEAD_NONCE_LENGTH = 24;
export const AEAD_TAG_LENGTH = 16;

export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array {
  const cipher = xchacha20poly1305(key, nonce, associatedData);
  return cipher.encrypt(plaintext);
}

/** 认证失败（密文被篡改 / key/nonce/AD 不匹配）时抛 Error。 */
export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array {
  const cipher = xchacha20poly1305(key, nonce, associatedData);
  return cipher.decrypt(ciphertext);
}
