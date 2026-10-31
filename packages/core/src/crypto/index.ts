/**
 * 密码原语封装层 —— 全部协议模块唯一允许直接接触 @noble/* 的位置。
 *
 * 上层（identity/signal/envelope/eds）只经此处导出的领域 API 使用原语，
 * 以便未来切换实现（如 libsignal WASM）时改动面最小（TR-1 缓解）。
 */
export {
  AEAD_KEY_LENGTH,
  AEAD_NONCE_LENGTH,
  AEAD_TAG_LENGTH,
  aeadDecrypt,
  aeadEncrypt,
} from "./aead.ts";
export { openWithEd25519, sealToEd25519 } from "./ecies.ts";
export {
  BLAKE3_OUTPUT_LENGTH,
  blake3Hash,
} from "./hash.ts";
export { HKDF_OUTPUT_LENGTH, hkdfSha256 } from "./kdf.ts";
export {
  KEY_LENGTH,
  type KeyPair,
  ed25519PublicKeyFromPrivate,
  ed25519Sign,
  ed25519Verify,
  generateEd25519KeyPair,
  generateX25519KeyPair,
  randomBytes,
  x25519PublicKeyFromPrivate,
  x25519SharedSecret,
} from "./keys.ts";
