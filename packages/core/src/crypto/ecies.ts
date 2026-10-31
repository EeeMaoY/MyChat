/**
 * ECIES 公钥加密（以 Ed25519 身份公钥为收件方）—— 恢复分片等"发给特定身份"的密文封装。
 *
 * 方案：临时 X25519 密钥对 + 收件方 Ed25519 公钥的 Montgomery 映射做 ECDH
 * → HKDF 派生密钥 → XChaCha20-Poly1305。输出：[ephPub(32B)][nonce(24B)][ct]。
 * 只有持有对应 Ed25519 私钥的一方可以解开。
 */
import { edwardsToMontgomeryPriv, edwardsToMontgomeryPub, x25519 } from "@noble/curves/ed25519";

import {
  AEAD_KEY_LENGTH,
  AEAD_NONCE_LENGTH,
  aeadDecrypt,
  aeadEncrypt,
  hkdfSha256,
  x25519SharedSecret,
} from "./index.ts";

const SEAL_INFO = "mychat:seal:v1";
const PUB_LEN = 32;

/** 以 Ed25519 公钥封装明文；输出 [ephPub||nonce||ct]。 */
export function sealToEd25519(recipientPubEd: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (recipientPubEd.length !== PUB_LEN) throw new Error("收件方公钥长度非法");
  const eph = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(eph);
  const recipientMont = edwardsToMontgomeryPub(recipientPubEd);
  const shared = x25519SharedSecret(eph, recipientMont);
  const key = hkdfSha256(shared, new Uint8Array(32), SEAL_INFO, AEAD_KEY_LENGTH);
  const nonce = new Uint8Array(AEAD_NONCE_LENGTH);
  crypto.getRandomValues(nonce);
  const ct = aeadEncrypt(key, nonce, plaintext, ephPub);
  return new Uint8Array([...ephPub, ...nonce, ...ct]);
}

/** 以 Ed25519 私钥开启；认证失败抛错。 */
export function openWithEd25519(recipientPrivEd: Uint8Array, sealed: Uint8Array): Uint8Array {
  if (sealed.length < PUB_LEN + AEAD_NONCE_LENGTH + 16) throw new Error("封装数据截断");
  const ephPub = sealed.slice(0, PUB_LEN);
  const nonce = sealed.slice(PUB_LEN, PUB_LEN + AEAD_NONCE_LENGTH);
  const ct = sealed.slice(PUB_LEN + AEAD_NONCE_LENGTH);
  const recipientMont = edwardsToMontgomeryPriv(recipientPrivEd);
  const shared = x25519SharedSecret(recipientMont, ephPub);
  const key = hkdfSha256(shared, new Uint8Array(32), SEAL_INFO, AEAD_KEY_LENGTH);
  return aeadDecrypt(key, nonce, ct, ephPub);
}
