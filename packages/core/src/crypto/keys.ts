/**
 * 非对称原语封装：Ed25519（签名）与 X25519（密钥协商）。
 *
 * 算法基线（设计报告 §13）：Ed25519 / X25519，实现取自经审计的 @noble/curves。
 * 密钥长度：私钥 32B，公钥 32B；X25519 共享秘密 32B。
 */
import { ed25519, x25519 } from "@noble/curves/ed25519";

import { randomBytes } from "./random";

export const KEY_LENGTH = 32;

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateEd25519KeyPair(): KeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) };
}

export function generateX25519KeyPair(): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function ed25519PublicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey);
}

export function x25519PublicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

/** Ed25519 签名（64B）。 */
export function ed25519Sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

/** Ed25519 验签；签名或公钥非法时返回 false（不抛异常，便于协议层做拒收计数）。 */
export function ed25519Verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * X25519 ECDH 共享秘密（32B）。
 * 低阶点（全零输出）由底层实现拒绝并抛错——这是 RFC 7748 要求的防护，
 * 调用方不应吞掉该异常（说明对端公钥恶意）。
 */
export function x25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

/** 生成任意长度随机字节（预密钥 ID、nonce 等场景）。 */
export { randomBytes };
