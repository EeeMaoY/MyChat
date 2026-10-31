/**
 * AEAD 行为测试：往返正确性、关联数据绑定、篡改必败。
 * XChaCha20-Poly1305 无官方单测向量接入点（库自身审计覆盖），
 * 此处锁定领域封装的行为契约。
 */
import { describe, expect, it } from "vitest";

import {
  AEAD_KEY_LENGTH,
  AEAD_NONCE_LENGTH,
  AEAD_TAG_LENGTH,
  aeadDecrypt,
  aeadEncrypt,
} from "../aead.ts";
import { randomBytes } from "../random.ts";

describe("XChaCha20-Poly1305 封装", () => {
  it("加密-解密往返（含关联数据）", () => {
    const key = randomBytes(AEAD_KEY_LENGTH);
    const nonce = randomBytes(AEAD_NONCE_LENGTH);
    const ad = randomBytes(32);
    const plaintext = new TextEncoder().encode("MyChat E2EE message 0.1");

    const ciphertext = aeadEncrypt(key, nonce, plaintext, ad);
    expect(ciphertext.length).toBe(plaintext.length + AEAD_TAG_LENGTH);
    expect(new TextDecoder().decode(aeadDecrypt(key, nonce, ciphertext, ad))).toBe(
      "MyChat E2EE message 0.1",
    );
  });

  it("无关联数据往返", () => {
    const key = randomBytes(AEAD_KEY_LENGTH);
    const nonce = randomBytes(AEAD_NONCE_LENGTH);
    const plaintext = randomBytes(1024);
    const ciphertext = aeadEncrypt(key, nonce, plaintext);
    expect(aeadDecrypt(key, nonce, ciphertext)).toEqual(plaintext);
  });

  it("关联数据不匹配必须解密失败（密文与上下文绑定）", () => {
    const key = randomBytes(AEAD_KEY_LENGTH);
    const nonce = randomBytes(AEAD_NONCE_LENGTH);
    const ciphertext = aeadEncrypt(key, nonce, randomBytes(64), new Uint8Array([1, 2, 3]));
    expect(() => aeadDecrypt(key, nonce, ciphertext, new Uint8Array([1, 2, 4]))).toThrow();
    expect(() => aeadDecrypt(key, nonce, ciphertext)).toThrow();
  });

  it("密文单字节篡改必须解密失败（完整性，SR-4）", () => {
    const key = randomBytes(AEAD_KEY_LENGTH);
    const nonce = randomBytes(AEAD_NONCE_LENGTH);
    const ciphertext = aeadEncrypt(key, nonce, randomBytes(64));
    ciphertext[0]! ^= 1;
    expect(() => aeadDecrypt(key, nonce, ciphertext)).toThrow();
  });

  it("密钥或 nonce 不匹配必须解密失败", () => {
    const nonce = randomBytes(AEAD_NONCE_LENGTH);
    const ciphertext = aeadEncrypt(randomBytes(AEAD_KEY_LENGTH), nonce, randomBytes(64));
    expect(() => aeadDecrypt(randomBytes(AEAD_KEY_LENGTH), nonce, ciphertext)).toThrow();
    const key = randomBytes(AEAD_KEY_LENGTH);
    expect(() => aeadDecrypt(key, randomBytes(AEAD_NONCE_LENGTH), ciphertext)).toThrow();
  });

  it("同 key 同 nonce 对不同明文的密文不同（确定性加密不可复用 nonce 的前提）", () => {
    const key = randomBytes(AEAD_KEY_LENGTH);
    const nonce = randomBytes(AEAD_NONCE_LENGTH);
    const c1 = aeadEncrypt(key, nonce, randomBytes(64));
    const c2 = aeadEncrypt(key, nonce, randomBytes(64));
    expect(c1).not.toEqual(c2);
  });
});
