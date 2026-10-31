/**
 * 已知答案测试（KAT）—— 对照 RFC 官方向量，锁定原语行为。
 * M0 Gate §3：X3DH/Double Ratchet 具备测试向量与已知答案测试的基线。
 */
import { hex } from "@scure/base";
import { describe, expect, it } from "vitest";

import { blake3Hash } from "../hash.ts";
import { hkdfSha256 } from "../kdf.ts";
import {
  ed25519PublicKeyFromPrivate,
  ed25519Sign,
  ed25519Verify,
  x25519PublicKeyFromPrivate,
  x25519SharedSecret,
} from "../keys.ts";

describe("X25519（RFC 7748 §6.1）", () => {
  // RFC 7748 A.6 Diffie-Hellman 秘密交换向量
  const alicePriv = hex.decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  );
  const alicePub = hex.decode(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  );
  const bobPriv = hex.decode(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  );
  const bobPub = hex.decode(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  );
  const shared = hex.decode(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  );

  it("公钥推导与 RFC 一致", () => {
    expect(hex.encode(x25519PublicKeyFromPrivate(alicePriv))).toBe(
      hex.encode(alicePub),
    );
    expect(hex.encode(x25519PublicKeyFromPrivate(bobPriv))).toBe(
      hex.encode(bobPub),
    );
  });

  it("双方共享秘密一致且与 RFC 一致", () => {
    const s1 = x25519SharedSecret(alicePriv, bobPub);
    const s2 = x25519SharedSecret(bobPriv, alicePub);
    expect(hex.encode(s1)).toBe(hex.encode(shared));
    expect(hex.encode(s2)).toBe(hex.encode(shared));
  });

  it("低阶点（全零输出）被拒绝", () => {
    // RFC 7748 §6.1 要求拒绝产生全零共享秘密的输入（防护小型子群攻击）
    const lowOrderPoint = new Uint8Array(32);
    expect(() => x25519SharedSecret(alicePriv, lowOrderPoint)).toThrow();
  });
});

describe("Ed25519（RFC 8032 §7.1）", () => {
  it("TEST 1：空消息", () => {
    const priv = hex.decode(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );
    const pub = hex.decode(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
    const sig = hex.decode(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    expect(hex.encode(ed25519PublicKeyFromPrivate(priv))).toBe(hex.encode(pub));
    expect(hex.encode(ed25519Sign(priv, new Uint8Array(0)))).toBe(hex.encode(sig));
    expect(ed25519Verify(sig, new Uint8Array(0), pub)).toBe(true);
    // 篡改消息必须验签失败
    expect(ed25519Verify(sig, new Uint8Array([1]), pub)).toBe(false);
  });

  it("TEST 2：单字节消息", () => {
    const priv = hex.decode(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    );
    const pub = hex.decode(
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
    const msg = hex.decode("72");
    const sig = hex.decode(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );
    expect(hex.encode(ed25519PublicKeyFromPrivate(priv))).toBe(hex.encode(pub));
    expect(hex.encode(ed25519Sign(priv, msg))).toBe(hex.encode(sig));
    expect(ed25519Verify(sig, msg, pub)).toBe(true);
  });
});

describe("HKDF-SHA-256（RFC 5869）", () => {
  it("Test Case 1", () => {
    const ikm = hex.decode("0b".repeat(22));
    const salt = hex.decode("000102030405060708090a0b0c");
    const info = hex.decode("f0f1f2f3f4f5f6f7f8f9");
    const okm = hex.decode(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
    const out = hkdfSha256(ikm, salt, info, 42);
    expect(hex.encode(out)).toBe(hex.encode(okm));
  });
});

describe("BLAKE3", () => {
  it("官方向量：空输入", () => {
    expect(hex.encode(blake3Hash(new Uint8Array(0)))).toBe(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
  });

  it("官方向量：abc", () => {
    expect(hex.encode(blake3Hash(new TextEncoder().encode("abc")))).toBe(
      "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    );
  });
});
