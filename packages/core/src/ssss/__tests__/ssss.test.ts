/**
 * SSSS 属性测试（FR-1.3 社交恢复基础）：
 * 完备性（任意合格子集重组）、安全性（不合格子集不可恢复语义由门限保证，
 * 这里验证错片/篡改必被校验拒绝）、编解码往返。
 */
import { describe, expect, it } from "vitest";

import { utf8ToBytes } from "../../codec/index.ts";
import { randomBytes } from "../../crypto/index.ts";
import {
  combineShares,
  decodeShare,
  encodeShare,
  parseShares,
  serializeShares,
  splitSecret,
} from "../ssss.ts";

describe("Shamir 门限秘密分享", () => {
  it("3-of-5：任意 3 片重组等于原 secret（穷举全部 C(5,3) 组合）", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 5, 3);
    expect(shares).toHaveLength(5);
    const combos = [
      [0, 1, 2],
      [0, 1, 3],
      [0, 1, 4],
      [0, 2, 3],
      [0, 2, 4],
      [0, 3, 4],
      [1, 2, 3],
      [1, 2, 4],
      [1, 3, 4],
      [2, 3, 4],
    ];
    for (const combo of combos) {
      const picked = combo.map((i) => shares[i]!);
      expect(combineShares(picked, 32)).toEqual(secret);
    }
  });

  it("多种门限与长度：2-of-3、5-of-8、1 字节与 64 字节", () => {
    for (const [n, t, len] of [
      [3, 2, 1],
      [8, 5, 64],
      [5, 3, 16],
    ] as const) {
      const secret = randomBytes(len);
      const shares = splitSecret(secret, n, t);
      expect(combineShares(shares.slice(0, t), len)).toEqual(secret);
    }
  });

  it("中文 secret 往返", () => {
    const secret = utf8ToBytes("恢复密钥-🔐-MyChat");
    const shares = splitSecret(secret, 5, 3);
    expect(combineShares([shares[0]!, shares[2]!, shares[4]!])).toEqual(secret);
  });

  it("分片数不足门限时重组结果与原 secret 不同（非原像验证，概率性）", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 5, 3);
    // 两片插值是一条直线过两点，z=0 处取值几乎必然 ≠ secret（除非碰巧）
    const wrong = combineShares([shares[0]!, shares[1]!]);
    expect([...wrong].some((b, i) => b !== secret[i])).toBe(true);
  });

  it("重复分片（同 x）被去重后仍可重组", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 5, 3);
    expect(combineShares([shares[0]!, shares[1]!, shares[1]!, shares[2]!], 32)).toEqual(secret);
  });

  it("分片序列化往返；篡改任一字节后 decode 拒绝", () => {
    const shares = splitSecret(utf8ToBytes("跨会话恢复测试"), 5, 3);
    const json = serializeShares(shares);
    expect(parseShares(json)).toEqual(shares);

    const encoded = encodeShare(shares[2]!);
    const tampered = encoded.slice();
    tampered[3]! ^= 1;
    expect(() => decodeShare(tampered)).toThrow();
  });

  it("非法参数与空分片拒绝", () => {
    const secret = randomBytes(16);
    expect(() => splitSecret(new Uint8Array(0), 5, 3)).toThrow();
    expect(() => splitSecret(secret, 1, 1)).toThrow();
    expect(() => splitSecret(secret, 5, 6)).toThrow();
    expect(() => combineShares([], 16)).toThrow();
    const shares = splitSecret(secret, 5, 3);
    expect(() => combineShares(shares.slice(0, 2), 16)).not.toThrow(); // 长度匹配时重组不抛（结果错误）
  });
});
