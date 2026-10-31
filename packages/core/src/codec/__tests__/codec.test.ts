import { describe, expect, it } from "vitest";

import { base58Decode, base58Encode } from "../base58";
import { bytesEqual, bytesToUtf8, concatBytes, utf8ToBytes } from "../bytes";

describe("base58", () => {
  it("编解码往返（空、边界值、随机长度）", () => {
    const cases = [new Uint8Array(0), new Uint8Array([0]), new Uint8Array([0, 0, 1])];
    for (let len = 1; len <= 64; len++) {
      cases.push(crypto.getRandomValues(new Uint8Array(len)));
    }
    for (const bytes of cases) {
      expect(base58Decode(base58Encode(bytes))).toEqual(bytes);
    }
  });

  it("已知向量：全零前导字节保留（base58 经典性质）", () => {
    expect(base58Encode(new Uint8Array([0, 0, 1]))).toBe("112");
  });
});

describe("bytes 工具", () => {
  it("concatBytes 拼接多段", () => {
    expect(concatBytes(new Uint8Array([1]), new Uint8Array(), new Uint8Array([2, 3]))).toEqual(
      new Uint8Array([1, 2, 3]),
    );
  });

  it("bytesEqual 常数时间比较语义正确", () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });

  it("UTF-8 往返（含中文与 emoji）", () => {
    const text = "MyChat 端到端加密 🔒";
    expect(bytesToUtf8(utf8ToBytes(text))).toBe(text);
  });
});
