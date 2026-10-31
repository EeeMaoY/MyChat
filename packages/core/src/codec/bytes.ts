/**
 * 字节工具：同构（浏览器/Node）的字节拼接、比较与 UTF-8 转换。
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8ToBytes(text: string): Uint8Array {
  return textEncoder.encode(text);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** 常数时间比较（长度不同直接 false，不泄露前缀匹配信息）。 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
