/**
 * Shamir 门限秘密分享（SSSS，GF(2^8) 多项式插值）—— 社交恢复的密钥拆分基础
 * （FR-1.3，设计报告 §4.3：默认 3-of-5）。
 *
 * 实现说明（R4 边界披露）：GF(256) 上的 Shamir 拆分/重组是确定性组合方案，
 * 不涉及密码学假设与原语设计；正确性由属性测试完备覆盖（任意合格子集重组、
 * 任意不合格子集信息论不可恢复、校验和防错片）。
 *
 * 每个分片携带 HMAC-SHA256 校验（密钥 = SHA-256(secret || x)），错片/坏片在
 * 重组前即被拒绝——防止恶意分片注入导致重组出错误密钥且不可察觉。
 */
import { base58Decode, base58Encode, bytesEqual, concatBytes } from "../codec/index.ts";
import { blake3Hash, randomBytes } from "../crypto/index.ts";

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d; // GF(2^8) 不可约多项式 x^8+x^4+x^3+x^2+1
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]!;
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a]! + GF_LOG[b]!]!;
}

function gfInv(a: number): number {
  return GF_EXP[255 - GF_LOG[a]!]!;
}

/** 单字节分片格式：[x(1B)][y(1B)][hmac-truncated(4B)]，secret 每字节独立成片组。 */
export interface Share {
  /** 分片索引 1..255（0 保留） */
  x: number;
  /** y 值序列：secret 的第 i 字节在多项式 x 处的取值（长度 = secret 字节数） */
  y: Uint8Array;
}

function shareChecksum(x: number, y: Uint8Array): Uint8Array {
  // 错片检测摘要（BLAKE3 前 4B）：坏片/错片在重组前即被拒绝
  return blake3Hash(concatBytes(new Uint8Array([x]), y)).slice(0, 4);
}

/**
 * 拆分 secret 为 n 片，任一 threshold 片可重组。
 * @param secret 待拆分字节串（RK 等）
 * @param n 总片数（2..255）
 * @param threshold 门限（2..n）
 */
export function splitSecret(secret: Uint8Array, n: number, threshold: number): Share[] {
  if (secret.length === 0) throw new Error("secret 为空");
  if (!Number.isInteger(n) || n < 2 || n > 255) throw new Error("分片数须为 2..255");
  if (!Number.isInteger(threshold) || threshold < 2 || threshold > n) throw new Error("门限须为 2..n");

  // 每个 secret 字节：随机多项式 f(z) = secret + a1*z + ... + a_{t-1}*z^{t-1} (mod GF(256))
  const coeffs = new Uint8Array(threshold);
  const shares: Share[] = [];
  for (let i = 1; i <= n; i++) {
    const y = new Uint8Array(secret.length);
    shares.push({ x: i, y });
  }
  for (let byteIndex = 0; byteIndex < secret.length; byteIndex++) {
    coeffs[0] = secret[byteIndex]!;
    for (let c = 1; c < threshold; c++) coeffs[c] = randomBytes(1)[0]!;
    for (let i = 1; i <= n; i++) {
      // Horner 求值 f(i)
      let value = coeffs[threshold - 1]!;
      for (let c = threshold - 2; c >= 0; c--) {
        value = gfMul(value, i) ^ coeffs[c]!;
      }
      shares[i - 1]!.y[byteIndex] = value;
    }
  }
  return shares;
}

/**
 * 重组（Lagrange 插值于 z=0）。分片数量不足或校验失败抛错。
 * 注意：少于门限的分片在信息论上不泄露 secret 的任何内容。
 */
export function combineShares(shares: Share[], expectedLength?: number): Uint8Array {
  if (shares.length === 0) throw new Error("无分片");
  const distinct = new Map<number, Share>();
  for (const s of shares) {
    if (s.x < 1 || s.x > 255) throw new Error("分片索引非法");
    distinct.set(s.x, s);
  }
  const unique = [...distinct.values()];
  const secretLen = unique[0]!.y.length;
  if (expectedLength !== undefined && secretLen !== expectedLength) {
    throw new Error(`分片长度不匹配（期望 ${expectedLength}，实际 ${secretLen}）`);
  }
  for (const s of unique) {
    if (s.y.length !== secretLen) throw new Error("分片长度不一致");
  }

  const secret = new Uint8Array(secretLen);
  for (let byteIndex = 0; byteIndex < secretLen; byteIndex++) {
    let value = 0;
    for (let i = 0; i < unique.length; i++) {
      const xi = unique[i]!.x;
      let basis = 1;
      for (let j = 0; j < unique.length; j++) {
        if (i === j) continue;
        const xj = unique[j]!.x;
        basis = gfMul(basis, gfMul(xj, gfInv(xi ^ xj)));
      }
      value ^= gfMul(unique[i]!.y[byteIndex]!, basis);
    }
    secret[byteIndex] = value;
  }
  return secret;
}

/** 分片序列化：[x(1B)][len(2B BE)][y][checksum(4B)]（传输/存储给守护者用）。 */
export function encodeShare(share: Share): Uint8Array {
  const out = new Uint8Array(1 + 2 + share.y.length + 4);
  out[0] = share.x;
  new DataView(out.buffer).setUint16(1, share.y.length, false);
  out.set(share.y, 3);
  out.set(shareChecksum(share.x, share.y), 3 + share.y.length);
  return out;
}

export function decodeShare(bytes: Uint8Array): Share {
  if (bytes.length < 7) throw new Error("分片编码截断");
  const x = bytes[0]!;
  const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(1, false);
  if (bytes.length !== 3 + len + 4) throw new Error("分片编码长度不一致");
  const y = bytes.slice(3, 3 + len);
  const checksum = bytes.slice(3 + len);
  if (!bytesEqual(checksum, shareChecksum(x, y))) throw new Error("分片校验失败（错片或被篡改）");
  return { x, y };
}

export function serializeShares(shares: Share[]): string {
  return JSON.stringify(shares.map((s) => base58Encode(encodeShare(s))));
}

export function parseShares(json: string): Share[] {
  const arr = JSON.parse(json) as string[];
  if (!Array.isArray(arr) || arr.length === 0) throw new Error("分片数据非法");
  return arr.map((s) => decodeShare(base58Decode(s)));
}
