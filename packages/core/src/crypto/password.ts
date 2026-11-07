/**
 * 口令密钥派生：scrypt（RFC 7914，内存硬 KDF，@noble/hashes 审计实现）。
 *
 * 用途（W1 密钥存储保护，加固批次 ①）：由用户口令派生 KEK（密钥加密密钥），
 * 用以在 IndexedDB 中包裹全部私钥材料——浏览器本地存储无系统级保护（W1 边界），
 * 口令包裹是 Web 客户端所能做到的最强本地防护（对抗"他人物理使用设备/拷库"）。
 *
 * 参数（OWASP 推荐）：N=2^15、r=8、p=1、dkLen=32 → ~32MB 内存、浏览器端数百毫秒。
 */
import { scrypt } from "@noble/hashes/scrypt";

export const PASSPHRASE_SALT_LENGTH = 32;
export const PASSPHRASE_KEK_LENGTH = 32;
/** scrypt 成本参数（N 以 2 的幂表示；调整会使既有 vault 不可解，视为格式版本变更） */
export const SCRYPT_N = 1 << 15;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;

/** 口令 → KEK（UTF-8 编码口令 + 随机盐 → 32B 密钥加密密钥）。同步计算（阻塞数百毫秒）。 */
export function deriveKekFromPassphrase(passphrase: string, salt: Uint8Array): Uint8Array {
  return scrypt(new TextEncoder().encode(passphrase), salt, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    dkLen: PASSPHRASE_KEK_LENGTH,
  });
}
