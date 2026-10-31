/**
 * 密钥派生：HKDF-SHA-256（RFC 5869）。
 *
 * 约定：info 参数统一传入字符串，由本模块做 UTF-8 编码并拼接
 * 域分隔前缀（domain separation），防止跨协议场景的密钥复用。
 */
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

export const HKDF_OUTPUT_LENGTH = 32;

export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string | Uint8Array,
  length: number = HKDF_OUTPUT_LENGTH,
): Uint8Array {
  const infoBytes = typeof info === "string" ? new TextEncoder().encode(info) : info;
  return hkdf(sha256, ikm, salt, infoBytes, length);
}
