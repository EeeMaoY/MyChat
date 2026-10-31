/**
 * 哈希：BLAKE3（EDS 内容寻址 CID 与通用哈希，设计报告 §6.1 / §11.2）。
 */
import { blake3 } from "@noble/hashes/blake3";

export const BLAKE3_OUTPUT_LENGTH = 32;

export function blake3Hash(data: Uint8Array): Uint8Array {
  return blake3(data);
}
