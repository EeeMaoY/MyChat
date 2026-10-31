/**
 * Base58BTC 编码（DID 与 CID 的文本表示，设计报告 §11.2）。
 * 实现取自 @scure/base（审计库，与 @noble 同族）。
 */
import { base58 } from "@scure/base";

export function base58Encode(bytes: Uint8Array): string {
  return base58.encode(bytes);
}

export function base58Decode(text: string): Uint8Array {
  return base58.decode(text);
}
