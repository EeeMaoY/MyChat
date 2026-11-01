/**
 * Base64 编码（JSON 载体中二进制字段的统一文本形态：签名/nonce/密文指针）。
 * 实现取自 @scure/base（审计库）；标准字母表 + padding，与节点/客户端既有 base64 用法一致。
 */
import { base64 } from "@scure/base";

export function base64Encode(bytes: Uint8Array): string {
  return base64.encode(bytes);
}

export function base64Decode(text: string): Uint8Array {
  return base64.decode(text);
}
