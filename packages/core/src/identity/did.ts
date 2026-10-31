/**
 * DID（去中心化标识符）—— did:mychat:<base58(IK Ed25519 公钥)>
 *
 * 自认证 DID：标识符本体即 Ed25519 身份密钥（IK）公钥的 base58 编码，
 * 无需注册机构即可全局唯一且可验证归属（设计报告 §4.1）。
 */
import { base58Decode, base58Encode } from "../codec/index.ts";
import { KEY_LENGTH } from "../crypto/index.ts";

/** DID 方法前缀（设计报告 §4.1，M0 冻结为 mychat 方法） */
export const DID_PREFIX = "did:mychat:";

/** IK Ed25519 公钥 → DID。长度不符时抛错（自认证不变量，防御性校验）。 */
export function didFromEd25519PublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== KEY_LENGTH) {
    throw new Error(`DID 派生失败：Ed25519 公钥长度须为 ${KEY_LENGTH} 字节，实际 ${publicKey.length}`);
  }
  return DID_PREFIX + base58Encode(publicKey);
}

/**
 * DID → IK Ed25519 公钥。
 * 前缀不符、base58 含非法字符或解码结果长度 ≠ 32B 时 throw。
 */
export function didToEd25519PublicKey(did: string): Uint8Array {
  if (!did.startsWith(DID_PREFIX)) {
    throw new Error(`DID 非法：前缀须为 "${DID_PREFIX}"`);
  }
  let publicKey: Uint8Array;
  try {
    publicKey = base58Decode(did.slice(DID_PREFIX.length));
  } catch {
    throw new Error("DID 非法：主体不是合法的 base58 编码");
  }
  if (publicKey.length !== KEY_LENGTH) {
    throw new Error(`DID 非法：解码公钥长度须为 ${KEY_LENGTH} 字节，实际 ${publicKey.length}`);
  }
  return publicKey;
}

/** DID 格式是否合法（不校验持有权，只校验可解析性与密钥长度）。 */
export function isValidDid(did: string): boolean {
  try {
    didToEd25519PublicKey(did);
    return true;
  } catch {
    return false;
  }
}
