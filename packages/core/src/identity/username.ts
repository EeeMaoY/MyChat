/**
 * 用户名记录（UserNameRecord）—— 用户名是 IK 上的一层别名，
 * 映射由用户 IK 签名，客户端验签后才可采信（SR-5，设计报告 §4.1）。
 *
 * 签名覆盖确定性编码（防拼接歧义）：
 *   "mychat:name-v1:" || len(name)(2B 大端) || name(UTF-8) || did(UTF-8) || ktIndex(8B 大端)
 */
import { concatBytes, utf8ToBytes } from "../codec";
import { ed25519Sign, ed25519Verify } from "../crypto";
import { didToEd25519PublicKey } from "./did";
import type { UserNameRecord } from "../protocol/interfaces";

/** 域分隔前缀，含格式版本 v1 */
const USERNAME_SIGNING_PREFIX = "mychat:name-v1:";

/** name 长度前缀为 2B 大端，最长 65535 字节 */
const NAME_MAX_BYTES = 0xffff;

/**
 * 构造被签消息。len(name) 为 UTF-8 字节长度（自主设计决定：按字节而非码点计数，
 * 与线上的确定性编码一致）；ktIndex 按 8B 大端无符号整数编码。
 */
export function userNameRecordMessage(name: string, did: string, ktIndex: number): Uint8Array {
  const nameBytes = utf8ToBytes(name);
  if (nameBytes.length > NAME_MAX_BYTES) {
    throw new Error(`用户名过长：UTF-8 编码须不超过 ${NAME_MAX_BYTES} 字节`);
  }
  if (!Number.isSafeInteger(ktIndex) || ktIndex < 0) {
    throw new Error("ktIndex 须为非负安全整数");
  }
  const nameLength = new Uint8Array(2);
  new DataView(nameLength.buffer).setUint16(0, nameBytes.length, false);
  const ktIndexBytes = new Uint8Array(8);
  new DataView(ktIndexBytes.buffer).setBigUint64(0, BigInt(ktIndex), false);
  return concatBytes(
    utf8ToBytes(USERNAME_SIGNING_PREFIX),
    nameLength,
    nameBytes,
    utf8ToBytes(did),
    ktIndexBytes,
  );
}

/** 用 IK-ed 私钥对 (name, did, ktIndex) 的确定性编码签名。 */
export function signUserNameRecord(
  ikEdPrivateKey: Uint8Array,
  name: string,
  did: string,
  ktIndex: number,
): Uint8Array {
  return ed25519Sign(ikEdPrivateKey, userNameRecordMessage(name, did, ktIndex));
}

/** 签名并组装完整的用户名记录（供 Registry 注册，FR-1.2）。 */
export function makeUserNameRecord(
  ikEdPrivateKey: Uint8Array,
  name: string,
  did: string,
  ktIndex: number,
): UserNameRecord {
  return {
    name,
    did,
    ktIndex,
    signature: signUserNameRecord(ikEdPrivateKey, name, did, ktIndex),
  };
}

/** 验签 + name/did 非空 + did 格式合法；任一不满足返回 false。 */
export function verifyUserNameRecord(record: UserNameRecord): boolean {
  if (record.name.length === 0 || record.name.trim().length === 0) {
    return false;
  }
  let ikPublic: Uint8Array;
  try {
    ikPublic = didToEd25519PublicKey(record.did);
  } catch {
    return false;
  }
  let message: Uint8Array;
  try {
    message = userNameRecordMessage(record.name, record.did, record.ktIndex);
  } catch {
    return false;
  }
  return ed25519Verify(record.signature, message, ikPublic);
}
