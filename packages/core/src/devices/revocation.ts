/**
 * 设备吊销（Device Revocation，FR-1.4，设计报告 §4.2）—— IK 签名的吊销声明。
 *
 * 吊销以 KT 事件（device-revoke）锚定 + 节点立即停发该设备的预密钥材料：
 * 被吊销设备不再收到新 OPK 分发，对端在设备集核验中发现变化后自动轮换会话
 * （联系人无需手动操作）。签名覆盖确定性编码（与 certificate.ts 同一惯例）：
 *   "mychat:device-revoke-v1:" || len(did)(2B) || did || len(dkId)(2B) || dkId || revokedAt(8B 大端)
 */
import { base58Decode, base64Decode, base64Encode } from "../codec/index.ts";
import { concatBytes, utf8ToBytes } from "../codec/index.ts";
import { KEY_LENGTH, ed25519Sign, ed25519Verify } from "../crypto/index.ts";
import { didToEd25519PublicKey } from "../identity/did.ts";

const REVOKE_SIGNING_PREFIX = "mychat:device-revoke-v1:";
const SIGNATURE_LENGTH = 64;

export interface DeviceRevocation {
  version: 1;
  did: string;
  /** 被吊销设备的 dkId（base58(DK 公钥)） */
  dkId: string;
  /** 吊销时间（ms epoch） */
  revokedAt: number;
  /** IK-ed 签名（64B） */
  signature: Uint8Array;
}

/** 被签消息（确定性编码；导出供测试与审计复核）。 */
export function deviceRevocationMessage(fields: Omit<DeviceRevocation, "signature" | "version">): Uint8Array {
  const times = new Uint8Array(8);
  new DataView(times.buffer).setBigUint64(0, BigInt(fields.revokedAt), false);
  return concatBytes(utf8ToBytes(REVOKE_SIGNING_PREFIX), prefixed(fields.did), prefixed(fields.dkId), times);
}

function prefixed(text: string): Uint8Array {
  const bytes = utf8ToBytes(text);
  const out = new Uint8Array(2 + bytes.length);
  new DataView(out.buffer).setUint16(0, bytes.length, false);
  out.set(bytes, 2);
  return out;
}

export interface MakeRevocationOptions {
  now?: number;
}

/** 由 IK 签发设备吊销声明。 */
export function makeDeviceRevocation(
  ikEdPrivateKey: Uint8Array,
  did: string,
  dkId: string,
  opts: MakeRevocationOptions = {},
): DeviceRevocation {
  const revokedAt = opts.now ?? Date.now();
  return {
    version: 1,
    did,
    dkId,
    revokedAt,
    signature: ed25519Sign(ikEdPrivateKey, deviceRevocationMessage({ did, dkId, revokedAt })),
  };
}

/** 验证吊销声明：签名/DID 一致/dkId 编码全部通过才有效。 */
export function verifyDeviceRevocation(revocation: DeviceRevocation): boolean {
  if (revocation.version !== 1) return false;
  if (!Number.isSafeInteger(revocation.revokedAt)) return false;
  let dkPublic: Uint8Array;
  try {
    dkPublic = base58Decode(revocation.dkId);
  } catch {
    return false;
  }
  if (dkPublic.length !== KEY_LENGTH) return false;
  if (revocation.signature.length !== SIGNATURE_LENGTH) return false;
  let ikPublic: Uint8Array;
  try {
    ikPublic = didToEd25519PublicKey(revocation.did);
  } catch {
    return false;
  }
  return ed25519Verify(
    revocation.signature,
    deviceRevocationMessage({ did: revocation.did, dkId: revocation.dkId, revokedAt: revocation.revokedAt }),
    ikPublic,
  );
}

// ----- JSON 编解码（KT payload / 端点传输；signature 为 base64） -----

export function encodeDeviceRevocationJson(revocation: DeviceRevocation): string {
  return JSON.stringify({
    version: revocation.version,
    did: revocation.did,
    dkId: revocation.dkId,
    revokedAt: revocation.revokedAt,
    signature: base64Encode(revocation.signature),
  });
}

export function decodeDeviceRevocationJson(text: string): DeviceRevocation {
  const raw = JSON.parse(text) as Record<string, unknown>;
  if (raw.version !== 1) throw new Error("吊销声明版本不识别");
  if (typeof raw.did !== "string" || typeof raw.dkId !== "string") throw new Error("吊销声明字段非法");
  if (typeof raw.revokedAt !== "number" || !Number.isSafeInteger(raw.revokedAt)) throw new Error("吊销声明时间字段非法");
  if (typeof raw.signature !== "string") throw new Error("吊销声明签名字段缺失");
  return {
    version: 1,
    did: raw.did,
    dkId: raw.dkId,
    revokedAt: raw.revokedAt,
    signature: base64Decode(raw.signature),
  };
}
