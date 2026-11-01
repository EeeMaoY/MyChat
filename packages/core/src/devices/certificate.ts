/**
 * 设备凭证（Device Certificate，FR-1.4，设计报告 §4.2）—— 多设备的设备身份层。
 *
 * 模型（设计报告 §4.1 分层密钥）：IK 是长期身份，DK（Ed25519）是设备的签名密钥；
 * 设备凭证由 IK 签发，覆盖 {did, dkId, label, 有效期}，经 KT 日志锚定后
 * 所有联系人客户端可自动核验（SR-5：节点存储不代表可信，本地验签为准）。
 *
 * 签名覆盖确定性编码（防拼接歧义，与 username.ts 同一惯例）：
 *   "mychat:device-cert-v1:" || len(did)(2B) || did || len(dkId)(2B) || dkId
 *     || len(label)(2B) || label || issuedAt(8B 大端) || expiresAt(8B 大端)
 *
 * 边界（M2-S10 如实披露）：当前 Web 客户端每台设备持有 IK 私钥副本（Level0），
 * DK 凭证承载设备生命周期（登记/列表/吊销/KT 锚定/联系人核验）；
 * "DK 作为实际加密操作者（SPK 由 DK 签名、IK 不落端）"需 bundle wire v2，属后续里程碑。
 */
import { base58Decode, base58Encode, base64Decode, base64Encode } from "../codec/index.ts";
import { concatBytes, utf8ToBytes } from "../codec/index.ts";
import { KEY_LENGTH, ed25519Sign, ed25519Verify } from "../crypto/index.ts";
import { didToEd25519PublicKey } from "../identity/did.ts";

const CERT_SIGNING_PREFIX = "mychat:device-cert-v1:";
const SIGNATURE_LENGTH = 64;
/** dkId 编码校验用：base58 解码后须为 32B 公钥 */
const LABEL_MAX_BYTES = 512;

export interface DeviceCertificate {
  version: 1;
  /** 属主身份 DID */
  did: string;
  /** 设备标识 = base58(DK-ed 公钥) */
  dkId: string;
  /** 设备描述（用户可读，如 "MacBook · Chrome"） */
  label: string;
  /** 签发时间（ms epoch） */
  issuedAt: number;
  /** 过期时间（ms epoch，到期后节点停止分发该设备材料；续期 = 重新登记） */
  expiresAt: number;
  /** IK-ed 签名（64B） */
  signature: Uint8Array;
}

/** 被签消息（确定性编码；导出供测试与审计复核）。 */
export function deviceCertificateMessage(fields: Omit<DeviceCertificate, "signature" | "version">): Uint8Array {
  const didBytes = utf8ToBytes(fields.did);
  const dkIdBytes = utf8ToBytes(fields.dkId);
  const labelBytes = utf8ToBytes(fields.label);
  if (labelBytes.length > LABEL_MAX_BYTES) {
    throw new Error(`设备描述过长（UTF-8 编码须不超过 ${LABEL_MAX_BYTES} 字节）`);
  }
  const times = new Uint8Array(16);
  const view = new DataView(times.buffer);
  view.setBigUint64(0, BigInt(fields.issuedAt), false);
  view.setBigUint64(8, BigInt(fields.expiresAt), false);
  return concatBytes(
    utf8ToBytes(CERT_SIGNING_PREFIX),
    prefix(didBytes),
    prefix(dkIdBytes),
    prefix(labelBytes),
    times,
  );
}

function prefix(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + bytes.length);
  new DataView(out.buffer).setUint16(0, bytes.length, false);
  out.set(bytes, 2);
  return out;
}

export interface IssueDeviceCertificateOptions {
  /** 签发基准时间（默认 Date.now()；测试注入固定时钟） */
  now?: number;
}

/** 由 IK 签发设备凭证。dkPublic 为设备 DK-ed 公钥（32B）。 */
export function makeDeviceCertificate(
  ikEdPrivateKey: Uint8Array,
  did: string,
  dkPublic: Uint8Array,
  label: string,
  ttlMs: number,
  opts: IssueDeviceCertificateOptions = {},
): DeviceCertificate {
  const now = opts.now ?? Date.now();
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
    throw new Error("凭证有效期须为正整数毫秒");
  }
  if (dkPublic.length !== KEY_LENGTH) {
    throw new Error(`DK 公钥长度须为 ${KEY_LENGTH} 字节`);
  }
  const issuedAt = now;
  const expiresAt = now + ttlMs;
  return {
    version: 1,
    did,
    dkId: base58Encode(dkPublic),
    label,
    issuedAt,
    expiresAt,
    signature: ed25519Sign(ikEdPrivateKey, deviceCertificateMessage({ did, dkId: base58Encode(dkPublic), label, issuedAt, expiresAt })),
  };
}

/** 验证设备凭证：签名/DID 一致/dkId 编码/时间窗全部通过才有效（SR-5 客户端本地执行）。 */
export function verifyDeviceCertificate(cert: DeviceCertificate, opts: IssueDeviceCertificateOptions = {}): boolean {
  const now = opts.now ?? Date.now();
  if (cert.version !== 1) return false;
  if (
    !Number.isSafeInteger(cert.issuedAt) ||
    !Number.isSafeInteger(cert.expiresAt) ||
    cert.issuedAt >= cert.expiresAt
  ) {
    return false;
  }
  if (cert.label.length === 0 || utf8ToBytes(cert.label).length > LABEL_MAX_BYTES) return false;
  // 时间窗：issuedAt 起生效，expiresAt 当刻即失效
  if (!(cert.issuedAt <= now && now < cert.expiresAt)) return false;
  let dkPublic: Uint8Array;
  try {
    dkPublic = base58Decode(cert.dkId);
  } catch {
    return false;
  }
  if (dkPublic.length !== KEY_LENGTH) return false;
  if (cert.signature.length !== SIGNATURE_LENGTH) return false;
  let ikPublic: Uint8Array;
  try {
    ikPublic = didToEd25519PublicKey(cert.did);
  } catch {
    return false;
  }
  return ed25519Verify(
    cert.signature,
    deviceCertificateMessage({ did: cert.did, dkId: cert.dkId, label: cert.label, issuedAt: cert.issuedAt, expiresAt: cert.expiresAt }),
    ikPublic,
  );
}

// ----- JSON 编解码（KT payload / 节点端点 / 客户端传输统一形态；signature 为 base64） -----

export function encodeDeviceCertificateJson(cert: DeviceCertificate): string {
  return JSON.stringify({
    version: cert.version,
    did: cert.did,
    dkId: cert.dkId,
    label: cert.label,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt,
    signature: base64Encode(cert.signature),
  });
}

/** 严格解码：字段类型/版本/长度任一不符即 throw（节点准入与客户端解析共用）。 */
export function decodeDeviceCertificateJson(text: string): DeviceCertificate {
  const raw = JSON.parse(text) as Record<string, unknown>;
  if (raw.version !== 1) throw new Error("设备凭证版本不识别");
  if (typeof raw.did !== "string" || typeof raw.dkId !== "string" || typeof raw.label !== "string") {
    throw new Error("设备凭证字段非法");
  }
  if (typeof raw.issuedAt !== "number" || typeof raw.expiresAt !== "number" || !Number.isSafeInteger(raw.issuedAt) || !Number.isSafeInteger(raw.expiresAt)) {
    throw new Error("设备凭证时间字段非法");
  }
  if (typeof raw.signature !== "string") throw new Error("设备凭证签名字段缺失");
  return {
    version: 1,
    did: raw.did,
    dkId: raw.dkId,
    label: raw.label,
    issuedAt: raw.issuedAt,
    expiresAt: raw.expiresAt,
    signature: base64Decode(raw.signature),
  };
}
