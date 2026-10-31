/**
 * 身份（Identity）—— M0 单设备全密钥身份（设计报告 §4.1 分层密钥体系）。
 *
 * - IK-ed：Ed25519 身份签名密钥，DID 即派生自其公钥；
 * - IK-x：X25519 身份 DH 密钥，公钥由 IK-ed 签名绑定（防中间人替换，§5.2 X3DH）；
 * - DK：设备签名密钥（M0 单设备，一身份一设备）。
 *
 * FR-1.1：身份全自动无感创建，无任何参数与用户交互。
 */
import { bytesEqual, concatBytes, utf8ToBytes } from "../codec/index.ts";
import {
  type KeyPair,
  KEY_LENGTH,
  ed25519PublicKeyFromPrivate,
  ed25519Sign,
  ed25519Verify,
  generateEd25519KeyPair,
  generateX25519KeyPair,
  x25519PublicKeyFromPrivate,
} from "../crypto/index.ts";
import { didFromEd25519PublicKey } from "./did.ts";

/** IK-x 绑定签名的域分隔前缀（与 PreKeyBundle.ikxSignature 同构，§5.2） */
export const IKX_BINDING_PREFIX = utf8ToBytes("mychat:ikx-bind:");

/** 序列化格式版本（字段演进时递增） */
const IDENTITY_JSON_VERSION = 1;

/** Ed25519 签名固定 64 字节 */
const SIGNATURE_LENGTH = 64;

export interface Identity {
  /** 派生自 ikEd.publicKey 的自认证 DID */
  did: string;
  /** Ed25519：DID 本体，签名（IK） */
  ikEd: KeyPair;
  /** X25519：X3DH 身份 DH 密钥（公钥由 IK-ed 签名绑定，防中间人替换） */
  ikX: KeyPair;
  /** Ed25519：设备签名密钥（M0 单设备，DK） */
  dkEd: KeyPair;
  /** ed25519Sign(ikEd.privateKey, "mychat:ikx-bind:" || ikX.publicKey) */
  ikxBindingSig: Uint8Array;
}

/** 构造 IK-x 绑定签名的被签消息："mychat:ikx-bind:" || ikX 公钥 */
export function ikxBindingMessage(ikxPublic: Uint8Array): Uint8Array {
  return concatBytes(IKX_BINDING_PREFIX, ikxPublic);
}

/** FR-1.1 无感身份创建：全自动、无参数，全部密钥由密码学安全随机数生成。 */
export function createIdentity(): Identity {
  const ikEd = generateEd25519KeyPair();
  const ikXRaw = generateX25519KeyPair();
  // 规范化 clamp：消除 X25519 私钥的 clamp 等价类（RFC 7748 掩码位），
  // 使"公钥重算一致性"校验对私钥的每一个字节篡改都可检出（防篡改序列化的前提）。
  const ikX: KeyPair = {
    privateKey: clampX25519PrivateKey(ikXRaw.privateKey),
    publicKey: ikXRaw.publicKey,
  };
  const dkEd = generateEd25519KeyPair();
  const ikxBindingSig = ed25519Sign(ikEd.privateKey, ikxBindingMessage(ikX.publicKey));
  return {
    did: didFromEd25519PublicKey(ikEd.publicKey),
    ikEd,
    ikX,
    dkEd,
    ikxBindingSig,
  };
}

/** RFC 7748 §5 私钥 clamp：k[0]&=248, k[31]&=127, k[31]|=64。 */
function clampX25519PrivateKey(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== KEY_LENGTH) throw new Error("X25519 私钥长度非法");
  const out = privateKey.slice();
  out[0]! &= 248;
  out[31]! &= 127;
  out[31]! |= 64;
  return out;
}

function isClampedX25519PrivateKey(privateKey: Uint8Array): boolean {
  const clamped = clampX25519PrivateKey(privateKey);
  return bytesEqual(clamped, privateKey);
}

// ---- 本地小写 hex 编解码（JSON 序列化用；codec 未提供 hex，依约束不引第三方） ----

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

function fromHex(hex: string, expectedLength: number, fieldName: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-f]/.test(hex)) {
    throw new Error(`身份反序列化失败：${fieldName} 不是合法的小写 hex`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)!;
  }
  if (bytes.length !== expectedLength) {
    throw new Error(`身份反序列化失败：${fieldName} 长度须为 ${expectedLength} 字节，实际 ${bytes.length}`);
  }
  return bytes;
}

function serializeKeyPair(kp: KeyPair): { publicKey: string; privateKey: string } {
  return { publicKey: toHex(kp.publicKey), privateKey: toHex(kp.privateKey) };
}

function checkKeyPairHex(
  raw: { publicKey: string; privateKey: string } | undefined,
  fieldName: string,
  derivePublic: (privateKey: Uint8Array) => Uint8Array,
  requireClamp = false,
): KeyPair {
  if (raw === undefined || typeof raw.publicKey !== "string" || typeof raw.privateKey !== "string") {
    throw new Error(`身份反序列化失败：缺少字段 ${fieldName}`);
  }
  const keyPair: KeyPair = {
    publicKey: fromHex(raw.publicKey, KEY_LENGTH, `${fieldName}.publicKey`),
    privateKey: fromHex(raw.privateKey, KEY_LENGTH, `${fieldName}.privateKey`),
  };
  // X25519 私钥必须是 clamp 规范形式（createIdentity 保证）：掩码位上的
  // 篡改不改变公钥，唯有显式校验规范形才能保证全字节可检出。
  if (requireClamp && !isClampedX25519PrivateKey(keyPair.privateKey)) {
    throw new Error(`身份反序列化失败：${fieldName}.privateKey 不是 clamp 规范形式`);
  }
  // 私钥 ↔ 公钥一致性（防篡改：仅改私钥 hex 也能被检出）
  if (!bytesEqual(derivePublic(keyPair.privateKey), keyPair.publicKey)) {
    throw new Error(`身份反序列化失败：${fieldName} 私钥与公钥不匹配`);
  }
  return keyPair;
}

/** 序列化为 JSON；所有二进制字段用小写 hex（本地持久化格式，防篡改靠反序列化校验）。 */
export function serializeIdentity(identity: Identity): string {
  return JSON.stringify({
    version: IDENTITY_JSON_VERSION,
    did: identity.did,
    ikEd: serializeKeyPair(identity.ikEd),
    ikX: serializeKeyPair(identity.ikX),
    dkEd: serializeKeyPair(identity.dkEd),
    ikxBindingSig: toHex(identity.ikxBindingSig),
  });
}

/**
 * 从 JSON 反序列化身份，任何篡改都会抛错（防存储篡改）：
 * 1. JSON 结构与字段类型完整；
 * 2. did 可由 ikEd 公钥重算且一致；
 * 3. 三对密钥私钥 ↔ 公钥一致；
 * 4. ikxBindingSig 对 ikX 公钥的绑定验签通过。
 */
export function deserializeIdentity(json: string): Identity {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new Error("身份反序列化失败：不是合法的 JSON");
  }
  if (typeof raw !== "object" || raw === null) {
    throw new Error("身份反序列化失败：顶层须为对象");
  }
  const obj = raw as Record<string, unknown>;
  if (obj["version"] !== IDENTITY_JSON_VERSION) {
    throw new Error(`身份反序列化失败：version 须为 ${IDENTITY_JSON_VERSION}`);
  }
  if (typeof obj["did"] !== "string") {
    throw new Error("身份反序列化失败：缺少字段 did");
  }

  const ikEd = checkKeyPairHex(
    obj["ikEd"] as { publicKey: string; privateKey: string } | undefined,
    "ikEd",
    ed25519PublicKeyFromPrivate,
  );
  const ikX = checkKeyPairHex(
    obj["ikX"] as { publicKey: string; privateKey: string } | undefined,
    "ikX",
    x25519PublicKeyFromPrivate,
    true,
  );
  const dkEd = checkKeyPairHex(
    obj["dkEd"] as { publicKey: string; privateKey: string } | undefined,
    "dkEd",
    ed25519PublicKeyFromPrivate,
  );

  if (typeof obj["ikxBindingSig"] !== "string") {
    throw new Error("身份反序列化失败：缺少字段 ikxBindingSig");
  }
  const ikxBindingSig = fromHex(obj["ikxBindingSig"], SIGNATURE_LENGTH, "ikxBindingSig");

  // did 必须可由 IK 公钥重算（自认证不变量）
  const did = didFromEd25519PublicKey(ikEd.publicKey);
  if (obj["did"] !== did) {
    throw new Error("身份反序列化失败：did 与 ikEd 公钥不一致");
  }
  // IK-x 绑定签名必须可被 IK 公钥验证（防中间人替换 X25519 身份密钥）
  if (!ed25519Verify(ikxBindingSig, ikxBindingMessage(ikX.publicKey), ikEd.publicKey)) {
    throw new Error("身份反序列化失败：ikxBindingSig 验签不通过");
  }

  return { did, ikEd, ikX, dkEd, ikxBindingSig };
}
