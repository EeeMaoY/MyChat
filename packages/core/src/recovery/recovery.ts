/**
 * 社交恢复模块（FR-1.3 / UX-2，设计报告 §4.3，M1 形态）。
 *
 * 角色：
 *   RecoveryAnnouncement —— 恢复公告（IK 签名，节点按 DID 存"当前版本"）：
 *     { did, wrapCid, threshold, guardians: did[] }。任何人可取并可验签（did 即 IK 公钥）。
 *   GuardianShare —— 守护者分片包：RK 分片经守护者 Ed25519 公钥 ECIES 封装 +
 *     wrap 引用。守护者接受邀请后本地保存，恢复时凭人工确认回传。
 *
 * M1 边界（如实披露，M1 计划 §2 S7）：
 *   - 守护者确认 = 人工判定请求者身份（Web of Trust 语义）；"24h 冷静期 + 原设备
 *     一键否决"为 M2（当前 UI 提供"拒绝"入口，无自动延迟窗口）。
 *   - 恢复公告由节点按 DID 存当前版本，其不可静默替换性由 IK 签名保证（SR-5 同源）。
 */
import {
  base58Decode,
  base58Encode,
  bytesToUtf8,
  concatBytes,
  utf8ToBytes,
} from "../codec/index.ts";
import {
  AEAD_KEY_LENGTH,
  AEAD_NONCE_LENGTH,
  aeadDecrypt,
  aeadEncrypt,
  blake3Hash,
  ed25519Sign,
  ed25519Verify,
  hkdfSha256,
  randomBytes,
} from "../crypto/index.ts";
import { openWithEd25519, sealToEd25519 } from "../crypto/index.ts";
import {
  type Identity,
  didToEd25519PublicKey,
  serializeIdentity,
} from "../identity/index.ts";
import {
  type Share,
  combineShares,
  decodeShare,
  encodeShare,
  splitSecret,
} from "../ssss/index.ts";

export interface RecoveryAnnouncement {
  did: string;
  /** 身份包裹块的 CAS CID（wrapBlob = AEAD(RK, identity JSON)） */
  wrapCid: string;
  threshold: number;
  guardians: string[];
  /** IK 签名（覆盖全部字段，见 recoveryMessage） */
  signature: Uint8Array;
}

/** 公告被签消息（确定性编码）。 */
export function recoveryMessage(a: Omit<RecoveryAnnouncement, "signature">): Uint8Array {
  const guardianPart = concatBytes(...a.guardians.map((g) => utf8ToBytes(g)));
  const header = utf8ToBytes(`mychat:recovery-v1:${a.did}:${a.wrapCid}:${a.threshold}:${a.guardians.length}:`);
  return concatBytes(header, guardianPart);
}

export function makeRecoveryAnnouncement(
  identity: Identity,
  wrapCid: string,
  threshold: number,
  guardians: string[],
): RecoveryAnnouncement {
  if (threshold < 2 || threshold > guardians.length) throw new Error("门限非法（2..守护者数）");
  const unsigned = { did: identity.did, wrapCid, threshold, guardians };
  return { ...unsigned, signature: ed25519Sign(identity.ikEd.privateKey, recoveryMessage(unsigned)) };
}

/** 验证公告：签名必须来自 did 本身（公告不可被第三方伪造）。 */
export function verifyRecoveryAnnouncement(a: RecoveryAnnouncement): boolean {
  const { signature, ...rest } = a;
  try {
    return ed25519Verify(signature, recoveryMessage(rest), didToEd25519PublicKey(a.did));
  } catch {
    return false;
  }
}

// ---------- 身份包裹（RK 加密身份全套） ----------

const WRAP_INFO = "mychat:recovery-wrap:v1";

/** RK 加密身份 JSON（serializeIdentity 产物）。 */
export function sealIdentityWrap(rk: Uint8Array, identityJson: string): Uint8Array {
  const key = hkdfSha256(rk, new Uint8Array(32), WRAP_INFO, AEAD_KEY_LENGTH);
  const nonce = randomBytes(AEAD_NONCE_LENGTH);
  const saltPart = randomBytes(16);
  const ct = aeadEncrypt(key, nonce, utf8ToBytes(identityJson), saltPart);
  return new Uint8Array([...saltPart, ...nonce, ...ct]);
}

export function openIdentityWrap(rk: Uint8Array, wrap: Uint8Array): string {
  if (wrap.length < 16 + AEAD_NONCE_LENGTH + 16) throw new Error("身份包裹截断");
  const saltPart = wrap.slice(0, 16);
  const nonce = wrap.slice(16, 16 + AEAD_NONCE_LENGTH);
  const ct = wrap.slice(16 + AEAD_NONCE_LENGTH);
  const key = hkdfSha256(rk, new Uint8Array(32), WRAP_INFO, AEAD_KEY_LENGTH);
  return bytesToUtf8(aeadDecrypt(key, nonce, ct, saltPart));
}

// ---------- 守护者分片包 ----------

export interface GuardianShare {
  /** 被恢复身份的 DID */
  did: string;
  /** 身份包裹块 CID（恢复时取） */
  wrapCid: string;
  /** ECIES 封装的 RK 分片（收件方 = 守护者 IK-ed 公钥） */
  sealedShare: Uint8Array;
}

export interface RecoverySetup {
  did: string;
  wrapCid: string;
  rk: Uint8Array;
  shares: { guardianDid: string; share: Share }[];
  wrap: Uint8Array;
  announcement: RecoveryAnnouncement;
}

/** 生成恢复材料：RK + 分片包（每守护者一份）+ 身份包裹 + 公告。 */
export function createRecoverySetup(
  identity: Identity,
  guardianDids: string[],
  threshold: number,
): RecoverySetup {
  if (guardianDids.length < 2) throw new Error("守护者至少 2 位");
  const rk = randomBytes(32);
  const shares = splitSecret(rk, guardianDids.length, threshold).map((share, i) => ({
    guardianDid: guardianDids[i]!,
    share,
  }));
  const wrap = sealIdentityWrap(rk, serializeIdentity(identity));
  const wrapCid = base58Encode(blake3Hash(wrap));
  const announcement = makeRecoveryAnnouncement(identity, wrapCid, threshold, guardianDids);
  return { did: identity.did, wrapCid, rk, shares, wrap, announcement };
}

/** 给守护者的分片包（sealedShare 以守护者公钥封装，守护者私钥方可解）。 */
export function sealGuardianShare(setup: RecoverySetup, guardianDid: string): GuardianShare {
  const entry = setup.shares.find((s) => s.guardianDid === guardianDid);
  if (!entry) throw new Error("非守护者 DID");
  const sealed = sealToEd25519(didToEd25519PublicKey(guardianDid), encodeShare(entry.share));
  return { did: setup.did, wrapCid: setup.wrapCid, sealedShare: sealed };
}

/** 守护者开启分片包（用自己的 IK 私钥）。 */
export function openGuardianShare(myPrivateEd: Uint8Array, pack: GuardianShare): Share {
  return decodeShare(openWithEd25519(myPrivateEd, pack.sealedShare));
}

/** 由合格分片集合重组 RK。 */
export function recoverRk(shares: Share[], expectedLength = 32): Uint8Array {
  return combineShares(shares, expectedLength);
}
