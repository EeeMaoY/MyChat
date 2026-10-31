/**
 * X3DH 握手（Extended Triple Diffie-Hellman，Signal 规范）的去中心化适配。
 *
 * 对应 ADR-1 / 设计报告 §5.2：预密钥束不经中心目录服务，
 * 而由对端 EDS 公开区/存储网络承载（S2 节点实现分发），本模块只做密码学核心。
 *
 * 安全要点：
 * - SPK 与 IK-x 的签名验证在 identity/bundle.verifyPreKeyBundle 中完成，
 *   发起前必须已通过验证（本模块二次校验以防误用）；
 * - SK = HKDF(F || DH1..DH4)，F 为 32 字节零（curve25519 规范要求）；
 * - AD = 发起方 IK-x 公钥 || 响应方 IK-x 公钥，绑定双方身份。
 */
import {
  type KeyPair,
  hkdfSha256,
  x25519SharedSecret,
} from "../crypto";
import { concatBytes } from "../codec";
import type { Identity } from "../identity";
import type { PreKeyBundle } from "../identity";
import { verifyPreKeyBundle } from "../identity";

const X3DH_INFO = "mychat:x3dh:v1";
/** curve25519 规范要求的 32 字节零前缀（F）。 */
const F = new Uint8Array(32);

/** 初始消息头：响应方据此外推 SK。 */
export interface X3dhInitialHeader {
  /** 发起方 IK-x 公钥（32B） */
  ikxSenderPublic: Uint8Array;
  /** 发起方临时密钥公钥（32B） */
  ekPublic: Uint8Array;
  /** 使用的一次性预密钥编号（响应方据此定位并销毁 OPK） */
  opkId: number;
}

export interface X3dhInitiateResult {
  /** 共享秘密（32B），作为 Double Ratchet 的 root key 输入 */
  sk: Uint8Array;
  header: X3dhInitialHeader;
}

/**
 * 发起方（Alice）侧 X3DH。
 * @param identity 发起方身份（使用其 ikX 参与 DH）
 * @param bundle 已通过 verifyPreKeyBundle 验证的对方预密钥束
 * @param ek 一次性临时密钥对（调用方生成后即弃）
 */
export function x3dhInitiate(
  identity: Identity,
  bundle: PreKeyBundle,
  ek: KeyPair,
): X3dhInitiateResult {
  if (!verifyPreKeyBundle(bundle)) {
    // 防误用：即使调用方已验证，此处再拒一次（SR-5：不可采信未签名映射材料）
    throw new Error("x3dh: 预密钥束验证失败（签名或有效期不通过）");
  }

  const dh1 = x25519SharedSecret(identity.ikX.privateKey, bundle.spkPublic);
  const dh2 = x25519SharedSecret(ek.privateKey, bundle.ikxPublic);
  const dh3 = x25519SharedSecret(ek.privateKey, bundle.spkPublic);
  const dh4 = x25519SharedSecret(ek.privateKey, bundle.opkPublic);

  const sk = hkdfSha256(concatBytes(F, dh1, dh2, dh3, dh4), F, X3DH_INFO, 32);

  return {
    sk,
    header: {
      ikxSenderPublic: identity.ikX.publicKey,
      ekPublic: ek.publicKey,
      opkId: bundle.opkId,
    },
  };
}

/**
 * 响应方（Bob）侧 X3DH：以自身预密钥私钥对初始头做镜像 DH，推出同一 SK。
 * @param spk 响应方 signed prekey 密钥对
 * @param opk 对应 header.opkId 的一次性预密钥密钥对；**调用方在返回后必须立即销毁该 OPK**（Signal 规范）
 */
export function x3dhAccept(
  identity: Identity,
  spk: KeyPair,
  opk: KeyPair,
  header: X3dhInitialHeader,
): { sk: Uint8Array } {
  const dh1 = x25519SharedSecret(spk.privateKey, header.ikxSenderPublic);
  const dh2 = x25519SharedSecret(identity.ikX.privateKey, header.ekPublic);
  const dh3 = x25519SharedSecret(spk.privateKey, header.ekPublic);
  const dh4 = x25519SharedSecret(opk.privateKey, header.ekPublic);

  return { sk: hkdfSha256(concatBytes(F, dh1, dh2, dh3, dh4), F, X3DH_INFO, 32) };
}

/** 会话 AD：发起方 IK-x || 响应方 IK-x（双方均可从初始头重建）。 */
export function x3dhAssociatedData(initiatorIkxPublic: Uint8Array, responderIkxPublic: Uint8Array): Uint8Array {
  return concatBytes(initiatorIkxPublic, responderIkxPublic);
}
