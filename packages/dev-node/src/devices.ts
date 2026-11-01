/**
 * 设备注册表（M2-S10 FR-1.4，设计报告 §4.2）：设备凭证的登记 / 吊销 / 列表。
 *
 * 信任边界与 Registry 一致（SR-5）：节点验签后仅作"防垃圾准入"，联系人客户端
 * 仍须从 KT 事件流本地折叠并逐事件验签；节点视图只作加速，不作采信依据。
 *
 * 生命周期语义：
 * - 登记（device-add）：IK 签名凭证；同 dkId 重登记 = 续期（覆盖 label/有效期）；
 * - 吊销（device-revoke）：IK 签名声明；节点随即停发该设备的预密钥材料
 *   （bundle/OPK 池删除，见 dropDeviceMaterials），对端经设备集核验自动轮换会话；
 * - 过期（expiresAt）：运行时状态——准入不拒（签发时点有效即可），分发时排除。
 */
import type { DeviceCertificate, DeviceRevocation } from "@mychat/core";
import {
  decodeDeviceCertificateJson,
  decodeDeviceRevocationJson,
  verifyDeviceCertificate,
  verifyDeviceRevocation,
} from "@mychat/core";

export interface DeviceEntry {
  /** 凭证原始 JSON（客户端可逐字节复核的形态） */
  certificate: string;
  revokedAt: number | null;
}

export interface DeviceRegistryStore {
  /** did → (dkId → entry) */
  devices: Map<string, Map<string, DeviceEntry>>;
}

export function createDeviceRegistryStore(): DeviceRegistryStore {
  return { devices: new Map() };
}

export type DeviceResult =
  | { ok: true; certificate: DeviceCertificate }
  | { ok: false; error: string };

/** 登记设备凭证：解码 → 验签（以签发时点为基准，过期与否属运行时状态）→ did 一致 → 落库。 */
export function registerDevice(
  store: DeviceRegistryStore,
  did: string,
  certificateJson: string,
): DeviceResult {
  let certificate: DeviceCertificate;
  try {
    certificate = decodeDeviceCertificateJson(certificateJson);
    // 签发时点有效 = 签名/结构正确；时钟偏差不拒绝（过期由分发时判断）
    if (!verifyDeviceCertificate(certificate, { now: certificate.issuedAt })) {
      return { ok: false, error: "设备凭证验签失败" };
    }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "设备凭证格式非法" };
  }
  if (certificate.did !== did) {
    return { ok: false, error: "凭证 DID 与属主不一致" };
  }
  let perDid = store.devices.get(did);
  if (!perDid) {
    perDid = new Map();
    store.devices.set(did, perDid);
  }
  perDid.set(certificate.dkId, { certificate: certificateJson, revokedAt: null });
  return { ok: true, certificate };
}

export type DeviceRevokeResult =
  | { ok: true; revocation: DeviceRevocation; changed: boolean }
  | { ok: false; error: string };

/** 吊销设备：解码 → 验签 → did/dkId 一致；重复吊销幂等（changed=false，不再重复锚定 KT）。 */
export function revokeDevice(
  store: DeviceRegistryStore,
  did: string,
  revocationJson: string,
): DeviceRevokeResult {
  let revocation: DeviceRevocation;
  try {
    revocation = decodeDeviceRevocationJson(revocationJson);
    if (!verifyDeviceRevocation(revocation)) {
      return { ok: false, error: "吊销声明验签失败" };
    }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "吊销声明格式非法" };
  }
  if (revocation.did !== did) {
    return { ok: false, error: "吊销声明 DID 与属主不一致" };
  }
  const entry = store.devices.get(did)?.get(revocation.dkId);
  if (!entry) {
    return { ok: false, error: "设备不存在（未登记）" };
  }
  const changed = entry.revokedAt === null;
  if (changed) entry.revokedAt = revocation.revokedAt;
  return { ok: true, revocation, changed };
}

/** 该 DID 的设备条目（原始视图，含已吊销）。 */
export function listDeviceEntries(store: DeviceRegistryStore, did: string): DeviceEntry[] {
  return [...(store.devices.get(did)?.values() ?? [])];
}

export interface ActiveDevice {
  dkId: string;
  certificate: DeviceCertificate;
}

/** 有效设备集：未吊销且未过期，按签发时间升序（分发的确定性轮询顺序）。 */
export function activeDeviceEntries(store: DeviceRegistryStore, did: string, now: number): ActiveDevice[] {
  const out: ActiveDevice[] = [];
  for (const entry of store.devices.get(did)?.values() ?? []) {
    let certificate: DeviceCertificate;
    try {
      certificate = decodeDeviceCertificateJson(entry.certificate);
    } catch {
      continue; // 脏数据不进入分发
    }
    if (entry.revokedAt !== null) continue;
    if (certificate.expiresAt <= now) continue;
    out.push({ dkId: certificate.dkId, certificate });
  }
  return out.sort((a, b) => a.certificate.issuedAt - b.certificate.issuedAt);
}
