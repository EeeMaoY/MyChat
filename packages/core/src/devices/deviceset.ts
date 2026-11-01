/**
 * 设备集视图（FR-1.4）：从 KT 事件流折叠出设备的当前状态。
 *
 * KTLog 是设备生命周期的唯一权威记录（append-only，SR-5）：联系人客户端取回
 * 事件流后**本地**折叠 + 逐事件验签——节点提供的任何视图只作加速，不作采信依据。
 * 非法事件（解码失败/验签失败）跳过并计数，不中断折叠（KT 的可审计性允许事后追责）。
 */
import { blake3Hash } from "../crypto/index.ts";
import { base64Encode, bytesToUtf8, utf8ToBytes } from "../codec/index.ts";
import type { KTEvent } from "../protocol/interfaces.ts";
import { decodeDeviceCertificateJson, verifyDeviceCertificate, type DeviceCertificate } from "./certificate.ts";
import { decodeDeviceRevocationJson, verifyDeviceRevocation } from "./revocation.ts";

/** 单台设备的折叠视图（certificate 保留原始凭证供 UI 展示与再验证）。 */
export interface DeviceView {
  certificate: DeviceCertificate;
  revoked: boolean;
  revokedAt: number | null;
  /** 以查询时钟判断：expiresAt 已过（过期不算吊销，但同样停止分发/不再计入有效集） */
  expired: boolean;
}

export interface DeviceFoldResult {
  /** 按 issuedAt 升序；同 dkId 后事件覆盖前事件（重登记 = 续期语义） */
  devices: DeviceView[];
  /** 被跳过的非法事件数（解码失败或验签失败） */
  invalidEvents: number;
}

export interface FoldDeviceEventsOptions {
  now?: number;
}

/** 折叠 KT 事件流（device-add / device-revoke）为设备状态视图。其他类型事件忽略。 */
export function foldDeviceEvents(events: KTEvent[], opts: FoldDeviceEventsOptions = {}): DeviceFoldResult {
  const now = opts.now ?? Date.now();
  const byDkId = new Map<string, DeviceView>();
  let invalidEvents = 0;

  for (const event of events) {
    const text = bytesToUtf8(event.payload);
    try {
      if (event.type === "device-add") {
        const cert = decodeDeviceCertificateJson(text);
        // 凭证本身必须验签通过（时间窗不计入：expired 是状态不是伪造）
        if (cert.did !== event.did || !verifyDeviceCertificate(cert, { now: cert.issuedAt })) {
          throw new Error("设备凭证验签失败");
        }
        const prev = byDkId.get(cert.dkId);
        byDkId.set(cert.dkId, {
          certificate: cert,
          revoked: prev?.revoked ?? false,
          revokedAt: prev?.revokedAt ?? null,
          expired: cert.expiresAt <= now,
        });
      } else if (event.type === "device-revoke") {
        const revocation = decodeDeviceRevocationJson(text);
        if (revocation.did !== event.did || !verifyDeviceRevocation(revocation)) {
          throw new Error("吊销声明验签失败");
        }
        const prev = byDkId.get(revocation.dkId);
        if (prev) {
          prev.revoked = true;
          prev.revokedAt = revocation.revokedAt;
        }
        // 吊销先于登记事件到达（乱序/重放）：记录后仍忽略——登记事件会带来未吊销视图，
        // 由上层以"事件流完整取回"的约定保证不发生（KT list 为全量事件）。
      } else {
        continue; // register 等其他事件类型与本折叠无关
      }
    } catch {
      invalidEvents += 1;
    }
  }

  const devices = [...byDkId.values()].sort((a, b) => a.certificate.issuedAt - b.certificate.issuedAt);
  return { devices, invalidEvents };
}

/** 有效设备集：未吊销且未过期（节点分发的准入、对端轮换的比对基准）。 */
export function activeDeviceIds(result: DeviceFoldResult): string[] {
  return result.devices.filter((d) => !d.revoked && !d.expired).map((d) => d.certificate.dkId);
}

/**
 * 设备集指纹：有效 dkId 排序后拼接取 blake3 摘要（hex）。
 * 客户端为每个会话记录对端指纹；发送前重算，不一致即触发会话轮换
 * （吊销后对端密钥轮换的触发器，M2-S10）。
 */
export function fingerprintDeviceIds(dkIds: string[]): string {
  const canonical = [...dkIds].sort().join(",");
  return base64Encode(blake3Hash(utf8ToBytes(canonical)));
}
