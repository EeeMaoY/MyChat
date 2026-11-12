/**
 * foldDeviceEvents 事件序测试：IKTLog.list 未承诺返回有序数组，折叠必须按
 * event.index 升序（真实时序）进行——乱序输入（吊销事件在数组中先于其登记
 * 到达）此前会把吊销永久丢弃，设备以未吊销状态折叠。
 */
import { describe, expect, it } from "vitest";

import { utf8ToBytes } from "../../codec/index.ts";
import {
  activeDeviceIds,
  createIdentity,
  encodeDeviceCertificateJson,
  encodeDeviceRevocationJson,
  foldDeviceEvents,
  makeDeviceCertificate,
  makeDeviceRevocation,
  randomBytes,
  type KTEvent,
} from "../../index.ts";

const NOW = 1_700_000_000_000;
const TTL = 90 * 24 * 3600_000;

function ktEvent(did: string, type: KTEvent["type"], payloadJson: string, index: number): KTEvent {
  return { did, type, payload: utf8ToBytes(payloadJson), index };
}

describe("foldDeviceEvents 按事件序折叠", () => {
  it("乱序输入（吊销在数组中先于登记到达）折叠后设备仍为 revoked", () => {
    const identity = createIdentity();
    const dk = randomBytes(32);
    const cert = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, dk, "乱序机", TTL, { now: NOW });
    const rev = makeDeviceRevocation(identity.ikEd.privateKey, identity.did, cert.dkId, { now: NOW + 1000 });

    // 真实时序由 index 表达：登记(0) → 吊销(1)；数组顺序被乱序为吊销在前
    const addEvent = ktEvent(identity.did, "device-add", encodeDeviceCertificateJson(cert), 0);
    const revokeEvent = ktEvent(identity.did, "device-revoke", encodeDeviceRevocationJson(rev), 1);
    const folded = foldDeviceEvents([revokeEvent, addEvent], { now: NOW + 2000 });

    expect(folded.invalidEvents).toBe(0);
    const view = folded.devices.find((d) => d.certificate.dkId === cert.dkId);
    expect(view).toBeDefined();
    expect(view!.revoked).toBe(true);
    expect(view!.revokedAt).toBe(rev.revokedAt);
    expect(activeDeviceIds(folded)).toEqual([]);
  });

  it("乱序输入含多设备与其他事件类型时折叠结果与有序输入一致", () => {
    const identity = createIdentity();
    const dkA = randomBytes(32);
    const dkB = randomBytes(32);
    const certA = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, dkA, "A机", TTL, { now: NOW });
    const certB = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, dkB, "B机", TTL, { now: NOW });
    const revA = makeDeviceRevocation(identity.ikEd.privateKey, identity.did, certA.dkId, { now: NOW + 1000 });

    // 有序输入：register(2) → addA(3) → addB(4) → revokeA(5)
    const ordered = [
      ktEvent(identity.did, "register", "{}", 2),
      ktEvent(identity.did, "device-add", encodeDeviceCertificateJson(certA), 3),
      ktEvent(identity.did, "device-add", encodeDeviceCertificateJson(certB), 4),
      ktEvent(identity.did, "device-revoke", encodeDeviceRevocationJson(revA), 5),
    ];
    // 乱序输入：完全逆序的同一事件集
    const scrambled = [...ordered].reverse();

    const a = foldDeviceEvents(ordered, { now: NOW + 2000 });
    const b = foldDeviceEvents(scrambled, { now: NOW + 2000 });
    expect(b.invalidEvents).toBe(a.invalidEvents);
    expect(b.devices.map((d) => [d.certificate.dkId, d.revoked, d.revokedAt]))
      .toEqual(a.devices.map((d) => [d.certificate.dkId, d.revoked, d.revokedAt]));
    expect(activeDeviceIds(b)).toEqual([certB.dkId]);
  });

  it("同 index 冲突保持原序（稳定排序），全部登记正常折叠", () => {
    const identity = createIdentity();
    const dkA = randomBytes(32);
    const dkB = randomBytes(32);
    const certA = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, dkA, "A机", TTL, { now: NOW });
    const certB = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, dkB, "B机", TTL, { now: NOW });

    const folded = foldDeviceEvents([
      ktEvent(identity.did, "device-add", encodeDeviceCertificateJson(certA), 0),
      ktEvent(identity.did, "device-add", encodeDeviceCertificateJson(certB), 0),
    ], { now: NOW + 1000 });
    expect(folded.devices).toHaveLength(2);
    expect(activeDeviceIds(folded).sort()).toEqual([certA.dkId, certB.dkId].sort());
  });
});
