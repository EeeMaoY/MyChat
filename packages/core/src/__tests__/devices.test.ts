/**
 * 设备模块单测（M2-S10 FR-1.4）：凭证签发/验证、吊销、KT 事件流折叠、指纹稳定性。
 */
import { describe, expect, it } from "vitest";

import { base58Decode, base58Encode, createIdentity, randomBytes } from "../index.ts";
import { utf8ToBytes } from "../codec/index.ts";
import {
  activeDeviceIds,
  decodeDeviceCertificateJson,
  decodeDeviceRevocationJson,
  deviceCertificateMessage,
  encodeDeviceCertificateJson,
  encodeDeviceRevocationJson,
  fingerprintDeviceIds,
  foldDeviceEvents,
  makeDeviceCertificate,
  makeDeviceRevocation,
  verifyDeviceCertificate,
  verifyDeviceRevocation,
  type KTEvent,
} from "../index.ts";

const NOW = 1_700_000_000_000;
const TTL = 90 * 24 * 3600_000;

function makeKTEvent(did: string, type: KTEvent["type"], payloadJson: string, index: number): KTEvent {
  return { did, type, payload: utf8ToBytes(payloadJson), index };
}

describe("设备凭证（DeviceCertificate）", () => {
  it("签发 → 验证通过；dkId 与 DK 公钥 base58 一致", () => {
    const identity = createIdentity();
    const dk = randomBytes(32);
    const cert = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, dk, "测试机", TTL, { now: NOW });
    expect(cert.dkId).toBe(base58Encode(dk));
    expect(verifyDeviceCertificate(cert, { now: NOW })).toBe(true);
    expect(verifyDeviceCertificate(cert, { now: NOW + TTL - 1 })).toBe(true);
  });

  it("时间窗边界：过期后验证失败（expiresAt 当刻即失效）", () => {
    const identity = createIdentity();
    const cert = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, randomBytes(32), "过期机", TTL, { now: NOW });
    expect(verifyDeviceCertificate(cert, { now: NOW + TTL })).toBe(false);
    expect(verifyDeviceCertificate(cert, { now: NOW + TTL + 1 })).toBe(false);
  });

  it("篡改任一字段（label/expiresAt/dkId/did/签名）验证失败", () => {
    const identity = createIdentity();
    const base = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, randomBytes(32), "原机", TTL, { now: NOW });

    expect(verifyDeviceCertificate({ ...base, label: "改过名的机器" }, { now: NOW })).toBe(false);
    expect(verifyDeviceCertificate({ ...base, expiresAt: base.expiresAt + 1 }, { now: NOW })).toBe(false);
    expect(verifyDeviceCertificate({ ...base, dkId: base58Encode(randomBytes(32)) }, { now: NOW })).toBe(false);
    const other = createIdentity();
    expect(verifyDeviceCertificate({ ...base, did: other.did }, { now: NOW })).toBe(false);
    const badSig = base.signature.slice();
    badSig[0]! ^= 1;
    expect(verifyDeviceCertificate({ ...base, signature: badSig }, { now: NOW })).toBe(false);
  });

  it("伪造签名者（非 IK 持有者）签发的凭证验证失败", () => {
    const mallory = createIdentity();
    const cert = makeDeviceCertificate(mallory.ikEd.privateKey, mallory.did, randomBytes(32), "冒名机", TTL, { now: NOW });
    // did 换成受害者但签名来自 mallory 的 IK —— 验签必然失败
    const victim = createIdentity();
    expect(verifyDeviceCertificate({ ...cert, did: victim.did }, { now: NOW })).toBe(false);
  });

  it("JSON 编解码往返一致；畸形输入严格拒绝", () => {
    const identity = createIdentity();
    const cert = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, randomBytes(32), "往返机", TTL, { now: NOW });
    const round = decodeDeviceCertificateJson(encodeDeviceCertificateJson(cert));
    expect(round).toEqual(cert);

    expect(() => decodeDeviceCertificateJson('{"version":2}')).toThrow();
    expect(() => decodeDeviceCertificateJson('{"version":1,"did":1,"dkId":"x","label":"x","issuedAt":1,"expiresAt":2,"signature":""}')).toThrow();
    expect(() => decodeDeviceCertificateJson('{"version":1,"did":"x","dkId":"x","label":"x","issuedAt":"a","expiresAt":2,"signature":""}')).toThrow();
  });

  it("被签消息确定性：同字段重编码逐字节一致；超长 label 拒绝", () => {
    const identity = createIdentity();
    const fields = { did: identity.did, dkId: base58Encode(randomBytes(32)), label: "固定描述", issuedAt: NOW, expiresAt: NOW + TTL };
    expect(deviceCertificateMessage(fields)).toEqual(deviceCertificateMessage(fields));

    expect(() =>
      deviceCertificateMessage({ ...fields, label: "长".repeat(600) }),
    ).toThrow(/设备描述过长/);
  });
});

describe("设备吊销（DeviceRevocation）", () => {
  it("签发 → 验证通过；篡改 dkId/revokedAt/签名失败", () => {
    const identity = createIdentity();
    const rev = makeDeviceRevocation(identity.ikEd.privateKey, identity.did, base58Encode(randomBytes(32)), { now: NOW });
    expect(verifyDeviceRevocation(rev)).toBe(true);

    expect(verifyDeviceRevocation({ ...rev, dkId: base58Encode(randomBytes(32)) })).toBe(false);
    expect(verifyDeviceRevocation({ ...rev, revokedAt: rev.revokedAt + 1 })).toBe(false);
    const badSig = rev.signature.slice();
    badSig[10]! ^= 1;
    expect(verifyDeviceRevocation({ ...rev, signature: badSig })).toBe(false);
    // 非持有者 IK 签名
    expect(verifyDeviceRevocation(makeDeviceRevocation(createIdentity().ikEd.privateKey, identity.did, rev.dkId))).toBe(false);
  });

  it("JSON 编解码往返一致；版本不识别拒绝", () => {
    const identity = createIdentity();
    const rev = makeDeviceRevocation(identity.ikEd.privateKey, identity.did, base58Encode(randomBytes(32)), { now: NOW });
    expect(decodeDeviceRevocationJson(encodeDeviceRevocationJson(rev))).toEqual(rev);
    expect(() => decodeDeviceRevocationJson('{"version":9}')).toThrow();
  });
});

describe("KT 事件流折叠（foldDeviceEvents）", () => {
  function setupTwoDevices() {
    const identity = createIdentity();
    const dkA = randomBytes(32);
    const dkB = randomBytes(32);
    const certA = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, dkA, "设备A", TTL, { now: NOW });
    const certB = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, dkB, "设备B", TTL, { now: NOW + 1000 });
    return { identity, certA, certB };
  }

  it("add+add → 两台有效设备；吊销 B 后仅 A 有效", () => {
    const { identity, certA, certB } = setupTwoDevices();
    const events = [
      makeKTEvent(identity.did, "device-add", encodeDeviceCertificateJson(certA), 0),
      makeKTEvent(identity.did, "device-add", encodeDeviceCertificateJson(certB), 1),
    ];
    const folded = foldDeviceEvents(events, { now: NOW + 2000 });
    expect(folded.invalidEvents).toBe(0);
    expect(folded.devices).toHaveLength(2);
    expect(activeDeviceIds(folded).sort()).toEqual([certA.dkId, certB.dkId].sort());

    const rev = makeDeviceRevocation(identity.ikEd.privateKey, identity.did, certB.dkId, { now: NOW + 3000 });
    const afterRevoke = foldDeviceEvents(
      [...events, makeKTEvent(identity.did, "device-revoke", encodeDeviceRevocationJson(rev), 2)],
      { now: NOW + 4000 },
    );
    expect(activeDeviceIds(afterRevoke)).toEqual([certA.dkId]);
    const revokedView = afterRevoke.devices.find((d) => d.certificate.dkId === certB.dkId)!;
    expect(revokedView.revoked).toBe(true);
    expect(revokedView.revokedAt).toBe(NOW + 3000);
  });

  it("过期设备自动退出有效集（不算吊销）", () => {
    const { identity, certA } = setupTwoDevices();
    const shortLived = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, randomBytes(32), "短命机", 5000, { now: NOW });
    const events = [
      makeKTEvent(identity.did, "device-add", encodeDeviceCertificateJson(certA), 0),
      makeKTEvent(identity.did, "device-add", encodeDeviceCertificateJson(shortLived), 1),
    ];
    expect(activeDeviceIds(foldDeviceEvents(events, { now: NOW + 1000 }))).toHaveLength(2);
    const folded = foldDeviceEvents(events, { now: NOW + 6000 });
    expect(activeDeviceIds(folded)).toEqual([certA.dkId]);
    expect(folded.devices.find((d) => d.certificate.dkId === shortLived.dkId)!.expired).toBe(true);
  });

  it("重登记（同 dkId 续期）覆盖旧凭证且保留吊销状态不可洗白", () => {
    const { identity, certA } = setupTwoDevices();
    const renewed = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, base58Decode(certA.dkId), "设备A·续期", TTL, { now: NOW + 10_000 });
    const rev = makeDeviceRevocation(identity.ikEd.privateKey, identity.did, certA.dkId, { now: NOW + 11_000 });
    const events = [
      makeKTEvent(identity.did, "device-add", encodeDeviceCertificateJson(certA), 0),
      makeKTEvent(identity.did, "device-add", encodeDeviceCertificateJson(renewed), 1),
      makeKTEvent(identity.did, "device-revoke", encodeDeviceRevocationJson(rev), 2),
    ];
    const folded = foldDeviceEvents(events, { now: NOW + 12_000 });
    expect(folded.devices).toHaveLength(1);
    expect(folded.devices[0]!.certificate.label).toBe("设备A·续期");
    expect(folded.devices[0]!.revoked).toBe(true);
    expect(activeDeviceIds(folded)).toHaveLength(0);
  });

  it("非法事件（验签失败/伪造者签名）跳过并计数，不污染设备集", () => {
    const { identity, certA } = setupTwoDevices();
    const mallory = createIdentity();
    const fakeCert = makeDeviceCertificate(mallory.ikEd.privateKey, identity.did, randomBytes(32), "冒名机", TTL, { now: NOW });
    const events = [
      makeKTEvent(identity.did, "device-add", encodeDeviceCertificateJson(certA), 0),
      makeKTEvent(identity.did, "device-add", encodeDeviceCertificateJson(fakeCert), 1),
      makeKTEvent(identity.did, "device-add", "{not json", 2),
      makeKTEvent(identity.did, "device-revoke", encodeDeviceRevocationJson(makeDeviceRevocation(mallory.ikEd.privateKey, identity.did, certA.dkId)), 3),
    ];
    const folded = foldDeviceEvents(events, { now: NOW + 1000 });
    // certA 有效；fakeCert 验签失败跳过；坏 JSON 跳过；mallory 的吊销验签失败跳过（设备未被恶意吊销）
    expect(folded.invalidEvents).toBe(3);
    expect(activeDeviceIds(folded)).toEqual([certA.dkId]);
  });

  it("register 等无关事件类型被忽略", () => {
    const { identity, certA } = setupTwoDevices();
    const folded = foldDeviceEvents([
      makeKTEvent(identity.did, "register", '"name"', 0),
      makeKTEvent(identity.did, "device-add", encodeDeviceCertificateJson(certA), 1),
    ]);
    expect(folded.devices).toHaveLength(1);
    expect(folded.invalidEvents).toBe(0);
  });
});

describe("设备集指纹（fingerprintDeviceIds）", () => {
  it("同集合不同顺序 → 同指纹；增删/替换设备 → 指纹变化", () => {
    const ids = ["dk-1", "dk-2", "dk-3"];
    const shuffled = ["dk-3", "dk-1", "dk-2"];
    expect(fingerprintDeviceIds(ids)).toBe(fingerprintDeviceIds(shuffled));
    expect(fingerprintDeviceIds(ids)).not.toBe(fingerprintDeviceIds(["dk-1", "dk-2"]));
    expect(fingerprintDeviceIds(ids)).not.toBe(fingerprintDeviceIds(["dk-1", "dk-2", "dk-4"]));
    expect(fingerprintDeviceIds([])).toBe(fingerprintDeviceIds([]));
  });

  it("指纹为 44 字符 base64（blake3 摘要）", () => {
    expect(fingerprintDeviceIds(["x"])).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  });
});
