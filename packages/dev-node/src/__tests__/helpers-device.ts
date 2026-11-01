/**
 * 测试共享 helper：设备凭证登记（M2-S10 起 bundle 上传/OPK 池操作的前置步骤）。
 */
import {
  encodeDeviceCertificateJson,
  generateEd25519KeyPair,
  makeDeviceCertificate,
  type Identity,
} from "@mychat/core";

/** 以身份 IK 签发并登记一台测试设备，返回 dkId。 */
export async function registerDeviceCert(
  base: string,
  identity: Identity,
  label = "test-device",
  dkPublic?: Uint8Array,
): Promise<string> {
  const cert = makeDeviceCertificate(
    identity.ikEd.privateKey,
    identity.did,
    dkPublic ?? generateEd25519KeyPair().publicKey,
    label,
    3_600_000,
  );
  const res = await fetch(`${base}/v0/registry/devices/${encodeURIComponent(identity.did)}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ certificate: JSON.parse(encodeDeviceCertificateJson(cert)) }),
  });
  if (res.status !== 201) {
    throw new Error(`设备凭证登记失败：HTTP ${res.status} ${await res.text()}`);
  }
  return cert.dkId;
}
