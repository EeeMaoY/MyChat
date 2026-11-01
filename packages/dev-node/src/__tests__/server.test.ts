/**
 * dev-node 集成测试：真实 HTTP + WS 交互（无 mock）。
 * 覆盖：Registry 验签注册、Storage 块与信箱、KT 联动、Relay 唤醒与直投。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocket } from "ws";

import type { Envelope, KTEvent, KtInclusionProof } from "@mychat/core";
import {
  AEAD_NONCE_LENGTH,
  createIdentity,
  decodePreKeyBundle,
  deriveOpkId,
  encodeDeviceCertificateJson,
  encodeDeviceRevocationJson,
  encodePreKeyBundle,
  generateEd25519KeyPair,
  generateX25519KeyPair,
  issuePreKeyBundle,
  ktVerifyInclusion,
  makeDeviceCertificate,
  makeDeviceRevocation,
  makeUserNameRecord,
  randomBytes,
  base58Encode,
} from "@mychat/core";

import { startDevNode, type DevNode } from "../server";
import { envelopeToJson } from "../wire";
import { registerDeviceCert } from "./helpers-device";

let node: DevNode;
let base: string;

beforeEach(async () => {
  node = await startDevNode();
  base = `http://127.0.0.1:${node.port}`;
});

afterEach(async () => {
  await node.close();
});

function makeEnvelope(toPseudonym: string): Envelope {
  return {
    version: "1", // 信封二进制格式版本（core envelope 模块契约；协议规范版本另见 PROTOCOL_VERSION）
    epoch: 1,
    toPseudonym,
    padClass: 0,
    nonce: randomBytes(AEAD_NONCE_LENGTH),
    payload: randomBytes(200),
  };
}

async function registerUser(name: string) {
  const identity = createIdentity();
  const record = makeUserNameRecord(identity.ikEd.privateKey, name, identity.did, 0);
  const res = await fetch(`${base}/v0/registry/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
  });
  return { identity, record, res };
}

describe("Registry（验签 + 重名拒绝 + KT 联动）", () => {
  it("有效签名注册成功并可通过 resolve 查回", async () => {
    const { identity, record, res } = await registerUser("alice");
    expect(res.status).toBe(201);

    const found = await fetch(`${base}/v0/registry/resolve/alice`);
    expect(found.status).toBe(200);
    const { record: got } = (await found.json()) as { record: { name: string; did: string; signature: string; ktIndex: number } };
    expect(got.name).toBe("alice");
    expect(got.did).toBe(identity.did);
    expect(Buffer.from(got.signature, "base64")).toEqual(Buffer.from(record.signature));
  });

  it("OPK 池（M2-S9/S10）：按设备分槽、池化分发、一次性语义、消耗确认、低水位统计", async () => {
    const { identity } = await registerUser("pooluser");
    const did = identity.did;
    const enc = (did2: string) => encodeURIComponent(did2);
    const dkId = await registerDeviceCert(base, identity);
    const devQs = `?device=${encodeURIComponent(dkId)}`;

    // 先上传 bundle 模板（分发组装的前置；registerUser 只注册不传 bundle）
    const templateSpk = generateX25519KeyPair();
    const templateOpk = generateX25519KeyPair();
    const template = issuePreKeyBundle(identity, templateSpk, { ...templateOpk, id: deriveOpkId(templateOpk.publicKey) }, 3_600_000);
    const templatePut = await fetch(`${base}/v0/registry/bundle/${enc(did)}${devQs}`, {
      method: "PUT",
      body: Buffer.from(encodePreKeyBundle(template)),
    });
    expect(templatePut.status).toBe(201);

    // 补充 3 个 OPK 入池（public 统一 base58，与分发组装的解码一致）
    const opks = [generateX25519KeyPair(), generateX25519KeyPair(), generateX25519KeyPair()].map((k) => ({
      id: deriveOpkId(k.publicKey),
      public: base58Encode(k.publicKey),
    }));
    // id 冲突规避：确保 id 互不相同（随机公钥指纹理论上可碰撞，这里防御）
    const uniqueIds = new Set(opks.map((o) => o.id));
    expect(uniqueIds.size).toBe(opks.length);

    const add = await fetch(`${base}/v0/registry/bundle/${enc(did)}/opks${devQs}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ opks }),
    });
    expect(add.status).toBe(201);
    const statsAfterAdd = (await (await fetch(`${base}/v0/registry/bundle/${enc(did)}/stats${devQs}`)).json()) as {
      available: number;
    };
    expect(statsAfterAdd.available).toBe(4); // 模板 OPK 1 + 补充 3

    // 连续分发 3 次：每次得到不同 OPK（一次性语义）
    const seenIds: number[] = [];
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${base}/v0/registry/bundle/${enc(did)}`);
      expect(res.status).toBe(200);
      const decoded = decodePreKeyBundle(new Uint8Array(await res.arrayBuffer()));
      expect(seenIds).not.toContain(decoded.opkId);
      seenIds.push(decoded.opkId);
    }
    const statsAfterIssue = (await (await fetch(`${base}/v0/registry/bundle/${enc(did)}/stats${devQs}`)).json()) as {
      available: number;
      issued: number;
    };
    expect(statsAfterIssue.available).toBe(1); // 池共 4（模板 1 + 补充 3），已发 3
    expect(statsAfterIssue.issued).toBe(3);

    // 第 4 次分发：池空 → 复用（一次性退化，已知边界）
    const reuse = await fetch(`${base}/v0/registry/bundle/${enc(did)}`);
    expect(reuse.status).toBe(200);

    // 消耗确认：DELETE 后池与 issued 同步移除
    const del = await fetch(`${base}/v0/registry/bundle/${enc(did)}/opk/${seenIds[0]}${devQs}`, { method: "DELETE" });
    const delBody = (await del.json()) as { consumed: boolean };
    expect(delBody.consumed).toBe(true);
    const statsAfterConsume = (await (await fetch(`${base}/v0/registry/bundle/${enc(did)}/stats${devQs}`)).json()) as {
      available: number;
      issued: number;
    };
    // 语义确认：DELETE 移除的是已发出的 OPK（issued 与池同步收缩）；池中剩余全部处于已发状态
    expect(statsAfterConsume.issued).toBe(3);
    expect(statsAfterConsume.available).toBe(0);

    // 未登记设备的写操作被拒（M2-S10：bundle/池须挂靠有效设备）
    const stranger = createIdentity();
    const rogueSpk = generateX25519KeyPair();
    const rogueOpk = generateX25519KeyPair();
    const rogue = issuePreKeyBundle(stranger, rogueSpk, { ...rogueOpk, id: deriveOpkId(rogueOpk.publicKey) }, 3_600_000);
    const roguePut = await fetch(`${base}/v0/registry/bundle/${enc(stranger.did)}?device=${encodeURIComponent(base58Encode(randomBytes(32)))}`, {
      method: "PUT",
      body: Buffer.from(encodePreKeyBundle(rogue)),
    });
    expect(roguePut.status).toBe(403);
  });

  it("bundle 分发：有效上传 201 / 查回一致 / 篡改与坏 DID 被拒 / 缺失 404", async () => {
    const { identity } = await registerUser("bundleuser");
    const spk = generateX25519KeyPair();
    const opk = generateX25519KeyPair();
    const bundle = issuePreKeyBundle(identity, spk, { ...opk, id: deriveOpkId(opk.publicKey) }, 3_600_000);
    const encoded = encodePreKeyBundle(bundle);
    const dkId = await registerDeviceCert(base, identity);
    void decodePreKeyBundle; // 保持导入面一致（解码校验在节点内完成）

    const put = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}?device=${encodeURIComponent(dkId)}`, {
      method: "PUT",
      body: Buffer.from(encoded),
    });
    expect(put.status).toBe(201);

    const get = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}`);
    expect(new Uint8Array(await get.arrayBuffer())).toEqual(encoded);

    // 篡改一个字节 → 节点验签拒绝
    const tampered = encoded.slice();
    tampered[40]! ^= 1;
    const putBad = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}?device=${encodeURIComponent(dkId)}`, {
      method: "PUT",
      body: Buffer.from(tampered),
    });
    expect(putBad.status).toBe(400);

    // DID 格式非法
    const putBadDid = await fetch(`${base}/v0/registry/bundle/not-a-did?device=${encodeURIComponent(dkId)}`, { method: "PUT", body: Buffer.from(encoded) });
    expect(putBadDid.status).toBe(400);

    // 未上传 bundle 的合法格式 DID（格式非法才是 400）
    const stranger = createIdentity();
    const missing = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(stranger.did)}`);
    expect(missing.status).toBe(404);
  });

  it("设备注册表（M2-S10）：登记/KT 锚定/吊销停发/伪造拒绝/列表折叠", async () => {
    const { identity } = await registerUser("devuser");
    const did = identity.did;
    const enc = encodeURIComponent;

    // 登记 → 201 + KT device-add
    const dkA = await registerDeviceCert(base, identity, "设备A");
    const list1 = (await (await fetch(`${base}/v0/registry/devices/${enc(did)}`)).json()) as {
      devices: { certificate: { dkId: string; label: string }; revoked: boolean; expired: boolean }[];
    };
    expect(list1.devices).toHaveLength(1);
    expect(list1.devices[0]!.certificate.dkId).toBe(dkA);
    expect(list1.devices[0]!.certificate.label).toBe("设备A");
    expect(list1.devices[0]!.revoked).toBe(false);
    const kt1 = (await (await fetch(`${base}/v0/kt/list/${enc(did)}`)).json()) as { events: { type: string }[] };
    expect(kt1.events.map((e) => e.type)).toContain("device-add");

    // 第二台设备登记 → 列表 2 台
    const dkB = await registerDeviceCert(base, identity, "设备B");
    const list2 = (await (await fetch(`${base}/v0/registry/devices/${enc(did)}`)).json()) as {
      devices: { certificate: { dkId: string } }[];
    };
    expect(list2.devices).toHaveLength(2);

    // bundle 挂靠设备 A；吊销 A 后分发不再可用（停发），KT device-revoke 锚定
    const spk = generateX25519KeyPair();
    const opk = generateX25519KeyPair();
    const bundle = issuePreKeyBundle(identity, spk, { ...opk, id: deriveOpkId(opk.publicKey) }, 3_600_000);
    const put = await fetch(`${base}/v0/registry/bundle/${enc(did)}?device=${enc(dkA)}`, {
      method: "PUT",
      body: Buffer.from(encodePreKeyBundle(bundle)),
    });
    expect(put.status).toBe(201);

    const revocation = makeDeviceRevocation(identity.ikEd.privateKey, did, dkA);
    const revoke = await fetch(`${base}/v0/registry/devices/${enc(did)}/${enc(dkA)}`, {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        revocation: JSON.parse(encodeDeviceRevocationJson(revocation)),
      }),
    });
    expect(revoke.status).toBe(200);
    const revokeBody = (await revoke.json()) as { changed: boolean };
    expect(revokeBody.changed).toBe(true);

    // 分发轮询跳过已吊销设备 A：B 无 bundle → 404（停发语义）
    const afterRevoke = await fetch(`${base}/v0/registry/bundle/${enc(did)}`);
    expect(afterRevoke.status).toBe(404);

    const kt2 = (await (await fetch(`${base}/v0/kt/list/${enc(did)}`)).json()) as { events: { type: string }[] };
    expect(kt2.events.map((e) => e.type)).toContain("device-revoke");

    // 重复吊销幂等（changed=false，不再重复锚定 KT）
    const again = await fetch(`${base}/v0/registry/devices/${enc(did)}/${enc(dkA)}`, {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ revocation: JSON.parse(encodeDeviceRevocationJson(revocation)) }),
    });
    expect(again.status).toBe(200);
    expect(((await again.json()) as { changed: boolean }).changed).toBe(false);

    // 伪造吊销（攻击者 IK 签名）被拒
    const attacker = createIdentity();
    const fake = makeDeviceRevocation(attacker.ikEd.privateKey, did, dkB);
    const fakeRevoke = await fetch(`${base}/v0/registry/devices/${enc(did)}/${enc(dkB)}`, {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ revocation: JSON.parse(encodeDeviceRevocationJson(fake)) }),
    });
    expect(fakeRevoke.status).toBe(400);
    // B 未被吊销
    const list3 = (await (await fetch(`${base}/v0/registry/devices/${enc(did)}`)).json()) as {
      devices: { certificate: { dkId: string }; revoked: boolean }[];
    };
    expect(list3.devices.find((d) => d.certificate.dkId === dkB)!.revoked).toBe(false);

    // 伪造凭证（冒用他人 DID）登记被拒
    const rogue = createIdentity();
    const rogueCert = makeDeviceCertificate(rogue.ikEd.privateKey, rogue.did, generateEd25519KeyPair().publicKey, "冒名", 3_600_000);
    const roguePut = await fetch(`${base}/v0/registry/devices/${enc(did)}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ certificate: JSON.parse(encodeDeviceCertificateJson({ ...rogueCert, did })) }),
    });
    expect(roguePut.status).toBe(400);
  });

  it("重名注册被拒（409）", async () => {
    await registerUser("bob");
    const again = await registerUser("bob");
    expect(again.res.status).toBe(409);
  });

  it("签名无效的注册被拒（节点不落垃圾记录）", async () => {
    const identity = createIdentity();
    const record = makeUserNameRecord(identity.ikEd.privateKey, "mallory", identity.did, 0);
    const badSignature = Buffer.from(record.signature);
    badSignature[0]! ^= 1;
    const res = await fetch(`${base}/v0/registry/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        record: { ...record, signature: badSignature.toString("base64") },
      }),
    });
    expect(res.status).toBe(409);
    const resolveMallory = await fetch(`${base}/v0/registry/resolve/mallory`);
    expect(resolveMallory.status).toBe(404);
  });

  it("注册自动锚定 KT 日志（SR-5 可举证基础）", async () => {
    const { identity } = await registerUser("carol");
    const res = await fetch(`${base}/v0/kt/list/${encodeURIComponent(identity.did)}`);
    const { events } = (await res.json()) as { events: { type: string; did: string; index: number }[] };
    expect(events).toHaveLength(1);
    expect(events[0]!.type).toBe("register");
    expect(events[0]!.did).toBe(identity.did);
  });

  it("KT 前缀一致性：叶哈希增量端点与客户端核验互操作（M3-S11 捎带）", async () => {
    // 三个用户注册 → 日志 3 个事件；先取"旧时点"材料，再注册第 4 个制造增量
    for (const name of ["cons1", "cons2", "cons3"]) await registerUser(name);
    const before = (await (await fetch(`${base}/v0/kt/leaves?after=-1`)).json()) as { from: number; upTo: number; leafHashes: string[] };
    expect(before.from).toBe(0);
    expect(before.leafHashes.length).toBeGreaterThanOrEqual(3);
    const oldRoot = ((await (await fetch(`${base}/v0/kt/root`)).json()) as { root: string }).root;

    await registerUser("cons4");
    const after = (await (await fetch(`${base}/v0/kt/leaves?after=${before.upTo - 1}`)).json()) as { from: number; upTo: number; leafHashes: string[] };
    expect(after.from).toBe(before.upTo);
    expect(after.leafHashes).toHaveLength(1);
    const newRoot = ((await (await fetch(`${base}/v0/kt/root`)).json()) as { root: string }).root;

    // 客户端核验：前缀 + 增量重算双根比对
    const { base58Decode, ktVerifyConsistency } = await import("@mychat/core");
    expect(
      ktVerifyConsistency(
        before.leafHashes.map((h) => base58Decode(h)),
        after.leafHashes.map((h) => base58Decode(h)),
        oldRoot,
        newRoot,
      ),
    ).toBe(true);
    // 篡改任一叶哈希 → 一致性破坏
    expect(
      ktVerifyConsistency(
        before.leafHashes.map((h) => base58Decode(h)),
        [base58Decode(before.leafHashes[0]!)],
        oldRoot,
        newRoot,
      ),
    ).toBe(false);
  });

  it("KT Merkle：root/proof 端点与客户端核验互操作（FR-1.6 M1）", async () => {
    // 三个用户注册 → 日志 3 个事件
    const ids = [];
    for (const name of ["ktuser1", "ktuser2", "ktuser3"]) {
      const { identity } = await registerUser(name);
      ids.push(identity.did);
    }
    const rootRes = await fetch(`${base}/v0/kt/root`);
    const { size, root } = (await rootRes.json()) as { size: number; root: string };
    expect(size).toBeGreaterThanOrEqual(3);
    expect(root.length).toBeGreaterThan(0);

    // 逐事件：list 取回 → 重构 KTEvent → proof 验证
    for (const [i, did] of ids.entries()) {
      const listRes = await fetch(`${base}/v0/kt/list/${encodeURIComponent(did)}`);
      const { events } = (await listRes.json()) as { events: { did: string; type: string; index: number; payload: string }[] };
      const event = events[0]!;
      const ktEvent: KTEvent = {
        did: event.did,
        type: event.type as KTEvent["type"],
        index: event.index,
        payload: new Uint8Array(Buffer.from(event.payload, "base64")),
      };
      const proofRes = await fetch(`${base}/v0/kt/proof/${event.index}`);
      expect(proofRes.status).toBe(200);
      const { proof } = (await proofRes.json()) as { proof: KtInclusionProof };
      expect(ktVerifyInclusion(ktEvent, proof, root)).toBe(true);
      void i;
    }
    // 篡改事件后验证必须失败
    const proofRes = await fetch(`${base}/v0/kt/proof/0`);
    const { proof } = (await proofRes.json()) as { proof: KtInclusionProof };
    const fake: KTEvent = { did: "did:mychat:fake", type: "register", payload: new Uint8Array(1), index: 0 };
    expect(ktVerifyInclusion(fake, proof, root)).toBe(false);
  });

  it("非法用户名（含特殊字符）被拒", async () => {
    const identity = createIdentity();
    const record = makeUserNameRecord(identity.ikEd.privateKey, "bad name!", identity.did, 0);
    const res = await fetch(`${base}/v0/registry/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
    });
    expect(res.status).toBe(409);
  });
});

describe("Storage（块 + 信箱）", () => {
  it("块 PUT/GET 往返；缺失 404", async () => {
    const data = randomBytes(1024);
    const put = await fetch(`${base}/v0/storage/blocks/bafk-test-1`, { method: "PUT", body: Buffer.from(data) });
    expect(put.status).toBe(201);

    const get = await fetch(`${base}/v0/storage/blocks/bafk-test-1`);
    expect(new Uint8Array(await get.arrayBuffer())).toEqual(data);

    expect((await fetch(`${base}/v0/storage/blocks/bafk-missing`)).status).toBe(404);
  });

  it("信箱 append → fetch 增量拉取（cursor 语义）", async () => {
    const mailbox = "mailbox-pseudonym-A";
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailbox)}/append`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ envelope: envelopeToJson(makeEnvelope(mailbox)) }),
      });
      expect(res.status).toBe(201);
    }
    const first = (await (await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailbox)}`)).json()) as {
      envelopes: unknown[];
      cursor: number;
    };
    expect(first.envelopes).toHaveLength(3);
    expect(first.cursor).toBe(3);

    // 增量：cursor=2 起只拉 1 条
    const inc = (await (await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailbox)}?cursor=2`)).json()) as {
      envelopes: unknown[];
    };
    expect(inc.envelopes).toHaveLength(1);

    // 空信箱
    const empty = (await (await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent("nobody")}`)).json()) as {
      envelopes: unknown[];
      cursor: number;
    };
    expect(empty.envelopes).toHaveLength(0);
  });

  it("畸形信封被拒（nonce 长度 / 档位 / 空负载）", async () => {
    const mailbox = "mailbox-bad-envelope";
    const bad = makeEnvelope(mailbox);
    bad.nonce = randomBytes(12); // AES-GCM 长度，不是 XChaCha 的 24
    const res = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailbox)}/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope: envelopeToJson(bad) }),
    });
    expect(res.status).toBe(400);
  });
});

describe("Relay（WS 唤醒 + 直投）", () => {
  it("信箱新内容触发 mailbox-activity 唤醒", async () => {
    const mailbox = "mailbox-wake-test";
    const ws = new WebSocket(`ws://127.0.0.1:${node.port}/v0/relay/subscribe?mailbox=${encodeURIComponent(mailbox)}`);
    const received: string[] = [];
    ws.on("message", (data) => received.push(data.toString()));

    // 连接建立时节点先发一条当前活动（订阅确认）
    await vi.waitFor(() => expect(received.length).toBeGreaterThanOrEqual(1));

    await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailbox)}/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope: envelopeToJson(makeEnvelope(mailbox)) }),
    });

    await vi.waitFor(() => {
      const types = received.map((m) => (JSON.parse(m) as { type: string }).type);
      expect(types.filter((t) => t === "mailbox-activity").length).toBeGreaterThanOrEqual(2);
    });
    ws.close();
  });

  it("IRelay.send 直投：在线订阅者收到信封本体（协议边界保留）", async () => {
    const mailbox = "mailbox-direct";
    const ws = new WebSocket(`ws://127.0.0.1:${node.port}/v0/relay/subscribe?mailbox=${encodeURIComponent(mailbox)}`);
    const received: string[] = [];
    ws.on("message", (data) => received.push(data.toString()));
    await vi.waitFor(() => expect(received.length).toBeGreaterThanOrEqual(1));

    const send = await fetch(`${base}/v0/relay/send`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope: envelopeToJson(makeEnvelope(mailbox)) }),
    });
    expect(send.status).toBe(202);

    await vi.waitFor(() => {
      const envelopes = received
        .map((m) => JSON.parse(m) as { type: string; envelope?: unknown })
        .filter((m) => m.type === "envelope");
      expect(envelopes).toHaveLength(1);
    });
    ws.close();
  });
});
