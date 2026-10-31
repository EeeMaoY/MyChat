/**
 * dev-node 集成测试：真实 HTTP + WS 交互（无 mock）。
 * 覆盖：Registry 验签注册、Storage 块与信箱、KT 联动、Relay 唤醒与直投。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocket } from "ws";

import type { Envelope } from "@mychat/core";
import {
  AEAD_NONCE_LENGTH,
  createIdentity,
  decodePreKeyBundle,
  deriveOpkId,
  encodePreKeyBundle,
  generateX25519KeyPair,
  issuePreKeyBundle,
  makeUserNameRecord,
  randomBytes,
} from "@mychat/core";

import { startDevNode, type DevNode } from "../server";
import { envelopeToJson } from "../wire";

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

  it("bundle 分发：有效上传 201 / 查回一致 / 篡改与坏 DID 被拒 / 缺失 404", async () => {
    const { identity } = await registerUser("bundleuser");
    const spk = generateX25519KeyPair();
    const opk = generateX25519KeyPair();
    const bundle = issuePreKeyBundle(identity, spk, { ...opk, id: deriveOpkId(opk.publicKey) }, 3_600_000);
    const encoded = encodePreKeyBundle(bundle);
    void decodePreKeyBundle; // 保持导入面一致（解码校验在节点内完成）

    const put = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}`, {
      method: "PUT",
      body: Buffer.from(encoded),
    });
    expect(put.status).toBe(201);

    const get = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}`);
    expect(new Uint8Array(await get.arrayBuffer())).toEqual(encoded);

    // 篡改一个字节 → 节点验签拒绝
    const tampered = encoded.slice();
    tampered[40]! ^= 1;
    const putBad = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}`, {
      method: "PUT",
      body: Buffer.from(tampered),
    });
    expect(putBad.status).toBe(400);

    // DID 格式非法
    const putBadDid = await fetch(`${base}/v0/registry/bundle/not-a-did`, { method: "PUT", body: Buffer.from(encoded) });
    expect(putBadDid.status).toBe(400);

    // 未上传 bundle 的合法格式 DID（格式非法才是 400）
    const stranger = createIdentity();
    const missing = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(stranger.did)}`);
    expect(missing.status).toBe(404);
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
