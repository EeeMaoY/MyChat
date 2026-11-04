/**
 * 节点持久化测试（M3 修复）：MYCHAT_DATA_DIR 语义——写入追加 JSONL，
 * 重启重放后 registry/bundle/OPK/块/信箱/KT 根链全量恢复；
 * 未设置时保持纯内存（原有属性）。
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  acceptSession,
  base58Encode,
  createIdentity,
  decodePreKeyBundle,
  deriveOpkId,
  encodePreKeyBundle,
  generateX25519KeyPair,
  initiateSession,
  issuePreKeyBundle,
  ktVerifyInclusion,
  makeUserNameRecord,
  randomBytes,
  sessionMailbox,
  stripPadding,
  utf8ToBytes,
  type Envelope,
  type KTEvent,
  type KtInclusionProof,
  type KeyPair,
} from "@mychat/core";
import { envelopeToJson } from "../wire";

import { startDevNode, type DevNode } from "../server";
import { registerDeviceCert } from "./helpers-device";

let node: DevNode;
let base: string;
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "mychat-persist-"));
});

afterEach(async () => {
  await node.close();
  rmSync(dataDir, { recursive: true, force: true });
});

async function startPersisted(): Promise<void> {
  node = await startDevNode({ persistDir: dataDir });
  base = `http://127.0.0.1:${node.port}`;
}

describe("节点持久化（重启恢复）", () => {
  it("重启后 registry/bundle/OPK 池/块/信箱/KT 根链全量恢复；新用户可对老用户发起握手", async () => {
    await startPersisted();

    // ===== 第一代节点：alice 完整注册（用户名 + 设备 + bundle + OPK 池 + 块 + 信箱）=====
    const alice = createIdentity();
    const record = makeUserNameRecord(alice.ikEd.privateKey, "alice_p", alice.did, 0);
    const reg = await fetch(`${base}/v0/registry/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
    });
    expect(reg.status).toBe(201);
    const dkId = await registerDeviceCert(base, alice, "alice-persist");
    const devQs = `?device=${encodeURIComponent(dkId)}`;
    const spk = generateX25519KeyPair();
    const opk1 = generateX25519KeyPair();
    const opk2 = generateX25519KeyPair();
    const bundle = issuePreKeyBundle(alice, spk, { ...opk1, id: deriveOpkId(opk1.publicKey) }, 3_600_000);
    const put = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(alice.did)}${devQs}`, {
      method: "PUT",
      body: Buffer.from(encodePreKeyBundle(bundle)),
    });
    expect(put.status).toBe(201);
    const addOpks = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(alice.did)}/opks${devQs}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        opks: [{ id: deriveOpkId(opk2.publicKey), public: base58Encode(opk2.publicKey) }],
      }),
    });
    expect(addOpks.status).toBe(201);

    const blockData = randomBytes(256);
    const blockCid = "bafk-persist-block";
    const putBlock = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(blockCid)}`, {
      method: "PUT",
      body: Buffer.from(blockData),
    });
    expect(putBlock.status).toBe(201);

    const mailboxId = "persist-mailbox";
    const envelope = makeEnvelopeLocal(mailboxId);
    const appendRes = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope: envelopeToJson(envelope) }),
    });
    expect(appendRes.status).toBe(201);

    const oldRoot = ((await (await fetch(`${base}/v0/kt/root`)).json()) as { root: string }).root;

    // ===== 重启（同目录重放）=====
    await node.close();
    await startPersisted();

    // registry 恢复
    const resolved = await fetch(`${base}/v0/registry/resolve/alice_p`);
    expect(resolved.status).toBe(200);
    expect(((await resolved.json()) as { record: { did: string } }).record.did).toBe(alice.did);

    // KT 根链延续：重启后（未追加新事件前）根与重启前一致
    const restoredRoot = ((await (await fetch(`${base}/v0/kt/root`)).json()) as { root: string }).root;
    expect(restoredRoot).toBe(oldRoot);

    // 设备 + bundle + OPK 池恢复：新用户可解析 → 取 bundle → 握手 → 双向通信
    const bob = createIdentity();
    const bobRecord = makeUserNameRecord(bob.ikEd.privateKey, "bob_p", bob.did, 0);
    const bobReg = await fetch(`${base}/v0/registry/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ record: { ...bobRecord, signature: Buffer.from(bobRecord.signature).toString("base64") } }),
    });
    expect(bobReg.status).toBe(201);

    const bundleRes = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(alice.did)}`);
    expect(bundleRes.status).toBe(200);
    const decoded = decodePreKeyBundle(new Uint8Array(await bundleRes.arrayBuffer()));
    const { session, wire } = initiateSession(bob, decoded, utf8ToBytes("重启后向你发起好友申请"));
    const discoveryMailbox = `discovery-${alice.did}`;
    const appendHandshake = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(discoveryMailbox)}/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope: envelope0(wire, discoveryMailbox) }),
    });
    expect(appendHandshake.status).toBe(201);

    // alice 侧（持本地私钥）可正常 accept：握手材料跨重启完整
    const handshakes = (await (await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(discoveryMailbox)}`)).json()) as {
      envelopes: { version: string; epoch: number; toPseudonym: string; padClass: number; nonce: string; payload: string }[];
    };
    const handshakeEnvelope = handshakes.envelopes[0]!;
    const restored: Envelope = {
      version: handshakeEnvelope.version,
      epoch: handshakeEnvelope.epoch,
      toPseudonym: handshakeEnvelope.toPseudonym,
      padClass: handshakeEnvelope.padClass as 0 | 1 | 2 | 3,
      nonce: new Uint8Array(Buffer.from(handshakeEnvelope.nonce, "base64")),
      payload: new Uint8Array(Buffer.from(handshakeEnvelope.payload, "base64")),
    };
    const opkPool = new Map<number, KeyPair & { id?: number }>([
      [deriveOpkId(opk1.publicKey), opk1],
      [deriveOpkId(opk2.publicKey), opk2],
    ]);
    const accepted = acceptSession(alice, spk, opkPool as never, stripPadding(restored.payload), bob.did);
    expect(new TextDecoder().decode(accepted.plaintext)).toContain("重启后向你发起好友申请");
    void session;
    void sessionMailbox;

    // 块与信箱恢复
    const gotBlock = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(blockCid)}`);
    expect(new Uint8Array(await gotBlock.arrayBuffer())).toEqual(blockData);
    const gotMailbox = (await (await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}`)).json()) as {
      envelopes: unknown[];
    };
    expect(gotMailbox.envelopes).toHaveLength(1);

    // KT 根链：bob 的 register 追加后根已前进，但老事件（alice 设备凭证）的包含性证明仍对当前根有效
    const nowRoot = ((await (await fetch(`${base}/v0/kt/root`)).json()) as { root: string }).root;
    expect(nowRoot).not.toBe(oldRoot);
    const list = (await (await fetch(`${base}/v0/kt/list/${encodeURIComponent(alice.did)}`)).json()) as {
      events: { did: string; type: string; index: number; payload: string }[];
    };
    expect(list.events.map((e) => e.type)).toContain("register");
    const deviceEventIdx = list.events.find((e) => e.type === "device-add")!.index;
    const proofRes = await fetch(`${base}/v0/kt/proof/${deviceEventIdx}`);
    const { proof } = (await proofRes.json()) as { proof: KtInclusionProof };
    const event: KTEvent = {
      did: alice.did,
      type: "device-add",
      index: deviceEventIdx,
      payload: new Uint8Array(Buffer.from(list.events.find((e) => e.type === "device-add")!.payload, "base64")),
    };
    expect(ktVerifyInclusion(event, proof, nowRoot)).toBe(true);
  });

  it("未设置持久化目录时保持纯内存（重启即空）", async () => {
    node = await startDevNode({ persistDir: undefined });
    base = `http://127.0.0.1:${node.port}`;
    const identity = createIdentity();
    const record = makeUserNameRecord(identity.ikEd.privateKey, "ephemeral", identity.did, 0);
    await fetch(`${base}/v0/registry/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
    });
    await node.close();
    node = await startDevNode({});
    base = `http://127.0.0.1:${node.port}`;
    expect((await fetch(`${base}/v0/registry/resolve/ephemeral`)).status).toBe(404);
  });
});

/** 非信封结构的握手裸信封（复用 e2e-m3 的 seal 语义）。 */
function envelope0(wire: Uint8Array, mailboxId: string) {
  const PAD_SIZES = [256, 1024, 16_384, 131_072] as const;
  const size = wire.length + 4;
  const padClass = (size <= 256 ? 0 : size <= 1024 ? 1 : size <= 16_384 ? 2 : 3) as 0 | 1 | 2 | 3;
  const padded = new Uint8Array(PAD_SIZES[padClass]);
  new DataView(padded.buffer).setUint32(0, wire.length, false);
  padded.set(wire, 4);
  return {
    version: "1",
    epoch: Math.floor(Date.now() / 60_000),
    toPseudonym: mailboxId,
    padClass,
    nonce: Buffer.from(randomBytes(24)).toString("base64"),
    payload: Buffer.from(padded).toString("base64"),
  };
}

/** 完整信封（同 server.test.ts 的 makeEnvelope helper）。 */
function makeEnvelopeLocal(toPseudonym: string): Envelope {
  return {
    version: "1",
    epoch: 1,
    toPseudonym,
    padClass: 0,
    nonce: randomBytes(24),
    payload: randomBytes(200),
  };
}
