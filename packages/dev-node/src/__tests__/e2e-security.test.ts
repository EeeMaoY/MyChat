/**
 * 端到端密文性测试（M0 Gate §2 隐私门的自动化，需求报告 §11.1）。
 *
 * 以节点视角执行"诚实但好奇节点"检查（威胁模型 A1）：
 * 双客户端经真实 dev-node 完成注册→加好友→互发后，从节点 API
 * 拉取全部投递数据，断言其中不含任何明文内容与身份关联信息。
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  acceptSession,
  bytesToUtf8,
  createIdentity,
  decodePreKeyBundle,
  decodeSessionWire,
  deriveOpkId,
  encodePreKeyBundle,
  generateX25519KeyPair,
  initiateSession,
  issuePreKeyBundle,
  makeUserNameRecord,
  sessionMailbox,
  sessionReceive,
  sessionSend,
  utf8ToBytes,
  verifyUserNameRecord,
  type Envelope,
  type Identity,
  type KeyPair,
  type Session,
} from "@mychat/core";

import { startDevNode, type DevNode } from "../server";
import { registerDeviceCert } from "./helpers-device";

const EPOCH_MS = 60_000;
const PAD_SIZES = [256, 1024, 16_384, 131_072] as const;

let node: DevNode;
let base: string;

beforeEach(async () => {
  node = await startDevNode();
  base = `http://127.0.0.1:${node.port}`;
});

afterEach(async () => {
  await node.close();
});

// ---------- 最小客户端驱动（与 client-web lib 相同协议约定的 Node 版） ----------

interface ClientKeys {
  identity: Identity;
  spk: KeyPair;
  opk: KeyPair & { id: number };
}

async function registerClient(identity: Identity, name: string): Promise<ClientKeys> {
  const record = makeUserNameRecord(identity.ikEd.privateKey, name, identity.did, 0);
  expect(verifyUserNameRecord(record)).toBe(true);
  const res = await fetch(`${base}/v0/registry/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
  });
  expect(res.status).toBe(201);

  const spk = generateX25519KeyPair();
  const opk = generateX25519KeyPair();
  const bundle = issuePreKeyBundle(identity, spk, { ...opk, id: deriveOpkId(opk.publicKey) }, 3_600_000);
  const dkId = await registerDeviceCert(base, identity);
  const put = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}?device=${encodeURIComponent(dkId)}`, {
    method: "PUT",
    body: Buffer.from(encodePreKeyBundle(bundle)),
  });
  expect(put.status).toBe(201);
  return { identity, spk, opk: { ...opk, id: deriveOpkId(opk.publicKey) } };
}

async function resolveDid(name: string): Promise<string> {
  const res = await fetch(`${base}/v0/registry/resolve/${encodeURIComponent(name)}`);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { record: { did: string } };
  return body.record.did;
}

async function fetchBundleBytes(did: string): Promise<Uint8Array> {
  const res = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(did)}`);
  expect(res.status).toBe(200);
  return new Uint8Array(await res.arrayBuffer());
}

async function appendEnvelope(mailboxId: string, envelope: Envelope): Promise<void> {
  const res = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}/append`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      envelope: {
        version: envelope.version,
        epoch: envelope.epoch,
        toPseudonym: envelope.toPseudonym,
        padClass: envelope.padClass,
        nonce: Buffer.from(envelope.nonce).toString("base64"),
        payload: Buffer.from(envelope.payload).toString("base64"),
      },
    }),
  });
  expect(res.status).toBe(201);
}

async function fetchMailboxRaw(mailboxId: string): Promise<Envelope[]> {
  const res = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}`);
  const body = (await res.json()) as {
    envelopes: { version: string; epoch: number; toPseudonym: string; padClass: number; nonce: string; payload: string }[];
  };
  return body.envelopes.map((e) => ({
    version: e.version,
    epoch: e.epoch,
    toPseudonym: e.toPseudonym,
    padClass: e.padClass as 0 | 1 | 2 | 3,
    nonce: new Uint8Array(Buffer.from(e.nonce, "base64")),
    payload: new Uint8Array(Buffer.from(e.payload, "base64")),
  }));
}

/** 装信封：与 client-web lib.seal 相同约定（协议规范 §8）。 */
function sealWire(wire: Uint8Array, mailboxId: string): Envelope {
  const size = wire.length + 4;
  const padClass = (size <= 256 ? 0 : size <= 1024 ? 1 : size <= 16_384 ? 2 : 3) as 0 | 1 | 2 | 3;
  const padded = new Uint8Array(PAD_SIZES[padClass]);
  new DataView(padded.buffer).setUint32(0, wire.length, false);
  padded.set(wire, 4);
  return {
    version: "1",
    epoch: Math.floor(Date.now() / EPOCH_MS),
    toPseudonym: mailboxId,
    padClass,
    nonce: crypto.getRandomValues(new Uint8Array(24)),
    payload: padded,
  };
}

function unseal(envelope: Envelope): Uint8Array {
  const view = new DataView(envelope.payload.buffer, envelope.payload.byteOffset, envelope.payload.byteLength);
  const len = view.getUint32(0, false);
  return envelope.payload.slice(4, 4 + len);
}

describe("隐私门：节点视角无明文（A1 对策验证）", () => {
  it("全流程后，节点上所有投递数据不泄露消息明文与身份关联", async () => {
    const secretText = "绝密：明天下午三点老地方见 🔐";
    const aliceKeys = await registerClient(createIdentity(), "alice_sec");
    const bobKeys = await registerClient(createIdentity(), "bob_sec");
    const alice = aliceKeys.identity;
    const bob = bobKeys.identity;

    // —— A → B 握手（经 B 的发现信箱）——
    const bobDid = await resolveDid("bob_sec");
    const bobBundle = decodePreKeyBundle(await fetchBundleBytes(bobDid));
    const handshake = JSON.stringify({ v: 1, fromDid: alice.did, fromName: "alice_sec", note: "你好" });
    const { session: aliceSession, wire } = initiateSession(alice, bobBundle, utf8ToBytes(handshake));
    const bobInbox = `did-inbox-${bob.did}`; // 发现信箱（测试内简化派生，不影响密文性断言）
    await appendEnvelope(bobInbox, sealWire(wire, bobInbox));

    // —— B 接受握手 ——
    const inboxEnvelopes = await fetchMailboxRaw(bobInbox);
    expect(inboxEnvelopes).toHaveLength(1);
    const handshakeWire = unseal(inboxEnvelopes[0]!);
    expect(decodeSessionWire(handshakeWire).kind).toBe(1);
    const opkPool = new Map([[bobKeys.opk.id, bobKeys.opk]]);
    const { session: bobSession, plaintext } = acceptSession(bob, bobKeys.spk, opkPool, handshakeWire, alice.did);
    expect(JSON.parse(bytesToUtf8(plaintext)).fromDid).toBe(alice.did);

    // —— A → B 密信（经会话伪地址信箱）——
    const sendMailbox = sessionMailbox(aliceSession, "send", Date.now());
    await appendEnvelope(sendMailbox, sealWire(sessionSend(aliceSession, utf8ToBytes(secretText)), sendMailbox));

    // —— B 收（覆盖当前与前一 epoch 窗口，与 lib.pollSession 相同策略）——
    const received: string[] = [];
    for (const at of [Date.now() - EPOCH_MS, Date.now()]) {
      const recvMailbox = sessionMailbox(bobSession, "recv", at);
      const incoming = await fetchMailboxRaw(recvMailbox);
      for (const e of incoming) {
        try {
          received.push(bytesToUtf8(sessionReceive(bobSession, unseal(e))));
        } catch {
          /* 非本会话信封 */
        }
      }
    }
    expect(received).toContain(secretText);

    // ===== 隐私断言：枚举节点上与本对话有关的一切投递数据（A1 视角） =====
    const touchedMailboxes = new Set<string>([bobInbox, sendMailbox]);
    for (const at of [Date.now() - EPOCH_MS, Date.now()]) {
      touchedMailboxes.add(sessionMailbox(bobSession, "recv", at));
    }
    const nodeVisiblePayloads: Uint8Array[] = [];
    for (const mailboxId of touchedMailboxes) {
      for (const envelope of await fetchMailboxRaw(mailboxId)) {
        nodeVisiblePayloads.push(envelope.payload);
      }
    }
    expect(nodeVisiblePayloads.length).toBeGreaterThanOrEqual(2);

    // 1. 无消息明文
    for (const payload of nodeVisiblePayloads) {
      expect(bytesToUtf8(payload)).not.toContain(secretText);
      expect(bytesToUtf8(payload)).not.toContain("老地方");
    }
    // 2. 无收发双方 DID 明文
    for (const payload of nodeVisiblePayloads) {
      const text = bytesToUtf8(payload);
      expect(text).not.toContain(alice.did);
      expect(text).not.toContain(bob.did);
    }
    // 3. 填充定长（长度不泄露内容规模）：全部命中四档之一
    for (const payload of nodeVisiblePayloads) {
      expect([...PAD_SIZES]).toContain(payload.length);
    }
  });
});
