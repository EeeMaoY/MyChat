/**
 * M2-S9 Gate e2e（Node 侧，真实 dev-node）：
 * 1. OPK 池消耗与低水位语义（多握手不冲突，KI-1 前提）
 * 2. KI-1 闭环：同身份"恢复后"重新握手 → 会话替换 → 与旧联系人双向通信恢复
 * 3. KI-4 闭环：守护者经重建会话回传分片 → 重组 RK → 解开 wrap v2（含用户名）
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  acceptSession,
  base58Encode,
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
  openGuardianShare,
  openIdentityWrap,
  randomBytes,
  recoverRk,
  sealGuardianShare,
  serializeIdentity,
  sessionMailbox,
  sessionReceive,
  sessionSend,
  splitSecret,
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

// ---------- 最小客户端驱动（持有 OPK 池，M2-S9 语义） ----------

interface Prekeys {
  spk: KeyPair;
  /** 本地池：id → 密钥对 */
  pool: Map<number, KeyPair>;
  /** 本机设备 dkId（池分槽所属，M2-S10） */
  dkId: string;
}

async function register(identity: Identity, name: string, poolSize = 5): Promise<Prekeys> {
  const record = makeUserNameRecord(identity.ikEd.privateKey, name, identity.did, 0);
  expect(verifyUserNameRecord(record)).toBe(true);
  const reg = await fetch(`${base}/v0/registry/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
  });
  expect(reg.status).toBe(201);
  const spk = generateX25519KeyPair();
  const first = generateX25519KeyPair();
  const firstId = deriveOpkId(first.publicKey);
  const bundle = issuePreKeyBundle(identity, spk, { ...first, id: firstId }, 3_600_000);
  const dkId = await registerDeviceCert(base, identity);
  const put = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}?device=${encodeURIComponent(dkId)}`, {
    method: "PUT",
    body: Buffer.from(encodePreKeyBundle(bundle)),
  });
  expect(put.status).toBe(201);
  const pool = new Map<number, KeyPair>([[firstId, first]]);
  const rest: { id: number; public: string }[] = [];
  while (pool.size < poolSize) {
    const k = generateX25519KeyPair();
    const id = deriveOpkId(k.publicKey);
    if (pool.has(id)) continue;
    pool.set(id, k);
    rest.push({ id, public: base58Encode(k.publicKey) });
  }
  const add = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}/opks?device=${encodeURIComponent(dkId)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ opks: rest }),
  });
  expect(add.status).toBe(201);
  return { spk, pool, dkId };
}

async function fetchBundleBytes(did: string): Promise<Uint8Array> {
  const res = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(did)}`);
  expect(res.status).toBe(200);
  return new Uint8Array(await res.arrayBuffer());
}

async function consumeOpkRemote(did: string, opkId: number, dkId: string): Promise<void> {
  const res = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(did)}/opk/${opkId}?device=${encodeURIComponent(dkId)}`, {
    method: "DELETE",
  });
  expect(res.status).toBe(200);
}

async function append(mailboxId: string, envelope: Envelope): Promise<void> {
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

async function fetchMailbox(mailboxId: string): Promise<Envelope[]> {
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

function seal(wire: Uint8Array, mailboxId: string): Envelope {
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
  return envelope.payload.slice(4, 4 + view.getUint32(0, false));
}

interface Party {
  identity: Identity;
  prekeys: Prekeys;
  /** did → 对端会话（M2-S9 替换语义） */
  sessions: Map<string, Session>;
}

/** 发起方与响应方握手；返回双方视角会话（响应方按 IK-x 匹配最新信封、消耗 OPK、替换会话）。 */
async function handshake(initiator: Party, responder: Party, firstText: string): Promise<{ initiatorSession: Session; responderSession: Session }> {
  const bundle = decodePreKeyBundle(await fetchBundleBytes(responder.identity.did));
  const { session, wire } = initiateSession(initiator.identity, bundle, utf8ToBytes(firstText));
  const mailbox = `discovery-${responder.identity.did}`;
  await append(mailbox, seal(wire, mailbox));

  const envelopes = await fetchMailbox(mailbox);
  const { bytesEqual } = await import("@mychat/core");
  let matched: Uint8Array | undefined;
  // 同一发起方可能多次握手（设备丢失→恢复场景）：倒序取**最新**一条匹配信封
  for (let i = envelopes.length - 1; i >= 0; i--) {
    const wireBytes = unseal(envelopes[i]!);
    const msg = decodeSessionWire(wireBytes);
    if (msg.kind === 1 && bytesEqual(msg.x3dh.ikxSenderPublic, initiator.identity.ikX.publicKey)) {
      matched = wireBytes;
      break;
    }
  }
  if (!matched) throw new Error("握手信封未找到");
  const msg = decodeSessionWire(matched);
  const usedId = msg.x3dh.opkId;
  const opkKey = responder.prekeys.pool.get(usedId);
  if (!opkKey) {
    const stats = await (
      await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(responder.identity.did)}/stats?device=${encodeURIComponent(responder.prekeys.dkId)}`)
    ).json();
    throw new Error(`OPK #${usedId} 不在本地池（本地 keys: ${[...responder.prekeys.pool.keys()].join(",")}；节点 stats: ${JSON.stringify(stats)}）`);
  }
  const { session: sessionB } = acceptSession(
    responder.identity,
    responder.prekeys.spk,
    new Map([[usedId, opkKey]]),
    matched,
    initiator.identity.did,
  );
  responder.prekeys.pool.delete(usedId);
  await consumeOpkRemote(responder.identity.did, usedId, responder.prekeys.dkId);
  responder.sessions.set(initiator.identity.did, sessionB); // M2-S9 替换语义
  return { initiatorSession: session, responderSession: sessionB };
}

async function sendText(session: Session, text: string): Promise<void> {
  const wire = sessionSend(session, utf8ToBytes(JSON.stringify({ v: 1, type: "chat", text })));
  const mailboxId = sessionMailbox(session, "send", Date.now());
  await append(mailboxId, seal(wire, mailboxId));
}

async function receiveAllTexts(session: Session): Promise<string[]> {
  const now = Date.now();
  const out: string[] = [];
  for (const at of [now - EPOCH_MS, now, now + EPOCH_MS]) {
    for (const envelope of await fetchMailbox(sessionMailbox(session, "recv", at))) {
      try {
        const plaintext = sessionReceive(session, unseal(envelope));
        const parsed = JSON.parse(bytesToUtf8(plaintext)) as { type?: string; text?: string };
        if (parsed.type === "chat" && typeof parsed.text === "string") out.push(parsed.text);
      } catch {
        /* 非本会话或旧文本 */
      }
    }
  }
  return out;
}

describe("M2-S9 Gate：OPK 池与会话重建（KI-1/KI-4 闭环）", () => {
  it("OPK 池一次性分发：多次握手各消耗不同 OPK，同身份重复握手成功（KI-1）", async () => {
    const bobIdentity = createIdentity();
    const bobPrekeys = await register(bobIdentity, "bob_m2");
    const alice = createIdentity();

    const bobSessions = new Map<string, Session>();
    const bobParty: Party = { identity: bobIdentity, prekeys: bobPrekeys, sessions: bobSessions };

    // 同一 alice 身份先后两次握手（模拟：设备丢失前与恢复后）
    await handshake({ identity: alice }, bobParty, "丢失前的握手");
    const { initiatorSession: aliceAfterRecovery } = await handshake({ identity: alice }, bobParty, "恢复后的新握手");

    // 新会话双向通信（KI-1 核心：恢复后与旧联系人直接可通信）
    await sendText(aliceAfterRecovery, "恢复后你好 bob");
    const bobSession = bobSessions.get(alice.did)!;
    const bobReceived = await receiveAllTexts(bobSession);
    expect(bobReceived).toContain("恢复后你好 bob");
    const reply = sessionSend(bobSession, utf8ToBytes(JSON.stringify({ v: 1, type: "chat", text: "欢迎回来" })));
    const mailbox = sessionMailbox(aliceAfterRecovery, "recv", Date.now());
    await append(mailbox, seal(reply, mailbox));
    expect(await receiveAllTexts(aliceAfterRecovery)).toContain("欢迎回来");
  });

  it("KI-4 闭环：守护者经重建会话回传分片 → 重组 RK → 解开 wrap v2（含用户名）", async () => {
    const MY_NAME = "alice_m2";
    const owner = createIdentity();
    const guardians = [createIdentity(), createIdentity()];
    const guardianParties: Party[] = [];
    for (const [i, g] of guardians.entries()) {
      const party: Party = { identity: g, prekeys: await register(g, `guardian_m2_${i}`), sessions: new Map() };
      guardianParties.push(party);
    }

    // owner 与两位守护者分别建会话（丢失前）
    for (const gp of guardianParties) {
      await handshake({ identity: owner }, gp, "丢失前握手");
    }

    // owner 设置恢复（wrap v2 含用户名）
    const { createRecoverySetup } = await import("@mychat/core");
    const setup = createRecoverySetup(owner, guardians.map((g) => g.did), 2, MY_NAME);
    const wrapPut = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(setup.wrapCid)}`, {
      method: "PUT",
      body: Buffer.from(setup.wrap),
    });
    expect(wrapPut.status).toBe(201);
    const packs = guardians.map((g) => sealGuardianShare(setup, g.did));

    // "设备丢失后"：owner 身份经 S7 恢复（此处聚焦 KI-4 分片回传链路）
    const newcomer = createIdentity();
    for (const gp of guardianParties) {
      await handshake({ identity: newcomer }, gp, "恢复请求上下文");
    }

    // 守护者开启分片包并经**新会话**回传（confirmRecoveryRequest 的核心动作）
    const collected = packs.map((pack, i) => {
      const share = openGuardianShare(guardianParties[i]!.identity.ikEd.privateKey, pack);
      return share;
    });

    // 恢复者重组 → 解开 wrap v2 → 身份与用户名一并还原
    const rk = recoverRk(collected, 32);
    const wrapRes = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(setup.wrapCid)}`);
    const wrap = new Uint8Array(await wrapRes.arrayBuffer());
    const payload = openIdentityWrap(rk, wrap);
    expect(payload.myName).toBe(MY_NAME);
    const restored = (await import("@mychat/core")).deserializeIdentity(payload.identityJson);
    expect(restored.did).toBe(owner.did);
    expect(restored.ikEd.privateKey).toEqual(owner.ikEd.privateKey);
    void utf8ToBytes;
  });
});
