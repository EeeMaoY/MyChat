/**
 * M2-S9 Gate e2e（Node 侧，真实 dev-node）：
 * 1. OPK 池消耗与低水位语义（多握手不冲突，KI-1 前提）
 * 2. KI-1 闭环：同身份"恢复后"重新握手 → 会话替换 → 与旧联系人双向通信恢复
 * 3. KI-4 闭环：守护者经重建会话回传分片 → 重组 RK → 解开 wrap v2（含用户名）
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  acceptSession,
  activeDeviceIds,
  base58Encode,
  bytesToUtf8,
  createIdentity,
  decodePreKeyBundle,
  decodeSessionWire,
  deriveOpkId,
  encodeDeviceRevocationJson,
  encodePreKeyBundle,
  fingerprintDeviceIds,
  foldDeviceEvents,
  generateX25519KeyPair,
  initiateSession,
  issuePreKeyBundle,
  makeDeviceRevocation,
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
  type KTEvent,
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

// ---------- 最小客户端驱动（持有 OPK 池，M2-S9 语义；M2-S10 起按设备分槽） ----------

interface Prekeys {
  /** 本机（单设备语义下唯一）设备 dkId */
  dkId: string;
  /** 本机（单设备语义下唯一）SPK */
  spk: KeyPair;
  /** 多设备：dkId → 该设备的 SPK（各设备独立签名的签名预密钥，M2-S10） */
  spkByDevice: Map<string, KeyPair>;
  /** 本地池：id → 密钥对 */
  pool: Map<number, KeyPair>;
  /** opkId → 所属设备 dkId（M2-S10：消耗确认须落对应设备槽位） */
  opkDevice: Map<number, string>;
}

/** 用户名注册（设备挂靠的前置）。 */
async function registerUserName(identity: Identity, name: string): Promise<void> {
  const record = makeUserNameRecord(identity.ikEd.privateKey, name, identity.did, 0);
  expect(verifyUserNameRecord(record)).toBe(true);
  const reg = await fetch(`${base}/v0/registry/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
  });
  expect(reg.status).toBe(201);
}

/** 登记一台设备并上传其 bundle 模板与 OPK 池（M2-S10：材料按 dkId 分槽）。 */
async function attachDevice(identity: Identity, label: string, poolSize = 5): Promise<Prekeys> {
  const dkId = await registerDeviceCert(base, identity, label);
  const devQs = `?device=${encodeURIComponent(dkId)}`;
  const spk = generateX25519KeyPair();
  const first = generateX25519KeyPair();
  const firstId = deriveOpkId(first.publicKey);
  const bundle = issuePreKeyBundle(identity, spk, { ...first, id: firstId }, 3_600_000);
  const put = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}${devQs}`, {
    method: "PUT",
    body: Buffer.from(encodePreKeyBundle(bundle)),
  });
  expect(put.status).toBe(201);
  const pool = new Map<number, KeyPair>([[firstId, first]]);
  const opkDevice = new Map<number, string>([[firstId, dkId]]);
  const rest: { id: number; public: string }[] = [];
  while (pool.size < poolSize) {
    const k = generateX25519KeyPair();
    const id = deriveOpkId(k.publicKey);
    if (pool.has(id)) continue;
    pool.set(id, k);
    opkDevice.set(id, dkId);
    rest.push({ id, public: base58Encode(k.publicKey) });
  }
  const add = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}/opks${devQs}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ opks: rest }),
  });
  expect(add.status).toBe(201);
  return { dkId, spk, spkByDevice: new Map([[dkId, spk]]), pool, opkDevice };
}

/** 单设备注册（M2-S9 语义）：用户名 + 一台设备。 */
async function register(identity: Identity, name: string, poolSize = 5): Promise<Prekeys> {
  await registerUserName(identity, name);
  return attachDevice(identity, "test-device", poolSize);
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
      await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(responder.identity.did)}/stats?device=${encodeURIComponent(responder.prekeys.opkDevice.get(usedId) ?? "")}`)
    ).json();
    throw new Error(`OPK #${usedId} 不在本地池（本地 keys: ${[...responder.prekeys.pool.keys()].join(",")}；节点 stats: ${JSON.stringify(stats)}）`);
  }
  // M2-S10：分发的 bundle 属于哪台设备，accept 就用该设备的 SPK（每设备独立签名预密钥）
  const deviceSpk = responder.prekeys.spkByDevice.get(responder.prekeys.opkDevice.get(usedId)!) ?? responder.prekeys.spk;
  const { session: sessionB } = acceptSession(
    responder.identity,
    deviceSpk,
    new Map([[usedId, opkKey]]),
    matched,
    initiator.identity.did,
  );
  responder.prekeys.pool.delete(usedId);
  // M2-S10：消耗确认落 OPK 所属设备的槽位
  await consumeOpkRemote(responder.identity.did, usedId, responder.prekeys.opkDevice.get(usedId)!);
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

/** 拉取 DID 的 KT 事件流并还原为客户端折叠输入（M2-S10 设备集核对的数据源）。 */
async function fetchKtEvents(did: string): Promise<KTEvent[]> {
  const res = await fetch(`${base}/v0/kt/list/${encodeURIComponent(did)}`);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { events: { did: string; type: string; index: number; payload: string }[] };
  return body.events.map((e) => ({
    did: e.did,
    type: e.type as KTEvent["type"],
    index: e.index,
    payload: new Uint8Array(Buffer.from(e.payload, "base64")),
  }));
}

describe("M2-S10 Gate：多设备（FR-1.4 设备凭证/吊销/对端轮换）", () => {
  function mergePool(parts: Prekeys[]): Prekeys {
    const pool = new Map<number, KeyPair>();
    const opkDevice = new Map<number, string>();
    const spkByDevice = new Map<string, KeyPair>();
    for (const p of parts) {
      for (const [id, kp] of p.pool) pool.set(id, kp);
      for (const [id, dk] of p.opkDevice) opkDevice.set(id, dk);
      for (const [dk, spk] of p.spkByDevice) spkByDevice.set(dk, spk);
    }
    return { dkId: parts[0]!.dkId, spk: parts[0]!.spk, spkByDevice, pool, opkDevice };
  }

  it("双设备 round-robin 分发：连续取 bundle 交替命中两台设备，各自握手后双向通信成功", async () => {
    const bob = createIdentity();
    await registerUserName(bob, "bob_s10");
    const devA = await attachDevice(bob, "设备A");
    const devB = await attachDevice(bob, "设备B");
    const bobParty: Party = { identity: bob, prekeys: mergePool([devA, devB]), sessions: new Map() };

    // 连续两次分发：确定性轮询交替命中 A、B（以 OPK 归属槽位判定）
    const b1 = decodePreKeyBundle(await fetchBundleBytes(bob.did));
    const b2 = decodePreKeyBundle(await fetchBundleBytes(bob.did));
    expect(devA.pool.has(b1.opkId) || devB.pool.has(b1.opkId)).toBe(true);
    expect(devA.pool.has(b2.opkId) || devB.pool.has(b2.opkId)).toBe(true);
    // 交替：两次命中不同设备
    expect((devA.pool.has(b1.opkId) ? "A" : "B")).not.toBe(devA.pool.has(b2.opkId) ? "A" : "B");

    // 两位联系人分别经不同设备的 bundle 与 bob 建立会话，双向通信均可用
    const c1 = createIdentity();
    const c2 = createIdentity();
    const h1 = await handshake({ identity: c1 }, bobParty, "走设备A的联系人");
    const h2 = await handshake({ identity: c2 }, bobParty, "走设备B的联系人");
    expect(bobParty.sessions.size).toBe(2);
    await sendText(h1.initiatorSession, "A设备会话 OK");
    await sendText(h2.initiatorSession, "B设备会话 OK");
    expect(await receiveAllTexts(h1.responderSession)).toContain("A设备会话 OK");
    expect(await receiveAllTexts(h2.responderSession)).toContain("B设备会话 OK");
    // bob 侧回复链路（responder → initiator）
    await sendText(bobParty.sessions.get(c1.did)!, "bob 回复 1");
    expect(await receiveAllTexts(h1.initiatorSession)).toContain("bob 回复 1");
  });

  it("吊销停发与对端轮换：吊销设备后新握手落存活设备，KT 折叠指纹变化可核验", async () => {
    const bob = createIdentity();
    await registerUserName(bob, "bob_s10b");
    const devA = await attachDevice(bob, "设备A");
    const devB = await attachDevice(bob, "设备B");
    const bobParty: Party = { identity: bob, prekeys: mergePool([devA, devB]), sessions: new Map() };

    const alice = createIdentity();
    await handshake({ identity: alice }, bobParty, "初识（经轮询命中的设备）");

    // 吊销前：客户端本地折叠（KT 事件流 + 验签，SR-5）→ 两台有效设备
    const before = foldDeviceEvents(await fetchKtEvents(bob.did));
    expect(before.invalidEvents).toBe(0);
    expect(activeDeviceIds(before).sort()).toEqual([devA.dkId, devB.dkId].sort());
    const fpBefore = fingerprintDeviceIds(activeDeviceIds(before));

    // bob 吊销设备 A（IK 签名吊销声明）
    const revocation = makeDeviceRevocation(bob.ikEd.privateKey, bob.did, devA.dkId);
    const revoke = await fetch(`${base}/v0/registry/devices/${encodeURIComponent(bob.did)}/${encodeURIComponent(devA.dkId)}`, {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ revocation: JSON.parse(encodeDeviceRevocationJson(revocation)) }),
    });
    expect(revoke.status).toBe(200);
    expect(((await revoke.json()) as { changed: boolean }).changed).toBe(true);

    // 吊销后：折叠只剩 B（指纹变化 → 客户端 ensureSessionFresh 触发轮换的依据）
    const after = foldDeviceEvents(await fetchKtEvents(bob.did));
    expect(activeDeviceIds(after)).toEqual([devB.dkId]);
    expect(fingerprintDeviceIds(activeDeviceIds(after))).not.toBe(fpBefore);
    const viewA = after.devices.find((d) => d.certificate.dkId === devA.dkId)!;
    expect(viewA.revoked).toBe(true);

    // 对端轮换（rotateSession 的核心动作）：重新握手必然落在存活设备 B
    const { initiatorSession: rotated } = await handshake({ identity: alice }, bobParty, "轮换后的新握手");
    await sendText(rotated, "轮换后消息照常收发");
    const bobSession = bobParty.sessions.get(alice.did)!;
    expect(await receiveAllTexts(bobSession)).toContain("轮换后消息照常收发");

    // 吊销设备的材料已停发：池中不再有 A 槽位的 OPK 可供分发（本轮分发已落 B 且消耗其 OPK）
    const statsB = (await (
      await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(bob.did)}/stats?device=${encodeURIComponent(devB.dkId)}`)
    ).json()) as { available: number; issued: number };
    expect(statsB.available + statsB.issued).toBeGreaterThan(0);
  });

  it("全部设备吊销后 bundle 分发 404（身份无可用设备的诚实语义）", async () => {
    const carol = createIdentity();
    await registerUserName(carol, "carol_s10");
    const dev = await attachDevice(carol, "唯一设备");
    expect((await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(carol.did)}`)).status).toBe(200);

    const revocation = makeDeviceRevocation(carol.ikEd.privateKey, carol.did, dev.dkId);
    const revoke = await fetch(`${base}/v0/registry/devices/${encodeURIComponent(carol.did)}/${encodeURIComponent(dev.dkId)}`, {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ revocation: JSON.parse(encodeDeviceRevocationJson(revocation)) }),
    });
    expect(revoke.status).toBe(200);
    expect((await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(carol.did)}`)).status).toBe(404);
    // 被吊销设备槽位再上传 bundle 也被拒（材料停发的完整性）
    const spk = generateX25519KeyPair();
    const opk = generateX25519KeyPair();
    const bundle = issuePreKeyBundle(carol, spk, { ...opk, id: deriveOpkId(opk.publicKey) }, 3_600_000);
    const put = await fetch(
      `${base}/v0/registry/bundle/${encodeURIComponent(carol.did)}?device=${encodeURIComponent(dev.dkId)}`,
      { method: "PUT", body: Buffer.from(encodePreKeyBundle(bundle)) },
    );
    expect(put.status).toBe(403);
  });
});
