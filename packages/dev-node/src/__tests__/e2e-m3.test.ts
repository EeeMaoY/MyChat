/**
 * M3-S11 Gate e2e（Node 侧，真实 dev-node）：群组 v1（FR-6.1/6.2，M3 计划 §4）。
 * 1. 建群 + 密钥经 1:1 会话分发 + 多发送方群聊（全员可解、署名可验）
 * 2. 移除断读与防伪造：epoch+1 后被移除者不可达新信箱/新密钥，伪造被 IK 验签拒绝
 * 3. 新成员隔离：加入后仅见新消息（history: new-only）
 * 4. 群附件全链路（CAS + 组内 CK）
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  acceptSession,
  addGroupMember,
  applyGroupKeysPayload,
  base58Decode,
  base58Encode,
  bytesToUtf8,
  createGroup,
  createGroupView,
  createIdentity,
  decodePreKeyBundle,
  decodeSessionWire,
  decryptAttachment,
  deriveOpkId,
  encodePreKeyBundle,
  encryptAttachment,
  generateSenderKeys,
  generateX25519KeyPair,
  groupMailboxId,
  initiateSession,
  issuePreKeyBundle,
  makeEnvelope,
  makeGroupKeysPayload,
  makeUserNameRecord,
  openGroupMessage,
  randomBytes,
  removeGroupMember,
  sealGroupMessage,
  sessionMailbox,
  sessionReceive,
  sessionSend,
  stripPadding,
  utf8ToBytes,
  verifyUserNameRecord,
  type Envelope,
  type GroupKeysPayload,
  type GroupView,
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

// ---------- 最小客户端驱动（1:1 与群信箱） ----------

interface Prekeys {
  spk: KeyPair;
  pool: Map<number, KeyPair>;
  opkDevice: Map<number, string>;
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
  const dkId = await registerDeviceCert(base, identity);
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
  return { spk, pool, opkDevice };
}

function seal(wire: Uint8Array, mailboxId: string): Envelope {
  const size = wire.length + 4;
  const padClass = (size <= 256 ? 0 : size <= 1024 ? 1 : size <= 16_384 ? 2 : 3) as 0 | 1 | 2 | 3;
  const padded = new Uint8Array(PAD_SIZES[padClass]);
  new DataView(padded.buffer).setUint32(0, wire.length, false);
  padded.set(wire, 4);
  return makeEnvelope({ epoch: Math.floor(Date.now() / EPOCH_MS), toPseudonym: mailboxId, padClass, payload: padded });
}

function unseal(envelope: Envelope): Uint8Array {
  const view = new DataView(envelope.payload.buffer, envelope.payload.byteOffset, envelope.payload.byteLength);
  return envelope.payload.slice(4, 4 + view.getUint32(0, false));
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

interface Party {
  identity: Identity;
  prekeys: Prekeys;
  /** did → 1:1 会话 */
  sessions: Map<string, Session>;
  groupView: GroupView | null;
}

/** 发起方 → 响应方 1:1 握手（复用 M2-S9 替换语义）。 */
async function handshake(initiator: Party, responder: Party, firstText: string): Promise<{ initiatorSession: Session; responderSession: Session }> {
  const res = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(responder.identity.did)}`);
  expect(res.status).toBe(200);
  const bundle = decodePreKeyBundle(new Uint8Array(await res.arrayBuffer()));
  const { session, wire } = initiateSession(initiator.identity, bundle, utf8ToBytes(firstText));
  const mailbox = `discovery-${responder.identity.did}`;
  await append(mailbox, seal(wire, mailbox));

  const envelopes = await fetchMailbox(mailbox);
  const { bytesEqual } = await import("@mychat/core");
  let matched: Uint8Array | undefined;
  for (let i = envelopes.length - 1; i >= 0; i--) {
    const wireBytes = unseal(envelopes[i]!);
    const msg = decodeSessionWire(wireBytes);
    if (msg.kind === 1 && bytesEqual(msg.x3dh.ikxSenderPublic, initiator.identity.ikX.publicKey)) {
      matched = wireBytes;
      break;
    }
  }
  if (!matched) throw new Error("握手信封未找到");
  const usedId = decodeSessionWire(matched).x3dh.opkId;
  const opkKey = responder.prekeys.pool.get(usedId);
  if (!opkKey) throw new Error(`OPK #${usedId} 不在本地池`);
  const { session: sessionB } = acceptSession(
    responder.identity,
    responder.prekeys.spk,
    new Map([[usedId, opkKey]]),
    matched,
    initiator.identity.did,
  );
  responder.prekeys.pool.delete(usedId);
  const device = responder.prekeys.opkDevice.get(usedId)!;
  await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(responder.identity.did)}/opk/${usedId}?device=${encodeURIComponent(device)}`, {
    method: "DELETE",
  });
  responder.sessions.set(initiator.identity.did, sessionB);
  return { initiatorSession: session, responderSession: sessionB };
}

/** 发送 1:1 会话消息（owner → 对端；对端从其 recv 信箱拉取）。 */
async function sendSessionPayload(from: Party, toDid: string, payload: unknown): Promise<void> {
  const session = from.sessions.get(toDid);
  if (!session) throw new Error("会话不存在");
  const wire = sessionSendWire(session, utf8ToBytes(JSON.stringify(payload)));
  const mailboxId = sessionMailboxOf(session, "send", Date.now());
  await append(mailboxId, seal(wire, mailboxId));
}

/** 接收方按三 epoch 窗口拉取 1:1 会话载荷（对端 send 信箱 = 我的 recv 信箱）。 */
async function receiveSessionPayloads(party: Party, fromDid: string): Promise<unknown[]> {
  const session = party.sessions.get(fromDid);
  if (!session) throw new Error("会话不存在");
  const now = Date.now();
  const out: unknown[] = [];
  for (const at of [now - EPOCH_MS, now, now + EPOCH_MS]) {
    const mailboxId = sessionMailboxOf(session, "recv", at);
    for (const envelope of await fetchMailbox(mailboxId)) {
      try {
        const wire = stripPadding(envelope.payload);
        const { sessionReceive } = await import("@mychat/core");
        out.push(JSON.parse(bytesToUtf8(sessionReceive(session, wire))) as unknown);
      } catch {
        /* 非本会话/旧文本 */
      }
    }
  }
  return out;
}

// 组内消息投取（群信箱）
async function sendGroupWire(party: Party, groupWire: Uint8Array): Promise<void> {
  if (party.groupView === null) throw new Error("无群视角");
  const mailboxId = groupMailboxId(party.groupView.groupSecret, party.groupView.state.epoch);
  await append(mailboxId, seal(groupWire, mailboxId));
}

async function receiveGroupMessages(party: Party): Promise<{ text: string; senderDid: string }[]> {
  if (party.groupView === null) throw new Error("无群视角");
  const mailboxId = groupMailboxId(party.groupView.groupSecret, party.groupView.state.epoch);
  const { sessionReceive: _sr } = await import("@mychat/core");
  void _sr;
  const { openGroupMessage: open } = await import("@mychat/core");
  const out: { text: string; senderDid: string }[] = [];
  for (const envelope of await fetchMailbox(mailboxId)) {
    try {
      const opened = open(party.groupView, stripPadding(envelope.payload));
      out.push({ text: bytesToUtf8(opened.plaintext), senderDid: opened.senderDid });
    } catch {
      /* 非本群/伪造 */
    }
  }
  return out;
}

// sessionSend/sessionMailbox 顶层导入（上方已 import），此处仅保留别名以兼容旧文案
const sessionSendWire = sessionSend;
const sessionMailboxOf = sessionMailbox;

// ---------- 测试 ----------

async function setupThreeParties(): Promise<{ owner: Party; alice: Party; bob: Party }> {
  const mk = async (identity: Identity, name: string): Promise<Party> => ({
    identity,
    prekeys: await register(identity, name),
    sessions: new Map(),
    groupView: null,
  });
  const owner = await mk(createIdentity(), "g_owner");
  const alice = await mk(createIdentity(), "g_alice");
  const bob = await mk(createIdentity(), "g_bob");
  // 双侧会话都要登记（发起方视角由返回值补记；响应方由 handshake 内部登记）
  const h1 = await handshake(owner, alice, "owner→alice");
  owner.sessions.set(alice.identity.did, h1.initiatorSession);
  const h2 = await handshake(owner, bob, "owner→bob");
  owner.sessions.set(bob.identity.did, h2.initiatorSession);
  const h3 = await handshake(alice, bob, "alice→bob");
  alice.sessions.set(bob.identity.did, h3.initiatorSession);
  return { owner, alice, bob };
}

describe("M3-S11 Gate：群组 v1（FR-6.1/6.2）", () => {
  it("建群 → 密钥经 1:1 分发 → 多发送方群聊全员可解", async () => {
    const { owner, alice, bob } = await setupThreeParties();

    // owner 建群（3 人）并生成 epoch-1 发送密钥
    const { state, groupSecret } = createGroup(owner.identity.ikEd.privateKey, "项目小组", owner.identity.did, [alice.identity.did, bob.identity.did]);
    const senderKeys = generateSenderKeys(state.members.map((m) => m.did));
    owner.groupView = createGroupView(state, groupSecret, senderKeys);

    // GroupKeysPayload 经 1:1 会话分发（客户端 type:"group-keys" 的线上形态）
    const { makeGroupKeysPayload } = await import("@mychat/core");
    const payload = makeGroupKeysPayload(state, groupSecret, senderKeys);
    for (const member of [alice, bob]) {
      await sendSessionPayload(owner, member.identity.did, { v: 1, type: "group-keys", payload });
      const received = await receiveSessionPayloads(member, owner.identity.did);
      const keys = received.find((p) => (p as { type?: string }).type === "group-keys") as { payload: GroupKeysPayload } | undefined;
      expect(keys).toBeDefined();
      member.groupView = applyGroupKeysPayload(keys!.payload);
      expect(member.groupView.state.groupId).toBe(state.groupId);
    }

    // 多发送方互发：owner / alice / bob 各发一条，全员可解且署名正确
    const sendAndCheck = async (from: Party, text: string) => {
      const view = from.groupView!;
      const index = view.sendIndex;
      const wire = sealGroupMessage(from.identity.ikEd.privateKey, from.identity.did, view.senderKeys.get(from.identity.did)!, view.groupSecret, state.groupId, state.epoch, index, utf8ToBytes(text));
      view.sendIndex = index + 1;
      await sendGroupWire(from, wire);
    };
    await sendAndCheck(owner, "owner 到");
    await sendAndCheck(alice, "alice 到");
    await sendAndCheck(bob, "bob 到");

    for (const member of [owner, alice, bob]) {
      const got = await receiveGroupMessages(member);
      const texts = got.map((g) => g.text);
      expect(texts).toContain("owner 到");
      expect(texts).toContain("alice 到");
      expect(texts).toContain("bob 到");
      const aliceMsg = got.find((g) => g.text === "alice 到")!;
      expect(aliceMsg.senderDid).toBe(alice.identity.did);
    }
  });

  it("移除断读与防伪造：epoch+1 后被移除者不可达，伪造被拒", async () => {
    const { makeGroupKeysPayload, openGroupMessage: open } = await import("@mychat/core");
    const { owner, alice, bob } = await setupThreeParties();

    const created = createGroup(owner.identity.ikEd.privateKey, "隔离群", owner.identity.did, [alice.identity.did, bob.identity.did]);
    const senderKeys = generateSenderKeys(created.state.members.map((m) => m.did));
    owner.groupView = createGroupView(created.state, created.groupSecret, senderKeys);
    for (const member of [alice, bob]) {
      const payload = makeGroupKeysPayload(created.state, created.groupSecret, senderKeys);
      await sendSessionPayload(owner, member.identity.did, { v: 1, type: "group-keys", payload });
      const received = await receiveSessionPayloads(member, owner.identity.did);
      const keys = received.find((p) => (p as { type?: string }).type === "group-keys") as { payload: GroupKeysPayload };
      member.groupView = applyGroupKeysPayload(keys.payload);
    }

    // 移除 alice：epoch+1、SK 全量重生成、幸存成员重分发
    const nextState = removeGroupMember(owner.identity.ikEd.privateKey, owner.groupView!.state, alice.identity.did);
    const newKeys = generateSenderKeys(nextState.members.map((m) => m.did));
    owner.groupView = createGroupView(nextState, created.groupSecret, newKeys);
    for (const member of [bob]) {
      const payload = makeGroupKeysPayload(nextState, created.groupSecret, newKeys);
      await sendSessionPayload(owner, member.identity.did, { v: 1, type: "group-keys", payload });
      const received = await receiveSessionPayloads(member, owner.identity.did);
      const keys = received.find((p) => (p as { type?: string }).type === "group-keys") as { payload: GroupKeysPayload };
      member.groupView = applyGroupKeysPayload(keys.payload);
      expect(member.groupView.state.epoch).toBe(created.state.epoch + 1);
    }

    // bob 在新 epoch 发消息，owner 可解
    const bobWire = sealGroupMessage(bob.identity.ikEd.privateKey, bob.identity.did, bob.groupView!.senderKeys.get(bob.identity.did)!, bob.groupView!.groupSecret, nextState.groupId, nextState.epoch, 0, utf8ToBytes("移除后的消息"));
    await sendGroupWire(bob, bobWire);
    const ownerGot = await receiveGroupMessages(owner);
    expect(ownerGot.map((g) => g.text)).toContain("移除后的消息");

    // 断读：alice 滞留旧视角，新 epoch 群信箱 ID 不同 → 她拉不到也解不开新消息
    const aliceMailbox = groupMailboxId(alice.groupView!.groupSecret, alice.groupView!.state.epoch);
    const newMailbox = groupMailboxId(created.groupSecret, nextState.epoch);
    expect(aliceMailbox).not.toBe(newMailbox);
    const alicePolled = await fetchMailbox(newMailbox).then((envs) =>
      envs.filter((e) => {
        try {
          open(alice.groupView!, stripPadding(e.payload));
          return true;
        } catch {
          return false;
        }
      }),
    );
    expect(alicePolled).toHaveLength(0);

    // 防伪造：alice 用旧 SK + 自己 IK 在新 epoch 造消息——owner 侧外层可过（groupSecret 相同）但内层/验签拒绝
    const forged = sealGroupMessage(alice.identity.ikEd.privateKey, alice.identity.did, alice.groupView!.senderKeys.get(alice.identity.did)!, created.groupSecret, nextState.groupId, nextState.epoch, 0, utf8ToBytes("被移除者的伪造"));
    await sendGroupWire(alice, forged);
    const ownerAfterForge = await receiveGroupMessages(owner);
    expect(ownerAfterForge.map((g) => g.text)).not.toContain("被移除者的伪造");
    void makeGroupKeysPayload;
  });

  it("新成员隔离：加入者仅见加入后消息；群附件全链路可达", async () => {
    const { addGroupMember } = await import("@mychat/core");
    const { owner, alice, bob } = await setupThreeParties();

    const created = createGroup(owner.identity.ikEd.privateKey, "成长群", owner.identity.did, [alice.identity.did]);
    const keys1 = generateSenderKeys(created.state.members.map((m) => m.did));
    owner.groupView = createGroupView(created.state, created.groupSecret, keys1);

    // 加入前消息（alice 发；此时 alice 尚未被分发密钥，直接投当前群信箱）
    const preWire = sealGroupMessage(alice.identity.ikEd.privateKey, alice.identity.did, keys1.get(alice.identity.did)!, created.groupSecret, created.state.groupId, created.state.epoch, 0, utf8ToBytes("加入前的历史"));
    const preMailbox = groupMailboxId(created.groupSecret, created.state.epoch);
    await append(preMailbox, seal(preWire, preMailbox));

    // 邀请 bob：epoch+2、全量重分发（bob 与 alice 都拿新载荷）
    const nextState = addGroupMember(owner.identity.ikEd.privateKey, created.state, bob.identity.did);
    const keys2 = generateSenderKeys(nextState.members.map((m) => m.did));
    owner.groupView = createGroupView(nextState, created.groupSecret, keys2);
    const { makeGroupKeysPayload } = await import("@mychat/core");
    for (const member of [alice, bob]) {
      const payload = makeGroupKeysPayload(nextState, created.groupSecret, keys2);
      await sendSessionPayload(owner, member.identity.did, { v: 1, type: "group-keys", payload });
      const received = await receiveSessionPayloads(member, owner.identity.did);
      const keys = received.find((p) => (p as { type?: string }).type === "group-keys") as { payload: GroupKeysPayload };
      member.groupView = applyGroupKeysPayload(keys.payload);
    }

    // bob 加入后发消息（新 SK、index 从 0 起）
    const bobWire = sealGroupMessage(bob.identity.ikEd.privateKey, bob.identity.did, keys2.get(bob.identity.did)!, created.groupSecret, nextState.groupId, nextState.epoch, 0, utf8ToBytes("新人报到"));
    await sendGroupWire(bob, bobWire);
    const ownerGot = await receiveGroupMessages(owner);
    expect(ownerGot.map((g) => g.text)).toContain("新人报到");

    // bob 在新信箱拉不到加入前消息（历史隔离：旧 epoch 消息在旧信箱，bob 无旧秘密）
    const bobHistory = await receiveGroupMessages(bob);
    expect(bobHistory.map((g) => g.text)).not.toContain("加入前的历史");

    // 群附件全链路：owner 加密上传 → 组内消息带 CK → bob 取块解密
    const fileData = randomBytes(2048);
    const att = encryptAttachment(fileData);
    const put = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(att.cid)}`, {
      method: "PUT",
      body: Buffer.from(att.ciphertext),
    });
    expect(put.status).toBe(201);
    const attWire = sealGroupMessage(
      owner.identity.ikEd.privateKey,
      owner.identity.did,
      keys2.get(owner.identity.did)!,
      created.groupSecret,
      nextState.groupId,
      nextState.epoch,
      0,
      utf8ToBytes(JSON.stringify({ v: 1, type: "file", cid: att.cid, contentKey: base58Encode(att.contentKey), nonce: base58Encode(att.nonce), name: "data.bin", size: fileData.length, mime: "application/octet-stream" })),
    );
    await sendGroupWire(owner, attWire);
    const bobGot = await receiveGroupMessages(bob);
    const attMsg = bobGot.find((g) => g.text.startsWith("{") && (JSON.parse(g.text) as { type?: string }).type === "file");
    expect(attMsg).toBeDefined();
    const meta = JSON.parse(attMsg!.text) as { cid: string; contentKey: string; nonce: string };
    const blockRes = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(meta.cid)}`);
    const decrypted = decryptAttachment({
      ciphertext: new Uint8Array(await blockRes.arrayBuffer()),
      contentKey: (await import("@mychat/core")).base58Decode(meta.contentKey),
      nonce: (await import("@mychat/core")).base58Decode(meta.nonce),
    });
    expect(decrypted).toEqual(fileData);
  });
});
