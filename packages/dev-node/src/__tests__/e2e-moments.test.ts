/**
 * M3-S12 Gate e2e（Node 侧，真实 dev-node）：动态 v1（FR-4.1/4.2/4.4，M3 计划 §6.1）。
 * 1. 好友圈密钥分发 → 发布文字动态 → 好友时间线可见可读
 * 2. 图片动态全链路（动态块 + 图片 CAS 块，两层独立密钥）
 * 3. 删除：墓碑传播 + 物理删块（新读者 404、本地隐藏）
 * 4. 新加好友只见现存动态（已删不可见）
 * 5. 评论经 1:1 会话仅作者可见
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  acceptSession,
  base58Decode,
  base58Encode,
  bytesToUtf8,
  createIdentity,
  createMomentBlock,
  decodePreKeyBundle,
  decodeSessionWire,
  decryptAttachment,
  deriveOpkId,
  encodePreKeyBundle,
  encryptAttachment,
  generateX25519KeyPair,
  initiateSession,
  issuePreKeyBundle,
  makeEnvelope,
  makeUserNameRecord,
  momentFeedId,
  openFeedEntry,
  openMomentBlock,
  randomBytes,
  sealFeedEntry,
  sessionMailbox,
  sessionReceive,
  sessionSend,
  stripPadding,
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

// ---------- 最小客户端驱动（与 e2e-m3 相同协议约定） ----------

interface Prekeys {
  spk: KeyPair;
  pool: Map<number, KeyPair>;
  opkDevice: Map<number, string>;
}

async function register(identity: Identity, name: string): Promise<Prekeys> {
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
  while (pool.size < 3) {
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
  /** did → 对方好友圈密钥（base58；时间线数据源） */
  circleKeys: Map<string, string>;
  myMomentKey: string;
}

async function mkParty(name: string): Promise<Party> {
  const identity = createIdentity();
  const { generateMomentKey } = await import("@mychat/core");
  return { identity, prekeys: await register(identity, name), sessions: new Map(), circleKeys: new Map(), myMomentKey: base58Encode(generateMomentKey()) };
}

async function handshake(initiator: Party, responder: Party, firstText: string): Promise<void> {
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
  initiator.sessions.set(responder.identity.did, session);
  responder.sessions.set(initiator.identity.did, sessionB);
}

/** 通过 1:1 会话交换好友圈密钥（客户端 distributeMomentKeys / circle-keys 分支的核心动作）。 */
async function exchangeCircleKeys(a: Party, b: Party): Promise<void> {
  for (const [from, to] of [[a, b], [b, a]] as const) {
    const session = from.sessions.get(to.identity.did);
    if (!session) throw new Error("会话不存在");
    const wire = sessionSend(session, utf8ToBytes(JSON.stringify({ v: 1, type: "circle-keys", momentKey: from.myMomentKey })));
    const mailboxId = sessionMailbox(session, "send", Date.now());
    await append(mailboxId, seal(wire, mailboxId));
  }
  for (const [holder, other] of [[a, b], [b, a]] as const) {
    const session = holder.sessions.get(other.identity.did)!;
    const now = Date.now();
    for (const at of [now - EPOCH_MS, now, now + EPOCH_MS]) {
      const mailboxId = sessionMailbox(session, "recv", at);
      for (const envelope of await fetchMailbox(mailboxId)) {
        try {
          const parsed = JSON.parse(bytesToUtf8(sessionReceive(session, stripPadding(envelope.payload)))) as { type?: string; momentKey?: string };
          if (parsed.type === "circle-keys" && typeof parsed.momentKey === "string") {
            holder.circleKeys.set(other.identity.did, parsed.momentKey);
          }
        } catch {
          /* 非本会话 */
        }
      }
    }
    expect(holder.circleKeys.has(other.identity.did)).toBe(true);
  }
}

/** 作者发布动态（客户端 publishMoment 的核心动作；返回 cid）。 */
async function publishMoment(author: Party, text: string, imageBytes?: Uint8Array): Promise<{ cid: string; imageCid?: string }> {
  const { createMomentBlock } = await import("@mychat/core");
  let attachment;
  let imageCid: string | undefined;
  if (imageBytes !== undefined) {
    const img = encryptAttachment(imageBytes);
    const put = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(img.cid)}`, { method: "PUT", body: Buffer.from(img.ciphertext) });
    expect(put.status).toBe(201);
    attachment = { cid: img.cid, contentKey: base58Encode(img.contentKey), nonce: base58Encode(img.nonce), name: "pic.png", size: imageBytes.length, mime: "image/png" };
    imageCid = img.cid;
  }
  const created = createMomentBlock({ v: 1, text, ...(attachment ? { attachment } : {}) });
  const put = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(created.cid)}`, { method: "PUT", body: Buffer.from(created.block) });
  expect(put.status).toBe(201);
  const key = base58Decode(author.myMomentKey);
  const feedId = momentFeedId(key);
  const entry = { v: 1 as const, type: "post" as const, cid: created.cid, contentKey: created.contentKey, nonce: created.nonce, at: Date.now() };
  await append(feedId, seal(sealFeedEntry(key, entry), feedId));
  return { cid: created.cid, imageCid };
}

interface ReadMoment {
  text: string;
  attachment?: { cid: string; contentKey: string; nonce: string };
}

/** 好友拉取作者的动态日志并解密（客户端 pollMomentFeeds 的核心动作；返回可读动态与墓碑）。 */
async function pullFeed(reader: Party, authorDid: string): Promise<{ moments: ReadMoment[]; tombstones: string[] }> {
  const keyText = reader.circleKeys.get(authorDid);
  if (keyText === undefined) throw new Error("未持有对方好友圈密钥");
  const key = base58Decode(keyText);
  const moments: ReadMoment[] = [];
  const tombstones: string[] = [];
  for (const envelope of await fetchMailbox(momentFeedId(key))) {
    const entry = openFeedEntry(key, stripPadding(envelope.payload));
    if (entry.type === "delete") {
      tombstones.push(entry.cid);
      continue;
    }
    if (entry.contentKey === undefined || entry.nonce === undefined) continue;
    const res = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(entry.cid)}`);
    if (res.status === 404) continue; // 作者已物理删除
    expect(res.status).toBe(200);
    const payload = openMomentBlock(new Uint8Array(await res.arrayBuffer()), entry.contentKey, entry.nonce);
    moments.push({ text: payload.text, ...(payload.attachment ? { attachment: payload.attachment } : {}) });
  }
  return { moments, tombstones };
}

// ---------- 测试 ----------

describe("M3-S12 Gate：动态 v1（FR-4.1/4.2/4.4）", () => {
  it("密钥分发 → 文字动态 → 好友时间线可见可读；陌生人/非好友不可读", async () => {
    const alice = await mkParty("m_alice");
    const bob = await mkParty("m_bob");
    await handshake(alice, bob, "加好友");
    await exchangeCircleKeys(alice, bob);

    await publishMoment(alice, "第一条动态");
    const { moments } = await pullFeed(bob, alice.identity.did);
    expect(moments.map((m) => m.text)).toContain("第一条动态");

    // 未持密钥的陌生人拉同一信箱：解不开任何条目
    const stranger = await mkParty("m_stranger");
    const raw = await fetchMailbox(momentFeedId(base58Decode(alice.myMomentKey)));
    const { openFeedEntry: open } = await import("@mychat/core");
    for (const envelope of raw) {
      expect(() => open(base58Decode(stranger.myMomentKey), stripPadding(envelope.payload))).toThrow();
    }
  });

  it("图片动态全链路：动态块 + 图片块两层密钥均可解", async () => {
    const alice = await mkParty("m_alice2");
    const bob = await mkParty("m_bob2");
    await handshake(alice, bob, "加好友");
    await exchangeCircleKeys(alice, bob);

    const imageBytes = randomBytes(2048);
    await publishMoment(alice, "看图说话", imageBytes);
    const { moments } = await pullFeed(bob, alice.identity.did);
    const withImage = moments.find((m) => m.attachment !== undefined);
    expect(withImage).toBeDefined();
    const res = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(withImage!.attachment!.cid)}`);
    expect(res.status).toBe(200);
    const decrypted = decryptAttachment({
      ciphertext: new Uint8Array(await res.arrayBuffer()),
      contentKey: base58Decode(withImage!.attachment!.contentKey),
      nonce: base58Decode(withImage!.attachment!.nonce),
    });
    expect(decrypted).toEqual(imageBytes);
  });

  it("删除：墓碑传播 + 物理删块；新读者只见现存动态", async () => {
    const alice = await mkParty("m_alice3");
    const bob = await mkParty("m_bob3");
    await handshake(alice, bob, "加好友");
    await exchangeCircleKeys(alice, bob);

    const kept = await publishMoment(alice, "保留的动态");
    const removed = await publishMoment(alice, "将被删除的动态");

    // 作者删除：墓碑 + 物理删块
    const key = base58Decode(alice.myMomentKey);
    const feedId = momentFeedId(key);
    await append(feedId, seal(sealFeedEntry(key, { v: 1, type: "delete", cid: removed.cid, at: Date.now() }), feedId));
    const del = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(removed.cid)}`, { method: "DELETE" });
    expect(((await del.json()) as { deleted: boolean }).deleted).toBe(true);

    // 好友拉取：保留动态可读；被删动态的块 404 跳过；墓碑可见
    const { moments, tombstones } = await pullFeed(bob, alice.identity.did);
    expect(moments.map((m) => m.text)).toContain("保留的动态");
    expect(moments.map((m) => m.text)).not.toContain("将被删除的动态");
    expect(tombstones).toContain(removed.cid);
    expect((await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(kept.cid)}`)).status).toBe(200);

    // 新好友（拿到密钥后）同样只见现存动态、只见墓碑
    const carol = await mkParty("m_carol");
    await handshake(alice, carol, "后加的好友");
    // alice 分发密钥给 carol（1:1 会话）；carol 从自己的 recv 信箱拉取
    const session = alice.sessions.get(carol.identity.did)!;
    const wire = sessionSend(session, utf8ToBytes(JSON.stringify({ v: 1, type: "circle-keys", momentKey: alice.myMomentKey })));
    const mailboxId = sessionMailbox(session, "send", Date.now());
    await append(mailboxId, seal(wire, mailboxId));
    const carolSession = carol.sessions.get(alice.identity.did)!;
    const now = Date.now();
    for (const at of [now - EPOCH_MS, now, now + EPOCH_MS]) {
      const box = sessionMailbox(carolSession, "recv", at);
      for (const envelope of await fetchMailbox(box)) {
        try {
          const parsed = JSON.parse(bytesToUtf8(sessionReceive(carolSession, stripPadding(envelope.payload)))) as { type?: string; momentKey?: string };
          if (parsed.type === "circle-keys" && typeof parsed.momentKey === "string") carol.circleKeys.set(alice.identity.did, parsed.momentKey);
        } catch {
          /* 非 */
        }
      }
    }
    const carolView = await pullFeed(carol, alice.identity.did);
    expect(carolView.moments.map((m) => m.text)).toContain("保留的动态");
    expect(carolView.moments.map((m) => m.text)).not.toContain("将被删除的动态");
    expect(carolView.tombstones).toContain(removed.cid);
  });

  it("评论经 1:1 会话仅作者可见并挂载", async () => {
    const alice = await mkParty("m_alice4");
    const bob = await mkParty("m_bob4");
    await handshake(alice, bob, "加好友");
    await exchangeCircleKeys(alice, bob);
    const { cid } = await publishMoment(alice, "求留言");

    // bob 留言（1:1 会话，非动态信箱——其他好友不可见）
    const session = bob.sessions.get(alice.identity.did)!;
    const wire = sessionSend(session, utf8ToBytes(JSON.stringify({ v: 1, type: "moment-comment", cid, text: "写得真好" })));
    const mailboxId = sessionMailbox(session, "send", Date.now());
    await append(mailboxId, seal(wire, mailboxId));

    // 作者收到并挂载
    const recv = alice.sessions.get(bob.identity.did)!;
    const now = Date.now();
    let comment: { cid: string; text: string } | null = null;
    for (const at of [now - EPOCH_MS, now, now + EPOCH_MS]) {
      const box = sessionMailbox(recv, "recv", at);
      for (const envelope of await fetchMailbox(box)) {
        try {
          const parsed = JSON.parse(bytesToUtf8(sessionReceive(recv, stripPadding(envelope.payload)))) as { type?: string; cid?: string; text?: string };
          if (parsed.type === "moment-comment") comment = { cid: parsed.cid!, text: parsed.text! };
        } catch {
          /* 非 */
        }
      }
    }
    expect(comment).not.toBeNull();
    expect(comment!.cid).toBe(cid);
    expect(comment!.text).toBe("写得真好");
  });
});
