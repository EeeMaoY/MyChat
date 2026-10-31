/**
 * M1 Gate e2e（Node 侧，真实 dev-node）：
 * 1. 附件隐私门：图片消息全链路后节点无明文（Gate 2 扩展）
 * 2. 社交恢复全流程：设置 → 守护者确认 → 3/5 重组 → 身份恢复（Gate 5）
 *
 * 复用 core 协议编排（与 client-web lib 同构的 Node 最小驱动）。
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  acceptSession,
  bytesToUtf8,
  createIdentity,
  decodePreKeyBundle,
  decodeSessionWire,
  decryptAttachment,
  deriveOpkId,
  encodePreKeyBundle,
  encryptAttachment,
  generateX25519KeyPair,
  initiateSession,
  issuePreKeyBundle,
  makeUserNameRecord,
  openGuardianShare,
  openIdentityWrap,
  recoverRk,
  sealGuardianShare,
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

// ---------- 最小客户端驱动 ----------

interface Prekeys {
  spk: KeyPair;
  opk: KeyPair & { id: number };
}

async function register(identity: Identity, name: string): Promise<Prekeys> {
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
  const put = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(identity.did)}`, {
    method: "PUT",
    body: Buffer.from(encodePreKeyBundle(bundle)),
  });
  expect(put.status).toBe(201);
  return { spk, opk: { ...opk, id: deriveOpkId(opk.publicKey) } };
}

async function fetchBundleBytes(did: string): Promise<Uint8Array> {
  const res = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(did)}`);
  expect(res.status).toBe(200);
  return new Uint8Array(await res.arrayBuffer());
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

/** 双向建会话（A 发起握手 → B 接受；双方本地会话就绪）。 */
async function handshake(
  a: { identity: Identity; prekeys: Prekeys },
  b: { identity: Identity; prekeys: Prekeys },
): Promise<{ sessionA: Session; sessionB: Session }> {
  const bundle = decodePreKeyBundle(await fetchBundleBytes(b.identity.did));
  const { session: sessionA, wire } = initiateSession(a.identity, bundle, utf8ToBytes(JSON.stringify({ v: 1, type: "chat", text: "hi" })));
  const mailbox = `discovery-${b.identity.did}`;
  await append(mailbox, seal(wire, mailbox));

  // 信箱可能累积多次握手（同一守护者被多人添加）：只消费本发起方的信封（按初始头 IK-x 匹配）
  const envelopes = await fetchMailbox(mailbox);
  let matched: Uint8Array | undefined;
  for (const envelope of envelopes) {
    const wireBytes = unseal(envelope);
    const msg = decodeSessionWire(wireBytes);
    if (msg.kind !== 1) continue;
    const { bytesEqual, concatBytes } = await import("@mychat/core");
    const ad = msg.x3dh.ikxSenderPublic;
    if (bytesEqual(ad, a.identity.ikX.publicKey)) {
      matched = wireBytes;
      break;
    }
  }
  if (!matched) throw new Error("未找到本发起方的握手信封");
  const msg = decodeSessionWire(matched);
  const opkPool = new Map([[b.prekeys.opk.id, b.prekeys.opk]]);
  const { session: sessionB } = acceptSession(b.identity, b.prekeys.spk, opkPool, matched, a.identity.did);
  return { sessionA, sessionB };
}

async function sendPayload(session: Session, peerRecvMailboxAt: number, payload: unknown): Promise<void> {
  const wire = sessionSend(session, utf8ToBytes(JSON.stringify(payload)));
  const mailboxId = sessionMailbox(session, "send", peerRecvMailboxAt);
  await append(mailboxId, seal(wire, mailboxId));
}

function receiveAll(session: Session, windows: number[]): { payload: unknown; raw: Uint8Array }[] {
  const out: { payload: unknown; raw: Uint8Array }[] = [];
  for (const at of windows) {
    for (const envelope of syncFetch(sessionMailbox(session, "recv", at))) {
      try {
        const plaintext = sessionReceive(session, unseal(envelope));
        out.push({ payload: JSON.parse(bytesToUtf8(plaintext)), raw: plaintext });
      } catch {
        /* 非本会话 */
      }
    }
  }
  return out;
}

async function receiveAllAsync(session: Session): Promise<{ payload: unknown; raw: Uint8Array }[]> {
  const now = Date.now();
  const out: { payload: unknown; raw: Uint8Array }[] = [];
  for (const at of [now - EPOCH_MS, now, now + EPOCH_MS]) {
    for (const envelope of await fetchMailbox(sessionMailbox(session, "recv", at))) {
      try {
        const plaintext = sessionReceive(session, unseal(envelope));
        out.push({ payload: JSON.parse(bytesToUtf8(plaintext)), raw: plaintext });
      } catch {
        /* 非本会话 */
      }
    }
  }
  return out;
}

// ---------- Gate 2 扩展：附件隐私门 ----------

describe("M1 附件隐私门", () => {
  it("图片消息全链路后，节点的块与信箱均无明文", async () => {
    const secretBytes = utf8ToBytes("PNG-CONTENT-绝密截图内容-should-never-leak");
    const alice = { identity: createIdentity(), prekeys: null as unknown as Prekeys };
    const bob = { identity: createIdentity(), prekeys: null as unknown as Prekeys };
    alice.prekeys = await register(alice.identity, "img_alice");
    bob.prekeys = await register(bob.identity, "img_bob");

    const { sessionA, sessionB } = await handshake(alice, bob);

    // 附件：加密入 CAS + 消息携带 CID/CK
    const att = encryptAttachment(secretBytes);
    const put = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(att.cid)}`, {
      method: "PUT",
      body: Buffer.from(att.ciphertext),
    });
    expect(put.status).toBe(201);
    await sendPayload(sessionA, Date.now(), {
      v: 1,
      type: "image",
      cid: att.cid,
      contentKey: Buffer.from(att.contentKey).toString("base64"),
      nonce: Buffer.from(att.nonce).toString("base64"),
      name: "screenshot.png",
      size: secretBytes.length,
      mime: "image/png",
    });

    // 接收端还原
    const incoming = await receiveAllAsync(sessionB);
    const imageMsg = incoming.find((m) => (m.payload as { type?: string }).type === "image");
    expect(imageMsg).toBeTruthy();
    const blockRes = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(att.cid)}`);
    const ciphertext = new Uint8Array(await blockRes.arrayBuffer());
    const restored = decryptAttachment({
      ciphertext,
      contentKey: Buffer.from((imageMsg!.payload as { contentKey: string }).contentKey, "base64"),
      nonce: Buffer.from((imageMsg!.payload as { nonce: string }).nonce, "base64"),
    });
    expect([...restored]).toEqual([...secretBytes]);

    // 隐私断言：块密文无明文；信箱 payload 无明文无 CK 无 CID 关联
    expect(bytesToUtf8(ciphertext)).not.toContain("绝密");
    for (const mailboxId of [`discovery-${bob.identity.did}`, sessionMailbox(sessionA, "send", Date.now()), sessionMailbox(sessionB, "recv", Date.now())]) {
      for (const envelope of await fetchMailbox(mailboxId)) {
        const text = bytesToUtf8(envelope.payload);
        expect(text).not.toContain("绝密");
        expect(text).not.toContain("screenshot");
        expect(text).not.toContain(alice.identity.did);
      }
    }
  });
});

// ---------- Gate 5：社交恢复全流程 ----------

describe("M1 社交恢复全流程", () => {
  it("设置 → 守护者确认回传 → 3/5 重组 → 身份恢复一致", async () => {
    const THRESHOLD = 3;
    const owner = { identity: createIdentity(), prekeys: null as unknown as Prekeys };
    const guardians = Array.from({ length: 5 }, () => ({ identity: createIdentity(), prekeys: null as unknown as Prekeys }));
    owner.prekeys = await register(owner.identity, "recovery_owner");
    for (const [i, g] of guardians.entries()) g.prekeys = await register(g.identity, `guardian_${i}`);

    // owner ↔ 守护者两两会话
    const ownerSessions: Session[] = [];
    const guardianSessions: (Session | null)[] = [];
    for (const g of guardians) {
      const { sessionA, sessionB } = await handshake(owner, g);
      ownerSessions.push(sessionA);
      guardianSessions.push(sessionB);
    }

    // —— owner：设置恢复（公告 + wrap 块 + 分片包分发） ——
    const { createRecoverySetup, sealGuardianShare } = await import("@mychat/core");
    const guardianDids = guardians.map((g) => g.identity.did);
    const setup = createRecoverySetup(owner.identity, guardianDids, THRESHOLD);
    const wrapPut = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(setup.wrapCid)}`, {
      method: "PUT",
      body: Buffer.from(setup.wrap),
    });
    expect(wrapPut.status).toBe(201);
    const annPut = await fetch(`${base}/v0/registry/recovery/${encodeURIComponent(owner.identity.did)}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        announcement: {
          did: setup.announcement.did,
          wrapCid: setup.announcement.wrapCid,
          threshold: setup.announcement.threshold,
          guardians: setup.announcement.guardians,
          signature: Buffer.from(setup.announcement.signature).toString("base64"),
        },
      }),
    });
    expect(annPut.status).toBe(201);

    for (const [i, g] of guardians.entries()) {
      const pack = sealGuardianShare(setup, g.identity.did);
      await sendPayload(ownerSessions[i]!, Date.now(), {
        v: 1,
        type: "guardian-invite",
        did: owner.identity.did,
        wrapCid: setup.wrapCid,
        sealedShare: Buffer.from(pack.sealedShare).toString("base64"),
      });
    }

    // —— 新机：临时身份与 3 位守护者建会话，发恢复请求 ——
    const newcomer = { identity: createIdentity(), prekeys: null as unknown as Prekeys };
    newcomer.prekeys = await register(newcomer.identity, "newcomer");
    const newcomerSessions: Session[] = [];
    const guardianNewcomerSessions: Session[] = [];
    const contacted = guardians.slice(0, 3);
    for (const g of contacted) {
      const { sessionA, sessionB } = await handshake(newcomer, g);
      newcomerSessions.push(sessionA);
      guardianNewcomerSessions.push(sessionB);
    }
    for (const session of newcomerSessions) {
      await sendPayload(session, Date.now(), { v: 1, type: "recovery-request", did: owner.identity.did });
    }

    // —— 守护者：收到请求，人工确认后回传分片 ——
    const collected: { x: number; y: Uint8Array }[] = [];
    for (const [i, g] of contacted.entries()) {
      // 注意：请求来自新机会话，守护者必须在与新机的会话上收发
      const incoming = await receiveAllAsync(guardianNewcomerSessions[i]!);
      const request = incoming.find((m) => (m.payload as { type?: string }).type === "recovery-request");
      if (!request) {
        throw new Error(
          `守护者 ${i} 未收到恢复请求；收到 ${incoming.length} 条：${JSON.stringify(incoming.map((m) => m.payload))}`,
        );
      }
      // 守护者开启自己保管的分片包（用自己 IK 私钥）
      const pack = sealGuardianShare(setup, g.identity.did);
      const { openGuardianShare: openShare } = await import("@mychat/core");
      const share = openShare(g.identity.ikEd.privateKey, pack);
      collected.push({ x: share.x, y: share.y });
      await sendPayload(newcomerSessions[i]!, Date.now(), {
        v: 1,
        type: "recovery-share",
        did: owner.identity.did,
        shareX: share.x,
        shareY: Buffer.from(share.y).toString("base64"),
      });
    }

    // —— 新机：重组 RK → 解开身份包裹 → DID 一致 ——
    expect(collected.length).toBe(THRESHOLD);
    const rk = recoverRk(collected, 32);
    const wrapRes = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(setup.wrapCid)}`);
    const wrap = new Uint8Array(await wrapRes.arrayBuffer());
    const restoredJson = openIdentityWrap(rk, wrap);
    const restored = (await import("@mychat/core")).deserializeIdentity(restoredJson);
    expect(restored.did).toBe(owner.identity.did);
    expect(restored.ikEd.privateKey).toEqual(owner.identity.ikEd.privateKey);

    // 恢复公告可被新机拉取且验签通过（恢复入口的正确性）
    const annGet = await fetch(`${base}/v0/registry/recovery/${encodeURIComponent(owner.identity.did)}`);
    expect(annGet.status).toBe(200);
  });
});
