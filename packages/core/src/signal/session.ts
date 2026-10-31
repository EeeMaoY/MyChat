/**
 * 1:1 加密会话封装：X3DH 建立 + Double Ratchet 收发 + 伪地址派生（FR-2.1 / FR-3.1）。
 *
 * 会话是 M0 客户端的唯一收发入口：
 * - initiateSession/acceptSession 完成握手（响应方须自持 SPK/OPK 池）；
 * - sessionSend/sessionReceive 输出/消费传输层字节（由信封层装封投递）；
 * - sessionMailbox 按当前 epoch 派生收发信箱伪地址（每 EPOCH_MS 轮换）；
 * - 会话状态可序列化持久化（本地优先，FR-7.1）。
 */
import {
  AEAD_KEY_LENGTH,
  type KeyPair,
  generateX25519KeyPair,
  hkdfSha256,
} from "../crypto/index.ts";
import { base58Decode, base58Encode, concatBytes, utf8ToBytes } from "../codec/index.ts";
import type { Identity, PreKeyBundle } from "../identity/index.ts";
import { verifyPreKeyBundle } from "../identity/index.ts";
import { deriveSessionMailbox } from "../envelope/index.ts";
import {
  type RatchetState,
  ratchetDecrypt,
  ratchetEncrypt,
  ratchetInitInitiator,
  ratchetInitResponder,
} from "./ratchet.ts";
import { x3dhAccept, x3dhAssociatedData, x3dhInitiate } from "./x3dh.ts";
import { decodeSessionWire, encodeSessionWire, type SessionWire } from "./wire.ts";

/** 伪地址轮换周期：M0 取 1 分钟（设计报告 §5.1 epoch 轮换的演示尺度）。 */
export const EPOCH_MS = 60_000;
const MAILBOX_SECRET_INFO = "mychat:mailbox-secret:v1";

export type SessionRole = "initiator" | "responder";

export interface Session {
  role: SessionRole;
  /** 对端用户名级标识（initiator 来自 bundle.did；responder 由联系人记录补充，可为 null） */
  peerDid: string | null;
  selfIkxPublic: Uint8Array;
  peerIkxPublic: Uint8Array;
  /** 伪地址派生专用密钥（从 SK 派生，与消息加密密钥隔离） */
  mailboxSecret: Uint8Array;
  ratchet: RatchetState;
}

export function initiateSession(
  identity: Identity,
  bundle: PreKeyBundle,
  firstPlaintext: Uint8Array,
): { session: Session; wire: Uint8Array } {
  if (!verifyPreKeyBundle(bundle)) {
    throw new Error("session: 预密钥束验证失败，拒绝建立会话");
  }
  const ek = generateX25519KeyPair();
  const { sk, header } = x3dhInitiate(identity, bundle, ek);
  const ad = x3dhAssociatedData(identity.ikX.publicKey, bundle.ikxPublic);

  const ratchet = ratchetInitInitiator(sk, bundle.spkPublic);
  const sent = ratchetEncrypt(ratchet, firstPlaintext, ad);
  const wire = encodeSessionWire({ kind: 1, x3dh: header, ...sent });

  return { session: makeSession("initiator", identity, bundle.ikxPublic, bundle.did, sk, ratchet), wire };
}

/**
 * 响应方接受初始消息。
 * @param spk 当前 signed prekey 密钥对
 * @param opkPool 全量未消耗 OPK 池；命中后**调用方必须删除对应 OPK**（Signal 规范）
 * @param peerDid 可选，从联系人记录补充对端 DID
 */
export function acceptSession(
  identity: Identity,
  spk: KeyPair,
  opkPool: Map<number, KeyPair>,
  wire: Uint8Array,
  peerDid: string | null = null,
): { session: Session; plaintext: Uint8Array } {
  const msg = decodeSessionWire(wire);
  if (msg.kind !== 1) throw new Error("session: 会话必须以初始消息建立");
  const opk = opkPool.get(msg.x3dh.opkId);
  if (!opk) throw new Error(`session: OPK #${msg.x3dh.opkId} 不存在或已被消耗`);

  const ad = x3dhAssociatedData(msg.x3dh.ikxSenderPublic, identity.ikX.publicKey);
  const { sk } = x3dhAccept(identity, spk, opk, msg.x3dh);
  const ratchet = ratchetInitResponder(sk, spk);
  const plaintext = ratchetDecrypt(ratchet, msg.header, msg.nonce, msg.ciphertext, ad);

  return {
    session: makeSession("responder", identity, msg.x3dh.ikxSenderPublic, peerDid, sk, ratchet),
    plaintext,
  };
}

/** 加密一条消息，返回可直接装入信封 payload 的传输字节。 */
export function sessionSend(session: Session, plaintext: Uint8Array): Uint8Array {
  const wire = encodeSessionWire({ kind: 2, ...ratchetEncrypt(session.ratchet, plaintext, sessionAd(session)) });
  return wire;
}

/** 解密一条 regular 传输字节（初始消息请走 acceptSession）。 */
export function sessionReceive(session: Session, wire: Uint8Array): Uint8Array {
  const msg = decodeSessionWire(wire);
  if (msg.kind !== 2) throw new Error("session: 初始消息不可在已建立会话上重放（请走 acceptSession）");
  return ratchetDecrypt(session.ratchet, msg.header, msg.nonce, msg.ciphertext, sessionAd(session));
}

/** 按当前时间派生会话的收/发信箱伪地址（每 epoch 轮换，FR-3.1）。 */
export function sessionMailbox(session: Session, direction: "send" | "recv", atMs: number = Date.now()): string {
  const epoch = Math.floor(atMs / EPOCH_MS);
  return deriveSessionMailbox(session.mailboxSecret, epoch, session.role === "initiator", direction === "send");
}

function sessionAd(session: Session): Uint8Array {
  return session.role === "initiator"
    ? concatBytes(session.selfIkxPublic, session.peerIkxPublic)
    : concatBytes(session.peerIkxPublic, session.selfIkxPublic);
}

function makeSession(
  role: SessionRole,
  identity: Identity,
  peerIkxPublic: Uint8Array,
  peerDid: string | null,
  sk: Uint8Array,
  ratchet: RatchetState,
): Session {
  return {
    role,
    peerDid,
    selfIkxPublic: identity.ikX.publicKey,
    peerIkxPublic,
    mailboxSecret: hkdfSha256(sk, new Uint8Array(32), MAILBOX_SECRET_INFO, AEAD_KEY_LENGTH),
    ratchet,
  };
}

// ---------- 持久化（本地优先，FR-7.1：设备是权威副本） ----------

export function serializeSession(session: Session): string {
  const r = session.ratchet;
  return JSON.stringify({
    role: session.role,
    peerDid: session.peerDid,
    selfIkx: base58Encode(session.selfIkxPublic),
    peerIkx: base58Encode(session.peerIkxPublic),
    mailboxSecret: base58Encode(session.mailboxSecret),
    ratchet: {
      rootKey: base58Encode(r.rootKey),
      dhSelfPub: base58Encode(r.dhSelf.publicKey),
      dhSelfPriv: base58Encode(r.dhSelf.privateKey),
      dhRemote: r.dhRemote === null ? null : base58Encode(r.dhRemote),
      sendChainKey: r.sendChainKey === null ? null : base58Encode(r.sendChainKey),
      recvChainKey: r.recvChainKey === null ? null : base58Encode(r.recvChainKey),
      sendCount: r.sendCount,
      recvCount: r.recvCount,
      prevSendCount: r.prevSendCount,
      skipped: [...r.skipped.entries()].map(([k, v]) => [k, base58Encode(v)]),
    },
  });
}

export function deserializeSession(json: string): Session {
  const raw = JSON.parse(json) as SerializedSession;
  if (typeof raw !== "object" || raw === null) throw new Error("session: 序列化数据非法");
  return {
    role: raw.role,
    peerDid: raw.peerDid,
    selfIkxPublic: base58Decode(raw.selfIkx),
    peerIkxPublic: base58Decode(raw.peerIkx),
    mailboxSecret: base58Decode(raw.mailboxSecret),
    ratchet: {
      rootKey: base58Decode(raw.ratchet.rootKey),
      dhSelf: {
        publicKey: base58Decode(raw.ratchet.dhSelfPub),
        privateKey: base58Decode(raw.ratchet.dhSelfPriv),
      },
      dhRemote: raw.ratchet.dhRemote === null ? null : base58Decode(raw.ratchet.dhRemote),
      sendChainKey: raw.ratchet.sendChainKey === null ? null : base58Decode(raw.ratchet.sendChainKey),
      recvChainKey: raw.ratchet.recvChainKey === null ? null : base58Decode(raw.ratchet.recvChainKey),
      sendCount: raw.ratchet.sendCount,
      recvCount: raw.ratchet.recvCount,
      prevSendCount: raw.ratchet.prevSendCount,
      skipped: new Map(raw.ratchet.skipped.map(([k, v]) => [k, base58Decode(v)])),
    },
  };
}

interface SerializedSession {
  role: SessionRole;
  peerDid: string | null;
  selfIkx: string;
  peerIkx: string;
  mailboxSecret: string;
  ratchet: {
    rootKey: string;
    dhSelfPub: string;
    dhSelfPriv: string;
    dhRemote: string | null;
    sendChainKey: string | null;
    recvChainKey: string | null;
    sendCount: number;
    recvCount: number;
      prevSendCount: number;
      skipped: [string, string][];
    };
  }

