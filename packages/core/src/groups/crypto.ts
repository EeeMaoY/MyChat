/**
 * 群组加密（Sender-Keys 过渡形态，FR-6.1/6.2，M3 计划 §3.3）。
 *
 * 双层结构（节点不可见任何群元数据——FR-6.1 Level0）：
 *   信封 payload = nonce(24B) || XChaCha(mailboxKey, nonce, encode(envelope))
 *     mailboxKey = HKDF(groupSecret, "mailbox-key:" + epoch) —— 外层：仅当前 epoch 成员可解
 *     envelope   = { groupId, sender, epoch, index, signature, inner }
 *     inner      = nonce(24B) || XChaCha(msgKey, nonce, plaintext)
 *       msgKey   = HKDF(SK[sender], "group-msg:" + groupId:epoch:sender:index)
 *                  —— 内层每消息独立派生：无链状态、无失步问题；组内前向保密
 *                    依赖 epoch 轮换（Sender-Keys 边界，M3 评估报告 §6 如实登记）
 *     signature  = sender IK 签名（覆盖 header + inner）——被移除者拿不到新 SK
 *                  也无法伪造（IK 验签拒绝，FR-6.2）
 *
 * 防重放：接收端按 (sender, index) 单调推进。群信箱 FIFO + 发送方串行投递
 * 保证同发送方消息有序；内层独立派生使个别丢帧不阻断后续消费。
 */
import { base58Decode, base58Encode, base64Decode, base64Encode, bytesToUtf8, concatBytes, utf8ToBytes } from "../codec/index.ts";
import {
  AEAD_KEY_LENGTH,
  AEAD_NONCE_LENGTH,
  aeadDecrypt,
  aeadEncrypt,
  ed25519Sign,
  ed25519Verify,
  hkdfSha256,
  randomBytes,
} from "../crypto/index.ts";
import { didToEd25519PublicKey } from "../identity/did.ts";
import { type GroupState, decodeGroupStateJson, encodeGroupStateJson, verifyGroupState } from "./state.ts";

const MAILBOX_KEY_PREFIX = "mychat:group-mailbox-key:";
const MAILBOX_ID_PREFIX = "mychat:group-mailbox-id:";
const MSG_KEY_PREFIX = "mychat:group-msg-v1:";
const ENVELOPE_SIGNING_PREFIX = "mychat:group-msg-sig-v1:";

/** 群信箱伪地址：随 epoch 轮换——被移除者对新 epoch 信箱不可见（断读的物理面）。 */
export function groupMailboxId(groupSecret: Uint8Array, epoch: number): string {
  return base58Encode(hkdfSha256(groupSecret, new Uint8Array(0), `${MAILBOX_ID_PREFIX}${epoch}`));
}

/** 群信箱密钥（外层信封加密；随 epoch 轮换）。 */
export function groupMailboxKey(groupSecret: Uint8Array, epoch: number): Uint8Array {
  return hkdfSha256(groupSecret, new Uint8Array(0), `${MAILBOX_KEY_PREFIX}${epoch}`);
}

/**
 * 为当前 epoch 的全部成员生成发送密钥（SK）：did → 32B。
 * epoch 变更时全量重生成重分发（经各成员 1:1 会话，被移除者不可达）。
 */
export function generateSenderKeys(memberDids: string[]): Map<string, Uint8Array> {
  const keys = new Map<string, Uint8Array>();
  for (const did of memberDids) keys.set(did, randomBytes(AEAD_KEY_LENGTH));
  return keys;
}

/** 组内消息密钥：每消息独立派生（无链状态，见模块注释）。 */
export function groupMessageKey(sk: Uint8Array, groupId: string, epoch: number, senderDid: string, index: number): Uint8Array {
  return hkdfSha256(sk, new Uint8Array(0), `${MSG_KEY_PREFIX}${groupId}:${epoch}:${senderDid}:${index}`);
}

/** 组内消息的接收视角（客户端按群持有；分发载荷见 GroupKeysPayload）。 */
export interface GroupView {
  state: GroupState;
  groupSecret: Uint8Array;
  /** 当前 epoch 的发送密钥：did → SK（仅当前 epoch；历史 SK 随 epoch 丢弃） */
  senderKeys: Map<string, Uint8Array>;
  /** 我的发送序号（群内单调递增） */
  sendIndex: number;
  /** 各发送方已消费的最大 index（防重放） */
  recvIndex: Map<string, number>;
}

/** 由群状态、群秘密与当前 epoch 发送密钥集构造接收视角（状态必须验签通过）。 */
export function createGroupView(state: GroupState, groupSecret: Uint8Array, senderKeys: Map<string, Uint8Array>): GroupView {
  if (!verifyGroupState(state)) throw new Error("群状态验签失败，拒绝构造群视角");
  return { state, groupSecret, senderKeys, sendIndex: 0, recvIndex: new Map() };
}

// ---- nonce 前缀式 AEAD（24B nonce || 密文）：组内两层信封统一格式 ----

function sealAead(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = randomBytes(AEAD_NONCE_LENGTH);
  return concatBytes(nonce, aeadEncrypt(key, nonce, plaintext));
}

function openAead(key: Uint8Array, blob: Uint8Array): Uint8Array {
  if (blob.length < AEAD_NONCE_LENGTH + 16) throw new Error("密文过短（nonce/认证标签缺失）");
  return aeadDecrypt(key, blob.slice(0, AEAD_NONCE_LENGTH), blob.slice(AEAD_NONCE_LENGTH));
}

/**
 * 发送组内消息：返回**已加外层**的字节（客户端直接作为信封 payload 投群信箱）。
 * 发送序号由调用方维护并推进（GroupView.sendIndex）。
 */
export function sealGroupMessage(
  ikEdPrivateKey: Uint8Array,
  senderDid: string,
  sk: Uint8Array,
  groupSecret: Uint8Array,
  groupId: string,
  epoch: number,
  index: number,
  plaintext: Uint8Array,
): Uint8Array {
  const inner = sealAead(groupMessageKey(sk, groupId, epoch, senderDid, index), plaintext);
  const envelope = {
    v: 1,
    groupId,
    sender: senderDid,
    epoch,
    index,
    signature: base64Encode(ed25519Sign(ikEdPrivateKey, envelopeSigningMessage(groupId, senderDid, epoch, index, inner))),
    inner: base64Encode(inner),
  };
  return sealAead(groupMailboxKey(groupSecret, epoch), utf8ToBytes(JSON.stringify(envelope)));
}

export interface OpenedGroupMessage {
  plaintext: Uint8Array;
  senderDid: string;
  index: number;
}

/**
 * 接收组内消息：外层解（仅当前 epoch 成员可能成功）→ header → 内层解 →
 * IK 验签 → 防重放。外层失败（被移除者/旧 epoch 信箱密文）、内层失败、
 * 伪造签名均抛错，调用方安全丢弃（SR-4 语义）。
 */
export function openGroupMessage(view: GroupView, payload: Uint8Array): OpenedGroupMessage {
  const envelope = JSON.parse(bytesToUtf8(openAead(groupMailboxKey(view.groupSecret, view.state.epoch), payload))) as {
    v: number;
    groupId: string;
    sender: string;
    epoch: number;
    index: number;
    signature: string;
    inner: string;
  };
  if (envelope.v !== 1 || envelope.groupId !== view.state.groupId || envelope.epoch !== view.state.epoch) {
    throw new Error("群信封与当前群视角不一致");
  }
  const inner = base64Decode(envelope.inner);
  // IK 验签（伪造拒绝，FR-6.2）：签名覆盖 header + 完整 inner blob
  const signature = base64Decode(envelope.signature);
  if (!ed25519Verify(signature, envelopeSigningMessage(envelope.groupId, envelope.sender, envelope.epoch, envelope.index, inner), didToEd25519PublicKey(envelope.sender))) {
    throw new Error("群消息签名验证失败（伪造或篡改）");
  }
  const sk = view.senderKeys.get(envelope.sender);
  if (!sk) throw new Error(`缺少发送方 ${envelope.sender} 的当前 epoch 发送密钥`);
  const plaintext = openAead(groupMessageKey(sk, envelope.groupId, envelope.epoch, envelope.sender, envelope.index), inner);
  // 防重放：同发送方 index 单调（初始 -1：首条 index=0 不被误判）
  const seen = view.recvIndex.get(envelope.sender) ?? -1;
  if (envelope.index <= seen) throw new Error("群消息重放（index 未前进）");
  view.recvIndex.set(envelope.sender, envelope.index);
  return { plaintext, senderDid: envelope.sender, index: envelope.index };
}

function envelopeSigningMessage(groupId: string, senderDid: string, epoch: number, index: number, inner: Uint8Array): Uint8Array {
  const groupIdBytes = utf8ToBytes(groupId);
  const senderBytes = utf8ToBytes(senderDid);
  const head = new Uint8Array(2 + groupIdBytes.length + 2 + senderBytes.length + 8);
  const headView = new DataView(head.buffer);
  let off = 0;
  headView.setUint16(off, groupIdBytes.length, false);
  off += 2;
  head.set(groupIdBytes, off);
  off += groupIdBytes.length;
  headView.setUint16(off, senderBytes.length, false);
  off += 2;
  head.set(senderBytes, off);
  off += senderBytes.length;
  headView.setUint32(off, epoch, false);
  headView.setUint32(off + 4, index, false);
  return concatBytes(utf8ToBytes(ENVELOPE_SIGNING_PREFIX), head, inner);
}

// ---------------------------------------------------------------------------
// 群密钥分发载荷（经各成员 1:1 DR 会话投递；被移除者不可达 = 断读的密码面）
// ---------------------------------------------------------------------------

/** 经 1:1 会话分发的群密钥载荷（JSON 形态，二进制字段 base58/base64）。 */
export interface GroupKeysPayload {
  v: 1;
  groupId: string;
  epoch: number;
  /** 群对称秘密（base58） */
  groupSecret: string;
  /** 当前权威群状态（GroupState 的 JSON 对象形态，含签名） */
  state: Record<string, unknown>;
  /** 当前 epoch 全体成员的发送密钥（base58） */
  senderKeys: { did: string; key: string }[];
}

export function makeGroupKeysPayload(state: GroupState, groupSecret: Uint8Array, senderKeys: Map<string, Uint8Array>): GroupKeysPayload {
  return {
    v: 1,
    groupId: state.groupId,
    epoch: state.epoch,
    groupSecret: base58Encode(groupSecret),
    state: JSON.parse(encodeGroupStateJson(state)) as Record<string, unknown>,
    senderKeys: [...senderKeys.entries()].map(([did, key]) => ({ did, key: base58Encode(key) })),
  };
}

/**
 * 消费群密钥载荷：验证群状态签名后构造视角（新成员入群 / 全员 epoch 刷新共用）。
 * 载荷虽经 1:1 DR 会话到达，仍须本地验签（SR-5：分发通道可信 ≠ 内容免验）。
 */
export function applyGroupKeysPayload(payload: GroupKeysPayload): GroupView {
  if (payload.v !== 1) throw new Error("群密钥载荷版本不识别");
  const state = decodeGroupStateJson(JSON.stringify(payload.state));
  if (state.groupId !== payload.groupId || state.epoch !== payload.epoch) {
    throw new Error("群密钥载荷与群状态不一致");
  }
  const senderKeys = new Map<string, Uint8Array>();
  for (const entry of payload.senderKeys) {
    senderKeys.set(entry.did, base58Decode(entry.key));
  }
  return createGroupView(state, base58Decode(payload.groupSecret), senderKeys);
}
