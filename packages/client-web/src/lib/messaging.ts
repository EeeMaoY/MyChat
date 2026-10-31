/**
 * 消息编排层：身份/联系人/会话/收发的全流程编排（M0 主线 FR-1.1/1.2/2.1/5.1/8.1）。
 *
 * 安全不变量（本层负责执行）：
 * - UserNameRecord 与 PreKeyBundle 采信前必须本地验签（SR-5）；
 * - 会话建立只经 core 的 X3DH + Double Ratchet（ADR-1）；
 * - 出站消息一律装信封（伪地址 + 填充，FR-3.1/3.3），节点只接触密文；
 * - 私钥材料仅存 IndexedDB（W1 约束，社交恢复 M1 补强）。
 */
import {
  acceptSession,
  applyPadding,
  createIdentity,
  decodePreKeyBundle,
  decodeSessionWire,
  type Envelope,
  type Identity,
  type KVStore,
  type KeyPair,
  type PreKeyBundle,
  type Session,
  createRecoverySetup,
  deriveOpkId,
  deserializeIdentity,
  deserializeSession,
  encodePreKeyBundle,
  generateX25519KeyPair,
  initiateSession,
  issuePreKeyBundle,
  makeEnvelope,
  makeUserNameRecord,
  openGuardianShare,
  openIdentityWrap,
  padClassForLength,
  recoverRk,
  sealGuardianShare,
  serializeIdentity,
  serializeSession,
  sessionMailbox,
  sessionReceive,
  sessionSend,
  stripPadding,
  utf8ToBytes,
  bytesToUtf8,
  base58Encode,
  base58Decode,
  decryptAttachment,
  encryptAttachment,
  verifyPreKeyBundle,
  verifyUserNameRecord,
  EPOCH_MS,
} from "@mychat/core";

import { fromHex, toBase64, toHex } from "./base64";
import { discoveryInboxId } from "./discovery";
import type { NodeApi } from "./node-api";

/** 握手首条消息的明文结构（协议规范 v0.1 §握手；对端据此识别发起方） */
interface HandshakePayload {
  v: 1;
  fromDid: string;
  fromName: string | null;
  note: string;
}

export interface Contact {
  did: string;
  name: string | null;
  addedAt: number;
}

/** 附件元数据（contentKey/nonce 为 base58；整体存放于 E2EE 消息体内，节点不可见） */
export interface AttachmentMeta {
  cid: string;
  contentKey: string;
  nonce: string;
  name: string;
  size: number;
  mime: string;
}

export type MessageKind = "handshake" | "chat" | "image" | "file";

export interface ChatMessage {
  id: string;
  did: string;
  direction: "in" | "out";
  kind: MessageKind;
  /** chat=文本；image/file=文件名 */
  text: string;
  /** image/file 时存在 */
  attachment?: AttachmentMeta;
  at: number;
  /** out 消息的回执状态：sent=已投递节点信箱，delivered=对端已拉取，read=对端已读（FR-5.2） */
  status?: "sent" | "delivered" | "read";
}

/**
 * 会话明文载荷（M1 计划 §3.1 结构化约定；wire 格式不变，协议规范 §7 不升版）。
 * receipt 的 delivered/read 为对端消息 id 列表（批量合并，MR-1）。
 */
type SessionPayload =
  | { v: 1; type: "chat"; text: string }
  | { v: 1; type: "receipt"; delivered: string[]; read: string[] }
  | ({ v: 1; type: "image" | "file" } & AttachmentMeta)
  /** 好友托管：请求回传副本 / 回传副本（清单块 CID + 清单密钥，均为密文材料，FR-7.3） */
  | { v: 1; type: "custody-request"; forName: string | null }
  | { v: 1; type: "custody-reply"; cid: string; contentKey: string; nonce: string }
  /** 社交恢复（FR-1.3）：邀请成为守护者 / 请求回传分片 / 回传分片（设计报告 §4.3） */
  | { v: 1; type: "guardian-invite"; did: string; wrapCid: string; sealedShare: string }
  | { v: 1; type: "recovery-request"; did: string }
  | { v: 1; type: "recovery-share"; did: string; shareX: number; shareY: string };

/** 开放备份包格式（FR-7.2；明文 JSON，导出文件的保管责任在用户，UX-7 披露） */
interface ExportBundle {
  format: "mychat-backup";
  version: 1;
  createdAt: string;
  identity: string;
  myName: string | null;
  spk: StoredKeyPair;
  opk: { id: number } & StoredKeyPair;
  msgSeq: number;
  contacts: Contact[];
  sessions: { did: string; session: string }[];
  messages: { did: string; items: ChatMessage[] }[];
  cursors: Record<string, number>;
  readReceipts: "on" | "off";
}

export interface MessagingDeps {
  api: NodeApi;
  kv: KVStore;
}

// ---------- 键空间（core/store/interface.ts 约定） ----------
const K_IDENTITY = "identity";
const K_MY_NAME = "my-name";
const K_SPK = "spk";
const K_OPK = "opk";
const K_MSG_SEQ = "msgseq";
const SETTING_READ_RECEIPTS = "setting:read-receipts";
const contactKey = (did: string) => `contact:${did}`;
const sessionKey = (did: string) => `session:${did}`;
const msgKey = (did: string, seq: number) => `msg:${did}:${String(seq).padStart(8, "0")}`;
const cursorKey = (mailboxId: string) => `cursor:${mailboxId}`;

interface StoredKeyPair {
  publicKey: string;
  privateKey: string;
}

function kpToJson(kp: KeyPair): StoredKeyPair {
  return { publicKey: toHex(kp.publicKey), privateKey: toHex(kp.privateKey) };
}

function kpFromJson(raw: StoredKeyPair): KeyPair {
  return { publicKey: fromHex(raw.publicKey), privateKey: fromHex(raw.privateKey) };
}

export class Messaging {
  identity!: Identity;
  spk!: KeyPair;
  opk!: KeyPair & { id: number };
  myName: string | null = null;

  /** did → 会话/联系人/消息（内存态；持久化镜像于 kv） */
  sessions = new Map<string, Session>();
  contacts = new Map<string, Contact>();
  messages = new Map<string, ChatMessage[]>();
  online = true;

  private cursors = new Map<string, number>();
  private msgSeq = 0;
  /** message.id → kv 键（回执更新重写旧消息时定位原键，避免写错序号） */
  private messageKeys = new Map<string, string>();
  /** 已确认发出 read 回执的 in 消息 id（幂等，防重复回执） */
  private readConfirmed = new Set<string>();
  private stopWs: (() => void) | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;

  /** 状态变化回调（UI 绑定） */
  onStateChange: () => void = () => {};

  /** 新消息回调（S8 通知：app 层据此在页面隐藏时发系统通知；W2 边界见 M1 计划） */
  onIncomingMessage: ((message: ChatMessage) => void) | null = null;

  private constructor(private deps: MessagingDeps) {}

  /** 载入已有身份；不存在返回 null（进入欢迎流程）。 */
  static async load(deps: MessagingDeps): Promise<Messaging | null> {
    const identityJson = await deps.kv.get(K_IDENTITY);
    if (!identityJson) return null;
    const m = new Messaging(deps);
    m.identity = deserializeIdentity(bytesToUtf8(identityJson));
    await m.loadKeyMaterial();
    await m.loadSocialState();
    return m;
  }

  /** FR-1.1 无感身份创建：生成 IK/DK/SPK/OPK 并持久化，全程无用户输入。 */
  static async createNew(deps: MessagingDeps): Promise<Messaging> {
    const m = new Messaging(deps);
    m.identity = createIdentity();
    await deps.kv.put(K_IDENTITY, utf8ToBytes(serializeIdentity(m.identity)));
    // 预密钥材料（M0：单 SPK + 单 OPK，轮换为 M1）
    m.spk = generateX25519KeyPair();
    const opk = generateX25519KeyPair();
    m.opk = { ...opk, id: deriveOpkId(opk.publicKey) };
    await deps.kv.put(K_SPK, utf8ToBytes(JSON.stringify(kpToJson(m.spk))));
    await deps.kv.put(K_OPK, utf8ToBytes(JSON.stringify({ id: m.opk.id, ...kpToJson(opk) })));
    return m;
  }

  /** 与 identity/bundle 的 opkId 契约保持一致（见 deriveOpkId）。 */
  private opkId(): number {
    return deriveOpkId(this.opk.publicKey);
  }

  private async loadKeyMaterial(): Promise<void> {
    const spkRaw = await this.deps.kv.get(K_SPK);
    const opkRaw = await this.deps.kv.get(K_OPK);
    if (spkRaw) this.spk = kpFromJson(JSON.parse(bytesToUtf8(spkRaw)) as StoredKeyPair);
    if (opkRaw) {
      const parsed = JSON.parse(bytesToUtf8(opkRaw)) as { id: number } & StoredKeyPair;
      this.opk = { id: parsed.id, ...kpFromJson(parsed) };
    }
  }

  private async loadSocialState(): Promise<void> {
    const nameRaw = await this.deps.kv.get(K_MY_NAME);
    this.myName = nameRaw ? bytesToUtf8(nameRaw) : null;

    for (const key of await this.deps.kv.keys("contact:")) {
      const raw = await this.deps.kv.get(key);
      if (!raw) continue;
      const contact = JSON.parse(bytesToUtf8(raw)) as Contact;
      this.contacts.set(contact.did, contact);
    }
    for (const did of this.contacts.keys()) {
      const sessionRaw = await this.deps.kv.get(sessionKey(did));
      if (sessionRaw) this.sessions.set(did, deserializeSession(bytesToUtf8(sessionRaw)));
      await this.loadMessages(did);
    }
    for (const key of await this.deps.kv.keys("cursor:")) {
      const raw = await this.deps.kv.get(key);
      if (raw) this.cursors.set(key.slice("cursor:".length), Number(bytesToUtf8(raw)));
    }
    const seqRaw = await this.deps.kv.get(K_MSG_SEQ);
    this.msgSeq = seqRaw ? Number(bytesToUtf8(seqRaw)) : 0;
  }

  private async loadMessages(did: string): Promise<void> {
    const keys = await this.deps.kv.keys(`msg:${did}:`);
    const list: ChatMessage[] = [];
    for (const key of keys) {
      const raw = await this.deps.kv.get(key);
      if (!raw) continue;
      const message = JSON.parse(bytesToUtf8(raw)) as ChatMessage;
      this.messageKeys.set(message.id, key);
      list.push(message);
    }
    list.sort((a, b) => a.at - b.at);
    this.messages.set(did, list);
  }

  // ----- 用户名（FR-1.2） -----

  /** 注册用户名并上传预密钥束；节点侧与客户端侧双重验签。 */
  async setUsername(name: string): Promise<void> {
    const record = makeUserNameRecord(this.identity.ikEd.privateKey, name, this.identity.did, 0);
    await this.deps.api.register(record);
    // bundle：以 core 权威实现重派生 opkId（防本地持久化被篡改后不一致）
    this.opk.id = deriveOpkId(this.opk.publicKey);
    const bundle = this.issueBundle();
    await this.deps.api.putBundle(this.identity.did, encodePreKeyBundle(bundle));
    this.myName = name;
    await this.deps.kv.put(K_MY_NAME, utf8ToBytes(name));
    this.emit();
  }

  private issueBundle(): PreKeyBundle {
    return issuePreKeyBundle(this.identity, this.spk, { ...this.opk, id: deriveOpkId(this.opk.publicKey) }, 30 * 24 * 3600_000);
  }

  // ----- 加好友（FR-8.1：用户名路径） -----

  /**
   * 解析用户名 → 验签记录与 bundle → X3DH 发起 → 握手信封投递到对方发现信箱。
   * 返回错误文案（null = 成功）；异常不抛出到 UI 层。
   */
  async addFriend(name: string, note: string): Promise<string | null> {
    try {
      const record = await this.deps.api.resolve(name);
      if (!record) return "用户名不存在";
      if (!verifyUserNameRecord(record)) return "用户名记录验签失败（映射可能被篡改）";

      const bundleBytes = await this.deps.api.getBundle(record.did);
      if (!bundleBytes) return "对方预密钥束不可用";
      const bundle = decodePreKeyBundle(bundleBytes);
      if (bundle.did !== record.did || !verifyPreKeyBundle(bundle)) {
        return "对方预密钥束验签失败";
      }

      const handshake: HandshakePayload = {
        v: 1,
        fromDid: this.identity.did,
        fromName: this.myName,
        note: note || (this.myName ? `${this.myName} 请求添加你为好友` : "请求添加你为好友"),
      };
      const { session, wire } = initiateSession(this.identity, bundle, utf8ToBytes(JSON.stringify(handshake)));

      const envelope = this.seal(wire, discoveryInboxId(record.did));
      await this.deps.api.mailboxAppend(envelope.toPseudonym, envelope);

      this.sessions.set(record.did, session);
      this.contacts.set(record.did, { did: record.did, name, addedAt: Date.now() });
      await this.saveContact(record.did);
      await this.saveSession(record.did);
      await this.appendLocalMessage(record.did, "out", note || "（握手请求已发送）", "handshake");
      this.emit();
      return null;
    } catch (err) {
      return err instanceof Error ? err.message : "添加失败";
    }
  }

  // ----- 数据导出与好友托管（FR-7.2 / FR-7.3 M1，M1 计划 §3.4） -----

  /**
   * 一键导出全部数据的开放格式包（身份/联系人/会话/消息/游标/设置）。
   * 明文 JSON——导出文件本身等同设备数据，调用方应提示用户妥善保管（UX-7）。
   */
  async exportAll(): Promise<string> {
    const sessions: { did: string; session: string }[] = [];
    for (const [did, session] of this.sessions) sessions.push({ did, session: serializeSession(session) });
    const messages: { did: string; items: ChatMessage[] }[] = [];
    for (const [did, items] of this.messages) messages.push({ did, items });
    const cursors: Record<string, number> = Object.fromEntries(this.cursors);
    return JSON.stringify({
      format: "mychat-backup",
      version: 1,
      createdAt: new Date().toISOString(),
      identity: serializeIdentity(this.identity),
      myName: this.myName,
      spk: kpToJson(this.spk),
      opk: { id: this.opk.id, ...kpToJson(this.opk) },
      msgSeq: this.msgSeq,
      contacts: [...this.contacts.values()],
      sessions,
      messages,
      cursors,
      readReceipts: (await this.readReceiptsEnabled()) ? "on" : "off",
    } satisfies ExportBundle);
  }

  /** 导入恢复：清空本机数据后整包写入并重建内存态（新环境/数据丢失场景）。 */
  async importAll(json: string): Promise<void> {
    let bundle: ExportBundle;
    try {
      bundle = JSON.parse(json) as ExportBundle;
    } catch {
      throw new Error("备份文件不是合法 JSON");
    }
    if (bundle?.format !== "mychat-backup" || bundle.version !== 1) {
      throw new Error("备份包格式不识别（format/version 不匹配）");
    }
    // 完整性：身份可经反序列化全字节校验（防篡改序列化的同一保证）
    const identity = deserializeIdentity(bundle.identity);

    this.stopRealtime();
    await this.deps.kv.clear();
    await this.deps.kv.put(K_IDENTITY, utf8ToBytes(bundle.identity));
    await this.deps.kv.put(K_SPK, utf8ToBytes(JSON.stringify(bundle.spk)));
    await this.deps.kv.put(K_OPK, utf8ToBytes(JSON.stringify(bundle.opk)));
    this.msgSeq = bundle.msgSeq;
    await this.deps.kv.put(K_MSG_SEQ, utf8ToBytes(String(bundle.msgSeq)));
    if (bundle.myName !== null) await this.deps.kv.put(K_MY_NAME, utf8ToBytes(bundle.myName));
    await this.deps.kv.put(SETTING_READ_RECEIPTS, utf8ToBytes(bundle.readReceipts));

    // 内存态重建
    this.identity = identity;
    this.spk = kpFromJson(bundle.spk);
    this.opk = { id: bundle.opk.id, ...kpFromJson(bundle.opk) };
    this.myName = bundle.myName;
    this.contacts = new Map(bundle.contacts.map((c) => [c.did, c]));
    this.sessions = new Map();
    this.messages = new Map();
    this.cursors = new Map(Object.entries(bundle.cursors).map(([k, v]) => [k, v]));
    this.messageKeys = new Map();
    this.readConfirmed = new Set();
    for (const c of bundle.contacts) await this.deps.kv.put(contactKey(c.did), utf8ToBytes(JSON.stringify(c)));
    for (const s of bundle.sessions) {
      const session = deserializeSession(s.session);
      this.sessions.set(s.did, session);
      await this.deps.kv.put(sessionKey(s.did), utf8ToBytes(s.session));
    }
    for (const m of bundle.messages) {
      for (const item of m.items) await this.persistMessage(m.did, item);
    }
    this.startRealtime();
    void this.poll();
    this.emit();
  }

  /**
   * 好友托管备份（FR-7.3 M1 最小形态）：整包加密 → CAS 块 → 清单指针
   * （CID + 清单密钥）经 E2EE 会话发给前 2 位联系人。好友不可读、互不知晓对方也是托管者。
   */
  async createCustodyBackup(): Promise<{ hosts: string[] }> {
    const hostDid = [...this.contacts.keys()].slice(0, 2);
    if (hostDid.length === 0) throw new Error("暂无联系人，无法设置托管");
    const bundleJson = await this.exportAll();
    const att = encryptAttachment(utf8ToBytes(bundleJson));
    await this.deps.api.putBlock(att.cid, att.ciphertext);
    for (const did of hostDid) {
      const session = this.sessions.get(did);
      if (!session) continue;
      const wire = sessionSend(
        session,
        utf8ToBytes(
          JSON.stringify({
            v: 1,
            type: "custody-reply",
            cid: att.cid,
            contentKey: base58Encode(att.contentKey),
            nonce: base58Encode(att.nonce),
          } satisfies SessionPayload),
        ),
      );
      const mailboxId = sessionMailbox(session, "send", Date.now());
      await this.deps.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
    }
    this.emit();
    return { hosts: hostDid };
  }

  /** 我持有的他人托管副本（恢复流 S7：凭身份恢复后向持有者请求回传）。 */
  async listCustodyCopies(): Promise<{ fromDid: string; cid: string; contentKey: string; nonce: string }[]> {
    const out: { fromDid: string; cid: string; contentKey: string; nonce: string }[] = [];
    for (const key of await this.deps.kv.keys("custody:")) {
      const raw = await this.deps.kv.get(key);
      if (!raw) continue;
      const payload = JSON.parse(bytesToUtf8(raw)) as { cid: string; contentKey: string; nonce: string };
      out.push({ fromDid: key.slice("custody:".length), ...payload });
    }
    return out;
  }

  /** 解密一份托管副本为备份 JSON（恢复流：先社交恢复身份，再解密清单导入）。 */
  async decryptCustodyCopy(copy: { cid: string; contentKey: string; nonce: string }): Promise<string> {
    const ciphertext = await this.deps.api.getBlock(copy.cid);
    if (!ciphertext) throw new Error("托管副本块不存在（节点无此数据）");
    return bytesToUtf8(
      decryptAttachment({
        ciphertext,
        contentKey: base58Decode(copy.contentKey),
        nonce: base58Decode(copy.nonce),
      }),
    );
  }

  // ----- 社交恢复（FR-1.3，M1 计划 §2 S7） -----

  /** 我作为守护者持有的分片包：ownerDid → { wrapCid, sealedShare } */
  async listGuardianships(): Promise<{ ownerDid: string; wrapCid: string }[]> {
    const out: { ownerDid: string; wrapCid: string }[] = [];
    for (const key of await this.deps.kv.keys("guardianship:")) {
      const raw = await this.deps.kv.get(key);
      if (!raw) continue;
      const g = JSON.parse(bytesToUtf8(raw)) as { wrapCid: string };
      out.push({ ownerDid: key.slice("guardianship:".length), wrapCid: g.wrapCid });
    }
    return out;
  }

  /** 待确认的恢复请求（守护者人工确认 = Web of Trust 语义，UX 上明确警示）。 */
  async listRecoveryRequests(): Promise<{ ownerDid: string; fromDid: string }[]> {
    const out: { ownerDid: string; fromDid: string }[] = [];
    for (const key of await this.deps.kv.keys("recovery-request:")) {
      const raw = await this.deps.kv.get(key);
      if (!raw) continue;
      const r = JSON.parse(bytesToUtf8(raw)) as { ownerDid: string; fromDid: string };
      out.push(r);
    }
    return out;
  }

  /**
   * 守护者确认恢复请求：解出分片（自己的 IK 私钥）并回传给请求者。
   * UI 必须醒目提示"确认对方确为本人、你本人未丢失设备"（M1 无自动冷静期，边界见 M1 计划 §2 S7）。
   */
  async confirmRecoveryRequest(fromDid: string, ownerDid: string): Promise<void> {
    const raw = await this.deps.kv.get(`guardianship:${ownerDid}`);
    if (!raw) throw new Error("你不是该账户的守护者");
    const g = JSON.parse(bytesToUtf8(raw)) as { wrapCid: string; sealedShare: string };
    const share = openGuardianShare(this.identity.ikEd.privateKey, {
      did: ownerDid,
      wrapCid: g.wrapCid,
      sealedShare: base58Decode(g.sealedShare),
    });
    const session = this.sessions.get(fromDid);
    if (!session) throw new Error("与请求者的会话不存在");
    const wire = sessionSend(
      session,
      utf8ToBytes(
        JSON.stringify({
          v: 1,
          type: "recovery-share",
          did: ownerDid,
          shareX: share.x,
          shareY: base58Encode(share.y),
        } satisfies SessionPayload),
      ),
    );
    const mailboxId = sessionMailbox(session, "send", Date.now());
    await this.deps.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
    await this.deps.kv.delete(`recovery-request:${fromDid}`);
    this.emit();
  }

  /** 守护者拒绝恢复请求（UX-2：拒绝入口，防社工）。 */
  async rejectRecoveryRequest(fromDid: string): Promise<void> {
    await this.deps.kv.delete(`recovery-request:${fromDid}`);
    this.emit();
  }

  /**
   * 设置紧急联系人（原机）：生成 RK → 身份包裹入 CAS → 公告上节点 → 分片经会话分发。
   * 守护者接受（guardian-invite 静默存储）后生效；建议选 5 位、门限 3（FR-1.3 默认）。
   */
  async setupGuardians(guardianDids: string[], threshold = 3): Promise<{ wrapCid: string }> {
    if (guardianDids.length < 2) throw new Error("守护者至少 2 位");
    for (const did of guardianDids) {
      if (!this.sessions.has(did)) throw new Error("守护者必须是已建立会话的联系人");
    }
    const setup = createRecoverySetup(this.identity, guardianDids, threshold);
    await this.deps.api.putBlock(setup.wrapCid, setup.wrap);
    await this.deps.api.putRecoveryAnnouncement(this.identity.did, {
      did: setup.announcement.did,
      wrapCid: setup.announcement.wrapCid,
      threshold: setup.announcement.threshold,
      guardians: setup.announcement.guardians,
      signature: toBase64(setup.announcement.signature),
    });

    for (const did of guardianDids) {
      const pack = sealGuardianShare(setup, did);
      const session = this.sessions.get(did)!;
      const wire = sessionSend(
        session,
        utf8ToBytes(
          JSON.stringify({
            v: 1,
            type: "guardian-invite",
            did: this.identity.did,
            wrapCid: setup.wrapCid,
            sealedShare: base58Encode(pack.sealedShare),
          } satisfies SessionPayload),
        ),
      );
      const mailboxId = sessionMailbox(session, "send", Date.now());
      await this.deps.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
    }
    await this.deps.kv.put(
      "recovery-self",
      utf8ToBytes(JSON.stringify({ wrapCid: setup.wrapCid, threshold, guardians: guardianDids })),
    );
    this.emit();
    return { wrapCid: setup.wrapCid };
  }

  async getRecoverySelf(): Promise<{ wrapCid: string; threshold: number; guardians: string[] } | null> {
    const raw = await this.deps.kv.get("recovery-self");
    return raw ? (JSON.parse(bytesToUtf8(raw)) as { wrapCid: string; threshold: number; guardians: string[] }) : null;
  }

  /** 发起恢复请求（新机/临时身份视角）：向守护者请求分片回传。 */
  async sendRecoveryRequest(ownerDid: string): Promise<void> {
    for (const [did, session] of this.sessions) {
      const wire = sessionSend(
        session,
        utf8ToBytes(JSON.stringify({ v: 1, type: "recovery-request", did: ownerDid } satisfies SessionPayload)),
      );
      const mailboxId = sessionMailbox(session, "send", Date.now());
      await this.deps.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
      void did;
    }
    this.emit();
  }

  /** 已收集的恢复分片（恢复收集器）。 */
  collectedShares: { shareX: number; shareY: string; fromDid: string }[] = [];

  /** 恢复完成判定：收集数达门限后重组 RK → 解开身份包裹 → 返回身份 JSON。 */
  async tryFinishRecovery(
    ownerDid: string,
    wrapCid: string,
    threshold: number,
  ): Promise<string | null> {
    if (this.collectedShares.length < threshold) return null;
    const shares = this.collectedShares.slice(0, threshold).map((s) => ({
      x: s.shareX,
      y: base58Decode(s.shareY),
    }));
    const rk = recoverRk(shares, 32);
    const wrapCiphertext = await this.deps.api.getBlock(wrapCid);
    if (!wrapCiphertext) throw new Error("身份包裹块不存在（节点无此数据）");
    return openIdentityWrap(rk, wrapCiphertext);
  }

  // ----- 发送（FR-5.1 / FR-5.2 / FR-5.3 子集） -----

  async sendMessage(did: string, text: string): Promise<void> {
    const session = this.sessions.get(did);
    if (!session) throw new Error("会话不存在（请先添加好友）");
    await this.sendPayload(session, did, { v: 1, type: "chat", text }, "chat", text);
  }

  /**
   * 发送图片/文件：随机 CK 加密 → CAS 块 → 消息携带 CID + CK（M1 计划 §3.4）。
   * 节点只见密文块；CK 仅存在于 E2EE 消息体。
   */
  async sendAttachment(
    did: string,
    file: { data: Uint8Array; name: string; mime: string },
    kind: "image" | "file",
  ): Promise<void> {
    const session = this.sessions.get(did);
    if (!session) throw new Error("会话不存在（请先添加好友）");
    if (file.data.length > 8 * 1024 * 1024) throw new Error("附件超过 8MB 上限");

    const att = encryptAttachment(file.data);
    await this.deps.api.putBlock(att.cid, att.ciphertext);
    const payload = {
      v: 1 as const,
      type: kind,
      cid: att.cid,
      contentKey: base58Encode(att.contentKey),
      nonce: base58Encode(att.nonce),
      name: file.name,
      size: file.data.length,
      mime: file.mime,
    };
    await this.sendPayload(session, did, payload, kind, file.name);
  }

  private async sendPayload(
    session: Session,
    did: string,
    payload: SessionPayload,
    kind: MessageKind,
    text: string,
  ): Promise<void> {
    const wire = sessionSend(session, utf8ToBytes(JSON.stringify(payload)));
    const mailboxId = sessionMailbox(session, "send", Date.now());
    const envelope = this.seal(wire, mailboxId);
    await this.deps.api.mailboxAppend(envelope.toPseudonym, envelope);
    if (payload.type !== "receipt") {
      await this.appendLocalMessage(did, "out", text, kind, payload);
    }
    this.emit();
  }

  /** 装信封：内层 wire → 填充（档位自适应）→ 信封（伪地址，FR-3.1/3.3）。 */
  private seal(wire: Uint8Array, mailboxId: string): Envelope {
    const padClass = padClassForLength(wire.length + 4);
    const padded = applyPadding(wire, padClass);
    return makeEnvelope({ epoch: Math.floor(Date.now() / EPOCH_MS), toPseudonym: mailboxId, padClass, payload: padded });
  }

  // ----- 接收（FR-5.1 在线直投 + 离线信箱） -----

  /** 拉取发现信箱 + 全部会话的接收信箱（覆盖上一个/当前/下一个 epoch，防轮换漏收）。 */
  async poll(): Promise<void> {
    try {
      await this.pollDiscovery();
      for (const did of this.contacts.keys()) {
        await this.pollSession(did);
      }
      this.online = true;
    } catch {
      this.online = false;
    }
    this.emit();
  }

  private async cursorFor(mailboxId: string): Promise<number> {
    return this.cursors.get(mailboxId) ?? 0;
  }

  private async advanceCursor(mailboxId: string, cursor: number): Promise<void> {
    this.cursors.set(mailboxId, cursor);
    await this.deps.kv.put(cursorKey(mailboxId), utf8ToBytes(String(cursor)));
  }

  private async pollDiscovery(): Promise<void> {
    const mailboxId = discoveryInboxId(this.identity.did);
    const cursor = await this.cursorFor(mailboxId);
    const { envelopes, cursor: next } = await this.deps.api.mailboxFetch(mailboxId, cursor);
    for (const envelope of envelopes) {
      await this.handleHandshake(envelope);
    }
    await this.advanceCursor(mailboxId, next);
  }

  private async handleHandshake(envelope: Envelope): Promise<void> {
    let wire: Uint8Array;
    try {
      wire = stripPadding(envelope.payload);
    } catch {
      return; // 畸形信封静默丢弃（A3 防注入）
    }
    let msg: ReturnType<typeof decodeSessionWire>;
    try {
      msg = decodeSessionWire(wire);
    } catch {
      return;
    }
    if (msg.kind !== 1) return;

    try {
      const opkPool = new Map([[this.opk.id, this.opk]]);
      const { session, plaintext } = acceptSession(this.identity, this.spk, opkPool, wire);
      const handshake = JSON.parse(bytesToUtf8(plaintext)) as HandshakePayload;
      if (handshake.v !== 1 || typeof handshake.fromDid !== "string") return;
      if (this.contacts.has(handshake.fromDid)) return; // 已是联系人：忽略重复握手

      this.sessions.set(handshake.fromDid, session);
      this.contacts.set(handshake.fromDid, {
        did: handshake.fromDid,
        name: handshake.fromName ?? null,
        addedAt: Date.now(),
      });
      await this.saveContact(handshake.fromDid);
      await this.saveSession(handshake.fromDid);
      await this.appendLocalMessage(handshake.fromDid, "in", handshake.note, "handshake");
      this.restartRealtime(); // 新会话需订阅其接收信箱
    } catch {
      // OPK 消耗/篡改等失败：忽略（陌生人重放握手被天然拒绝）
    }
  }

  private async pollSession(did: string): Promise<void> {
    const session = this.sessions.get(did);
    if (!session) return;
    const now = Date.now();
    const deliveredIds: string[] = [];
    for (const at of [now - EPOCH_MS, now, now + EPOCH_MS]) {
      const mailboxId = sessionMailbox(session, "recv", at);
      const cursor = await this.cursorFor(mailboxId);
      const { envelopes, cursor: next } = await this.deps.api.mailboxFetch(mailboxId, cursor);
      for (const envelope of envelopes) {
        try {
          const wire = stripPadding(envelope.payload);
          const plaintext = sessionReceive(session, wire);
          const message = await this.handleSessionPayload(did, bytesToUtf8(plaintext));
          if (message) deliveredIds.push(message.id);
        } catch {
          // 篡改/重放/跨会话密文：丢弃（SR-4）
        }
      }
      await this.advanceCursor(mailboxId, next);
    }
    // delivered 回执：本轮拉取到的内容类消息聚合为一条（MR-1）
    if (deliveredIds.length > 0) {
      await this.sendReceipt(did, { delivered: deliveredIds, read: [] });
    }
  }

  /** 解析会话载荷并落库；返回内容类消息（回执返回 null）。兼容 M0 纯文本消息。 */
  private async handleSessionPayload(did: string, raw: string): Promise<ChatMessage | null> {
    let payload: SessionPayload;
    try {
      const parsed = JSON.parse(raw) as SessionPayload;
      if (parsed?.v !== 1 || typeof parsed.type !== "string") throw new Error("bad payload");
      payload = parsed;
    } catch {
      // M0 时期的纯文本消息（协议规范 v0.1 过渡兼容）
      return await this.appendLocalMessage(did, "in", raw, "chat");
    }

    if (payload.type === "receipt") {
      await this.applyReceipt(did, payload);
      return null;
    }
    if (payload.type === "custody-request") {
      // 恢复流（S7）：对方以已验证身份请求回传其托管副本；仅当所存副本归属与请求方一致时回传
      await this.replyCustopyIfHeld(did);
      return null;
    }
    if (payload.type === "custody-reply") {
      // 静默存储：好友的托管材料（密文清单指针），不出现在聊天记录
      await this.deps.kv.put(
        `custody:${did}`,
        utf8ToBytes(JSON.stringify({ cid: payload.cid, contentKey: payload.contentKey, nonce: payload.nonce })),
      );
      return null;
    }
    if (payload.type === "guardian-invite") {
      // 成为守护者：静默存储分片包（ECIES 密文，仅我可解）；列表可见（UX-2 "紧急联系人"心智）
      await this.deps.kv.put(
        `guardianship:${payload.did}`,
        utf8ToBytes(JSON.stringify({ wrapCid: payload.wrapCid, sealedShare: payload.sealedShare })),
      );
      this.emit();
      return null;
    }
    if (payload.type === "recovery-request") {
      // 恢复请求：存入待确认队列，由守护者人工判定（M1 无自动冷静期，边界披露见 recovery.ts）
      await this.deps.kv.put(
        `recovery-request:${did}`,
        utf8ToBytes(JSON.stringify({ ownerDid: payload.did, fromDid: did, at: Date.now() })),
      );
      this.emit();
      return null;
    }
    if (payload.type === "recovery-share") {
      // 收到守护者回传的分片（恢复收集器）
      this.collectedShares.push({ shareX: payload.shareX, shareY: payload.shareY, fromDid: did });
      this.emit();
      return null;
    }
    if (payload.type === "chat") {
      return await this.appendLocalMessage(did, "in", payload.text, "chat");
    }
    // image / file
    return await this.appendLocalMessage(did, "in", payload.name, payload.type, payload);
  }

  /** 收到 custody-request：若我持有该 DID 的托管副本则回传（did 不可伪造，会话建立即身份证明）。 */
  private async replyCustopyIfHeld(requesterDid: string): Promise<void> {
    const raw = await this.deps.kv.get(`custody:${requesterDid}`);
    if (!raw) return;
    const session = this.sessions.get(requesterDid);
    if (!session) return;
    const held = JSON.parse(bytesToUtf8(raw)) as { cid: string; contentKey: string; nonce: string };
    const wire = sessionSend(
      session,
      utf8ToBytes(JSON.stringify({ v: 1, type: "custody-reply", ...held } satisfies SessionPayload)),
    );
    const mailboxId = sessionMailbox(session, "send", Date.now());
    await this.deps.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
  }

  /** 收到对端回执：升级本地 out 消息状态（read > delivered > sent）。 */
  private async applyReceipt(did: string, receipt: { delivered: string[]; read: string[] }): Promise<void> {
    const list = this.messages.get(did) ?? [];
    let changed = false;
    for (const message of list) {
      if (message.direction !== "out") continue;
      if (receipt.read.includes(message.id) && message.status !== "read") {
        message.status = "read";
        changed = true;
      } else if (receipt.delivered.includes(message.id) && (message.status === "sent" || message.status === undefined)) {
        message.status = "delivered";
        changed = true;
      }
    }
    if (changed) {
      for (const message of list) {
        if (message.direction === "out") await this.persistMessage(did, message);
      }
    }
  }

  /** 发送回执（E2EE 会话消息；已读回执关闭时 read 列表恒为空，无可分析差异，FR-5.2）。 */
  private async sendReceipt(did: string, receipt: { delivered: string[]; read: string[] }): Promise<void> {
    const session = this.sessions.get(did);
    if (!session) return;
    if (receipt.delivered.length === 0 && receipt.read.length === 0) return;
    try {
      const wire = sessionSend(session, utf8ToBytes(JSON.stringify({ v: 1, type: "receipt", ...receipt } satisfies SessionPayload)));
      const mailboxId = sessionMailbox(session, "send", Date.now());
      await this.deps.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
    } catch {
      /* 回执失败不影响内容消息 */
    }
  }

  /**
   * UI 打开会话时调用：把对方发来的、尚未确认已读的消息聚合发出 read 回执。
   * 已读回执关闭（FR-5.2 隐私开关）时完全不产生 read 回执。
   */
  async markChatOpened(did: string): Promise<void> {
    if (!(await this.readReceiptsEnabled())) return;
    const list = this.messages.get(did) ?? [];
    const readIds = list
      .filter((m) => m.direction === "in" && m.kind !== "handshake" && !this.readConfirmed.has(m.id))
      .map((m) => m.id);
    if (readIds.length === 0) return;
    for (const id of readIds) this.readConfirmed.add(id);
    await this.sendReceipt(did, { delivered: [], read: readIds });
  }

  /** 已读回执开关（默认开启；kv 持久化，UI 设置项）。 */
  async readReceiptsEnabled(): Promise<boolean> {
    const raw = await this.deps.kv.get(SETTING_READ_RECEIPTS);
    return raw === undefined ? true : bytesToUtf8(raw) === "on";
  }

  async setReadReceiptsEnabled(enabled: boolean): Promise<void> {
    await this.deps.kv.put(SETTING_READ_RECEIPTS, utf8ToBytes(enabled ? "on" : "off"));
    this.emit();
  }

  // ----- 实时（WS 唤醒 + 轮询兜底，W2 约束） -----

  startRealtime(): void {
    this.stopRealtime();
    const mailboxes = [discoveryInboxId(this.identity.did)];
    for (const did of this.contacts.keys()) {
      const session = this.sessions.get(did);
      if (!session) continue;
      const now = Date.now();
      for (const at of [now, now + EPOCH_MS]) {
        mailboxes.push(sessionMailbox(session, "recv", at));
      }
    }
    const stopWs = this.deps.api.subscribeMailboxes(mailboxes, () => void this.poll());
    this.pollTimer = setInterval(() => void this.poll(), 3000);
    this.stopWs = stopWs;
  }

  stopRealtime(): void {
    this.stopWs?.();
    this.stopWs = null;
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.pollTimer = null;
  }

  private restartRealtime(): void {
    if (this.stopWs) this.startRealtime();
  }

  // ----- 持久化辅助 -----

  private async saveContact(did: string): Promise<void> {
    const contact = this.contacts.get(did);
    if (contact) await this.deps.kv.put(contactKey(did), utf8ToBytes(JSON.stringify(contact)));
  }

  private async saveSession(did: string): Promise<void> {
    const session = this.sessions.get(did);
    if (session) await this.deps.kv.put(sessionKey(did), utf8ToBytes(serializeSession(session)));
  }

  private async appendLocalMessage(
    did: string,
    direction: "in" | "out",
    text: string,
    kind: MessageKind,
    payload?: SessionPayload,
  ): Promise<ChatMessage> {
    const attachment: AttachmentMeta | undefined =
      payload && (payload.type === "image" || payload.type === "file")
        ? {
            cid: payload.cid,
            contentKey: payload.contentKey,
            nonce: payload.nonce,
            name: payload.name,
            size: payload.size,
            mime: payload.mime,
          }
        : undefined;
    const message: ChatMessage = {
      id: `m${this.msgSeq}`,
      did,
      direction,
      kind,
      text,
      ...(attachment ? { attachment } : {}),
      at: Date.now(),
      ...(direction === "out" && kind !== "handshake" ? { status: "sent" as const } : {}),
    };
    await this.persistMessage(did, message);
    if (direction === "in" && kind !== "handshake") {
      this.onIncomingMessage?.(message);
    }
    this.emit();
    return message;
  }

  private async persistMessage(did: string, message: ChatMessage): Promise<void> {
    const list = this.messages.get(did) ?? [];
    if (!list.includes(message)) list.push(message);
    this.messages.set(did, list);
    let key = this.messageKeys.get(message.id);
    if (!key) {
      this.msgSeq += 1;
      key = msgKey(did, this.msgSeq);
      this.messageKeys.set(message.id, key);
    }
    await this.deps.kv.put(key, utf8ToBytes(JSON.stringify(message)));
    await this.deps.kv.put(K_MSG_SEQ, utf8ToBytes(String(this.msgSeq)));
  }

  /** UI 层取附件块的最小访问面（deps 保持私有）。 */
  getNodeApi(): NodeApi {
    return this.deps.api;
  }

  private emit(): void {
    this.onStateChange();
  }
}
