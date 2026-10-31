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
  deriveOpkId,
  deserializeIdentity,
  deserializeSession,
  encodePreKeyBundle,
  generateX25519KeyPair,
  initiateSession,
  issuePreKeyBundle,
  makeEnvelope,
  makeUserNameRecord,
  padClassForLength,
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

import { fromHex, toHex } from "./base64";
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
  | ({ v: 1; type: "image" | "file" } & AttachmentMeta);

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
    if (payload.type === "chat") {
      return await this.appendLocalMessage(did, "in", payload.text, "chat");
    }
    // image / file
    return await this.appendLocalMessage(did, "in", payload.name, payload.type, payload);
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
