/**
 * DemoClient —— 端到端加密聊天客户端的课程演示最小实现。
 *
 * 刻意只做主线（对照完整版 packages/client-web/src/lib/messaging.ts）：
 *   创建身份 → 登记设备凭证 → 发布预密钥束（SPK+OPK）→ 注册用户名 →
 *   加好友（X3DH 握手，含 ikxSig 身份绑定校验）→ Double Ratchet 收发文本 →
 *   轮询信箱（三 epoch 时间桶）。
 *
 * 不做（演示不需要）：群组/动态/社交恢复/多设备/Web Push/撤回/引用。
 * 协议语义与协议规范（docs/protocol/协议规范.md）§2-§7 对齐。
 */
import {
  acceptSession,
  base58Decode,
  base58Encode,
  bytesToUtf8,
  createIdbKVStore,
  createIdentity,
  decodePreKeyBundle,
  decodeSessionWire,
  deriveOpkId,
  deserializeIdentity,
  deserializeSession,
  didToEd25519PublicKey,
  EPOCH_MS,
  ed25519Verify,
  encodeDeviceCertificateJson,
  encodePreKeyBundle,
  generateEd25519KeyPair,
  generateX25519KeyPair,
  hkdfSha256,
  ikxBindingMessage,
  initiateSession,
  issuePreKeyBundle,
  makeDeviceCertificate,
  makeEnvelope,
  makeUserNameRecord,
  padClassForLength,
  applyPadding,
  serializeIdentity,
  serializeSession,
  sessionMailbox,
  sessionReceive,
  sessionSend,
  stripPadding,
  utf8ToBytes,
  verifyPreKeyBundle,
  verifyUserNameRecord,
  type Envelope,
  type Identity,
  type KeyPair,
  type PadClass,
  type Session,
  type UserNameRecord,
} from "@mychat/core";

import { envelopeFromJson, NodeClient } from "./node-client";

/** 一条聊天消息（演示最小形态：纯文本，方向 + 时间）。 */
export interface DemoChatItem {
  dir: "in" | "out";
  text: string;
  at: number;
}

/** 供 UI 渲染的状态快照（DemoClient 不碰 DOM）。 */
export interface DemoClientState {
  did: string | null;
  userName: string | null;
  contacts: { did: string; name: string }[];
  messages: { did: string; items: DemoChatItem[] }[];
  log: string[];
}

const DISCOVERY_INFO = "mychat:discovery:v1";

/** 发现信箱（握手可达地址）——DID 公开材料派生；与 client-web lib/discovery.ts 同构。 */
function discoveryInboxId(did: string): string {
  return base58Encode(hkdfSha256(didToEd25519PublicKey(did), new Uint8Array(32), DISCOVERY_INFO, 18));
}

function shortDid(did: string): string {
  return did.length > 18 ? `${did.slice(0, 18)}…` : did;
}

/** 敏感身份（含全部私钥）的持久化形态（serializeIdentity 全字节校验可逆）。 */
interface StoredIdentity {
  identity: string;
  sessions: [string, string][];
  userName: string | null;
}

export class DemoClient {
  /** UI 栏名（Alice/Bob），同时作为 IndexedDB 库名的一部分。 */
  readonly slot: string;
  private api: NodeClient;
  private kv: Awaited<ReturnType<typeof createIdbKVStore>> | null = null;
  identity: Identity | null = null;
  userName: string | null = null;
  private spk: KeyPair | null = null;
  private opk: (KeyPair & { id: number }) | null = null;
  private dkId: string | null = null;
  private sessions = new Map<string, Session>();
  private contacts = new Map<string, string>();
  private cursors = new Map<string, number>();
  private messages = new Map<string, DemoChatItem[]>();
  private log: string[] = [];
  /** 状态变化回调（UI 装配）。 */
  onChange: (() => void) | null = null;

  constructor(slot: string, nodeBaseUrl: string) {
    this.slot = slot;
    this.api = new NodeClient(nodeBaseUrl);
  }

  /**
   * 供节点视角栏展示的信箱面：发现信箱 + 各会话的会话信箱（当前时间桶）。
   * 注意 send 与 recv 会话信箱是**同一个伪地址**（与对端镜像）——同一伪地址
   * 承载双向流量，节点无法区分收发方向；label 刻意不含用户名（节点数据中
   * 本就没有用户名，UI 也不引入）。
   */
  mailboxes(): { id: string; label: string }[] {
    if (this.identity === null) return [];
    const out: { id: string; label: string }[] = [{ id: discoveryInboxId(this.identity.did), label: `${this.slot}·发现信箱` }];
    for (const session of this.sessions.values()) {
      out.push({ id: sessionMailbox(session, "recv"), label: `${this.slot}·会话信箱` });
    }
    return out;
  }

  getState(): DemoClientState {
    return {
      did: this.identity?.did ?? null,
      userName: this.userName,
      contacts: [...this.contacts.entries()].map(([did, name]) => ({ did, name })),
      messages: [...this.messages.entries()].map(([did, items]) => ({ did, items })),
      log: [...this.log],
    };
  }

  private say(line: string): void {
    this.log.push(`${new Date().toLocaleTimeString()} ${line}`);
  }

  private changed(): void {
    this.onChange?.();
  }

  // ---------- 第 1 步：创建身份（本地密钥 + 设备凭证 + 预密钥束发布） ----------

  /**
   * 无感创建身份：IK（Ed25519 签名 + X25519 协商）本地生成，仅存本机 IndexedDB；
   * 设备凭证与 SPK/OPK 经 IK 签名后上节点（节点验签准入，但拿不到任何私钥）。
   * 刷新页面：身份/用户名/会话从本机恢复；SPK/OPK 重新生成覆盖发布（旧 OPK 未
   * 消耗即作废——零信任节点本就允许覆盖，演示从简）。
   */
  async setup(): Promise<string> {
    this.kv = await createIdbKVStore(`mychat-demo-${this.slot}`);
    const savedIdentity = await this.kv.get("identity");
    if (savedIdentity !== undefined) {
      const saved = JSON.parse(bytesToUtf8(savedIdentity)) as StoredIdentity;
      this.identity = deserializeIdentity(saved.identity);
      this.userName = saved.userName;
      for (const [did, json] of saved.sessions) this.sessions.set(did, deserializeSession(json));
      await this.publishPreKeys();
      this.say(`身份已从本机恢复（DID ${shortDid(this.identity.did)}），预密钥已重新发布`);
      this.changed();
      return this.identity.did;
    }
    this.identity = createIdentity();
    await this.publishPreKeys();
    await this.persistIdentity();
    this.say(`身份已创建：DID ${shortDid(this.identity.did)}（Ed25519 签名密钥 + X25519 协商密钥，不出本机）`);
    this.changed();
    return this.identity.did;
  }

  /** 设备凭证 + SPK + OPK → 预密钥束（bundle 即"可被任何人联系"的公共名片）。 */
  private async publishPreKeys(): Promise<void> {
    const identity = this.identity!;
    const dk = generateEd25519KeyPair();
    this.dkId = base58Encode(dk.publicKey);
    const cert = makeDeviceCertificate(identity.ikEd.privateKey, identity.did, dk.publicKey, `demo-${this.slot}`, 24 * 60 * 60 * 1000);
    await this.api.putDevice(identity.did, JSON.parse(encodeDeviceCertificateJson(cert)) as Record<string, unknown>);
    this.spk = generateX25519KeyPair();
    const opk = generateX25519KeyPair();
    this.opk = { ...opk, id: deriveOpkId(opk.publicKey) };
    const bundle = issuePreKeyBundle(identity, this.spk, this.opk, 24 * 60 * 60 * 1000);
    await this.api.putBundle(identity.did, encodePreKeyBundle(bundle), this.dkId);
    this.say("设备凭证 + 预密钥束已上节点（SPK/OPK 私钥不出本机；节点只存公钥并验签）");
  }

  // ---------- 第 2 步：注册用户名 ----------

  /** 用户名记录 = IK 签名的 (name, did, ktIndex)；节点验签准入，解析方再验一次。 */
  async register(name: string): Promise<void> {
    const record: UserNameRecord = makeUserNameRecord(this.identity!.ikEd.privateKey, name, this.identity!.did, 0);
    await this.api.register(record);
    this.userName = name;
    await this.persistIdentity();
    this.say(`用户名「${name}」已注册（IK 签名锚定，节点无法冒名改绑）`);
    this.changed();
  }

  // ---------- 第 3 步：加好友（发起方 X3DH） ----------

  /** 解析对方用户名 → 验签名记录 → 取并验预密钥束 → X3DH 建会话 → 握手投递其发现信箱。 */
  async addFriend(userName: string): Promise<string> {
    const record = await this.api.resolve(userName);
    if (record === null) throw new Error(`用户名「${userName}」不存在`);
    if (!verifyUserNameRecord(record)) throw new Error("用户名记录验签失败（可能被节点篡改）");
    const peerDid = record.did;
    const bundleBytes = await this.api.getBundle(peerDid);
    if (bundleBytes === null) throw new Error("对方预密钥束不存在");
    const bundle = decodePreKeyBundle(bundleBytes);
    if (!verifyPreKeyBundle(bundle)) throw new Error("预密钥束验签失败（身份与 SPK/OPK 绑定不成立）");
    if (bundle.did !== peerDid) throw new Error("预密钥束 DID 不匹配");

    const handshake = {
      v: 1,
      fromDid: this.identity!.did,
      fromName: this.userName,
      // 身份绑定签名（协议规范 §5 v0.2.1）：IK-ed 对本次 X3DH 的 X25519 公钥签名，响应方必须校验——防冒名握手
      ikxSig: base58Encode(this.identity!.ikxBindingSig),
    };
    const { session, wire } = initiateSession(this.identity!, bundle, utf8ToBytes(JSON.stringify(handshake)));
    this.sessions.set(peerDid, session);
    this.contacts.set(peerDid, record.name);
    await this.persistIdentity();
    const mailboxId = discoveryInboxId(peerDid);
    await this.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
    this.say(`已向「${record.name}」发起 X3DH 握手（DH1-DH4 → 会话密钥；握手密文投其发现信箱）`);
    this.changed();
    return peerDid;
  }

  // ---------- 收发（Double Ratchet + 时间桶信箱） ----------

  /** DR 密文 → 四档定长填充（长度侧信道抑制）→ 信封（节点只见伪地址与密文）。 */
  private seal(wire: Uint8Array, mailboxId: string): Envelope {
    const padClass: PadClass = padClassForLength(wire.length + 4);
    const padded = applyPadding(wire, padClass);
    return makeEnvelope({ epoch: Math.floor(Date.now() / EPOCH_MS), toPseudonym: mailboxId, padClass, payload: padded });
  }

  async send(did: string, text: string): Promise<void> {
    const session = this.sessions.get(did);
    if (session === undefined) throw new Error("尚未与对方建立会话（先加好友）");
    const wire = sessionSend(session, utf8ToBytes(text));
    const mailboxId = sessionMailbox(session, "send");
    await this.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
    this.pushMessage(did, { dir: "out", text, at: Date.now() });
    this.say("已发送：每条消息用一次性棘轮密钥加密，节点只收到密文");
    this.changed();
  }

  /** 轮询：发现信箱（握手）+ 每会话接收信箱（now / now±EPOCH 三桶防轮换漏收）。 */
  async poll(): Promise<void> {
    if (this.identity === null) return;
    const discovery = discoveryInboxId(this.identity.did);
    await this.pollMailbox(discovery, (raw) => void this.onEnvelopeDiscovery(raw));
    for (const did of this.sessions.keys()) {
      const session = this.sessions.get(did)!;
      for (const at of [Date.now() - EPOCH_MS, Date.now(), Date.now() + EPOCH_MS]) {
        const mailboxId = sessionMailbox(session, "recv", at);
        await this.pollMailbox(mailboxId, (raw) => this.onEnvelopeChat(did, raw));
      }
    }
    this.changed();
  }

  private async pollMailbox(mailboxId: string, handle: (raw: Record<string, unknown>) => void): Promise<void> {
    const cursor = this.cursors.get(mailboxId) ?? 0;
    const { envelopes, cursor: next } = await this.api.mailboxFetchRaw(mailboxId, cursor);
    for (const raw of envelopes) handle(raw);
    if (envelopes.length > 0) this.cursors.set(mailboxId, next);
  }

  /** 发现信箱信封 → 握手接受（响应方 X3DH：验身份绑定、消耗 OPK、建立会话）。 */
  private async onEnvelopeDiscovery(raw: Record<string, unknown>): Promise<void> {
    try {
      const envelope = envelopeFromJson(raw);
      const wire = stripPadding(envelope.payload);
      const msg = decodeSessionWire(wire);
      if (msg.kind !== 1) return;
      const opkPool = this.opk !== null ? new Map([[this.opk.id, this.opk]]) : new Map<number, KeyPair & { id: number }>();
      const { session, plaintext } = acceptSession(this.identity!, this.spk!, opkPool, wire);
      const handshake = JSON.parse(bytesToUtf8(plaintext)) as { v: number; fromDid: string; fromName: string | null; ikxSig: string };
      // 身份绑定校验（v0.2.1）：自报 fromDid 必须能对 wire 头的 X25519 公钥验签——防冒名顶替会话
      const bound = ed25519Verify(base58Decode(handshake.ikxSig), ikxBindingMessage(msg.x3dh.ikxSenderPublic), didToEd25519PublicKey(handshake.fromDid));
      if (!bound) throw new Error("握手身份绑定校验失败（冒名握手）");
      this.sessions.set(handshake.fromDid, session);
      this.contacts.set(handshake.fromDid, handshake.fromName ?? shortDid(handshake.fromDid));
      await this.persistIdentity();
      // OPK 一次性语义：消耗（DELETE）后立即生成新 OPK 重发 bundle——下次握手仍可被接受
      await this.api.consumeOpk(this.identity!.did, msg.x3dh.opkId, this.dkId!);
      await this.publishPreKeys();
      this.say(`接受了「${this.contacts.get(handshake.fromDid)}」的握手：X3DH 响应方推导出同一会话密钥，OPK 已消耗并轮换`);
      this.changed();
    } catch (err) {
      // 非握手信封 / 伪造 / 重放：静默丢弃（零信任节点可投递任意字节，密码学层兜底）
      this.say(`丢弃一个无法接受的信封：${err instanceof Error ? err.message.slice(0, 60) : "未知"}`);
    }
  }

  /** 会话信箱信封 → Double Ratchet 解密 → 纯文本消息。 */
  private onEnvelopeChat(did: string, raw: Record<string, unknown>): void {
    try {
      const envelope = envelopeFromJson(raw);
      const wire = stripPadding(envelope.payload);
      const session = this.sessions.get(did)!;
      const plaintext = sessionReceive(session, wire);
      this.pushMessage(did, { dir: "in", text: bytesToUtf8(plaintext), at: Date.now() });
    } catch {
      // 重放/篡改/乱序缺失密钥：DR 层拒绝（课程可现场演示"重放被拒"）
    }
  }

  private pushMessage(did: string, item: DemoChatItem): void {
    const list = this.messages.get(did) ?? [];
    list.push(item);
    this.messages.set(did, list);
  }

  /** 身份 + 用户名 + 全部会话（serializeSession 全字节校验形态）持久化。 */
  private async persistIdentity(): Promise<void> {
    if (this.kv === null || this.identity === null) return;
    const savedIdentity = await this.kv.get("identity");
    const previous = savedIdentity !== undefined ? (JSON.parse(bytesToUtf8(savedIdentity)) as StoredIdentity) : null;
    await this.kv.put(
      "identity",
      utf8ToBytes(JSON.stringify({
        identity: serializeIdentity(this.identity),
        sessions: [...this.sessions.entries()].map(([did, s]) => [did, serializeSession(s)]),
        userName: this.userName ?? previous?.userName ?? null,
      } satisfies StoredIdentity)),
    );
  }
}
