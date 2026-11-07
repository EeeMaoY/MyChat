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
  type GroupKeysPayload,
  type GroupState,
  type GroupView,
  type Identity,
  type KTEvent,
  type KVStore,
  type KeyPair,
  type PreKeyBundle,
  type Session,
  createRecoverySetup,
  addGroupMember,
  applyGroupKeysPayload,
  createGroup,
  createGroupView,
  createMomentBlock,
  decodeDeviceCertificateJson,
  decodeGroupStateJson,
  deriveOpkId,
  deserializeIdentity,
  deserializeSession,
  encodeDeviceCertificateJson,
  encodeDeviceRevocationJson,
  encodeGroupStateJson,
  encodePreKeyBundle,
  fingerprintDeviceIds,
  activeDeviceIds,
  foldDeviceEvents,
  generateEd25519KeyPair,
  generateMomentKey,
  generateSenderKeys,
  generateX25519KeyPair,
  groupMailboxId,
  initiateSession,
  issuePreKeyBundle,
  makeDeviceCertificate,
  makeDeviceRevocation,
  makeGroupKeysPayload,
  makeEnvelope,
  makeMomentEntry,
  makeUserNameRecord,
  momentFeedId,
  openFeedEntry,
  openGroupMessage,
  openGuardianShare,
  openIdentityWrap,
  openMomentBlock,
  padClassForLength,
  recoverRk,
  removeGroupMember,
  sealFeedEntry,
  sealGuardianShare,
  sealGroupMessage,
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
  verifyDeviceCertificate,
  verifyGroupState,
  verifyPreKeyBundle,
  verifyUserNameRecord,
  type DeviceCertificate,
  type DeviceView,
  EPOCH_MS,
} from "@mychat/core";

import { fromBase64, fromHex, toBase64, toHex } from "./base64";
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
  /** 群消息（did = group:<groupId>）：实际发送者（UI 显示气泡署名，M3-S11） */
  senderDid?: string;
}

/** 会话键：1:1 = 对方 DID；群组 = group:<groupId>（UI 与消息存储统一路由）。 */
export function groupChatKey(groupId: string): string {
  return `group:${groupId}`;
}

/** 待确认的好友申请（M3 修复：陌生人握手不再自动成为好友）。 */
export interface FriendRequestItem {
  fromDid: string;
  name: string | null;
  note: string;
  at: number;
}

/** 队列存储形态（会话序列化随申请保存，通过即生效）。 */
interface FriendRequestStored {
  fromDid: string;
  name: string | null;
  note: string;
  sessionWire: string;
  at: number;
}

/** 群组条目（UI 快照用）。 */
export interface GroupSummary {
  groupId: string;
  name: string;
  owner: string;
  epoch: number;
  memberCount: number;
  /** 我是否群主（管理权限判定） */
  amOwner: boolean;
}

/** 动态条目（UI 快照；本地缓存形态，M3-S12）。 */
export interface MomentItem {
  authorDid: string;
  cid: string;
  text: string;
  at: number;
  attachment?: AttachmentMeta;
  /** 墓碑后本地标记（缓存副本保留但 UI 不渲染内容，FR-4.4 固有边界） */
  deleted?: boolean;
  comments: { fromDid: string; text: string; at: number }[];
}

/** GroupKeysPayload 的客户端持久化 JSON 形态（kv 存储；senderKeys base58）。 */
export interface GroupKeysPayloadJson {
  v: 1;
  groupId: string;
  epoch: number;
  groupSecret: string;
  state: Record<string, unknown>;
  senderKeys: { did: string; key: string }[];
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
  | { v: 1; type: "recovery-share"; did: string; shareX: number; shareY: string }
  /** 群组（FR-6.1，M3-S11）：群密钥分发载荷（经 1:1 DR 会话，被移除者不可达） */
  | { v: 1; type: "group-keys"; payload: GroupKeysPayloadJson }
  /** 动态（FR-4.x，M3-S12）：好友圈密钥分发 / 动态评论（仅作者可见） */
  | { v: 1; type: "circle-keys"; momentKey: string }
  | { v: 1; type: "moment-comment"; cid: string; text: string };

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
const K_OPK_POOL = "opk-pool";
const K_MSG_SEQ = "msgseq";
const K_DEVICE_DK = "device-dk";
const K_DEVICE_CERT = "device-cert";
const K_MOMENT_KEY = "moment-key";
const SETTING_READ_RECEIPTS = "setting:read-receipts";
/** OPK 池目标规模与低水位（M2 计划 §3.1：低于水位自动补充）。 */
export const OPK_POOL_TARGET = 20;
export const OPK_POOL_LOW = 5;
/** 设备凭证有效期与提前续期窗口（M2-S10：默认 90 天，临期 7 天内自动续签）。 */
export const DEVICE_CERT_TTL = 90 * 24 * 3600_000;
const DEVICE_RENEW_AHEAD = 7 * 24 * 3600_000;
/** 对端设备集核对节流：发送路径每联系人至多每 60s 拉一次 KT 事件流。 */
const DEVICE_CHECK_INTERVAL = 60_000;
const contactKey = (did: string) => `contact:${did}`;
const sessionKey = (did: string) => `session:${did}`;
const deviceFpKey = (did: string) => `device-fp:${did}`;
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
  /** 本机设备（M2-S10）：DK-ed 签名密钥与 IK 签发的设备凭证 */
  dkEd!: KeyPair;
  deviceCert!: DeviceCertificate;

  /** did → 会话/联系人/消息（内存态；持久化镜像于 kv） */
  sessions = new Map<string, Session>();
  contacts = new Map<string, Contact>();
  messages = new Map<string, ChatMessage[]>();
  /** groupId → 群视角（状态/群秘密/发送密钥/序号；M3-S11） */
  groups = new Map<string, GroupView>();
  online = true;

  private cursors = new Map<string, number>();
  private msgSeq = 0;
  /** 本地持有私钥的 OPK 池（id → 密钥对；节点侧为对应公钥，M2-S9） */
  private opkPool = new Map<number, KeyPair>();
  /** 会话重建回调（KI-1：已知联系人新握手替换会话时上抛 UI 提示） */
  onSessionRebuilt: ((did: string) => void) | null = null;
  /** message.id → kv 键（回执更新重写旧消息时定位原键，避免写错序号） */
  private messageKeys = new Map<string, string>();
  /** 已确认发出 read 回执的 in 消息 id（幂等，防重复回执） */
  private readConfirmed = new Set<string>();
  private stopWs: (() => void) | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  /** 对端设备集核对的上次时间（发送路径节流，M2-S10） */
  private deviceCheckAt = new Map<string, number>();

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
    await m.ensureDevice();
    await m.ensureMomentKey();
    void m.distributeMomentKeys().catch(() => undefined); // 启动补发（网络失败下轮重试）
    return m;
  }

  /** FR-1.1 无感身份创建：生成 IK/DK/SPK/OPK 并持久化，全程无用户输入。 */
  static async createNew(deps: MessagingDeps): Promise<Messaging> {
    const m = new Messaging(deps);
    m.identity = createIdentity();
    await deps.kv.put(K_IDENTITY, utf8ToBytes(serializeIdentity(m.identity)));
    // 预密钥材料（M2-S9：SPK + OPK 池）
    m.spk = generateX25519KeyPair();
    const opk = generateX25519KeyPair();
    m.opk = { ...opk, id: deriveOpkId(opk.publicKey) };
    m.opkPool = new Map([[m.opk.id, { publicKey: opk.publicKey, privateKey: opk.privateKey }]]);
    for (let i = 1; i < OPK_POOL_TARGET; i++) {
      const k = generateX25519KeyPair();
      m.opkPool.set(deriveOpkId(k.publicKey), k);
    }
    await deps.kv.put(K_SPK, utf8ToBytes(JSON.stringify(kpToJson(m.spk))));
    await deps.kv.put(K_OPK, utf8ToBytes(JSON.stringify({ id: m.opk.id, ...kpToJson(opk) })));
    await m.persistOpkPool();
    await m.ensureDevice();
    return m;
  }

  // ----- 本机设备（M2-S10 FR-1.4） -----

  /** 本机设备标识（设备凭证中的 dkId）。 */
  get deviceDkId(): string {
    return this.deviceCert.dkId;
  }

  /**
   * 确保本机设备凭证可用：dk 不存在则生成；凭证缺失/临期（<7 天）则重签；
   * 并向节点登记（网络失败不致命，下次启动重试——bundle 上传前置条件，见 setUsername）。
   */
  async ensureDevice(): Promise<void> {
    const dkRaw = await this.deps.kv.get(K_DEVICE_DK);
    if (dkRaw) {
      this.dkEd = kpFromJson(JSON.parse(bytesToUtf8(dkRaw)) as StoredKeyPair);
    } else {
      this.dkEd = generateEd25519KeyPair();
      await this.deps.kv.put(K_DEVICE_DK, utf8ToBytes(JSON.stringify(kpToJson(this.dkEd))));
    }

    let cert: DeviceCertificate | null = null;
    const certRaw = await this.deps.kv.get(K_DEVICE_CERT);
    if (certRaw) {
      try {
        const parsed = decodeDeviceCertificateJson(bytesToUtf8(certRaw));
        // 复用条件：凭证属当前 dk、验签通过、未临期
        if (parsed.dkId === base58Encode(this.dkEd.publicKey) && verifyDeviceCertificate(parsed)) {
          cert = parsed;
        }
      } catch {
        cert = null;
      }
    }
    if (!cert || cert.expiresAt < Date.now() + DEVICE_RENEW_AHEAD) {
      cert = makeDeviceCertificate(
        this.identity.ikEd.privateKey,
        this.identity.did,
        this.dkEd.publicKey,
        this.deriveDeviceLabel(),
        DEVICE_CERT_TTL,
      );
      await this.deps.kv.put(K_DEVICE_CERT, utf8ToBytes(encodeDeviceCertificateJson(cert)));
    }
    this.deviceCert = cert;

    try {
      await this.deps.api.putDevice(this.identity.did, JSON.parse(encodeDeviceCertificateJson(cert)));
    } catch {
      /* 节点不可达：登记延后（凭证已持久化，bundle 上传前会重试） */
    }
  }

  /** 设备描述（注册时一次生成；从 UA 提取浏览器与平台的可读摘要）。 */
  private deriveDeviceLabel(): string {
    const ua = navigator.userAgent;
    const browser = /Edg\//.test(ua)
      ? "Edge"
      : /Firefox\//.test(ua)
        ? "Firefox"
        : /Chrome\//.test(ua)
          ? "Chrome"
          : /Safari\//.test(ua)
            ? "Safari"
            : "浏览器";
    const platform = /Windows/.test(ua)
      ? "Windows"
      : /Mac OS/.test(ua)
        ? "macOS"
        : /Android/.test(ua)
          ? "Android"
          : /iPhone|iPad/.test(ua)
            ? "iOS"
            : /Linux/.test(ua)
              ? "Linux"
              : "未知系统";
    return `${platform} · ${browser}`;
  }

  /** 我名下的设备列表（KT 事件流本地折叠 + 逐事件验签，SR-5：不采信节点视图）。 */
  async listMyDevices(): Promise<DeviceView[]> {
    return (await this.fetchDeviceFold(this.identity.did)).devices;
  }

  /** 吊销我名下的一台设备（IK 签名吊销声明；节点停发其预密钥材料 + KT 锚定）。 */
  async revokeMyDevice(dkId: string): Promise<void> {
    const revocation = makeDeviceRevocation(this.identity.ikEd.privateKey, this.identity.did, dkId);
    await this.deps.api.revokeDevice(
      this.identity.did,
      dkId,
      JSON.parse(encodeDeviceRevocationJson(revocation)) as Record<string, unknown>,
    );
    this.emit();
  }

  /** 拉取 DID 的 KT 事件流并本地折叠为设备状态（发送路径核对与设备管理共用）。 */
  private async fetchDeviceFold(did: string): Promise<ReturnType<typeof foldDeviceEvents>> {
    const raw = await this.deps.api.getKtEvents(did);
    const events: KTEvent[] = raw.map((e) => ({
      did: e.did,
      type: e.type as KTEvent["type"],
      index: e.index,
      payload: fromBase64(e.payload),
    }));
    return foldDeviceEvents(events);
  }

  /**
   * KT 日志完整性核验（加固批次 ④，SR-5）：拉取我名下的全部 KT 事件，
   * 逐事件向节点索取 Merkle 包含性证明并本地验签对当前根。
   * 检测：事件被删/篡改、根与日志不一致。单节点核验防不了"整体重造日志"
   * （那需要 M4 多副本交叉核验），边界如实登记。
   */
  async verifyKTIntegrity(): Promise<{ ok: boolean; checked: number; detail: string }> {
    try {
      const raw = await this.deps.api.getKtEvents(this.identity.did);
      if (raw.length === 0) return { ok: true, checked: 0, detail: "尚无 KT 事件（未注册用户名/设备）" };
      const { root } = await this.deps.api.getKtRoot();
      let checked = 0;
      for (const e of raw) {
        const { proof } = await this.deps.api.getKtProof(e.index);
        const event: KTEvent = {
          did: e.did,
          type: e.type as KTEvent["type"],
          index: e.index,
          payload: fromBase64(e.payload),
        };
        const { ktVerifyInclusion } = await import("@mychat/core");
        if (!ktVerifyInclusion(event, proof, root)) {
          return { ok: false, checked, detail: `事件 #${e.index}（${e.type}）包含性验证失败：日志可能被篡改或损坏` };
        }
        checked += 1;
      }
      return { ok: true, checked, detail: `${checked} 条事件的包含性证明全部验证通过` };
    } catch (err) {
      return { ok: false, checked: 0, detail: err instanceof Error ? `核验失败：${err.message}` : "核验失败" };
    }
  }

  /** 持久化本地 OPK 池。 */
  private async persistOpkPool(): Promise<void> {
    const arr = [...this.opkPool.entries()].map(([id, kp]) => ({ id, ...kpToJson(kp) }));
    await this.deps.kv.put(K_OPK_POOL, utf8ToBytes(JSON.stringify(arr)));
  }

  /** 向节点补充上传本地池中尚未登记的 OPK（bundle 主 OPK 由 setUsername 上传）。 */
  async uploadOpkPool(): Promise<void> {
    await this.deps.api.addOpks(
      this.identity.did,
      [...this.opkPool.entries()].map(([id, kp]) => ({ id, public: base58Encode(kp.publicKey) })),
      this.deviceDkId,
    );
  }

  /** 池低水位时自动补充至目标规模（accept 消耗后调用）。 */
  private async topUpOpkPool(): Promise<void> {
    if (this.opkPool.size >= OPK_POOL_LOW) return;
    const batch = [];
    while (this.opkPool.size < OPK_POOL_TARGET) {
      const k = generateX25519KeyPair();
      const id = deriveOpkId(k.publicKey);
      if (this.opkPool.has(id)) continue;
      this.opkPool.set(id, k);
      batch.push({ id, public: base58Encode(k.publicKey) });
    }
    await this.persistOpkPool();
    await this.deps.api.addOpks(this.identity.did, batch, this.deviceDkId);
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
    // OPK 池（M2-S9）；旧版本仅单 OPK 时迁移入池
    const poolRaw = await this.deps.kv.get(K_OPK_POOL);
    if (poolRaw) {
      const arr = JSON.parse(bytesToUtf8(poolRaw)) as ({ id: number } & StoredKeyPair)[];
      this.opkPool = new Map(arr.map((o) => [o.id, kpFromJson(o)]));
    } else if (this.opk) {
      this.opkPool = new Map([[this.opk.id, { publicKey: this.opk.publicKey, privateKey: this.opk.privateKey }]]);
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
    // 群视角恢复（M3-S11）：kv 存 GroupKeysPayloadJson，加载即重建可解密状态
    for (const key of await this.deps.kv.keys("groupview:")) {
      const raw = await this.deps.kv.get(key);
      if (!raw) continue;
      try {
        const view = applyGroupKeysPayload(JSON.parse(bytesToUtf8(raw)) as GroupKeysPayload);
        this.groups.set(view.state.groupId, view);
      } catch {
        /* 损坏条目跳过（不阻塞其余群恢复） */
      }
    }
    for (const did of this.contacts.keys()) {
      const sessionRaw = await this.deps.kv.get(sessionKey(did));
      if (sessionRaw) this.sessions.set(did, deserializeSession(bytesToUtf8(sessionRaw)));
      await this.loadMessages(did);
    }
    for (const groupId of this.groups.keys()) {
      await this.loadMessages(groupChatKey(groupId));
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

  /**
   * 与节点对账（启动时调用；M3 修复"重启后半可用"问题）：
   * - 设备凭证重登记（ensureDevice，幂等）；
   * - 用户名记录缺失或被改 → 重新注册（被他人抢注则提示更换）；
   * - bundle 与 OPK 池全量重传（幂等覆盖）；
   * - 恢复公告缺失（节点重启/清空）→ 依本地 wrap 密文副本重传块并重签公告
   *   （不重新 setup：RK 与守护者手里的旧分片保持有效）。
   * 返回需要 UI 呈现的提示（null = 无异常）；失败不抛出（刷新页面即重试）。
   */
  async reconcileWithNode(): Promise<string | null> {
    const notices: string[] = [];
    await this.ensureDevice();

    // 1) 用户名
    if (this.myName !== null) {
      let needRegister = false;
      try {
        const existing = await this.deps.api.resolve(this.myName);
        needRegister = existing === null || existing.did !== this.identity.did;
      } catch {
        needRegister = true;
      }
      if (needRegister) {
        try {
          const record = makeUserNameRecord(this.identity.ikEd.privateKey, this.myName, this.identity.did, 0);
          await this.deps.api.register(record);
          notices.push(`节点数据已重置，用户名「${this.myName}」已自动重新登记`);
        } catch {
          notices.push(`用户名「${this.myName}」重新登记失败（可能已被他人占用），请在"我"页重新设置用户名`);
        }
      }
    }

    // 2) bundle + OPK 池（新好友能找到我的前提）
    if (this.spk !== undefined && this.opk !== undefined) {
      try {
        this.opk.id = deriveOpkId(this.opk.publicKey);
        await this.deps.api.putBundle(this.identity.did, encodePreKeyBundle(this.issueBundle()), this.deviceDkId);
        await this.uploadOpkPool();
      } catch {
        notices.push("预密钥材料重新上传失败（新好友暂时无法联系你），请刷新页面重试");
      }
    }

    // 3) 恢复公告（凭本地 wrap 副本重传 + 重签）
    const self = await this.getRecoverySelf();
    if (self?.wrapCipher !== undefined) {
      try {
        const remote = await this.deps.api.getRecoveryAnnouncement(this.identity.did).catch(() => null);
        if (remote === null) {
          const wrap = base58Decode(self.wrapCipher);
          await this.deps.api.putBlock(self.wrapCid, wrap);
          const { makeRecoveryAnnouncement } = await import("@mychat/core");
          const announcement = makeRecoveryAnnouncement(this.identity, self.wrapCid, self.threshold, self.guardians);
          await this.deps.api.putRecoveryAnnouncement(this.identity.did, {
            did: announcement.did,
            wrapCid: announcement.wrapCid,
            threshold: announcement.threshold,
            guardians: announcement.guardians,
            signature: toBase64(announcement.signature),
          });
          notices.push("恢复公告已重新发布到节点");
        }
      } catch {
        /* 公告对账失败不影响主流程（下次启动重试） */
      }
    }

    if (notices.length > 0) this.emit();
    return notices.length > 0 ? notices.join("；") : null;
  }

  /** 注册用户名并上传预密钥束；节点侧与客户端侧双重验签。 */
  async setUsername(name: string): Promise<void> {
    const record = makeUserNameRecord(this.identity.ikEd.privateKey, name, this.identity.did, 0);
    await this.deps.api.register(record);
    // 设备登记重试（M2-S10：bundle 上传的前置；ensureDevice 失败过的话此处补挂靠）
    await this.ensureDevice();
    // bundle：以 core 权威实现重派生 opkId（防本地持久化被篡改后不一致）
    this.opk.id = deriveOpkId(this.opk.publicKey);
    const bundle = this.issueBundle();
    await this.deps.api.putBundle(this.identity.did, encodePreKeyBundle(bundle), this.deviceDkId);
    await this.uploadOpkPool(); // M2-S9：其余池成员一并登记（挂靠本机设备槽位）
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
      // 新好友：分发我的好友圈密钥（对方的 key 由对方主动发来，M3-S12）
      void this.distributeMomentKeys().catch(() => undefined);
      this.emit();
      return null;
    } catch (err) {
      return err instanceof Error ? err.message : "添加失败";
    }
  }

  // ----- 群组（FR-6.1/6.2，M3-S11：Sender-Keys 1:1 扇出，M3 计划 §3） -----

  /** 群条目快照（UI 侧栏/群聊头）。 */
  groupSummaries(): GroupSummary[] {
    return [...this.groups.values()].map((v) => ({
      groupId: v.state.groupId,
      name: v.state.name,
      owner: v.state.owner,
      epoch: v.state.epoch,
      memberCount: v.state.members.length,
      amOwner: v.state.owner === this.identity.did,
    }));
  }

  /**
   * 建群并分发密钥：生成群状态（IK 签名）与 epoch-1 发送密钥集，
   * GroupKeysPayload 经各成员 1:1 DR 会话投递（节点只见群信箱伪地址与密文）。
   * 返回错误文案（null = 成功）。
   */
  async createGroupAndInvite(name: string, memberDids: string[]): Promise<string | null> {
    try {
      if (memberDids.length < 2) return "群组至少需要 2 位联系人（含你共 3 人）";
      for (const did of memberDids) {
        if (!this.sessions.has(did)) return "群成员必须是已建立会话的联系人";
      }
      const { state, groupSecret } = createGroup(this.identity.ikEd.privateKey, name, this.identity.did, memberDids);
      const senderKeys = generateSenderKeys(state.members.map((m) => m.did));
      this.groups.set(state.groupId, createGroupView(state, groupSecret, senderKeys));
      await this.persistGroupView(state.groupId);
      for (const did of state.members.map((m) => m.did)) {
        if (did === this.identity.did) continue;
        await this.sendGroupKeysTo(did, state.groupId);
      }
      await this.appendLocalMessage(groupChatKey(state.groupId), "out", `群「${name}」已创建，邀请已发送`, "handshake");
      this.restartRealtime();
      this.emit();
      return null;
    } catch (err) {
      return err instanceof Error ? err.message : "建群失败";
    }
  }

  /** 把某群当前 epoch 的密钥载荷经 1:1 会话投给指定成员。 */
  private async sendGroupKeysTo(memberDid: string, groupId: string): Promise<void> {
    const view = this.groups.get(groupId);
    const session = this.sessions.get(memberDid);
    if (!view || !session) throw new Error("群或会话不存在");
    const wire = sessionSend(
      session,
      utf8ToBytes(
        JSON.stringify({
          v: 1,
          type: "group-keys",
          payload: makeGroupKeysPayload(view.state, view.groupSecret, view.senderKeys) satisfies GroupKeysPayload,
        } satisfies SessionPayload),
      ),
    );
    const mailboxId = sessionMailbox(session, "send", Date.now());
    await this.deps.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
  }

  /** 消费 1:1 会话收到的群密钥载荷：验签、落库、订阅群信箱。 */
  private async handleGroupKeys(payload: GroupKeysPayload): Promise<void> {
    const view = applyGroupKeysPayload(payload);
    // 仅接受自己确为成员的群（防陌生人推送伪造群配置）
    if (!view.state.members.some((m) => m.did === this.identity.did)) return;
    const existed = this.groups.get(view.state.groupId);
    // epoch 必须前进（重放旧载荷无意义；载荷内状态已验签）
    if (existed && view.state.epoch <= existed.state.epoch) return;
    this.groups.set(view.state.groupId, view);
    await this.persistGroupView(view.state.groupId);
    if (!existed) {
      await this.appendLocalMessage(groupChatKey(view.state.groupId), "in", `已加入群「${view.state.name}」`, "handshake");
    } else {
      this.onGroupRotated?.(view.state.groupId, view.state.name);
    }
    this.restartRealtime();
    this.emit();
  }

  /** 群 epoch 轮换回调（成员变更后 UI 提示）。 */
  onGroupRotated: ((groupId: string, name: string) => void) | null = null;

  /** 群视角持久化（GroupKeysPayloadJson 形态，加载即恢复可解密状态）。 */
  private async persistGroupView(groupId: string): Promise<void> {
    const view = this.groups.get(groupId);
    if (!view) return;
    const payload = makeGroupKeysPayload(view.state, view.groupSecret, view.senderKeys);
    await this.deps.kv.put(`groupview:${groupId}`, utf8ToBytes(JSON.stringify(payload)));
  }

  /** 发送群文本消息（组内双层信封 → 群信箱）。 */
  async sendGroupMessage(groupId: string, text: string): Promise<void> {
    await this.sendGroupPayload(groupId, { v: 1, type: "chat", text }, "chat", text);
  }

  /** 发送群附件（随机 CK → CAS 块 → CID/CK 进组内密文，群成员可取）。 */
  async sendGroupAttachment(
    groupId: string,
    file: { data: Uint8Array; name: string; mime: string },
    kind: "image" | "file",
  ): Promise<void> {
    if (file.data.length > 8 * 1024 * 1024) throw new Error("附件超过 8MB 上限");
    const att = encryptAttachment(file.data);
    await this.deps.api.putBlock(att.cid, att.ciphertext);
    await this.sendGroupPayload(
      groupId,
      {
        v: 1,
        type: kind,
        cid: att.cid,
        contentKey: base58Encode(att.contentKey),
        nonce: base58Encode(att.nonce),
        name: file.name,
        size: file.data.length,
        mime: file.mime,
      },
      kind,
      file.name,
    );
  }

  private async sendGroupPayload(groupId: string, payload: SessionPayload, kind: MessageKind, text: string): Promise<void> {
    const view = this.groups.get(groupId);
    if (!view) throw new Error("群不存在");
    const mySk = view.senderKeys.get(this.identity.did);
    if (!mySk) throw new Error("缺少本群发送密钥（等待群主重新分发）");
    const index = view.sendIndex;
    const plaintext = utf8ToBytes(JSON.stringify(payload));
    const groupWire = sealGroupMessage(
      this.identity.ikEd.privateKey,
      this.identity.did,
      mySk,
      view.groupSecret,
      groupId,
      view.state.epoch,
      index,
      plaintext,
    );
    view.sendIndex = index + 1;
    const mailboxId = groupMailboxId(view.groupSecret, view.state.epoch);
    await this.deps.api.mailboxAppend(mailboxId, this.seal(groupWire, mailboxId));
    if (payload.type !== "receipt") {
      await this.appendLocalMessage(groupChatKey(groupId), "out", text, kind, payload);
    }
    this.emit();
  }

  /** 邀请成员（群主）：epoch+1 → 新 SK 集重分发全员（断读语义不含新成员的历史）。 */
  async addMemberToGroup(groupId: string, memberDid: string): Promise<string | null> {
    return await this.rotateGroup(groupId, (ik, state) => addGroupMember(ik, state, memberDid));
  }

  /** 移除成员（群主，FR-6.2 断读）：epoch+1 → 幸存成员重分发；被移除者不可达新面。 */
  async removeMemberFromGroup(groupId: string, memberDid: string): Promise<string | null> {
    return await this.rotateGroup(groupId, (ik, state) => removeGroupMember(ik, state, memberDid));
  }

  /** 成员变更统一路径：重签状态 → 重生成 SK → 分发幸存成员 → 刷新本地视角。 */
  private async rotateGroup(
    groupId: string,
    mutate: (ik: Uint8Array, state: GroupState) => GroupState,
  ): Promise<string | null> {
    try {
      const view = this.groups.get(groupId);
      if (!view) return "群不存在";
      if (view.state.owner !== this.identity.did) return "仅群主可管理成员";
      const nextState = mutate(this.identity.ikEd.privateKey, view.state);
      if (!verifyGroupState(nextState)) return "群状态重签失败";
      const newKeys = generateSenderKeys(nextState.members.map((m) => m.did));
      this.groups.set(groupId, createGroupView(nextState, view.groupSecret, newKeys));
      await this.persistGroupView(groupId);
      for (const member of nextState.members) {
        if (member.did === this.identity.did) continue;
        if (!this.sessions.has(member.did)) continue;
        await this.sendGroupKeysTo(member.did, groupId);
      }
      this.onGroupRotated?.(groupId, nextState.name);
      this.restartRealtime();
      this.emit();
      return null;
    } catch (err) {
      return err instanceof Error ? err.message : "群成员变更失败";
    }
  }

  /** 拉取全部群信箱（当前 epoch；epoch 轮换后旧信箱自然废弃）。 */
  private async pollGroups(): Promise<void> {
    for (const [groupId, view] of this.groups) {
      const mailboxId = groupMailboxId(view.groupSecret, view.state.epoch);
      const cursor = await this.cursorFor(mailboxId);
      const { envelopes, cursor: next } = await this.deps.api.mailboxFetch(mailboxId, cursor);
      for (const envelope of envelopes) {
        try {
          const groupWire = stripPadding(envelope.payload);
          const opened = openGroupMessage(view, groupWire);
          const parsed = JSON.parse(bytesToUtf8(opened.plaintext)) as SessionPayload;
          const chatKey = groupChatKey(groupId);
          if (parsed?.v === 1 && typeof parsed.type === "string") {
            if (parsed.type === "chat") {
              await this.appendLocalMessage(chatKey, "in", parsed.text, "chat", undefined, opened.senderDid);
            } else if (parsed.type === "image" || parsed.type === "file") {
              await this.appendLocalMessage(chatKey, "in", parsed.name, parsed.type, parsed, opened.senderDid);
            }
          }
        } catch {
          // 外层/内层解密失败、伪造签名、重放：安全丢弃（SR-4）
        }
      }
      await this.advanceCursor(mailboxId, next, envelopes.length > 0);
    }
  }

  // ----- 动态（FR-4.1/4.2/4.4，M3-S12：EDS-min 好友圈，M3 计划 §6） -----

  /** 我的好友圈密钥（base58；v1 不轮换，边界见 M3 计划 §6.1）。 */
  myMomentKey: string | null = null;

  /** 确保好友圈密钥存在（load/createNew 调用；缺失即生成）。 */
  async ensureMomentKey(): Promise<void> {
    if (this.myMomentKey !== null) return;
    const raw = await this.deps.kv.get(K_MOMENT_KEY);
    if (raw) {
      this.myMomentKey = bytesToUtf8(raw);
      return;
    }
    const key = base58Encode(generateMomentKey());
    this.myMomentKey = key;
    await this.deps.kv.put(K_MOMENT_KEY, utf8ToBytes(key));
  }

  /**
   * 把我的好友圈密钥发给联系人（加好友/启动补发/重置后全量重发共用）。
   * force=true 时对已持有旧密钥的联系人也重发（重置好友圈场景，加固批次 ③）。
   */
  async distributeMomentKeys(force = false): Promise<void> {
    await this.ensureMomentKey();
    for (const did of this.contacts.keys()) {
      const held = await this.deps.kv.get(`momentkey:${did}`);
      if (held !== undefined && !force) continue;
      const session = this.sessions.get(did);
      if (!session) continue;
      try {
        const wire = sessionSend(session, utf8ToBytes(JSON.stringify({ v: 1, type: "circle-keys", momentKey: this.myMomentKey! } satisfies SessionPayload)));
        const mailboxId = sessionMailbox(session, "send", Date.now());
        await this.deps.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
      } catch {
        /* 单个分发失败不阻塞其余（下轮补发） */
      }
    }
  }

  /**
   * 重置好友圈（加固批次 ③）：换发全新圈密钥并全量重发——旧密钥（含泄露情形）
   * 从此无法解密新日志；旧动态信箱随 feedId 变化自然废弃。本地缓存与好友端
   * 已缓存副本不受影响（FR-4.4 固有边界，重置不追溯删除）。
   */
  async resetMomentCircle(): Promise<void> {
    const fresh = base58Encode(generateMomentKey());
    this.myMomentKey = fresh;
    await this.deps.kv.put(K_MOMENT_KEY, utf8ToBytes(fresh));
    await this.distributeMomentKeys(true);
    this.emit();
  }

  /** 发布动态（文字 + 可选图片）：内容块独立密钥 → CAS → 日志条目（好友圈密钥加密）。 */
  async publishMoment(text: string, file?: { data: Uint8Array; name: string; mime: string }): Promise<void> {
    if (this.myMomentKey === null) throw new Error("好友圈未就绪");
    let attachment: MomentItem["attachment"];
    if (file) {
      if (file.data.length > 8 * 1024 * 1024) throw new Error("附件超过 8MB 上限");
      const img = encryptAttachment(file.data);
      await this.deps.api.putBlock(img.cid, img.ciphertext);
      attachment = { cid: img.cid, contentKey: base58Encode(img.contentKey), nonce: base58Encode(img.nonce), name: file.name, size: file.data.length, mime: file.mime };
    }
    const created = createMomentBlock({ v: 1, text, ...(attachment ? { attachment } : {}) });
    await this.deps.api.putBlock(created.cid, created.block);
    // 条目带 IK 签名（加固批次 ②）：好友端验签作者性，圈密钥持有者无法伪造
    const entry = makeMomentEntry(this.identity.ikEd.privateKey, {
      v: 1,
      type: "post",
      cid: created.cid,
      authorDid: this.identity.did,
      contentKey: created.contentKey,
      nonce: created.nonce,
      at: Date.now(),
    });
    const feedId = momentFeedId(base58Decode(this.myMomentKey));
    await this.deps.api.mailboxAppend(feedId, this.seal(sealFeedEntry(base58Decode(this.myMomentKey), entry), feedId));
    // 本地立即入时间线（作者视角）
    const item: MomentItem = { authorDid: this.identity.did, cid: created.cid, text, at: entry.at, ...(attachment ? { attachment } : {}), comments: [] };
    await this.deps.kv.put(`moment:${this.identity.did}:${created.cid}`, utf8ToBytes(JSON.stringify(item)));
    this.emit();
  }

  /** 删除动态（FR-4.4）：墓碑条目 + 物理删块；已缓存副本无法强制删除（如实披露）。 */
  async deleteMoment(cid: string): Promise<void> {
    if (this.myMomentKey === null) throw new Error("好友圈未就绪");
    const key = base58Decode(this.myMomentKey);
    const feedId = momentFeedId(key);
    const tombstone = makeMomentEntry(this.identity.ikEd.privateKey, {
      v: 1,
      type: "delete",
      cid,
      authorDid: this.identity.did,
      at: Date.now(),
    });
    await this.deps.api.mailboxAppend(feedId, this.seal(sealFeedEntry(key, tombstone), feedId));
    try {
      await this.deps.api.deleteBlock(cid);
    } catch {
      /* 块可能已被删（幂等） */
    }
    // 本地标记（缓存保留，UI 不渲染内容）
    const kvKey = `moment:${this.identity.did}:${cid}`;
    const raw = await this.deps.kv.get(kvKey);
    if (raw) {
      const item = JSON.parse(bytesToUtf8(raw)) as MomentItem;
      await this.deps.kv.put(kvKey, utf8ToBytes(JSON.stringify({ ...item, deleted: true })));
    }
    this.emit();
  }

  /** 评论好友动态（v1：经 1:1 会话仅作者可见，M3 计划 §6.5）。 */
  async commentMoment(authorDid: string, cid: string, text: string): Promise<void> {
    const session = this.sessions.get(authorDid);
    if (!session) throw new Error("与该作者的会话不存在");
    const wire = sessionSend(session, utf8ToBytes(JSON.stringify({ v: 1, type: "moment-comment", cid, text } satisfies SessionPayload)));
    const mailboxId = sessionMailbox(session, "send", Date.now());
    await this.deps.api.mailboxAppend(mailboxId, this.seal(wire, mailboxId));
    this.emit();
  }

  /** 时间线（本地聚合：我的 + 持有其好友圈密钥的联系人的动态，按时间倒序）。 */
  async listTimeline(): Promise<MomentItem[]> {
    const out: MomentItem[] = [];
    for (const key of await this.deps.kv.keys("moment:")) {
      const raw = await this.deps.kv.get(key);
      if (!raw) continue;
      try {
        out.push(JSON.parse(bytesToUtf8(raw)) as MomentItem);
      } catch {
        /* 损坏条目跳过 */
      }
    }
    return out.sort((a, b) => b.at - a.at);
  }

  /** 拉取全部好友的动态日志（时间线增量；post 取块解密，delete 应用墓碑）。 */
  private async pollMomentFeeds(): Promise<void> {
    for (const did of this.contacts.keys()) {
      const keyRaw = await this.deps.kv.get(`momentkey:${did}`);
      if (keyRaw === undefined) continue;
      const theirKey = base58Decode(bytesToUtf8(keyRaw));
      const feedId = momentFeedId(theirKey);
      const cursor = await this.cursorFor(feedId);
      const { envelopes, cursor: next } = await this.deps.api.mailboxFetch(feedId, cursor);
      for (const envelope of envelopes) {
        try {
          const entry = openFeedEntry(theirKey, stripPadding(envelope.payload));
          // 双重作者性断言：签名者即条目作者（open 内验签），且条目属于该日志的作者
          if (entry.authorDid !== did) continue;
          const kvKey = `moment:${did}:${entry.cid}`;
          if (entry.type === "delete") {
            const raw = await this.deps.kv.get(kvKey);
            if (raw) {
              const item = JSON.parse(bytesToUtf8(raw)) as MomentItem;
              await this.deps.kv.put(kvKey, utf8ToBytes(JSON.stringify({ ...item, deleted: true })));
            }
            continue;
          }
          if (entry.contentKey === undefined || entry.nonce === undefined) continue;
          // 幂等：重复条目跳过
          if (await this.deps.kv.get(kvKey)) continue;
          const block = await this.deps.api.getBlock(entry.cid);
          if (!block) continue; // 作者已物理删除（墓碑可能尚未拉到）
          const payload = openMomentBlock(block, entry.contentKey, entry.nonce);
          const item: MomentItem = {
            authorDid: did,
            cid: entry.cid,
            text: payload.text,
            at: entry.at,
            ...(payload.attachment ? { attachment: payload.attachment } : {}),
            comments: [],
          };
          await this.deps.kv.put(kvKey, utf8ToBytes(JSON.stringify(item)));
        } catch {
          // 非好友密文/篡改/块缺失：安全丢弃（SR-4 语义）
        }
      }
      await this.advanceCursor(feedId, next, envelopes.length > 0);
    }
  }

  // ----- 好友申请确认（M3 修复 FR-8.1：申请 → 通过/拒绝） -----

  /** 待确认申请列表（按时间倒序）。 */
  async listFriendRequests(): Promise<FriendRequestItem[]> {
    const out: FriendRequestItem[] = [];
    for (const key of await this.deps.kv.keys("friend-request:")) {
      const raw = await this.deps.kv.get(key);
      if (!raw) continue;
      try {
        const req = JSON.parse(bytesToUtf8(raw)) as FriendRequestStored;
        out.push({ fromDid: req.fromDid, name: req.name, note: req.note, at: req.at });
      } catch {
        /* 损坏条目跳过 */
      }
    }
    return out.sort((a, b) => b.at - a.at);
  }

  /** 通过申请：恢复随申请保存的会话、建立联系人、分发好友圈密钥。 */
  async acceptFriendRequest(fromDid: string): Promise<void> {
    const raw = await this.deps.kv.get(`friend-request:${fromDid}`);
    if (!raw) throw new Error("申请不存在（可能已处理）");
    const req = JSON.parse(bytesToUtf8(raw)) as FriendRequestStored;
    const session = deserializeSession(req.sessionWire);
    this.sessions.set(fromDid, session);
    this.contacts.set(fromDid, { did: fromDid, name: req.name ?? null, addedAt: Date.now() });
    await this.saveContact(fromDid);
    await this.saveSession(fromDid);
    await this.appendLocalMessage(fromDid, "in", req.note, "handshake");
    await this.deps.kv.delete(`friend-request:${fromDid}`);
    // 新好友：分发我的好友圈密钥（与主动加好友对齐，M3-S12）
    void this.distributeMomentKeys().catch(() => undefined);
    this.restartRealtime();
    this.emit();
  }

  /** 拒绝申请（静默丢弃：对方无感知，可再次申请）。 */
  async rejectFriendRequest(fromDid: string): Promise<void> {
    await this.deps.kv.delete(`friend-request:${fromDid}`);
    this.emit();
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
    // 导入环境视为一台新设备：重新生成 DK 并登记凭证（M2-S10）
    await this.ensureDevice();
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
      // wrapCipher 本地副本（M3 修复）：节点为内存态/被清空时，对账可重传块并重签公告
      utf8ToBytes(JSON.stringify({ wrapCid: setup.wrapCid, threshold, guardians: guardianDids, wrapCipher: base58Encode(setup.wrap) })),
    );
    this.emit();
    return { wrapCid: setup.wrapCid };
  }

  async getRecoverySelf(): Promise<{ wrapCid: string; threshold: number; guardians: string[]; wrapCipher?: string } | null> {
    const raw = await this.deps.kv.get("recovery-self");
    if (!raw) return null;
    return JSON.parse(bytesToUtf8(raw)) as { wrapCid: string; threshold: number; guardians: string[]; wrapCipher?: string };
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

  /** 恢复完成判定：收集数达门限后重组 RK → 解开身份包裹（v2：身份 + 用户名）。 */
  async tryFinishRecovery(
    ownerDid: string,
    wrapCid: string,
    threshold: number,
  ): Promise<{ identityJson: string; myName: string | null } | null> {
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

  /**
   * 恢复演练 v1（UX-2，M2 计划 §2 S9-⑦）：原机本地完整性检查。
   * 完整演练（守护者实际回传分片）依赖守护者在线配合，UI 引导另行提示。
   */
  async rehearseRecovery(): Promise<{ ok: boolean; checks: { name: string; ok: boolean; detail: string }[] }> {
    const checks: { name: string; ok: boolean; detail: string }[] = [];
    const self = await this.getRecoverySelf();
    checks.push({ name: "本地恢复设置存在", ok: self !== null, detail: self ? `门限 ${self.threshold}、守护者 ${self.guardians.length} 位` : "尚未设置紧急联系人" });
    if (!self) return { ok: false, checks };

    let announcement: Record<string, unknown> | null = null;
    try {
      announcement = await this.deps.api.getRecoveryAnnouncement(this.identity.did);
    } catch {
      announcement = null;
    }
    checks.push({ name: "恢复公告可获取", ok: announcement !== null, detail: announcement === null ? "节点上未找到公告" : "" });
    if (announcement) {
      let verified = false;
      try {
        const { verifyRecoveryAnnouncement } = await import("@mychat/core");
        verified = verifyRecoveryAnnouncement({
          did: String(announcement.did),
          wrapCid: String(announcement.wrapCid),
          threshold: Number(announcement.threshold),
          guardians: announcement.guardians as string[],
          // 公告 signature 以 base64 上节点（见 setupGuardians），读取须同编码
          signature: fromBase64(String(announcement.signature)),
        });
      } catch {
        verified = false;
      }
      checks.push({ name: "公告签名验证", ok: verified, detail: verified ? "" : "公告签名与身份不匹配" });
      const guardiansMatch =
        JSON.stringify((announcement.guardians as string[]) ?? []) === JSON.stringify(self.guardians);
      checks.push({ name: "守护者列表一致", ok: guardiansMatch, detail: guardiansMatch ? "" : "公告与本地设置不一致" });
    }
    let wrapOk = false;
    try {
      const wrap = await this.deps.api.getBlock(self.wrapCid);
      wrapOk = wrap !== null && wrap.length > 0;
    } catch {
      wrapOk = false;
    }
    checks.push({ name: "身份包裹块可达", ok: wrapOk, detail: wrapOk ? "" : "节点上无法取回包裹块" });
    // KT 日志完整性（加固批次 ④）：我名下事件的包含性证明逐条核验
    const kt = await this.verifyKTIntegrity();
    checks.push({ name: "KT 日志完整性", ok: kt.ok, detail: kt.ok ? kt.detail : kt.detail });
    for (const g of self.guardians) {
      const inContacts = this.contacts.has(g);
      checks.push({ name: `守护者会话有效（${g.slice(11, 22)}…）`, ok: inContacts, detail: inContacts ? "" : "该守护者不在联系人中，恢复时无法联系" });
    }
    return { ok: checks.every((c) => c.ok), checks };
  }

  // ----- 发送（FR-5.1 / FR-5.2 / FR-5.3 子集） -----

  async sendMessage(did: string, text: string): Promise<void> {
    await this.ensureSessionFresh(did); // M2-S10：对方设备集变化时先轮换会话
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
    await this.ensureSessionFresh(did);
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

  /**
   * 对端设备集新鲜度核对（M2-S10，吊销后对端密钥轮换的触发器）：
   * 发送路径节流（每联系人 60s）拉取对方 KT 事件流 → 本地折叠有效设备集 →
   * 与会话建立时的指纹比对；不一致即重握手轮换（S9 会话替换语义，对端收到提示）。
   * 节点不可达时不阻塞发送（旧会话仍可用）。
   */
  private async ensureSessionFresh(did: string): Promise<void> {
    const now = Date.now();
    if (now - (this.deviceCheckAt.get(did) ?? 0) < DEVICE_CHECK_INTERVAL) return;
    this.deviceCheckAt.set(did, now);
    let fingerprint: string;
    try {
      fingerprint = fingerprintDeviceIds(activeDeviceIds(await this.fetchDeviceFold(did)));
    } catch {
      return;
    }
    const stored = await this.deps.kv.get(deviceFpKey(did));
    await this.deps.kv.put(deviceFpKey(did), utf8ToBytes(fingerprint));
    // 首次记录（stored=undefined）只建档不轮换；变化才轮换
    if (stored !== undefined && bytesToUtf8(stored) !== fingerprint) {
      await this.rotateSession(did);
    }
  }

  /** 对端设备集变化：取对方当前有效设备的 bundle 重新握手（S9 替换语义），UI 提示轮换。 */
  private async rotateSession(did: string): Promise<void> {
    try {
      const bundleBytes = await this.deps.api.getBundle(did);
      if (!bundleBytes) return; // 对端暂无有效设备（全部吊销/过期）：保持旧会话
      const bundle = decodePreKeyBundle(bundleBytes);
      if (bundle.did !== did || !verifyPreKeyBundle(bundle)) return;
      const handshake: HandshakePayload = {
        v: 1,
        fromDid: this.identity.did,
        fromName: this.myName,
        note: "检测到你的设备状态变化，我已轮换会话密钥（自动重建，历史消息保留）",
      };
      const { session, wire } = initiateSession(this.identity, bundle, utf8ToBytes(JSON.stringify(handshake)));
      const envelope = this.seal(wire, discoveryInboxId(did));
      await this.deps.api.mailboxAppend(envelope.toPseudonym, envelope);
      this.sessions.set(did, session);
      await this.saveSession(did);
      this.onSessionRebuilt?.(did);
      this.restartRealtime();
    } catch {
      /* 轮换失败不阻塞发送（旧会话仍可用，下次核对再试） */
    }
  }

  /** 装信封：内层 wire → 填充（档位自适应）→ 信封（伪地址，FR-3.1/3.3）。 */
  private seal(wire: Uint8Array, mailboxId: string): Envelope {
    const padClass = padClassForLength(wire.length + 4);
    const padded = applyPadding(wire, padClass);
    return makeEnvelope({ epoch: Math.floor(Date.now() / EPOCH_MS), toPseudonym: mailboxId, padClass, payload: padded });
  }

  // ----- 接收（FR-5.1 在线直投 + 离线信箱） -----

  /** 拉取发现信箱 + 全部会话的接收信箱 + 全部群信箱 + 好友圈动态日志（三 epoch 窗口防轮换漏收）。 */
  async poll(): Promise<void> {
    try {
      await this.pollDiscovery();
      for (const did of this.contacts.keys()) {
        await this.pollSession(did);
      }
      await this.pollGroups();
      await this.pollMomentFeeds();
      this.online = true;
    } catch {
      this.online = false;
    }
    this.emit();
  }

  private async cursorFor(mailboxId: string): Promise<number> {
    return this.cursors.get(mailboxId) ?? 0;
  }

  /**
   * cursor 治理（M2-S9 KI-3）：内存始终推进；**仅当本轮拉到过内容才落库**，
   * 避免三 epoch 窗口轮换产生大量空信箱键导致本地存储膨胀。
   */
  private async advanceCursor(mailboxId: string, cursor: number, persist: boolean): Promise<void> {
    this.cursors.set(mailboxId, cursor);
    if (persist) {
      await this.deps.kv.put(cursorKey(mailboxId), utf8ToBytes(String(cursor)));
    }
  }

  private async pollDiscovery(): Promise<void> {
    const mailboxId = discoveryInboxId(this.identity.did);
    const cursor = await this.cursorFor(mailboxId);
    const { envelopes, cursor: next } = await this.deps.api.mailboxFetch(mailboxId, cursor);
    for (const envelope of envelopes) {
      await this.handleHandshake(envelope);
    }
    await this.advanceCursor(mailboxId, next, envelopes.length > 0);
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
      // M2-S9：以全池 OPK 参与接受（任一匹配即可）；成功后消耗对应 OPK 并低水位补充
      const opkPool = new Map([...this.opkPool.entries()].map(([id, kp]) => [id, kp]));
      const { session, plaintext } = acceptSession(this.identity, this.spk, opkPool, wire);
      const usedOpkId = msg.x3dh.opkId;
      if (this.opkPool.delete(usedOpkId)) {
        await this.persistOpkPool();
        void this.deps.api.consumeOpk(this.identity.did, usedOpkId, this.deviceDkId).catch(() => undefined);
        void this.topUpOpkPool().catch(() => undefined);
      }
      const handshake = JSON.parse(bytesToUtf8(plaintext)) as HandshakePayload;
      if (handshake.v !== 1 || typeof handshake.fromDid !== "string") return;

      // M3 修复（好友确认流）：已知好友的新握手沿用 S9 替换语义（设备变更/恢复场景）；
      // 陌生人首次握手完成密码学处理（accept + OPK 消耗，与 Signal 语义一致）后
      // 进入待确认队列——不自动成为好友，由用户通过/拒绝。
      const existed = this.contacts.has(handshake.fromDid);
      if (existed) {
        this.sessions.set(handshake.fromDid, session);
        await this.saveSession(handshake.fromDid);
        this.onSessionRebuilt?.(handshake.fromDid);
        this.restartRealtime();
        return;
      }
      await this.deps.kv.put(
        `friend-request:${handshake.fromDid}`,
        utf8ToBytes(
          JSON.stringify({
            fromDid: handshake.fromDid,
            name: handshake.fromName ?? null,
            note: handshake.note,
            sessionWire: serializeSession(session),
            at: Date.now(),
          } satisfies FriendRequestStored),
        ),
      );
      this.emit();
    } catch {
      // OPK 全部消耗/篡改等失败：忽略（陌生人重放握手被天然拒绝）
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
      await this.advanceCursor(mailboxId, next, envelopes.length > 0);
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
    if (payload.type === "group-keys") {
      // 群密钥分发（经 1:1 DR 会话）：验签后入群/刷新 epoch（M3-S11）
      await this.handleGroupKeys(payload.payload);
      return null;
    }
    if (payload.type === "circle-keys") {
      // 好友圈密钥（M3-S12）：经 1:1 DR 会话到达即发送者认证（重放被 DR 拒绝），
      // 支持好友随时换钥（重置好友圈，加固批次 ③）——总是接受最新
      if (typeof payload.momentKey === "string") {
        await this.deps.kv.put(`momentkey:${did}`, utf8ToBytes(payload.momentKey));
      }
      return null;
    }
    if (payload.type === "moment-comment") {
      // 动态评论（仅作者可见）：挂载到我的对应动态
      const kvKey = `moment:${this.identity.did}:${payload.cid}`;
      const raw = await this.deps.kv.get(kvKey);
      if (raw && typeof payload.text === "string") {
        const item = JSON.parse(bytesToUtf8(raw)) as MomentItem;
        item.comments.push({ fromDid: did, text: payload.text, at: Date.now() });
        await this.deps.kv.put(kvKey, utf8ToBytes(JSON.stringify(item)));
        this.emit();
      }
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

  /** 当前实时订阅的信箱面（推送订阅与 WS 面一致，M4-S15；轮换/新会话后重算）。 */
  realtimeMailboxes(): string[] {
    const mailboxes = [discoveryInboxId(this.identity.did)];
    for (const did of this.contacts.keys()) {
      const session = this.sessions.get(did);
      if (!session) continue;
      const now = Date.now();
      for (const at of [now, now + EPOCH_MS]) {
        mailboxes.push(sessionMailbox(session, "recv", at));
      }
    }
    for (const view of this.groups.values()) {
      mailboxes.push(groupMailboxId(view.groupSecret, view.state.epoch));
    }
    return mailboxes;
  }

  startRealtime(): void {
    this.stopRealtime();
    const mailboxes = this.realtimeMailboxes();
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
    if (this.stopWs) {
      this.startRealtime();
      // 信箱面变化同步到离线推送订阅（M4-S15；fire-and-forget）
      void import("./push").then(({ updatePushMailboxes }) =>
        updatePushMailboxes(this.deps.api, this.realtimeMailboxes()),
      );
    }
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
    senderDid?: string,
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
      ...(senderDid ? { senderDid } : {}),
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
