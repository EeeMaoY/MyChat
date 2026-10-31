/**
 * 服务域四接口 —— 协议边界 v0.1（M0 冻结，见 docs/MVP范围与里程碑计划.md §5.2）
 *
 * client 与 node 之间只经这些接口 + 信封协议通信，任何第三方可按接口
 * 独立实现并部署自己的节点（ADR-11：单体部署形态，协议边界分离）。
 *
 * 术语对应《产品设计报告》§2.3：
 *   Relay    中继池（在线密文包投递）
 *   Storage  存储节点（信箱与加密块）
 *   Registry 目录（用户名 → DID 映射）
 *   KTLog    密钥透明日志（映射变更历史，v0 为 append-only 事件日志）
 */

/** 信封：中继可见层（《产品设计报告》§11.1 的 M0 子集） */
export interface Envelope {
  /** 协议版本（NFR-10：版本化与协商） */
  version: string;
  /** epoch：伪地址轮换周期，接收端用于防重放 */
  epoch: number;
  /** 目标信箱伪地址（每会话每 epoch 派生；不含收发双方 DID 明文） */
  toPseudonym: string;
  /** 填充档位：0=256B / 1=1KB / 2=16KB / 3=128KB（FR-3.3 时空模式混淆） */
  padClass: 0 | 1 | 2 | 3;
  /** AEAD 随机数 */
  nonce: Uint8Array;
  /** 外层 AEAD 密文负载（内层为端到端会话密文，中继不可读） */
  payload: Uint8Array;
}

/** 中继池：在线密文包投递。中继只见伪地址 → 伪地址（SR-2）。 */
export interface IRelay {
  /** 订阅本端信箱伪地址上的来包（伪地址按 epoch 轮换，由调用方管理重订阅） */
  subscribe(mailboxId: string, onEnvelope: (envelope: Envelope) => void): Promise<void>;
  send(envelope: Envelope): Promise<void>;
}

/** 存储节点：加密块与离线信箱。仅见密文（SR-1），不可静默替换（CAS 完整性）。 */
export interface IStorage {
  putBlock(cid: string, ciphertext: Uint8Array): Promise<void>;
  getBlock(cid: string): Promise<Uint8Array | undefined>;
  mailboxAppend(mailboxId: string, envelope: Envelope): Promise<void>;
  /** 按 cursor 增量取回信箱密文（发送顺序）；返回取回的 envelopes 与新 cursor */
  mailboxFetch(mailboxId: string, cursor?: number): Promise<{ envelopes: Envelope[]; cursor: number }>;
}

/** Registry 记录：用户名是 IK 上的一层别名，映射由用户 IK 签名（《产品设计报告》§4.1） */
export interface UserNameRecord {
  name: string;
  did: string;
  /** IK 签名，覆盖 (name, did, ktIndex)；客户端验签后才可采信（SR-5） */
  signature: Uint8Array;
  /** 对应 KT 日志序号 */
  ktIndex: number;
}

/** 目录：用户名 → DID 映射。不可伪造映射（签名 + KT 锚定），不可做登录/鉴权裁决。 */
export interface IRegistry {
  register(record: UserNameRecord): Promise<void>;
  resolve(name: string): Promise<UserNameRecord | undefined>;
}

/** KT 日志事件（v0：append-only 事件序列；Merkle 包含性/一致性证明 M1 完整化，FR-1.6） */
export interface KTEvent {
  did: string;
  type: "register" | "revoke" | "device-add" | "device-revoke";
  /** 事件负载（按 type 定义的编码，S4 协议规范定稿） */
  payload: Uint8Array;
  /** 全局单调递增序号 */
  index: number;
}

/** 密钥透明日志：映射变更历史可审计，静默删改可被客户端核验发现（SR-5）。 */
export interface IKTLog {
  append(event: Omit<KTEvent, "index">): Promise<KTEvent>;
  list(did: string): Promise<KTEvent[]>;
}
