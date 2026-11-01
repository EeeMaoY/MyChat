/**
 * Registry（目录）实现：用户名 → DID 映射 + 预密钥束/OPK 池分发（协议接口见 @mychat/core）。
 *
 * 信任边界（设计报告 §2.3）：节点验证记录签名后仅作"防垃圾准入"，
 * 映射的密码学可信性由客户端自行验签（SR-5）——节点拒绝无效记录，
 * 但客户端永远不因"节点接受了"而采信。
 */
import type { UserNameRecord } from "@mychat/core";
import {
  base58Decode,
  decodePreKeyBundle,
  encodePreKeyBundle,
  verifyUserNameRecord,
} from "@mychat/core";

export interface RegistryStore {
  records: Map<string, UserNameRecord>;
}

export function createRegistryStore(): RegistryStore {
  return { records: new Map() };
}

/** 注册结果：节点侧验证（签名、DID 格式、重名）全部通过才落库。 */
export function registerRecord(store: RegistryStore, record: UserNameRecord): { ok: true } | { ok: false; error: string } {
  const name = record.name;
  if (!name || name.length > 64) {
    return { ok: false, error: "用户名长度非法（1-64 字符）" };
  }
  // 用户名白名单：字母数字下划线与连字符（M0 简化约束，协议规范 S4 定稿）
  if (!/^[A-Za-z0-9_-]+$/.test(name)) {
    return { ok: false, error: "用户名仅允许字母、数字、下划线与连字符" };
  }
  if (!verifyUserNameRecord(record)) {
    return { ok: false, error: "用户名记录签名验证失败（记录未被该 DID 的 IK 签名）" };
  }
  if (store.records.has(name)) {
    return { ok: false, error: "用户名已被占用" };
  }
  store.records.set(name, record);
  return { ok: true };
}

export function resolveName(store: RegistryStore, name: string): UserNameRecord | undefined {
  return store.records.get(name);
}

/**
 * 预密钥束分发（Registry 角色的 M2 扩展，设计报告 §5.2 + M2 计划 §3.1）：
 * - bundle 主体（IK-x/SPK 材料 + 签名）按 DID 存"当前版本"；
 * - OPK 池独立存储；GET 时节点从池中挑一个未发出的 OPK 组装进 bundle 返回，
 *   返回即标记已发（服务端一次性语义，Signal 规范）；
 * - 响应方 accept 成功后经 DELETE 确认消耗；池空时复用已发 OPK（一次性退化为
 *   已知边界，协议规范 §10）。
 */
export interface BundleStore {
  /** did → 编码 bundle（模板，含最近一次上传的 OPK 字段——分发时会被池中 OPK 替换） */
  bundles: Map<string, Uint8Array>;
  /** did → (opkId → opkPublic base58) */
  opkPools: Map<string, Map<number, string>>;
  /** did → 已随 bundle 发出、尚未被 accept 确认消耗的 opkId 集 */
  issued: Map<string, Set<number>>;
}

export function createBundleStore(): BundleStore {
  return { bundles: new Map(), opkPools: new Map(), issued: new Map() };
}

export function putBundle(store: BundleStore, did: string, bundle: Uint8Array): void {
  if (bundle.length === 0 || bundle.length > 1024) throw new Error("bundle 长度非法");
  store.bundles.set(did, bundle);
}

/** 上传 OPK 入池（幂等；池上限 256，防滥用）。 */
export function putOpks(store: BundleStore, did: string, opks: { id: number; public: string }[]): void {
  let pool = store.opkPools.get(did);
  if (!pool) {
    pool = new Map();
    store.opkPools.set(did, pool);
  }
  for (const opk of opks) {
    if (!Number.isInteger(opk.id) || opk.id < 0) throw new Error("opkId 非法");
    if (typeof opk.public !== "string" || opk.public.length === 0 || opk.public.length > 128) {
      throw new Error("opk 公钥非法");
    }
    if (pool.size >= 256 && !pool.has(opk.id)) throw new Error("OPK 池已满");
    pool.set(opk.id, opk.public);
  }
}

export interface AssembledBundle {
  encoded: Uint8Array;
  /** 本次分发使用的 OPK（池空时为 null，bundle 保留模板 OPK 字段） */
  usedOpkId: number | null;
}

/** 组装分发：模板 + 池中一个未发出的 OPK；返回即标记已发。 */
export function assembleBundle(store: BundleStore, did: string): AssembledBundle | undefined {
  const template = store.bundles.get(did);
  if (!template) return undefined;
  const pool = store.opkPools.get(did);
  const issued = store.issued.get(did) ?? new Set<number>();
  if (!store.issued.has(did)) store.issued.set(did, issued);

  let usedOpkId: number | null = null;
  let assembled = template;
  if (pool && pool.size > 0) {
    const fresh = [...pool.entries()].find(([id]) => !issued.has(id));
    const [opkId, opkPublic] = fresh ?? [...pool.entries()][0]!;
    try {
      const decoded = decodePreKeyBundle(template);
      // 公钥字段为 base58 文本 → 字节
      assembled = encodePreKeyBundle({ ...decoded, opkId, opkPublic: base58Decode(opkPublic) });
      usedOpkId = opkId;
      issued.add(opkId);
    } catch {
      // 模板解码失败（脏数据）：原样返回
      assembled = template;
    }
  }
  return { encoded: assembled, usedOpkId };
}

/** 响应方 accept 成功后的消耗确认：从池与 issued 中移除。 */
export function consumeOpk(store: BundleStore, did: string, opkId: number): boolean {
  const pool = store.opkPools.get(did);
  const issued = store.issued.get(did);
  const had = pool?.delete(opkId) ?? false;
  issued?.delete(opkId);
  return had;
}

/** 池水位（客户端低水位补充用）。 */
export function opkPoolStats(store: BundleStore, did: string): { available: number; issued: number; poolKeys: number[]; issuedKeys: number[] } {
  const pool = store.opkPools.get(did);
  const issued = store.issued.get(did);
  const issuedKeys = issued ? [...issued] : [];
  const issuedCount = issuedKeys.filter((id) => pool?.has(id)).length;
  return {
    available: (pool?.size ?? 0) - issuedCount,
    issued: issuedCount,
    poolKeys: pool ? [...pool.keys()] : [],
    issuedKeys,
  };
}

