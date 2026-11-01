/**
 * Registry（目录）实现：用户名 → DID 映射 + 预密钥束/OPK 池分发（协议接口见 @mychat/core）。
 *
 * 信任边界（设计报告 §2.3）：节点验证记录签名后仅作"防垃圾准入"，
 * 映射的密码学可信性由客户端自行验签（SR-5）——节点拒绝无效记录，
 * 但客户端永远不因"节点接受了"而采信。
 *
 * M2-S10 多设备：bundle 与 OPK 池均按设备（dkId）分槽存储；分发的设备选择
 * 由调用方提供有效设备集（DeviceRegistry 折叠），节点内做确定性 round-robin——
 * 多设备在线时联系人分发自然负载均衡，吊销设备的槽位随吊销一并删除。
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
 * - bundle 主体（IK-x/SPK 材料 + 签名）按 (did, dkId) 存"当前版本"；
 * - OPK 池独立存储且按设备分槽；GET 时节点从有效设备中轮询挑一台、再从其池中
 *   挑一个未发出的 OPK 组装进 bundle 返回，返回即标记已发（服务端一次性语义）；
 * - 响应方 accept 成功后经 DELETE 确认消耗；池空时复用已发 OPK（一次性退化为
 *   已知边界，协议规范 §10）；
 * - 吊销设备时调用方删除其槽位（dropDeviceMaterials），分发自动落到其余设备。
 */
export interface BundleStore {
  /** did → (dkId → 编码 bundle 模板，含最近一次上传的 OPK 字段——分发时会被池中 OPK 替换) */
  bundles: Map<string, Map<string, Uint8Array>>;
  /** did → (dkId → (opkId → opkPublic base58)) */
  opkPools: Map<string, Map<string, Map<number, string>>>;
  /** did → (dkId → 已随 bundle 发出、尚未被 accept 确认消耗的 opkId 集) */
  issued: Map<string, Map<string, Set<number>>>;
  /** did → 上次分发的 dkId（确定性 round-robin 指针） */
  dispatchCursor: Map<string, string>;
}

export function createBundleStore(): BundleStore {
  return {
    bundles: new Map(),
    opkPools: new Map(),
    issued: new Map(),
    dispatchCursor: new Map(),
  };
}

/** did → (dkId → 容器) 的三层取用：返回该设备名下的容器，不存在则按 create 新建。 */
function deviceSlot<V>(outer: Map<string, Map<string, V>>, did: string, dkId: string, create: () => V): V {
  let inner = outer.get(did);
  if (!inner) {
    inner = new Map();
    outer.set(did, inner);
  }
  let slot = inner.get(dkId);
  if (!slot) {
    slot = create();
    inner.set(dkId, slot);
  }
  return slot;
}

function devicePool(store: BundleStore, did: string, dkId: string): Map<number, string> {
  return deviceSlot(store.opkPools, did, dkId, () => new Map());
}

function deviceIssued(store: BundleStore, did: string, dkId: string): Set<number> {
  return deviceSlot(store.issued, did, dkId, () => new Set());
}

export function putBundle(store: BundleStore, did: string, dkId: string, bundle: Uint8Array): void {
  if (bundle.length === 0 || bundle.length > 1024) throw new Error("bundle 长度非法");
  let inner = store.bundles.get(did);
  if (!inner) {
    inner = new Map();
    store.bundles.set(did, inner);
  }
  inner.set(dkId, bundle);
}

/** 上传 OPK 入指定设备的池（幂等；每设备池上限 256，防滥用）。 */
export function putOpks(store: BundleStore, did: string, dkId: string, opks: { id: number; public: string }[]): void {
  const pool = devicePool(store, did, dkId);
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
  /** 本次分发命中的设备 */
  device: string | null;
}

/**
 * 组装分发：在有效设备集内确定性轮询选一台（按 issuedAt 排序、指针推进），
 * 再从该设备池中挑一个未发出的 OPK；返回即标记已发。
 * activeDevices 为空或无任何设备槽位时返回 undefined（404 语义）。
 */
export function assembleBundle(
  store: BundleStore,
  did: string,
  activeDevices: string[],
): AssembledBundle | undefined {
  const deviceBundles = store.bundles.get(did);
  if (!deviceBundles || deviceBundles.size === 0) return undefined;
  const candidates = activeDevices.filter((dkId) => deviceBundles.has(dkId));
  if (candidates.length === 0) return undefined;

  const last = store.dispatchCursor.get(did);
  const index = last ? (candidates.indexOf(last) + 1) % candidates.length : 0;
  const device = candidates[index]!;
  store.dispatchCursor.set(did, device);

  const template = deviceBundles.get(device)!;
  const pool = devicePool(store, did, device);
  const issued = deviceIssued(store, did, device);

  let usedOpkId: number | null = null;
  let assembled = template;
  if (pool.size > 0) {
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
  return { encoded: assembled, usedOpkId, device };
}

/** 响应方 accept 成功后的消耗确认：从设备池与 issued 中移除。 */
export function consumeOpk(store: BundleStore, did: string, dkId: string, opkId: number): boolean {
  const pool = devicePool(store, did, dkId);
  const issued = deviceIssued(store, did, dkId);
  const had = pool.delete(opkId);
  issued.delete(opkId);
  return had;
}

/** 设备池水位（客户端低水位补充用）。 */
export function opkPoolStats(
  store: BundleStore,
  did: string,
  dkId: string,
): { available: number; issued: number; poolKeys: number[]; issuedKeys: number[] } {
  const pool = devicePool(store, did, dkId);
  const issued = deviceIssued(store, did, dkId);
  const issuedKeys = [...issued].filter((id) => pool.has(id));
  return {
    available: pool.size - issuedKeys.length,
    issued: issuedKeys.length,
    poolKeys: [...pool.keys()],
    issuedKeys,
  };
}

/** 吊销联动：删除该设备的 bundle 模板与 OPK 池（停发该设备的所有预密钥材料）。 */
export function dropDeviceMaterials(store: BundleStore, did: string, dkId: string): void {
  store.bundles.get(did)?.delete(dkId);
  store.opkPools.get(did)?.delete(dkId);
  store.issued.get(did)?.delete(dkId);
}
