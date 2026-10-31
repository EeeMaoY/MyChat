/**
 * Registry（目录）实现：用户名 → DID 映射（协议接口见 @mychat/core）。
 *
 * 信任边界（设计报告 §2.3）：节点验证记录签名后仅作"防垃圾准入"，
 * 映射的密码学可信性由客户端自行验签（SR-5）——节点拒绝无效记录，
 * 但客户端永远不因"节点接受了"而采信。
 */
import type { UserNameRecord } from "@mychat/core";
import { verifyUserNameRecord } from "@mychat/core";

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
 * 预密钥束分发表（Registry 角色的 M0 扩展，设计报告 §5.2）：
 * bundle 经节点验签后按 DID 存取——"任何人可读的公开身份材料"。
 * 存储键为 DID（每用户当前 bundle），bundle 轮换与历史版本为 M1。
 */
export interface BundleStore {
  bundles: Map<string, Uint8Array>;
}

export function createBundleStore(): BundleStore {
  return { bundles: new Map() };
}

export function putBundle(store: BundleStore, did: string, bundle: Uint8Array): void {
  // CID 语义留给客户端校验；节点只做定长防护（编码 251B v1，留余量）
  if (bundle.length === 0 || bundle.length > 1024) throw new Error("bundle 长度非法");
  store.bundles.set(did, bundle);
}

