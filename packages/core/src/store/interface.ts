/**
 * 本地持久化抽象（FR-7.1 本地优先：设备是数据的权威副本）。
 *
 * M0 采用最小 KV 语义：身份、会话状态、联系人、消息历史均以
 * 序列化字节 + 结构化键存放。上层自行约定键空间，例如：
 *   identity          → 本机身份
 *   contact:<did>     → 联系人
 *   session:<did>     → 1:1 会话状态
 *   msg:<did>:<n>     → 消息记录（n 为单调递增序号）
 *
 * Web 端实现为 IndexedDB（W3），测试与 dev-node 场景用内存实现。
 */
export interface KVStore {
  get(key: string): Promise<Uint8Array | undefined>;
  put(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  /** 按前缀枚举键（字典序），用于会话/消息列表加载 */
  keys(prefix?: string): Promise<string[]>;
  clear(): Promise<void>;
  close(): Promise<void>;
}
