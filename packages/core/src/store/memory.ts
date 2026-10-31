/**
 * 内存 KV 实现：单元测试、dev-node 侧逻辑与不持久化场景使用。
 */
import type { KVStore } from "./interface.ts";

export function createMemoryKVStore(): KVStore {
  const map = new Map<string, Uint8Array>();
  return {
    async get(key) {
      return map.get(key);
    },
    async put(key, value) {
      map.set(key, value);
    },
    async delete(key) {
      map.delete(key);
    },
    async keys(prefix) {
      const all = [...map.keys()].sort();
      return prefix === undefined ? all : all.filter((k) => k.startsWith(prefix));
    },
    async clear() {
      map.clear();
    },
    async close() {
      map.clear();
    },
  };
}
