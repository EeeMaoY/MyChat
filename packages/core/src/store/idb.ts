/**
 * IndexedDB KV 实现（Web 客户端本地权威存储，FR-7.1）。
 *
 * 单 object store（"kv"）：key = 字符串键，value = Uint8Array。
 * 注意（W3 约束披露）：浏览器可在存储压力下驱逐 IndexedDB 数据，
 * 好友托管加密副本（FR-7.3）在 M1 提供容灾。
 */
import type { KVStore } from "./interface";

const DB_VERSION = 1;

export function createIdbKVStore(name: string): Promise<KVStore> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(name, DB_VERSION);
    open.onupgradeneeded = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("kv")) db.createObjectStore("kv");
    };
    open.onerror = () => reject(open.error ?? new Error("IndexedDB 打开失败"));
    open.onsuccess = () => {
      const db = open.result;
      resolve({
        async get(key) {
          return requestValue(db, (store) => store.get(key));
        },
        async put(key, value) {
          await requestDone(db, (store) => store.put(value, key));
        },
        async delete(key) {
          await requestDone(db, (store) => store.delete(key));
        },
        async keys(prefix) {
          const all = (await requestValue(db, (store) => store.getAllKeys())) as string[];
          const sorted = (all ?? []).sort();
          return prefix === undefined ? sorted : sorted.filter((k) => k.startsWith(prefix));
        },
        async clear() {
          await requestDone(db, (store) => store.clear());
        },
        async close() {
          db.close();
        },
      });
    };
  });
}

function withStore<T>(db: IDBDatabase, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("kv", "readonly");
    const req = run(tx.objectStore("kv"));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB 操作失败"));
  });
}

function requestValue<T>(db: IDBDatabase, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T | undefined> {
  return withStore(db, run);
}

function requestDone(db: IDBDatabase, run: (store: IDBObjectStore) => IDBRequest): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("kv", "readwrite");
    const req = run(tx.objectStore("kv"));
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB 写入失败"));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB 写入中止"));
    void req;
  });
}
