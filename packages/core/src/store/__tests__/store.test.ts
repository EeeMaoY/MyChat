import { describe, expect, it } from "vitest";

import { createMemoryKVStore } from "../memory.ts";

describe("内存 KVStore（KV 语义契约）", () => {
  it("put/get/delete 往返", async () => {
    const store = createMemoryKVStore();
    await store.put("a", new Uint8Array([1, 2, 3]));
    expect(await store.get("a")).toEqual(new Uint8Array([1, 2, 3]));
    await store.delete("a");
    expect(await store.get("a")).toBeUndefined();
  });

  it("keys 前缀过滤且字典序", async () => {
    const store = createMemoryKVStore();
    await store.put("msg:b:2", new Uint8Array([2]));
    await store.put("msg:a:1", new Uint8Array([1]));
    await store.put("contact:x", new Uint8Array([3]));
    expect(await store.keys("msg:")).toEqual(["msg:a:1", "msg:b:2"]);
    expect(await store.keys()).toEqual(["contact:x", "msg:a:1", "msg:b:2"]);
  });

  it("clear 清空全部", async () => {
    const store = createMemoryKVStore();
    await store.put("k", new Uint8Array([1]));
    await store.clear();
    expect(await store.keys()).toEqual([]);
  });
});
