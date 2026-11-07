/**
 * 密钥库单测（加固批次 ①，W1）：设置/迁移/解锁/锁定/改口令全路径，
 * 错误口令拒绝、白名单键不加密、VaultLocked 态拒绝读密文。
 */
import { describe, expect, it } from "vitest";

import { utf8ToBytes, bytesToUtf8, type KVStore } from "@mychat/core";

import {
  isVaultConfigured,
  isVaultUnlocked,
  lockVault,
  setupVault,
  unlockVault,
  changeVaultPassphrase,
  wrapVault,
  VaultLockedError,
  WrongPassphraseError,
} from "../keyvault";

function memKV(): KVStore & { raw: Map<string, Uint8Array> } {
  const raw = new Map<string, Uint8Array>();
  return {
    raw,
    async get(key) {
      return raw.get(key);
    },
    async put(key, value) {
      raw.set(key, value);
    },
    async delete(key) {
      raw.delete(key);
    },
    async keys(prefix?: string) {
      return [...raw.keys()].filter((k) => (prefix === undefined || prefix === "" ? true : k.startsWith(prefix))).sort();
    },
    async clear() {
      raw.clear();
    },
    async close() {},
  };
}

async function seededKV(): Promise<ReturnType<typeof memKV>> {
  const kv = memKV();
  // 预置"旧版本明文数据"（迁移前形态）
  await kv.put("identity", utf8ToBytes('{"v":1,"ik":"明文身份"}'));
  await kv.put("spk", utf8ToBytes('{"pub":"aa","priv":"bb"}'));
  await kv.put("contact:did:mychat:x", utf8ToBytes('{"did":"did:mychat:x","name":"老朋友"}'));
  await kv.put("my-name", utf8ToBytes("alice"));
  await kv.put("cursor:mailbox-1", utf8ToBytes("42"));
  return kv;
}

describe("密钥库（W1 加密存储）", () => {
  it("设置口令 → 敏感键全量迁移为加密形态，白名单键保持明文", async () => {
    const kv = memKV();
    const store = wrapVault(await (async () => {
      const inner = kv;
      // 预置明文
      await inner.put("identity", utf8ToBytes("secret-identity"));
      await inner.put("my-name", utf8ToBytes("alice"));
      return inner;
    })());
    expect(await isVaultConfigured(store)).toBe(false);
    await setupVault(store, "correct horse battery");
    expect(await isVaultConfigured(store)).toBe(true);

    const rawIdentity = kv.raw.get("identity")!;
    expect(bytesToUtf8(rawIdentity)).not.toContain("secret-identity"); // 已加密
    expect(bytesToUtf8(kv.raw.get("my-name")!)).toBe("alice"); // 白名单保持明文
    // 解锁态读取为原值
    expect(bytesToUtf8((await store.get("identity"))!)).toBe("secret-identity");
  });

  it("锁定后读密文抛 VaultLocked；错误口令拒绝；正确口令解锁", async () => {
    const inner = memKV();
    await inner.put("spk", utf8ToBytes("spk-material"));
    const store = wrapVault(inner);
    await setupVault(store, "pass-12345");
    expect(isVaultUnlocked()).toBe(true);

    lockVault();
    expect(isVaultUnlocked()).toBe(false);
    await expect(store.get("spk")).rejects.toBeInstanceOf(VaultLockedError);
    // 未解锁时写入直通为明文（锁屏态不产生数据写入，此处为防御性语义）
    await unlockVault(store, "wrong-passphrase").catch((err: unknown) => {
      expect(err).toBeInstanceOf(WrongPassphraseError);
    });
    await expect(unlockVault(store, "wrong-passphrase")).rejects.toBeInstanceOf(WrongPassphraseError);
    await unlockVault(store, "pass-12345");
    expect(bytesToUtf8((await store.get("spk"))!)).toBe("spk-material");
  });

  it("旧明文用户迁移：设置口令前明文可读，设置后同键值不变", async () => {
    const inner = await seededKV();
    const store = wrapVault(inner);
    // 迁移前：明文直通可读
    expect(bytesToUtf8((await store.get("identity"))!)).toContain("明文身份");
    await setupVault(store, "migrate-pass-1");
    // 迁移后：值不变、落库已加密
    expect(bytesToUtf8((await store.get("identity"))!)).toContain("明文身份");
    expect(bytesToUtf8(inner.raw.get("identity")!)).not.toContain("明文身份");
    expect(bytesToUtf8((await store.get("contact:did:mychat:x"))!)).toContain("老朋友");
    // cursor 白名单不加密
    expect(bytesToUtf8(inner.raw.get("cursor:mailbox-1")!)).toBe("42");
  });

  it("修改口令：新口令可解、旧口令失效；错误旧口令被拒且原 KEK 不变", async () => {
    const inner = memKV();
    await inner.put("identity", utf8ToBytes("my-secret"));
    const store = wrapVault(inner);
    await setupVault(store, "old-pass-123");

    await expect(changeVaultPassphrase(store, "wrong-old", "new-pass-456")).rejects.toBeInstanceOf(WrongPassphraseError);
    // 原口令仍可用（KEK 未被破坏）
    expect(bytesToUtf8((await store.get("identity"))!)).toBe("my-secret");

    await changeVaultPassphrase(store, "old-pass-123", "new-pass-456");
    expect(bytesToUtf8((await store.get("identity"))!)).toBe("my-secret");
    lockVault();
    await unlockVault(store, "new-pass-456");
    expect(bytesToUtf8((await store.get("identity"))!)).toBe("my-secret");
    await expect(unlockVault(store, "old-pass-123")).rejects.toBeInstanceOf(WrongPassphraseError);
  });
});
