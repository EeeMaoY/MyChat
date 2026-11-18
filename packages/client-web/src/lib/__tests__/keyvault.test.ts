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
    // 成功路径不残留迁移标记与影子备份
    expect(inner.raw.has("vault-rekey-pending")).toBe(false);
    expect([...inner.raw.keys()].some((k) => k.startsWith("vault-rekey-bak:"))).toBe(false);
  });
});

describe("修改口令崩溃安全（两阶段提交）", () => {
  /** 在包裹层外再包一层计数代理：第 failAt 次写操作（put/delete）抛错，模拟落盘中途崩溃。 */
  function crashAtWrite(store: KVStore, failAt: number): KVStore {
    let writes = 0;
    const boom = (): never => {
      throw new Error(`模拟崩溃：第 ${failAt} 次写入`);
    };
    return {
      ...store,
      async put(key, value) {
        writes += 1;
        if (writes === failAt) boom();
        return store.put(key, value);
      },
      async delete(key) {
        writes += 1;
        if (writes === failAt) boom();
        return store.delete(key);
      },
    };
  }

  /**
   * 阶段 B 的写操作序列（3 个敏感键）：
   * 1 标记 → 2-4 影子备份 → 5 新 salt → 6 新 verifier → 7-9 新密文
   * → 10 删标记（提交点）→ 11-13 删影子。
   * 任意一次崩溃后：提交点之前（1-10）旧口令解锁自动回滚且数据无损；
   * 提交点之后（11-13，仅剩影子清理）新口令生效、旧口令失效。
   */
  it("任意一次落盘写入崩溃 → 解锁可恢复且数据无损", async () => {
    const TOTAL_WRITES = 13;
    for (let failAt = 1; failAt <= TOTAL_WRITES; failAt++) {
      const inner = await seededKV(); // 3 个敏感键：identity/spk/contact:did:mychat:x
      const store = wrapVault(inner);
      await setupVault(store, "old-pass-123");

      await expect(changeVaultPassphrase(crashAtWrite(store, failAt), "old-pass-123", "new-pass-456")).rejects.toThrow(
        "模拟崩溃",
      );

      lockVault();
      if (failAt <= 10) {
        // 提交点之前崩溃：改钥视为未发生，旧口令解锁自动回滚
        await unlockVault(store, "old-pass-123");
        expect(bytesToUtf8((await store.get("identity"))!)).toContain("明文身份");
        expect(bytesToUtf8((await store.get("spk"))!)).toContain("bb");
        expect(bytesToUtf8((await store.get("contact:did:mychat:x"))!)).toContain("老朋友");
      } else {
        // 提交点之后崩溃（仅影子清理中断）：改钥已生效
        await expect(unlockVault(store, "old-pass-123")).rejects.toBeInstanceOf(WrongPassphraseError);
        await unlockVault(store, "new-pass-456");
        expect(bytesToUtf8((await store.get("identity"))!)).toContain("明文身份");
      }
      // 回滚/清理后不残留迁移标记与影子备份
      expect(inner.raw.has("vault-rekey-pending")).toBe(false);
      expect([...inner.raw.keys()].some((k) => k.startsWith("vault-rekey-bak:"))).toBe(false);
    }
  }, 120_000);

  it("崩溃于切换后：新口令被明确拒绝并引导旧口令；回滚后新口令失效", async () => {
    const inner = await seededKV();
    const store = wrapVault(inner);
    await setupVault(store, "old-pass-123");

    // failAt=7：新 salt/verifier 已写、第一个新密文未写（键仍全为旧密文）
    await expect(changeVaultPassphrase(crashAtWrite(store, 7), "old-pass-123", "new-pass-456")).rejects.toThrow("模拟崩溃");

    lockVault();
    await expect(unlockVault(store, "new-pass-456")).rejects.toThrow("上次修改口令未完成");
    // 旧口令解锁：自动回滚为改钥前状态
    await unlockVault(store, "old-pass-123");
    expect(bytesToUtf8((await store.get("spk"))!)).toContain("bb");
    // 回滚后新口令失效（改钥视为未发生）
    lockVault();
    await expect(unlockVault(store, "new-pass-456")).rejects.toBeInstanceOf(WrongPassphraseError);
    await unlockVault(store, "old-pass-123");
    expect(bytesToUtf8((await store.get("identity"))!)).toContain("明文身份");
  }, 30_000);
});
