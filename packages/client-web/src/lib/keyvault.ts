/**
 * 密钥库（W1 密钥存储保护，加固批次 ①）：
 * 口令派生 KEK（scrypt）→ 对 IndexedDB 中的私钥/敏感材料做 AEAD 包裹。
 *
 * 模型：
 * - "默认加密，白名单明文"——除路由/设置类少量键外，全部键值以
 *   `{v:1, n: nonce, c: ciphertext}` 形态落库；口令校验用 verifier（加密已知明文）。
 * - 未设置口令时 KV 直通（兼容既有用户与"无感创建"UX-1）；设置口令时**全量迁移**：
 *   遍历既有键，用新 KEK 逐键重写。
 * - 解锁态 KEK 仅存内存；锁定 = 丢弃 KEK 并丢弃 Messaging 实例（app 层负责）。
 * - 自动锁定由 app 层基于用户活动计时调用 lock()。
 *
 * 边界（如实披露）：口令强度由用户负责；忘记口令无法解密本地库（通过备份文件
 * 导入恢复会覆盖本地数据）；加密对抗"拷库/他人使用设备"，不对抗运行中的恶意代码。
 */
import { randomBytes } from "@mychat/core";
import { base64Decode, base64Encode, bytesToUtf8, utf8ToBytes } from "@mychat/core";
import { aeadDecrypt, aeadEncrypt, AEAD_NONCE_LENGTH, deriveKekFromPassphrase, PASSPHRASE_SALT_LENGTH } from "@mychat/core";
import type { KVStore } from "@mychat/core";

const SALT_KEY = "vault-salt";
const VERIFIER_KEY = "vault-verifier";
const VERIFIER_PLAINTEXT = "mychat-vault-v1";
const VAULT_FORMAT = 1;

/** 明文白名单：无敏感字段的路由/设置数据 + 密钥库自身元数据（盐与 verifier 均非秘密）。 */
const PLAINTEXT_KEYS = new Set(["msgseq", "my-name", SALT_KEY, VERIFIER_KEY]);
const PLAINTEXT_PREFIXES = ["cursor:", "setting:"];

function isPlaintextKey(key: string): boolean {
  if (PLAINTEXT_KEYS.has(key)) return true;
  return PLAINTEXT_PREFIXES.some((p) => key.startsWith(p));
}

export class VaultLockedError extends Error {
  constructor() {
    super("密钥库已锁定");
  }
}

export class WrongPassphraseError extends Error {
  constructor() {
    super("口令不正确");
  }
}

let kek: Uint8Array | null = null;

export function isVaultUnlocked(): boolean {
  return kek !== null;
}

export function lockVault(): void {
  kek = null;
}

async function readSalt(kv: KVStore): Promise<Uint8Array | null> {
  const raw = await kv.get(SALT_KEY);
  return raw ? base64Decode(bytesToUtf8(raw)) : null;
}

/** 密钥库是否已配置（存在 salt + verifier）。 */
export async function isVaultConfigured(kv: KVStore): Promise<boolean> {
  return (await readSalt(kv)) !== null && (await kv.get(VERIFIER_KEY)) !== undefined;
}

/** 首次设置口令：生成盐、派生 KEK、写 verifier，并全量迁移既有明文敏感键。 */
export async function setupVault(kv: KVStore, passphrase: string): Promise<void> {
  if (await isVaultConfigured(kv)) throw new Error("密钥库已配置（请使用修改口令）");
  if (passphrase.length < 8) throw new Error("口令至少 8 位");
  const salt = randomBytes(PASSPHRASE_SALT_LENGTH);
  kek = deriveKekFromPassphrase(passphrase, salt);
  await kv.put(SALT_KEY, utf8ToBytes(base64Encode(salt)));
  await kv.put(VERIFIER_KEY, encryptUtf8(VERIFIER_PLAINTEXT));
  // 全量迁移：读（明文/或已是密文但旧 KEK 不存在→原样是明文）→ put（新 KEK 加密）
  await migrateAll(kv);
}

/** 解锁：派生 KEK 并以 verifier 试解。成功后 KEK 常驻内存直至锁定。 */
export async function unlockVault(kv: KVStore, passphrase: string): Promise<void> {
  const salt = await readSalt(kv);
  if (salt === null) throw new Error("密钥库未配置");
  const candidate = deriveKekFromPassphrase(passphrase, salt);
  const verifierRaw = await kv.get(VERIFIER_KEY);
  if (verifierRaw === undefined) throw new Error("密钥库未配置");
  try {
    const decrypted = decryptValue(candidate, parseEnvelope(verifierRaw));
    if (bytesToUtf8(decrypted) !== VERIFIER_PLAINTEXT) throw new Error("mismatch");
  } catch {
    throw new WrongPassphraseError();
  }
  kek = candidate;
}

/** 修改口令：旧口令验证 → 以旧 KEK 解出全部敏感键明文 → 换新 KEK 重加密写入。 */
export async function changeVaultPassphrase(kv: KVStore, oldPassphrase: string, newPassphrase: string): Promise<void> {
  await unlockVault(kv, oldPassphrase); // 失败即抛（kek 只在成功时更新；此刻 kek = 旧 KEK）
  if (newPassphrase.length < 8) throw new Error("口令至少 8 位");
  // 先用旧 KEK 解出全部敏感键（get 自动解密）
  const snapshot = new Map<string, Uint8Array>();
  for (const key of await kv.keys("")) {
    if (isPlaintextKey(key)) continue;
    const value = await kv.get(key);
    if (value !== undefined) snapshot.set(key, value);
  }
  // 再切换 KEK 并重加密写入
  const salt = randomBytes(PASSPHRASE_SALT_LENGTH);
  kek = deriveKekFromPassphrase(newPassphrase, salt);
  await kv.put(SALT_KEY, utf8ToBytes(base64Encode(salt)));
  await kv.put(VERIFIER_KEY, encryptUtf8(VERIFIER_PLAINTEXT));
  for (const [key, value] of snapshot) await kv.put(key, value);
}

/** 迁移/重加密全部非白名单键（读原值 → 以当前 KEK 重写）。 */
async function migrateAll(kv: KVStore): Promise<void> {
  for (const key of await kv.keys("")) {
    if (isPlaintextKey(key)) continue;
    const raw = await kv.get(key);
    if (raw === undefined) continue;
    await kv.put(key, raw);
  }
}

// ---------- 包裹层：EnvelopedKV ----------

interface EnvelopeFormat {
  v: 1;
  n: string;
  c: string;
}

function encryptValue(kekKey: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = randomBytes(AEAD_NONCE_LENGTH);
  const ciphertext = aeadEncrypt(kekKey, nonce, plaintext);
  return utf8ToBytes(
    JSON.stringify({ v: VAULT_FORMAT, n: base64Encode(nonce), c: base64Encode(ciphertext) } satisfies EnvelopeFormat),
  );
}

function parseEnvelope(raw: Uint8Array): EnvelopeFormat {
  const parsed = JSON.parse(bytesToUtf8(raw)) as Record<string, unknown>;
  if (parsed.v !== VAULT_FORMAT || typeof parsed.n !== "string" || typeof parsed.c !== "string") {
    throw new Error("密钥库条目格式非法");
  }
  return { v: 1, n: parsed.n, c: parsed.c };
}

function decryptValue(kekKey: Uint8Array, envelope: EnvelopeFormat): Uint8Array {
  return aeadDecrypt(kekKey, base64Decode(envelope.n), base64Decode(envelope.c));
}

function encryptUtf8(text: string): Uint8Array {
  if (kek === null) throw new VaultLockedError();
  return encryptValue(kek, utf8ToBytes(text));
}

function isEnvelopeFormat(raw: Uint8Array): boolean {
  try {
    const parsed = JSON.parse(bytesToUtf8(raw)) as Record<string, unknown>;
    return parsed.v === VAULT_FORMAT && typeof parsed.n === "string" && typeof parsed.c === "string";
  } catch {
    return false;
  }
}

/**
 * 包装 KVStore：非白名单键自动加解密。
 * - 未设置口令（kek=null 且条目非密文格式）：直通（兼容旧用户/迁移前）；
 * - 已解锁：put 加密、get 解密；
 * - 已配置但未解锁：get 到密文条目即抛 VaultLockedError（app 层保证此态不启动 Messaging）。
 */
export function wrapVault(inner: KVStore): KVStore {
  return {
    async get(key: string): Promise<Uint8Array | undefined> {
      const raw = await inner.get(key);
      if (raw === undefined) return undefined;
      if (isPlaintextKey(key) || !isEnvelopeFormat(raw)) return raw;
      if (kek === null) throw new VaultLockedError();
      return decryptValue(kek, parseEnvelope(raw));
    },
    async put(key: string, value: Uint8Array): Promise<void> {
      if (isPlaintextKey(key)) return inner.put(key, value);
      if (kek === null) return inner.put(key, value); // 未配置口令：明文直写（迁移前兼容）
      return inner.put(key, encryptValue(kek, value));
    },
    async delete(key: string): Promise<void> {
      return inner.delete(key);
    },
    async keys(prefix?: string): Promise<string[]> {
      return inner.keys(prefix);
    },
    async clear(): Promise<void> {
      return inner.clear();
    },
    async close(): Promise<void> {
      return inner.close();
    },
  };
}
