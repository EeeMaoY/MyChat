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
/** 改钥迁移标记：存在即"上次改钥未确认完成"，值为改钥前的 salt/verifier 快照。 */
const REKEY_PENDING_KEY = "vault-rekey-pending";
/** 改钥期间旧密文的影子备份键前缀（改钥未确认前被覆盖的键可由此恢复）。 */
const REKEY_BACKUP_PREFIX = "vault-rekey-bak:";

/** 明文白名单：无敏感字段的路由/设置数据 + 密钥库自身元数据（盐与 verifier 均非秘密；
 * 标记与影子备份须锁定态直通可读写，且均为密文形态或非秘密元数据）。 */
const PLAINTEXT_KEYS = new Set(["msgseq", "my-name", SALT_KEY, VERIFIER_KEY, REKEY_PENDING_KEY]);
const PLAINTEXT_PREFIXES = ["cursor:", "setting:", REKEY_BACKUP_PREFIX];

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

// ---------- 改钥两阶段提交（崩溃可恢复） ----------

/** 迁移标记内容（明文 JSON：旧 salt/verifier 快照，均非秘密——verifier 本就是密文形态）。 */
interface RekeyPendingRecord {
  v: 1;
  /** 改钥前的 salt（base64 文本，即 SALT_KEY 的原始值） */
  oldSalt: string;
  /** 改钥前的 verifier（envelope JSON 文本，即 VERIFIER_KEY 的原始值） */
  oldVerifier: string;
}

/** 读取迁移标记（不存在或损坏返回 null）。 */
async function readRekeyPending(kv: KVStore): Promise<RekeyPendingRecord | null> {
  const raw = await kv.get(REKEY_PENDING_KEY);
  if (raw === undefined) return null;
  try {
    const parsed = JSON.parse(bytesToUtf8(raw)) as Record<string, unknown>;
    if (parsed.v !== 1 || typeof parsed.oldSalt !== "string" || typeof parsed.oldVerifier !== "string") {
      return null;
    }
    return { v: 1, oldSalt: parsed.oldSalt, oldVerifier: parsed.oldVerifier };
  } catch {
    return null;
  }
}

/** 删除全部影子备份键（幂等）。 */
async function deleteRekeyBackups(kv: KVStore): Promise<void> {
  for (const key of await kv.keys(REKEY_BACKUP_PREFIX)) await kv.delete(key);
}

/** verifier 试解（AEAD 认证失败/格式错误均视为不匹配）。 */
function verifierMatches(kekKey: Uint8Array, verifierRaw: Uint8Array): boolean {
  try {
    return bytesToUtf8(decryptValue(kekKey, parseEnvelope(verifierRaw))) === VERIFIER_PLAINTEXT;
  } catch {
    return false;
  }
}

/**
 * 解锁：派生 KEK 并以 verifier 试解。成功后 KEK 常驻内存直至锁定。
 *
 * 崩溃恢复（上次改钥中断、迁移标记仍在时）：
 * - 旧口令可解旧 verifier → 回滚：影子备份恢复被覆盖的键、还原旧 salt/verifier、清场，
 *   之后按旧口令正常解锁（改钥视为未发生）；
 * - 新口令可解当前 verifier 但切换未确认 → 拒绝并引导用旧口令（键可能仍为旧密文或混合态）。
 */
export async function unlockVault(kv: KVStore, passphrase: string): Promise<void> {
  const salt = await readSalt(kv);
  if (salt === null) throw new Error("密钥库未配置");
  const verifierRaw = await kv.get(VERIFIER_KEY);
  if (verifierRaw === undefined) throw new Error("密钥库未配置");
  const candidate = deriveKekFromPassphrase(passphrase, salt);
  const pending = await readRekeyPending(kv);
  if (verifierMatches(candidate, verifierRaw)) {
    if (pending !== null && bytesToUtf8(verifierRaw) === pending.oldVerifier) {
      // 崩溃于切换之前（或回滚半程）：键仍为旧密文，清理残留影子与标记后正常解锁
      await deleteRekeyBackups(kv);
      await kv.delete(REKEY_PENDING_KEY);
    } else if (pending !== null) {
      // 崩溃于切换之后、确认之前：键仍为旧密文或新旧行混合，新口令不可用
      throw new Error("上次修改口令未完成：请先用修改前的旧口令解锁（将自动回滚）");
    } else {
      // 正常路径：顺手清理"确认后影子删除中断"的残留
      await deleteRekeyBackups(kv);
    }
    kek = candidate;
    return;
  }
  if (pending !== null) {
    const oldKek = deriveKekFromPassphrase(passphrase, base64Decode(pending.oldSalt));
    if (verifierMatches(oldKek, utf8ToBytes(pending.oldVerifier))) {
      // 崩溃于切换之中：用影子里的旧密文恢复被覆盖的键，还原旧 salt/verifier 后按旧口令解锁。
      // 恢复写入须绕过包裹层（锁定态 kek=null 直通；此处再显式置空防已解锁状态下重复调用）
      kek = null;
      for (const bakKey of await kv.keys(REKEY_BACKUP_PREFIX)) {
        const bak = await kv.get(bakKey);
        if (bak !== undefined) await kv.put(bakKey.slice(REKEY_BACKUP_PREFIX.length), bak);
      }
      await kv.put(SALT_KEY, utf8ToBytes(pending.oldSalt));
      await kv.put(VERIFIER_KEY, utf8ToBytes(pending.oldVerifier));
      await deleteRekeyBackups(kv);
      await kv.delete(REKEY_PENDING_KEY);
      kek = oldKek;
      return;
    }
  }
  throw new WrongPassphraseError();
}

/**
 * 修改口令（两阶段提交，崩溃可恢复）：
 * - 阶段 A（内存，磁盘未动）：旧口令验证 → 解出全部敏感键明文 → 预生成
 *   旧/新两组密文（影子备份 = 旧 KEK 重加密；新密文 = 新 KEK 加密）与新 salt/verifier/标记。
 * - 阶段 B（落盘切换）：写迁移标记 → 写影子备份 → 写新 salt/verifier → 逐键写新密文
 *   → 删除标记（提交点）→ 删除影子。全程直通写预生成字节，任何一步中断都留下
 *   "标记在 + 每个被覆盖键均有旧密文影子"的可回滚状态（unlock 时自动回滚，旧口令数据无损）。
 */
export async function changeVaultPassphrase(kv: KVStore, oldPassphrase: string, newPassphrase: string): Promise<void> {
  if (newPassphrase.length < 8) throw new Error("口令至少 8 位");
  // 旧口令验证（上次改钥中断时先自动回滚清场）；成功后 kek = 旧 KEK
  await unlockVault(kv, oldPassphrase);
  const oldKek = kek;
  if (oldKek === null) throw new VaultLockedError();

  // —— 阶段 A：内存预备（磁盘未动，任一步失败直接抛出）——
  const snapshot = new Map<string, Uint8Array>();
  for (const key of await kv.keys("")) {
    if (isPlaintextKey(key)) continue;
    const value = await kv.get(key);
    if (value !== undefined) snapshot.set(key, value);
  }
  const oldSaltRaw = await kv.get(SALT_KEY);
  const oldVerifierRaw = await kv.get(VERIFIER_KEY);
  if (oldSaltRaw === undefined || oldVerifierRaw === undefined) throw new Error("密钥库元数据缺失");
  const newSalt = randomBytes(PASSPHRASE_SALT_LENGTH);
  const newKek = deriveKekFromPassphrase(newPassphrase, newSalt);
  const backups = new Map<string, Uint8Array>();
  const newCiphers = new Map<string, Uint8Array>();
  for (const [key, plain] of snapshot) {
    backups.set(key, encryptValue(oldKek, plain));
    newCiphers.set(key, encryptValue(newKek, plain));
  }
  const pendingValue = utf8ToBytes(
    JSON.stringify({ v: 1, oldSalt: bytesToUtf8(oldSaltRaw), oldVerifier: bytesToUtf8(oldVerifierRaw) } satisfies RekeyPendingRecord),
  );

  // —— 阶段 B：落盘切换（kek 置空令包裹层直通，预生成字节原样落盘）——
  kek = null;
  try {
    await kv.put(REKEY_PENDING_KEY, pendingValue);
    for (const [key, backup] of backups) await kv.put(REKEY_BACKUP_PREFIX + key, backup);
    await kv.put(SALT_KEY, utf8ToBytes(base64Encode(newSalt)));
    await kv.put(VERIFIER_KEY, encryptValue(newKek, utf8ToBytes(VERIFIER_PLAINTEXT)));
    for (const [key, cipher] of newCiphers) await kv.put(key, cipher);
    await kv.delete(REKEY_PENDING_KEY); // 提交点：标记删除后改钥即完成
    await deleteRekeyBackups(kv);
  } catch (err) {
    // 落盘中断：内存 KEK 与磁盘形态可能不一致，强制锁定走解锁回滚
    lockVault();
    throw err;
  }
  kek = newKek;
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
