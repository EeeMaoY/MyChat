/**
 * 动态（Moments/EDS-min，FR-4.1/4.2/4.4，M3 计划 §6）—— 好友圈动态的协议原语。
 *
 * 模型（EDS-min：只做动态日志与能力包裹，完整 EDS 属后续里程碑）：
 * - 好友圈密钥 momentKey（32B，作者与好友持有，经 1:1 会话分发）派生动态信箱 ID；
 * - 动态信箱 = append-only 动态日志：条目（post/delete）以 momentKey AEAD 加密；
 * - 每条动态独立内容密钥（encryptAttachment 模式）：文字与图片引用一起入块，
 *   块 CID 经日志条目分发；删除 = 墓碑条目 + 物理删块（客户端语义为准）。
 *
 * 边界（如实披露）：momentKey v1 不轮换（泄露 = 好友圈历史暴露）；已缓存的
 * 密文副本无法物理强制删除（FR-4.4 固有边界）；评论仅作者可见（v1 子集）。
 */
import { base58Decode, base58Encode, bytesToUtf8, utf8ToBytes } from "../codec/index.ts";
import { AEAD_KEY_LENGTH, AEAD_NONCE_LENGTH, aeadDecrypt, aeadEncrypt, hkdfSha256, randomBytes } from "../crypto/index.ts";
import { decryptAttachment, encryptAttachment } from "../attachment/index.ts";

const FEED_ID_PREFIX = "mychat:moments-feed-v1:";

export function generateMomentKey(): Uint8Array {
  return randomBytes(AEAD_KEY_LENGTH);
}

/** 动态信箱 ID（好友按此增量拉取作者的动态日志）。 */
export function momentFeedId(momentKey: Uint8Array): string {
  return base58Encode(hkdfSha256(momentKey, new Uint8Array(0), FEED_ID_PREFIX));
}

/** 动态日志条目（AEAD 明文形态；post 携带内容指针，delete 携带墓碑目标）。 */
export interface FeedEntry {
  v: 1;
  type: "post" | "delete";
  /** post = 动态内容块 CID；delete = 被删动态的块 CID */
  cid: string;
  /** post 时为动态内容密钥（base58） */
  contentKey?: string;
  /** post 时为 AEAD nonce（base58） */
  nonce?: string;
  at: number;
}

export function sealFeedEntry(momentKey: Uint8Array, entry: FeedEntry): Uint8Array {
  const nonce = randomBytes(AEAD_NONCE_LENGTH);
  const ciphertext = aeadEncrypt(momentKey, nonce, utf8ToBytes(JSON.stringify(entry)));
  return new Uint8Array([...nonce, ...ciphertext]);
}

/** 解日志条目（AEAD 认证失败即抛错——非好友/篡改，调用方安全丢弃）。 */
export function openFeedEntry(momentKey: Uint8Array, payload: Uint8Array): FeedEntry {
  if (payload.length < AEAD_NONCE_LENGTH + 16) throw new Error("动态日志条目过短");
  const nonce = payload.slice(0, AEAD_NONCE_LENGTH);
  const plaintext = aeadDecrypt(momentKey, nonce, payload.slice(AEAD_NONCE_LENGTH));
  const raw = JSON.parse(bytesToUtf8(plaintext)) as Record<string, unknown>;
  if (raw.v !== 1 || (raw.type !== "post" && raw.type !== "delete") || typeof raw.cid !== "string") {
    throw new Error("动态日志条目字段非法");
  }
  const entry: FeedEntry = {
    v: 1,
    type: raw.type,
    cid: raw.cid,
    ...(typeof raw.at === "number" ? { at: raw.at } : { at: 0 }),
  };
  if (typeof raw.contentKey === "string" && typeof raw.nonce === "string") {
    entry.contentKey = raw.contentKey;
    entry.nonce = raw.nonce;
  }
  return entry;
}

/** 动态内容块明文（图片以引用形式与文字同块，图片本体另为独立 CAS 块）。 */
export interface MomentPayload {
  v: 1;
  text: string;
  attachment?: { cid: string; contentKey: string; nonce: string; name: string; size: number; mime: string };
}

/**
 * 创建动态内容块：独立内容密钥加密（encryptAttachment 模式）。
 * 返回可 PUT 的块与日志条目所需指针；图片块由调用方另行 encryptAttachment 上传。
 */
export function createMomentBlock(payload: MomentPayload): { block: Uint8Array; cid: string; contentKey: string; nonce: string } {
  const att = encryptAttachment(utf8ToBytes(JSON.stringify(payload)));
  return {
    block: att.ciphertext,
    cid: att.cid,
    contentKey: base58Encode(att.contentKey),
    nonce: base58Encode(att.nonce),
  };
}

/** 解动态内容块（好友侧：日志条目提供 cid/CK/nonce）。 */
export function openMomentBlock(block: Uint8Array, contentKey: string, nonce: string): MomentPayload {
  const plaintext = decryptAttachment({
    ciphertext: block,
    contentKey: base58Decode(contentKey),
    nonce: base58Decode(nonce),
  });
  const raw = JSON.parse(bytesToUtf8(plaintext)) as Record<string, unknown>;
  if (raw.v !== 1 || typeof raw.text !== "string") throw new Error("动态内容块字段非法");
  const attachment = raw.attachment as MomentPayload["attachment"] | undefined;
  return {
    v: 1,
    text: raw.text,
    ...(attachment && typeof attachment.cid === "string" ? { attachment } : {}),
  };
}
