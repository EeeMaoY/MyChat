/**
 * 会话信箱伪地址（FR-3.1 元数据保护 / 《产品设计报告》§5.1 Pseudonym 信封）。
 *
 * 每个会话每个 epoch 有两个方向的信箱：
 *   i2r：发起方 → 响应方（发起方发信写入；响应方以其收信地址订阅）
 *   r2i：响应方 → 发起方
 * 地址由双方共享秘密 + epoch 经 HKDF-SHA-256 派生，每 epoch 轮换。
 * 中继与存储节点只见伪地址 → 伪地址，无法关联到收发双方 DID 明文
 * （SR-2 / FR-3.1）。
 *
 * 纯函数库：无日志、无 I/O。
 */
import { base58Encode } from "../codec/index.ts";
import { hkdfSha256 } from "../crypto/index.ts";

/** 伪地址输出字节数（18B → base58 文本约 25 字符） */
const MAILBOX_BYTES = 18;

/** 派生域分隔前缀（跨协议防密钥复用，与 crypto/kdf.ts 的 info 约定一致） */
const DOMAIN = "mychat:mailbox:v1:";

/** 方向标签：发起方 → 响应方 */
const LABEL_I2R = "i2r";

/** 方向标签：响应方 → 发起方 */
const LABEL_R2I = "r2i";

/** epoch 的 8 字节大端编码（作为 HKDF salt），支持至 2^64-1 的整数值域 */
function epochToSalt(epoch: number): Uint8Array {
  const hi = Math.floor(epoch / 2 ** 32);
  const lo = epoch % 2 ** 32;
  const salt = new Uint8Array(8);
  salt[0] = (hi >>> 24) & 0xff;
  salt[1] = (hi >>> 16) & 0xff;
  salt[2] = (hi >>> 8) & 0xff;
  salt[3] = hi & 0xff;
  salt[4] = (lo >>> 24) & 0xff;
  salt[5] = (lo >>> 16) & 0xff;
  salt[6] = (lo >>> 8) & 0xff;
  salt[7] = lo & 0xff;
  return salt;
}

/**
 * 派生本端在本 epoch 指定方向的信箱伪地址。
 *
 * @param sharedSecret 会话双方共享秘密（如 ECDH 输出，不得为空）
 * @param epoch 伪地址轮换周期号（非负安全整数）
 * @param senderIsInitiator 本端是否为会话发起方
 * @param sending 本次操作是否为发信
 * @returns base58 编码的 18 字节伪地址（同参数确定性）
 *
 * 方向标签规则（设计报告 §5.1）：sending 与 senderIsInitiator 同向
 * （发起方发信 / 响应方收信）取 "i2r"，否则（响应方发信 / 发起方收信）
 * 取 "r2i" —— 收发两端各自以己方视角计算，得到同一信箱地址。
 *
 * @throws 共享秘密为空或 epoch 非法时抛错
 */
export function deriveSessionMailbox(
  sharedSecret: Uint8Array,
  epoch: number,
  senderIsInitiator: boolean,
  sending: boolean,
): string {
  if (sharedSecret.length === 0) {
    throw new Error("共享秘密不得为空");
  }
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new RangeError(`epoch 必须为非负安全整数，收到 ${epoch}`);
  }
  const label = senderIsInitiator === sending ? LABEL_I2R : LABEL_R2I;
  const derived = hkdfSha256(sharedSecret, epochToSalt(epoch), DOMAIN + label, MAILBOX_BYTES);
  return base58Encode(derived);
}
