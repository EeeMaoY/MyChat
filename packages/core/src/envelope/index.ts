/**
 * envelope 模块 —— 元数据保护层（FR-3.1 / FR-3.3，
 * 《产品设计报告》§5.1 消息投递、§11.1 协议分层与消息封装）。
 *
 * - padding：四档定长填充（长度侧信道抑制）
 * - pseudonym：会话信箱伪地址（每 epoch 轮换，中继只见伪地址）
 * - envelope：信封二进制编解码与时间桶（时序关联抑制）
 */
export {
  PAD_SIZES,
  type PadClass,
  applyPadding,
  padClassForLength,
  stripPadding,
} from "./padding";
export { deriveSessionMailbox } from "./pseudonym";
export {
  DEFAULT_TIME_BUCKET_MS,
  ENVELOPE_VERSION,
  decodeEnvelope,
  encodeEnvelope,
  makeEnvelope,
  timestampBucket,
} from "./envelope";
