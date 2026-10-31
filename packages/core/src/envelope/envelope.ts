/**
 * 信封二进制编解码 —— 中继可见层
 * （《产品设计报告》§11.1 协议分层与消息封装 的 M0 子集）。
 *
 * 线格式（全部大端）：
 * [1B version=1][4B epoch][1B padClass][24B nonce]
 * [1B toPseudonym 字节数 N][N 字节 toPseudonym-utf8]
 * [4B payload 长度][payload]
 *
 * 中继与存储节点仅见伪地址与外层密文（SR-1/SR-2）；epoch 驱动伪地址轮换，
 * padClass/时间桶分别抑制长度与时序侧信道（FR-3.3，配合 padding.ts）。
 *
 * 纯函数库：无日志、无 I/O。
 */
import { bytesToUtf8, utf8ToBytes } from "../codec";
import { AEAD_NONCE_LENGTH, randomBytes } from "../crypto";
import type { Envelope } from "../protocol/interfaces";

/** 信封二进制格式版本（NFR-10 版本化；对应线格式 1B version 字段） */
export const ENVELOPE_VERSION = 1;

/** Envelope.version 的字符串形态（与二进制版本一一对应，编解码往返可逆） */
const ENVELOPE_VERSION_STRING = String(ENVELOPE_VERSION);

/** 时间桶默认粒度 1 分钟（FR-3.3 时序关联抑制） */
export const DEFAULT_TIME_BUCKET_MS = 60_000;

/** nonce 固定 24B，与 AEAD_NONCE_LENGTH 保持一致 */
const NONCE_LENGTH = AEAD_NONCE_LENGTH;

/* 固定字段偏移 */
const VERSION_OFFSET = 0;
const EPOCH_OFFSET = 1;
const PAD_CLASS_OFFSET = 5;
const NONCE_OFFSET = 6;
const PSEUDO_LEN_OFFSET = 30;
const PSEUDO_OFFSET = 31;

/** 固定头长度：version(1) + epoch(4) + padClass(1) + nonce(24) + N(1) */
const FIXED_PREFIX_SIZE = 1 + 4 + 1 + NONCE_LENGTH + 1;
/** payload 长度字段（4B 大端） */
const PAYLOAD_LEN_SIZE = 4;
/** 不含伪地址与 payload 的最小信封总长 */
const MIN_SIZE = FIXED_PREFIX_SIZE + PAYLOAD_LEN_SIZE;

/** 大端写 32 位无符号整数 */
function writeUint32BE(out: Uint8Array, offset: number, value: number): void {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

/** 大端读 32 位无符号整数 */
function readUint32BE(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset]! << 24) |
      (bytes[offset + 1]! << 16) |
      (bytes[offset + 2]! << 8) |
      bytes[offset + 3]!) >>> 0
  );
}

/**
 * 时间桶：将毫秒时间戳折叠进 bucketMs 毫秒的桶（FR-3.3 时序关联抑制）。
 * 返回 Math.floor(tsMs / bucketMs)。
 *
 * @throws bucketMs 非正整数、tsMs 非有限数值时抛错
 */
export function timestampBucket(tsMs: number, bucketMs: number = DEFAULT_TIME_BUCKET_MS): number {
  if (!Number.isSafeInteger(bucketMs) || bucketMs <= 0) {
    throw new RangeError(`bucketMs 必须为正整数，收到 ${bucketMs}`);
  }
  if (!Number.isFinite(tsMs)) {
    throw new RangeError(`tsMs 必须为有限数值，收到 ${tsMs}`);
  }
  return Math.floor(tsMs / bucketMs);
}

/**
 * 信封编码为线格式字节（§11.1 布局，全部大端）。
 *
 * @throws 版本不受支持、epoch 超 4B、padClass 非法、nonce 非 24B、
 *         toPseudonym UTF-8 字节数越界（1..255）或 payload 超 4B 长度上限时抛错
 */
export function encodeEnvelope(e: Envelope): Uint8Array {
  if (e.version !== ENVELOPE_VERSION_STRING) {
    throw new Error(`不支持的信封版本: ${e.version}（本实现仅支持 ${ENVELOPE_VERSION_STRING}）`);
  }
  if (!Number.isSafeInteger(e.epoch) || e.epoch < 0 || e.epoch > 0xffffffff) {
    throw new RangeError(`epoch 必须在 [0, 2^32-1] 内，收到 ${e.epoch}`);
  }
  if (e.padClass !== 0 && e.padClass !== 1 && e.padClass !== 2 && e.padClass !== 3) {
    throw new RangeError(`非法填充档位: ${e.padClass}`);
  }
  if (e.nonce.length !== NONCE_LENGTH) {
    throw new RangeError(`nonce 长度必须为 ${NONCE_LENGTH} 字节，收到 ${e.nonce.length}`);
  }
  const pseudoBytes = utf8ToBytes(e.toPseudonym);
  if (pseudoBytes.length < 1 || pseudoBytes.length > 0xff) {
    throw new RangeError(
      `toPseudonym UTF-8 字节数必须在 [1, 255] 内，收到 ${pseudoBytes.length}`,
    );
  }
  if (!Number.isSafeInteger(e.payload.length) || e.payload.length < 0 || e.payload.length > 0xffffffff) {
    throw new RangeError(`payload 长度超出 4B 长度字段上限：${e.payload.length}`);
  }

  const out = new Uint8Array(MIN_SIZE + pseudoBytes.length + e.payload.length);
  out[VERSION_OFFSET] = ENVELOPE_VERSION;
  writeUint32BE(out, EPOCH_OFFSET, e.epoch);
  out[PAD_CLASS_OFFSET] = e.padClass;
  out.set(e.nonce, NONCE_OFFSET);
  out[PSEUDO_LEN_OFFSET] = pseudoBytes.length;
  out.set(pseudoBytes, PSEUDO_OFFSET);
  const payloadLenOffset = PSEUDO_OFFSET + pseudoBytes.length;
  writeUint32BE(out, payloadLenOffset, e.payload.length);
  out.set(e.payload, payloadLenOffset + PAYLOAD_LEN_SIZE);
  return out;
}

/**
 * 从线格式字节解码信封；任何畸形输入（截断、版本不支持、非法档位、
 * 长度字段与实际不符、尾部夹带数据）一律抛错，不静默容错。
 */
export function decodeEnvelope(bytes: Uint8Array): Envelope {
  if (bytes.length < MIN_SIZE) {
    throw new Error(`信封过短（${bytes.length} < ${MIN_SIZE} 字节），疑似截断`);
  }
  const version = bytes[VERSION_OFFSET]!;
  if (version !== ENVELOPE_VERSION) {
    throw new Error(`不支持的信封版本: ${version}（本实现仅支持 ${ENVELOPE_VERSION}）`);
  }
  const epoch = readUint32BE(bytes, EPOCH_OFFSET);
  const padClass = bytes[PAD_CLASS_OFFSET]!;
  if (padClass > 3) {
    throw new Error(`非法填充档位: ${padClass}`);
  }
  const nonce = bytes.slice(NONCE_OFFSET, NONCE_OFFSET + NONCE_LENGTH);

  const pseudoLen = bytes[PSEUDO_LEN_OFFSET]!;
  const pseudoEnd = PSEUDO_OFFSET + pseudoLen;
  if (bytes.length < pseudoEnd + PAYLOAD_LEN_SIZE) {
    throw new Error(`伪地址字段越界（声明 ${pseudoLen} 字节），疑似截断`);
  }
  const toPseudonym = bytesToUtf8(bytes.slice(PSEUDO_OFFSET, pseudoEnd));

  const payloadStart = pseudoEnd + PAYLOAD_LEN_SIZE;
  const payloadLen = readUint32BE(bytes, pseudoEnd);
  const totalEnd = payloadStart + payloadLen;
  if (bytes.length !== totalEnd) {
    throw new Error(
      `payload 长度字段（${payloadLen}）与实际可读字节数（${bytes.length - payloadStart}）不符，疑似截断或尾部夹带`,
    );
  }
  const payload = bytes.slice(payloadStart, totalEnd);

  return {
    version: ENVELOPE_VERSION_STRING,
    epoch,
    toPseudonym,
    padClass: padClass as Envelope["padClass"],
    nonce,
    payload,
  };
}

/**
 * 构造信封便捷函数：nonce 用 CSPRNG 自动生成 24B（经 crypto.randomBytes）。
 */
export function makeEnvelope(opts: {
  epoch: number;
  toPseudonym: string;
  padClass: 0 | 1 | 2 | 3;
  payload: Uint8Array;
}): Envelope {
  return {
    version: ENVELOPE_VERSION_STRING,
    epoch: opts.epoch,
    toPseudonym: opts.toPseudonym,
    padClass: opts.padClass,
    nonce: randomBytes(NONCE_LENGTH),
    payload: opts.payload,
  };
}
