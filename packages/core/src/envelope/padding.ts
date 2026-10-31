/**
 * 消息填充 —— 四档定长填充（FR-3.3 元数据保护 / 《产品设计报告》§5.1 消息投递）。
 *
 * 档位：0=256B / 1=1KB / 2=16KB / 3=128KB。填充后总长恒等于档位长度，
 * 使中继与存储节点无法从密文长度推断真实消息大小（长度侧信道抑制）。
 * 时间侧信道抑制由 envelope.ts 的 timestampBucket（时间桶）配合。
 *
 * 线格式（大端）：[4B 原始长度][payload][零填充至档位长度]。
 *
 * 纯函数库：无日志、无 I/O。
 */

/** 填充四档大小（字节）：FR-3.3 / 设计报告 §5.1 */
export const PAD_SIZES = [256, 1024, 16_384, 131_072] as const;

/** 填充档位：0=256B / 1=1KB / 2=16KB / 3=128KB */
export type PadClass = 0 | 1 | 2 | 3;

/** 长度头字节数（4B 大端原长） */
const LENGTH_HEADER_SIZE = 4;

/** 大端写 32 位无符号整数（手工逐字节，规避 TypedArray buffer 偏移陷阱） */
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
 * 按负载长度选择最小可容纳档位；超过最大档位（131072）抛错。
 *
 * 判定口径：length ≤ PAD_SIZES[c]（不含 4B 长度头的线路开销；
 * 含头的容量校验由 applyPadding 在落档时执行，payload 不合规即抛错）。
 */
export function padClassForLength(length: number): PadClass {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError(`填充长度必须为非负安全整数，收到 ${length}`);
  }
  for (const c of [0, 1, 2, 3] as const) {
    if (length <= PAD_SIZES[c]) {
      return c;
    }
  }
  throw new RangeError(`长度 ${length} 超过最大填充档位 ${PAD_SIZES[3]}`);
}

/**
 * 施加填充：[4B 原长 BE][payload][零填充]，输出总长恒等于档位长度
 * （填充不泄露真实长度，FR-3.3）。
 *
 * @throws payload 加 4B 长度头超过档位容量（PAD_SIZES[padClass] - 4）时
 */
export function applyPadding(payload: Uint8Array, padClass: PadClass): Uint8Array {
  const totalSize: number = PAD_SIZES[padClass];
  const maxPayload = totalSize - LENGTH_HEADER_SIZE;
  if (!Number.isSafeInteger(payload.length) || payload.length < 0) {
    throw new RangeError(`payload 长度非法：${payload.length}`);
  }
  if (payload.length > maxPayload) {
    throw new RangeError(
      `payload 长度 ${payload.length} 超过档位 ${padClass} 的可容纳上限 ${maxPayload}`,
    );
  }
  // Uint8Array 零初始化，尾部天然为零填充
  const out = new Uint8Array(totalSize);
  writeUint32BE(out, 0, payload.length);
  out.set(payload, LENGTH_HEADER_SIZE);
  return out;
}

/**
 * 剥离填充并校验完整性，违规即抛错（防畸形输入被静默误读）：
 *  1. 总长必须恰为某个档位长度；
 *  2. 长度头不得超过该档位的可容纳上限；
 *  3. 长度头之后的填充区必须全零。
 *
 * @returns payload 的独立副本（slice 拷贝，与输入缓冲区隔离）
 */
export function stripPadding(padded: Uint8Array): Uint8Array {
  const totalSize = padded.length;
  let padClass: PadClass | undefined;
  for (const c of [0, 1, 2, 3] as const) {
    if (totalSize === PAD_SIZES[c]) {
      padClass = c;
      break;
    }
  }
  if (padClass === undefined) {
    throw new Error(`填充总长 ${totalSize} 不是任何合法档位（${PAD_SIZES.join("/")}）`);
  }

  const maxPayload = totalSize - LENGTH_HEADER_SIZE;
  const origLength = readUint32BE(padded, 0);
  if (origLength > maxPayload) {
    throw new Error(`长度头 ${origLength} 超过档位 ${padClass} 容量上限 ${maxPayload}，疑似畸形输入`);
  }
  for (let i = LENGTH_HEADER_SIZE + origLength; i < totalSize; i++) {
    if (padded[i] !== 0) {
      throw new Error(`偏移 ${i} 处填充字节非零，疑似畸形或被篡改的填充`);
    }
  }
  return padded.slice(LENGTH_HEADER_SIZE, LENGTH_HEADER_SIZE + origLength);
}
