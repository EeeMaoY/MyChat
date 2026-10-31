/**
 * envelope 模块测试：填充四档（FR-3.3）、会话信箱伪地址（FR-3.1）、
 * 信封二进制编解码与时间桶（设计报告 §5.1 / §11.1 M0 子集）。
 */
import { describe, expect, it } from "vitest";

import * as envelopeApi from "../index.ts";
import {
  DEFAULT_TIME_BUCKET_MS,
  ENVELOPE_VERSION,
  decodeEnvelope,
  encodeEnvelope,
  makeEnvelope,
  timestampBucket,
} from "../envelope.ts";
import { PAD_SIZES, applyPadding, padClassForLength, stripPadding } from "../padding.ts";
import { deriveSessionMailbox } from "../pseudonym.ts";
import { base58Decode, concatBytes, utf8ToBytes } from "../../codec/index.ts";
import type { Envelope } from "../../protocol/interfaces.ts";

const PAD_CLASSES = [0, 1, 2, 3] as const;

/** 分块填充随机字节（crypto.getRandomValues 单次上限 65536 字节） */
function randomBytesForTest(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  const CHUNK = 65_536;
  for (let i = 0; i < length; i += CHUNK) {
    crypto.getRandomValues(bytes.subarray(i, Math.min(i + CHUNK, length)));
  }
  return bytes;
}

describe("padding：四档定长填充（FR-3.3 / 设计报告 §5.1）", () => {
  it("padClassForLength 档位边界", () => {
    const cases: Array<[number, 0 | 1 | 2 | 3]> = [
      [0, 0],
      [256, 0],
      [257, 1],
      [1024, 1],
      [1025, 2],
      [16_384, 2],
      [16_385, 3],
      [131_072, 3],
    ];
    for (const [length, expected] of cases) {
      expect(padClassForLength(length), `长度 ${length}`).toBe(expected);
    }
  });

  it("padClassForLength 超档与非法输入抛错", () => {
    expect(() => padClassForLength(131_073)).toThrow();
    expect(() => padClassForLength(-1)).toThrow();
    expect(() => padClassForLength(1.5)).toThrow();
    expect(() => padClassForLength(Number.NaN)).toThrow();
  });

  it("applyPadding/stripPadding 往返：空 payload 与各档位边界长度", () => {
    for (const c of PAD_CLASSES) {
      const maxPayload = PAD_SIZES[c] - 4;
      for (const len of [0, 1, Math.floor(maxPayload / 2), maxPayload - 1, maxPayload]) {
        const payload = randomBytesForTest(len);
        const round = stripPadding(applyPadding(payload, c));
        expect(round, `档位 ${c} 长度 ${len}`).toEqual(payload);
      }
    }
  });

  it("applyPadding 输出长度恒等于档位长度（填充不泄露真实长度）", () => {
    for (const c of PAD_CLASSES) {
      const maxPayload = PAD_SIZES[c] - 4;
      for (const len of [0, 1, Math.floor(maxPayload / 2), maxPayload - 1, maxPayload]) {
        expect(applyPadding(randomBytesForTest(len), c)).toHaveLength(PAD_SIZES[c]);
      }
    }
  });

  it("applyPadding 超档位 payload 抛错", () => {
    for (const c of PAD_CLASSES) {
      expect(() => applyPadding(randomBytesForTest(PAD_SIZES[c] - 3), c)).toThrow();
    }
    // 明显超档：131072B payload 配最小档
    expect(() => applyPadding(randomBytesForTest(131_072), 0)).toThrow();
  });

  it("stripPadding 对畸形输入抛错", () => {
    // 长度头 > 档位实际容量：256B 档内声明 253B payload（> 252）
    const badHeader = new Uint8Array(256);
    badHeader[3] = 253;
    expect(() => stripPadding(badHeader)).toThrow();

    // 尾部填充区非零
    const dirtyTail = applyPadding(utf8ToBytes("hello"), 0);
    dirtyTail[100] = 1;
    expect(() => stripPadding(dirtyTail)).toThrow();

    // 总长不是任何合法档位
    expect(() => stripPadding(new Uint8Array(100))).toThrow();

    // 截断：不足 4B 长度头
    expect(() => stripPadding(new Uint8Array(3))).toThrow();
    expect(() => stripPadding(new Uint8Array(0))).toThrow();
  });
});

describe("pseudonym：会话信箱伪地址（FR-3.1 / 设计报告 §5.1）", () => {
  const secret = randomBytesForTest(32);
  const secret2 = randomBytesForTest(32);

  it("同参数确定性", () => {
    const a = deriveSessionMailbox(secret, 7, true, true);
    const b = deriveSessionMailbox(secret, 7, true, true);
    expect(a).toBe(b);
  });

  it("两端视角派生同一信箱：发起方发信(i2r) == 响应方收信", () => {
    expect(deriveSessionMailbox(secret, 3, true, true)).toBe(
      deriveSessionMailbox(secret, 3, false, false),
    );
  });

  it("两端视角派生同一信箱：响应方发信(r2i) == 发起方收信", () => {
    expect(deriveSessionMailbox(secret, 3, false, true)).toBe(
      deriveSessionMailbox(secret, 3, true, false),
    );
  });

  it("不同 epoch / 不同共享秘密 / 不同方向产生不同值", () => {
    const base = deriveSessionMailbox(secret, 0, true, true);
    expect(deriveSessionMailbox(secret, 1, true, true)).not.toBe(base);
    expect(deriveSessionMailbox(secret2, 0, true, true)).not.toBe(base);
    // i2r 与 r2i 两方向信箱不同
    expect(deriveSessionMailbox(secret, 0, false, true)).not.toBe(base);
    expect(deriveSessionMailbox(secret, 0, true, false)).not.toBe(base);

    // 每 epoch 轮换：连续 8 个 epoch 两方向地址互不重复
    const seen = new Set<string>();
    for (let epoch = 0; epoch < 8; epoch++) {
      seen.add(deriveSessionMailbox(secret, epoch, true, true));
      seen.add(deriveSessionMailbox(secret, epoch, false, true));
    }
    expect(seen.size).toBe(16);
  });

  it("输出为合法 base58 且解码后恰为 18 字节", () => {
    for (const epoch of [0, 1, 12345, 2 ** 40]) {
      for (const [isInitiator, sending] of [
        [true, true],
        [true, false],
        [false, true],
        [false, false],
      ] as const) {
        const addr = deriveSessionMailbox(secret, epoch, isInitiator, sending);
        expect(base58Decode(addr), `epoch=${epoch}`).toHaveLength(18);
      }
    }
  });

  it("非法输入抛错（空共享秘密 / 负数或非整数 epoch）", () => {
    expect(() => deriveSessionMailbox(new Uint8Array(0), 0, true, true)).toThrow();
    expect(() => deriveSessionMailbox(secret, -1, true, true)).toThrow();
    expect(() => deriveSessionMailbox(secret, 1.5, true, true)).toThrow();
  });
});

describe("envelope：二进制编解码（设计报告 §11.1 M0 子集）", () => {
  const nonce = randomBytesForTest(24);
  const payload = randomBytesForTest(100);

  function sampleEnvelope(): Envelope {
    return {
      version: "1",
      epoch: 42,
      toPseudonym: "4ZHfqJBoBn",
      padClass: 1,
      nonce,
      payload,
    };
  }

  it("encode/decode 往返（含中文伪地址、全部档位、空 payload）", () => {
    const pseudonyms = ["mailbox-abc", "收件信箱-张三", "📮信箱"];
    for (const pseudo of pseudonyms) {
      for (const padClass of PAD_CLASSES) {
        const e: Envelope = { version: "1", epoch: 7, toPseudonym: pseudo, padClass, nonce, payload };
        const decoded = decodeEnvelope(encodeEnvelope(e));
        expect(decoded.version).toBe("1");
        expect(decoded.epoch).toBe(7);
        expect(decoded.toPseudonym).toBe(pseudo);
        expect(decoded.padClass).toBe(padClass);
        expect(decoded.nonce).toEqual(nonce);
        expect(decoded.payload).toEqual(payload);
      }
    }
    // 空 payload 往返
    const empty: Envelope = {
      version: "1",
      epoch: 0,
      toPseudonym: "x",
      padClass: 0,
      nonce,
      payload: new Uint8Array(0),
    };
    expect(decodeEnvelope(encodeEnvelope(empty)).payload).toEqual(new Uint8Array(0));
  });

  it("线格式布局符合 §11.1：字段偏移、大端序与总长", () => {
    const pseudo = "abc";
    const e: Envelope = {
      version: "1",
      epoch: 0x01_02_03_04,
      toPseudonym: pseudo,
      padClass: 2,
      nonce,
      payload,
    };
    const bytes = encodeEnvelope(e);
    expect(bytes[0]).toBe(ENVELOPE_VERSION);
    expect(bytes[1]).toBe(0x01); // epoch 大端：最高字节在前
    expect(bytes[2]).toBe(0x02);
    expect(bytes[3]).toBe(0x03);
    expect(bytes[4]).toBe(0x04);
    expect(bytes[5]).toBe(2); // padClass
    expect(bytes.slice(6, 30)).toEqual(nonce);
    expect(bytes[30]).toBe(pseudo.length); // N
    expect(bytes.slice(31, 31 + pseudo.length)).toEqual(utf8ToBytes(pseudo));
    // [4B payload 长度] 位于偏移 34..37，值 100 = 0x00000064
    expect(bytes[34]).toBe(0x00);
    expect(bytes[37]).toBe(0x64);
    expect(bytes).toHaveLength(35 + pseudo.length + payload.length);
    // 解码后重编码字节级一致（规范化）
    expect(encodeEnvelope(decodeEnvelope(bytes))).toEqual(bytes);
  });

  it("decode 对截断输入抛错", () => {
    const bytes = encodeEnvelope(sampleEnvelope());
    for (const cut of [0, 1, 5, 20, 33, bytes.length - 5, bytes.length - 1]) {
      expect(() => decodeEnvelope(bytes.slice(0, cut)), `截断至 ${cut} 字节`).toThrow();
    }
    // 伪地址长度声明越界
    const badPseudoLen = bytes.slice();
    badPseudoLen[30] = 200;
    expect(() => decodeEnvelope(badPseudoLen)).toThrow();
  });

  it("decode 对错误版本号抛错", () => {
    const bytes = encodeEnvelope(sampleEnvelope());
    const bad2 = bytes.slice();
    bad2[0] = 2;
    expect(() => decodeEnvelope(bad2)).toThrow();
    const bad0 = bytes.slice();
    bad0[0] = 0;
    expect(() => decodeEnvelope(bad0)).toThrow();
  });

  it("decode 对非法 padClass 与尾部夹带数据抛错", () => {
    const bytes = encodeEnvelope(sampleEnvelope());
    const badClass = bytes.slice();
    badClass[5] = 4;
    expect(() => decodeEnvelope(badClass)).toThrow();
    expect(() => decodeEnvelope(concatBytes(bytes, new Uint8Array([0x01])))).toThrow();
  });

  it("encode 对非法字段抛错（版本 / nonce 长度 / epoch 越界 / 伪地址越界）", () => {
    expect(() => encodeEnvelope({ ...sampleEnvelope(), version: "2" })).toThrow();
    expect(() => encodeEnvelope({ ...sampleEnvelope(), nonce: new Uint8Array(12) })).toThrow();
    expect(() => encodeEnvelope({ ...sampleEnvelope(), epoch: 2 ** 32 })).toThrow();
    expect(() => encodeEnvelope({ ...sampleEnvelope(), toPseudonym: "" })).toThrow();
    expect(() => encodeEnvelope({ ...sampleEnvelope(), toPseudonym: "x".repeat(256) })).toThrow();
  });

  it("makeEnvelope 自动生成 24B nonce，且编解码往返一致", () => {
    const a = makeEnvelope({ epoch: 1, toPseudonym: "p", padClass: 0, payload });
    const b = makeEnvelope({ epoch: 1, toPseudonym: "p", padClass: 0, payload });
    expect(a.version).toBe("1");
    expect(a.nonce).toHaveLength(24);
    expect(b.nonce).not.toEqual(a.nonce);
    expect(decodeEnvelope(encodeEnvelope(a))).toEqual(a);
  });
});

describe("timestampBucket：时间桶（FR-3.3 时序关联抑制）", () => {
  it("默认 60_000，跨桶边界正确", () => {
    expect(timestampBucket(0)).toBe(0);
    expect(timestampBucket(59_999)).toBe(0);
    expect(timestampBucket(60_000)).toBe(1);
    expect(timestampBucket(119_999)).toBe(1);
    expect(timestampBucket(120_000)).toBe(2);
    const now = Date.now();
    expect(timestampBucket(now)).toBe(timestampBucket(now, DEFAULT_TIME_BUCKET_MS));
    expect(DEFAULT_TIME_BUCKET_MS).toBe(60_000);
  });

  it("自定义桶粒度", () => {
    expect(timestampBucket(499, 500)).toBe(0);
    expect(timestampBucket(500, 500)).toBe(1);
    expect(timestampBucket(1_500, 500)).toBe(3);
    expect(timestampBucket(90_000, 30_000)).toBe(3);
  });

  it("非法桶宽与非有限时间戳抛错", () => {
    expect(() => timestampBucket(1, 0)).toThrow();
    expect(() => timestampBucket(1, -100)).toThrow();
    expect(() => timestampBucket(Number.NaN)).toThrow();
    expect(() => timestampBucket(Number.POSITIVE_INFINITY)).toThrow();
  });
});

describe("envelope/index 公共 API 面", () => {
  it("re-export 全部公共 API", () => {
    for (const name of [
      "PAD_SIZES",
      "applyPadding",
      "padClassForLength",
      "stripPadding",
      "deriveSessionMailbox",
      "DEFAULT_TIME_BUCKET_MS",
      "ENVELOPE_VERSION",
      "decodeEnvelope",
      "encodeEnvelope",
      "makeEnvelope",
      "timestampBucket",
    ]) {
      expect(envelopeApi, `缺少导出: ${name}`).toHaveProperty(name);
    }
  });
});
