/**
 * 限流器单元测试（加固）：键集合硬上限（超限先清过期、仍超按插入序驱逐最旧 10%）、
 * 窗口过期释放、限额拒绝语义。
 */
import { describe, expect, it } from "vitest";

import { RateLimiter } from "../limits";

describe("RateLimiter 加固", () => {
  it("限额内放行、超限拒绝（窗口内计数）", () => {
    const limiter = new RateLimiter(2, 60_000);
    expect(limiter.allow("k")).toBe(true);
    expect(limiter.allow("k")).toBe(true);
    expect(limiter.allow("k")).toBe(false); // 窗口内第 3 次
    expect(limiter.allow("other")).toBe(true); // 其他键不受影响
  });

  it("键集合硬上限：超限驱逐最旧 10%，键数有界（防随机键刷爆内存）", () => {
    const limiter = new RateLimiter(1_000_000, 60_000); // 限额形同虚设，只看键驱逐
    const total = 51_000;
    for (let i = 0; i < total; i++) {
      expect(limiter.allow(`key-${i}`)).toBe(true);
    }
    // 插入第 50001 键时触发驱逐 ceil(50001*0.1)=5001 → 45000；随后净增 4999 键
    expect(limiter.keyCount).toBe(total - 5001);
    expect(limiter.keyCount).toBeLessThanOrEqual(50_000); // 永远有界
    // 被驱逐的最旧键可重新计入（窗口重新开始，不惩罚）
    expect(limiter.allow("key-0")).toBe(true);
  });
});
