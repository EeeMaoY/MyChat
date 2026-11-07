/**
 * 资源限流（M4-S13）：资源治理而非鉴权——零信任语义下节点不裁决身份，
 * 只保护自身资源与投递质量：按信箱伪地址限速（防定向灌垃圾）、按节点全局
 * 限块/注册（防资源耗尽）。超限返回 429；参数可经启动选项注入（测试/部署调优）。
 */

/** 简单滑动窗口计数器（内存态；窗口过期即释放语义，不做持久化）。 */
export class RateLimiter {
  private windows = new Map<string, number[]>();
  private limit: number;
  private windowMs: number;

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  /** 是否允许本次操作（允许则记录；拒绝不记录，失败重试不加倍惩罚）。 */
  allow(key: string): boolean {
    const now = Date.now();
    const window = (this.windows.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (window.length >= this.limit) {
      this.windows.set(key, window);
      return false;
    }
    window.push(now);
    this.windows.set(key, window);
    // 窗口清理：防长期运行下的 key 累积
    if (this.windows.size > 10_000) {
      for (const [k, ts] of this.windows) {
        if (ts.every((t) => now - t >= this.windowMs)) this.windows.delete(k);
      }
    }
    return true;
  }
}

/** 默认限流参数（60s 窗口；部署可用启动选项覆盖）。 */
export const DEFAULT_LIMITS = {
  /** 每信箱每分钟 append 上限（防定向灌垃圾；正常会话三 epoch 轮询远低于此值） */
  mailboxAppendPerMin: 120,
  /** 每分钟块 PUT 上限（节点全局，含动态/附件/托管写入） */
  blockPutPerMin: 600,
  /** 每分钟注册上限（防脚本批量注册） */
  registerPerMin: 60,
  /** 块总量上限（内存/磁盘资源护栏） */
  maxBlocks: 20_000,
} as const;

export type Limits = { -readonly [K in keyof typeof DEFAULT_LIMITS]: number };
