/**
 * 资源限流（M4-S13）：资源治理而非鉴权——零信任语义下节点不裁决身份，
 * 只保护自身资源与投递质量：按信箱伪地址限速（防定向灌垃圾）、按节点全局
 * 限块/注册（防资源耗尽）。超限返回 429；参数可经启动选项注入（测试/部署调优）。
 */

/** 键集合硬上限（防键空间被随机键刷爆内存）：超限先清过期，仍超则按插入序驱逐最旧 10%。 */
const MAX_KEYS = 50_000;
/** 过期全量清扫的最小间隔（ms）：清扫 O(n)，限频防高频路径放大。 */
const SWEEP_MIN_INTERVAL_MS = 1_000;

/** 简单滑动窗口计数器（内存态；窗口过期即释放语义，不做持久化）。 */
export class RateLimiter {
  private windows = new Map<string, number[]>();
  private limit: number;
  private windowMs: number;
  private lastSweep = 0;

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  /** 当前键数（观测/测试用）。 */
  get keyCount(): number {
    return this.windows.size;
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
    // 窗口清理：防长期运行下的 key 累积（全量清扫限频；键数超限则强制清扫）
    if (this.windows.size > 10_000 && now - this.lastSweep >= SWEEP_MIN_INTERVAL_MS) {
      this.lastSweep = now;
      for (const [k, ts] of this.windows) {
        if (ts.every((t) => now - t >= this.windowMs)) this.windows.delete(k);
      }
    }
    if (this.windows.size > MAX_KEYS) {
      const evict = Math.ceil(this.windows.size * 0.1);
      let evicted = 0;
      for (const k of this.windows.keys()) {
        this.windows.delete(k); // Map 保持插入序：先删最旧
        if (++evicted >= evict) break;
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
  /** 每分钟手动 KT 追加上限（每次 append 全量重建 Merkle 根，O(n²) 累积，限流压住） */
  ktAppendPerMin: 60,
  /** 每 DID 每分钟设备凭证登记上限 */
  devicePutPerMin: 60,
  /** 单 DID 设备数上限（防凭证表被单 DID 无限膨胀） */
  maxDevicesPerDid: 32,
  /** 块字节总量上限（512MB；条数上限之外的内存/磁盘护栏） */
  maxBlocksTotalBytes: 536_870_912,
  /** 信箱总数上限（防轮换随机 mailboxId 绕过按箱限刷） */
  maxMailboxes: 5000,
  /** WS 并发连接数上限（半开连接/订阅表膨胀护栏） */
  maxWsConnections: 64,
  /** Push 订阅表总量上限 */
  maxPushSubscriptions: 10_000,
  /** 每分钟 push 订阅登记上限（节点全局） */
  pushSubscribePerMin: 60,
} as const;

export type Limits = { -readonly [K in keyof typeof DEFAULT_LIMITS]: number };
