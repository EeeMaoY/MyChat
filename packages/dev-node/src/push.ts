/**
 * Web Push 推送网关（M4-S15，W2 补全）：页面关闭后的新消息唤醒。
 *
 * 隐私模型（与 §9.5 唤醒网关同一语义的离线延伸）：节点向浏览器推送服务发送
 * **无 payload 的 push**（空消息体）——推送服务与节点都接触不到任何内容或信箱
 * 语义信息；SW 收到 push 事件后展示本地静态文案"有新消息"。订阅映射
 * （endpoint → 关注的信箱伪地址列表）仅存于本节点内存/数据目录。
 *
 * VAPID（RFC 8292，web-push 库）：密钥首次生成后持久化到数据目录（订阅的
 * applicationServerKey 必须与发送时私钥匹配）；纯内存模式每次重启重新生成
 * （旧订阅失效——开发属性，如实登记）。
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";

// web-push 为 CJS 包且无法经 ESM default 互操作加载（Node 直跑 TS 场景）：
// 以 createRequire 引入（strip-only 完全支持；TR-1 纪律不变——审计库仅换加载方式）。
const requireCjs = createRequire(import.meta.url);
const webpush = requireCjs("web-push") as typeof import("web-push");

export interface PushSubscriptionRecord {
  /** 浏览器推送服务分配的订阅端点（唯一键） */
  endpoint: string;
  /** 原始订阅（keys.p256dh/auth 用于协议握手；无 payload push 仍需合法结构） */
  subscription: webpush.PushSubscription;
  /** 该设备关注的信箱伪地址（与客户端 startRealtime 的订阅面一致） */
  mailboxes: string[];
}

export interface PushStore {
  /** endpoint → 订阅记录 */
  subscriptions: Map<string, PushSubscriptionRecord>;
  vapid: { publicKey: string; privateKey: string };
  /** 发送实现（默认 web-push；测试可注入 spy/桩） */
  sender?: (subscription: webpush.PushSubscription, vapidDetails: { publicKey: string; privateKey: string; subject: string }) => Promise<void>;
}

/** 载入或生成 VAPID 密钥：数据目录持久化（跨重启稳定）；无目录则内存生成。 */
function loadOrCreateVapid(persistDir: string | undefined): { publicKey: string; privateKey: string } {
  if (persistDir !== undefined) {
    const path = join(persistDir, "vapid.json");
    if (existsSync(path)) {
      try {
        const parsed = JSON.parse(readFileSync(path, "utf8")) as { publicKey?: string; privateKey?: string };
        if (typeof parsed.publicKey === "string" && typeof parsed.privateKey === "string") {
          return { publicKey: parsed.publicKey, privateKey: parsed.privateKey };
        }
      } catch {
        console.warn("[mychat-dev-node] VAPID 密钥文件损坏，重新生成");
      }
    }
    const keys = webpush.generateVAPIDKeys();
    writeFileSync(path, JSON.stringify(keys));
    return keys;
  }
  return webpush.generateVAPIDKeys();
}

export function createPushStore(persistDir: string | undefined): PushStore {
  return { subscriptions: new Map(), vapid: loadOrCreateVapid(persistDir) };
}

export interface PushResult {
  ok: boolean;
  removed: boolean;
}

/** 登记/更新订阅（幂等；mailboxes 覆盖——信箱面变化时客户端整体重发）。 */
export function putSubscription(store: PushStore, subscription: webpush.PushSubscription, mailboxes: string[]): void {
  store.subscriptions.set(subscription.endpoint, { endpoint: subscription.endpoint, subscription, mailboxes });
}

export function removeSubscription(store: PushStore, endpoint: string): boolean {
  return store.subscriptions.delete(endpoint);
}

/** 与信箱关联的订阅端点列表（投递用）。 */
export function endpointsForMailbox(store: PushStore, mailboxId: string): PushSubscriptionRecord[] {
  return [...store.subscriptions.values()].filter((s) => s.mailboxes.includes(mailboxId));
}

/**
 * 向某信箱关联的全部订阅发送无 payload push（fire-and-forget）。
 * 410 Gone（订阅过期）等终态错误自动移除订阅。永不抛出（推送失败不影响投递主路径）。
 */
export async function notifyMailbox(store: PushStore, mailboxId: string): Promise<void> {
  const vapidDetails = { subject: "mailto:dev@mychat.local", ...store.vapid };
  const send = store.sender ?? ((subscription, vapid) => webpush.sendNotification(subscription, undefined, { vapidDetails: vapid }));
  const targets = endpointsForMailbox(store, mailboxId);
  await Promise.allSettled(
    targets.map(async (record) => {
      try {
        await send(record.subscription, vapidDetails);
      } catch (err) {
        const statusCode = (err as { statusCode?: number }).statusCode;
        if (statusCode === 404 || statusCode === 410) {
          store.subscriptions.delete(record.endpoint);
        }
      }
    }),
  );
}
