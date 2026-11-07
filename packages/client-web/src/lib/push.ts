/**
 * Web Push 订阅编排（M4-S15，W2 补全）：页面关闭后的新消息系统通知。
 *
 * 时机：main 启动后异步注册（浏览器通知权限已 granted 才订阅，不主动弹窗）；
 * 信箱面变化（新会话/群/退出）随 startRealtime 的 mailboxes 列表整体重发 PUT。
 * 失败一律静默（推送是增强能力，不阻塞主路径）。
 *
 * 边界（如实登记）：通知内容为固定文案（无 payload push，隐私优先）；
 * Chrome/Edge 要求 HTTPS 或 localhost；iOS Safari 需 PWA 安装。
 */
import { fromBase64, toBase64 } from "./base64";
import type { NodeApi } from "./node-api";

let currentSubscriptionEndpoint: string | null = null;

/** 注册 SW 并（在权限允许时）建立 push 订阅；返回是否成功。 */
export async function ensurePushSubscription(api: NodeApi, mailboxes: string[]): Promise<boolean> {
  try {
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) return false;
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return false;
    const registration = await navigator.serviceWorker.register("/sw.js");
    await navigator.serviceWorker.ready;
    const { publicKey } = await api.getVapidPublicKey();
    const existing = await registration.pushManager.getSubscription();
    const applicationServerKey = urlBase64ToUint8Array(publicKey);
    const subscription =
      existing ??
      (await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey }));
    const json = subscription.toJSON() as { endpoint?: string; keys?: Record<string, string> };
    if (typeof json.endpoint !== "string") return false;
    await api.putPushSubscription(json as never, mailboxes);
    currentSubscriptionEndpoint = json.endpoint;
    return true;
  } catch {
    return false;
  }
}

/** 信箱面变化：整体重发 mailboxes（复用既有订阅，不再 subscribe）。 */
export async function updatePushMailboxes(api: NodeApi, mailboxes: string[]): Promise<void> {
  try {
    if (currentSubscriptionEndpoint === null) return;
    const registration = await navigator.serviceWorker.getRegistration();
    const subscription = await registration?.pushManager.getSubscription();
    if (subscription === undefined) return;
    const json = subscription.toJSON() as { endpoint?: string };
    if (typeof json.endpoint !== "string") return;
    await api.putPushSubscription(json as never, mailboxes);
  } catch {
    /* 静默 */
  }
}

/** 注销（锁定/退出时调用；尽力而为）。 */
export async function releasePushSubscription(api: NodeApi): Promise<void> {
  try {
    if (currentSubscriptionEndpoint !== null) {
      await api.deletePushSubscription(currentSubscriptionEndpoint);
      currentSubscriptionEndpoint = null;
    }
  } catch {
    /* 静默 */
  }
}

/** VAPID 公钥（base64url）→ 订阅所需的 Uint8Array。 */
function urlBase64ToUint8Array(base64url: string): Uint8Array {
  const padded = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const raw = fromBase64(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return raw;
}

void toBase64;
