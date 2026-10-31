/**
 * Relay（中继池）M0 实现：在线唤醒与直投的订阅中枢。
 *
 * - mailbox-activity：信箱新内容唤醒信号（M0 主投递路径的加速器，见 storage.ts 说明）
 * - envelope 直投：IRelay.send 的协议边界实现（不落盘，在线客户端可选用加速路径）
 *
 * 中继只见伪地址（订阅键即伪地址），不知收发双方身份（SR-2）。
 */
import type { WebSocket } from "ws";
import type { Envelope } from "@mychat/core";

export interface RelayNotification {
  type: "mailbox-activity";
  mailboxId: string;
}

export interface RelayDelivery {
  type: "envelope";
  envelope: Envelope;
}

export class RelayHub {
  private subs = new Map<string, Set<WebSocket>>();

  subscribe(mailboxId: string, ws: WebSocket): void {
    let set = this.subs.get(mailboxId);
    if (!set) {
      set = new Set();
      this.subs.set(mailboxId, set);
    }
    set.add(ws);
    ws.once("close", () => {
      set?.delete(ws);
      if (set && set.size === 0) this.subs.delete(mailboxId);
    });
  }

  /** 信箱有新内容：通知订阅者（携带信箱 ID，客户端自行拉取）。 */
  notifyActivity(mailboxId: string): void {
    const message = JSON.stringify({ type: "mailbox-activity", mailboxId } satisfies RelayNotification);
    for (const ws of this.subs.get(mailboxId) ?? []) {
      if (ws.readyState === ws.OPEN) ws.send(message);
    }
  }

  /** 在线直投：向订阅了该伪地址的客户端推送信封本体。 */
  deliver(mailboxId: string, envelope: Envelope): number {
    const message = JSON.stringify({ type: "envelope", envelope });
    let count = 0;
    for (const ws of this.subs.get(mailboxId) ?? []) {
      if (ws.readyState === ws.OPEN) {
        ws.send(message);
        count += 1;
      }
    }
    return count;
  }
}
