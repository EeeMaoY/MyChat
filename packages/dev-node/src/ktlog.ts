/**
 * KT Log（密钥透明日志）v0 实现：append-only 事件序列（M0 子集）。
 *
 * Merkle 包含性/一致性证明与第三方副本交叉核验为 M1（FR-1.6）；
 * v0 已保证：全局单调序号、append-only 接口（无删除/修改 API）、
 * 与 Registry 联动锚定全部用户名注册历史（SR-5 的可举证基础）。
 */
import type { KTEvent } from "@mychat/core";

export interface KTLogStore {
  events: KTEvent[];
  /** did → 事件下标数组（加速 list） */
  byDid: Map<string, number[]>;
  nextIndex: number;
}

export function createKTLogStore(): KTLogStore {
  return { events: [], byDid: new Map(), nextIndex: 0 };
}

export function appendEvent(store: KTLogStore, event: Omit<KTEvent, "index">): KTEvent {
  const full: KTEvent = { ...event, index: store.nextIndex++ };
  store.events.push(full);
  const list = store.byDid.get(full.did);
  if (list) list.push(full.index);
  else store.byDid.set(full.did, [full.index]);
  return full;
}

export function listEvents(store: KTLogStore, did: string): KTEvent[] {
  return (store.byDid.get(did) ?? []).map((i) => store.events[i]!);
}
