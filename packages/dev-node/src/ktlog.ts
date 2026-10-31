/**
 * KT Log（密钥透明日志）M1 实现：append-only 事件序列 + Merkle 根链（FR-1.6）。
 *
 * - 包含性证明：客户端可验证"我的注册事件在日志中"（与 @mychat/core ktmerkle 同构互验）
 * - 根链：每次 append 后的根按序记录（append-only），多副本比对根链可发现分叉（M2）
 * - RFC 6962 一致性证明与第三方副本交叉核验为 M2
 */
import type { KTEvent } from "@mychat/core";
import { type KtInclusionProof, ktInclusionProof, ktLeafHash, ktMerkleRoot } from "@mychat/core";

export interface KTLogStore {
  events: KTEvent[];
  /** 与 events 一一对应的叶哈希（Merkle 叶层，未补齐） */
  leaves: Uint8Array[];
  /** append-only 根链：每次 append 后的 (事件序号, 根) */
  rootHistory: { afterIndex: number; root: string }[];
  /** did → 事件下标数组（加速 list） */
  byDid: Map<string, number[]>;
  nextIndex: number;
}

export function createKTLogStore(): KTLogStore {
  return { events: [], leaves: [], rootHistory: [], byDid: new Map(), nextIndex: 0 };
}

export function appendEvent(store: KTLogStore, event: Omit<KTEvent, "index">): KTEvent {
  const full: KTEvent = { ...event, index: store.nextIndex++ };
  store.events.push(full);
  store.leaves.push(ktLeafHash(full));
  store.rootHistory.push({ afterIndex: full.index, root: ktMerkleRoot(store.leaves) });
  const list = store.byDid.get(full.did);
  if (list) list.push(full.index);
  else store.byDid.set(full.did, [full.index]);
  return full;
}

export function listEvents(store: KTLogStore, did: string): KTEvent[] {
  return (store.byDid.get(did) ?? []).map((i) => store.events[i]!);
}

export function ktLogRoot(store: KTLogStore): { size: number; root: string } {
  if (store.leaves.length === 0) return { size: 0, root: "" };
  return { size: store.leaves.length, root: ktMerkleRoot(store.leaves) };
}

export function ktLogInclusionProof(store: KTLogStore, index: number): KtInclusionProof | undefined {
  if (index < 0 || index >= store.leaves.length) return undefined;
  return ktInclusionProof(store.leaves, index);
}
