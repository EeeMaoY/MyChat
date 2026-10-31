/**
 * Storage（存储节点）实现：加密块 + 离线信箱（协议接口见 @mychat/core）。
 *
 * 信任边界（设计报告 §2.3 / SR-1）：只见密文——节点无法解密，
 * 唯一职责是"按地址存取字节"。块寻址内容由客户端 CID（BLAKE3）自校验。
 *
 * M0 信箱模型（ADR-11 补充决策）：信箱为主投递通道，Relay 仅作
 * 新内容唤醒信号（客户端单一处理路径，天然去重，NFR-5 最终一致）。
 * 每个信箱条目带单调 cursor，客户端增量拉取。
 */
import type { Envelope } from "@mychat/core";

export interface MailboxEntry {
  cursor: number;
  envelope: Envelope;
  appendedAt: number;
}

export interface StorageStore {
  blocks: Map<string, Uint8Array>;
  mailboxes: Map<string, { nextCursor: number; entries: MailboxEntry[] }>;
}

export function createStorageStore(): StorageStore {
  return { blocks: new Map(), mailboxes: new Map() };
}

export function putBlock(store: StorageStore, cid: string, data: Uint8Array): void {
  if (store.blocks.has(cid)) return; // 内容寻址：幂等
  store.blocks.set(cid, data);
}

export function getBlock(store: StorageStore, cid: string): Uint8Array | undefined {
  return store.blocks.get(cid);
}

export function mailboxAppend(store: StorageStore, mailboxId: string, envelope: Envelope): number {
  let box = store.mailboxes.get(mailboxId);
  if (!box) {
    box = { nextCursor: 0, entries: [] };
    store.mailboxes.set(mailboxId, box);
  }
  const entry: MailboxEntry = { cursor: box.nextCursor++, envelope, appendedAt: Date.now() };
  box.entries.push(entry);
  return entry.cursor;
}

export function mailboxFetch(
  store: StorageStore,
  mailboxId: string,
  cursor: number,
): { envelopes: Envelope[]; cursor: number } {
  const box = store.mailboxes.get(mailboxId);
  if (!box) return { envelopes: [], cursor: 0 };
  const envelopes = box.entries.filter((e) => e.cursor >= cursor).map((e) => e.envelope);
  return { envelopes, cursor: box.nextCursor };
}
