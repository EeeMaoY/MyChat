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
  /** 块字节总量（put/delete 时增减；字节配额护栏，防 16MB×N 的内存炸弹） */
  blocksTotalBytes: number;
  mailboxes: Map<string, { nextCursor: number; entries: MailboxEntry[] }>;
}

export function createStorageStore(): StorageStore {
  return { blocks: new Map(), blocksTotalBytes: 0, mailboxes: new Map() };
}

export function putBlock(store: StorageStore, cid: string, data: Uint8Array): void {
  if (store.blocks.has(cid)) return; // 内容寻址：幂等
  store.blocks.set(cid, data);
  store.blocksTotalBytes += data.length;
}

export function getBlock(store: StorageStore, cid: string): Uint8Array | undefined {
  return store.blocks.get(cid);
}

/** 物理删除（FR-4.4 动态删除的物理增强，M3-S12）；幂等，返回是否实际删除。 */
export function deleteBlock(store: StorageStore, cid: string): boolean {
  const data = store.blocks.get(cid);
  if (data === undefined) return false;
  store.blocks.delete(cid);
  store.blocksTotalBytes -= data.length;
  return true;
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

/** 单次 fetch 返回条数硬上限（响应放大护栏；客户端按返回 cursor 续拉）。 */
export const MAILBOX_FETCH_MAX = 500;

/**
 * 从 cursor 起增量拉取信箱。返回 cursor 语义不变：
 * - 取尽（或箱为空）返回箱尾 nextCursor（与既有行为一致）；
 * - 未取尽（触及单次上限）返回"下一条位置"（末条 cursor+1），客户端以该值续拉。
 */
export function mailboxFetch(
  store: StorageStore,
  mailboxId: string,
  cursor: number,
): { envelopes: Envelope[]; cursor: number } {
  const box = store.mailboxes.get(mailboxId);
  if (!box) return { envelopes: [], cursor: 0 };
  const matched = box.entries.filter((e) => e.cursor >= cursor);
  if (matched.length === 0) return { envelopes: [], cursor: box.nextCursor };
  const page = matched.slice(0, MAILBOX_FETCH_MAX);
  const outCursor = page.length < matched.length ? page[page.length - 1]!.cursor + 1 : box.nextCursor;
  return { envelopes: page.map((e) => e.envelope), cursor: outCursor };
}
