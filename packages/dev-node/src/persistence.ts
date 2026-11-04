/**
 * dev-node 持久化（M3 修复：重启丢数据问题）—— MYCHAT_DATA_DIR 启用。
 *
 * 形态：按操作追加 JSONL（append-only，崩溃安全），启动时全量重放重建内存态。
 * 记录的是"已成功通过准入的操作事实"（验签在写入路径已完成，重放直接落 store，
 * 不再验签——文件本身由节点进程写入）。
 *
 * 未持久化（如实登记）：
 * - OPK "已分发未消耗"集合（issued）：分发是读操作不记录，重启后同一 OPK 可能
 *   再次分发（一次性退化的既有边界档位，消耗确认 DELETE 有记录）；
 * - Relay WS 订阅（连接态）；
 * - 重放时 KT 事件随 register/device-add/device-revoke 一并重建，根链跨重启延续。
 *
 * 追加失败（磁盘问题）：请求仍成功但打印警告（开发节点尽力而为，不因磁盘拒绝服务）。
 */
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { join } from "node:path";

export type PersistRecord =
  | { t: "register"; record: Record<string, unknown> }
  | { t: "device-add"; did: string; json: string }
  | { t: "device-revoke"; did: string; dkId: string; json: string }
  | { t: "bundle"; did: string; dkId: string; bytes: string }
  | { t: "opks"; did: string; dkId: string; opks: { id: number; public: string }[] }
  | { t: "opk-consume"; did: string; dkId: string; opkId: number }
  | { t: "block"; cid: string; bytes: string }
  | { t: "block-delete"; cid: string }
  | { t: "envelope"; mailboxId: string; envelope: Record<string, unknown> }
  | { t: "recovery"; did: string; json: string };

export interface Persistence {
  append(record: PersistRecord): void;
  load(): PersistRecord[];
}

export class NoopPersistence implements Persistence {
  append(): void {}
  load(): PersistRecord[] {
    return [];
  }
}

const FILE_NAME = "node-log.jsonl";

export class FilePersistence implements Persistence {
  private fd: number | null = null;

  constructor(private dir: string) {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  }

  private filePath(): string {
    return join(this.dir, FILE_NAME);
  }

  append(record: PersistRecord): void {
    try {
      if (this.fd === null) {
        // 已有文件则追加；否则创建
        this.fd = openSync(this.filePath(), existsSync(this.filePath()) ? "a" : "w");
      }
      writeSync(this.fd, `${JSON.stringify(record)}\n`);
    } catch (err) {
      console.warn("[mychat-dev-node] 持久化追加失败（请求照常返回）:", err instanceof Error ? err.message : err);
    }
  }

  load(): PersistRecord[] {
    const path = this.filePath();
    if (!existsSync(path)) return [];
    const out: PersistRecord[] = [];
    const text = readFileSync(path, "utf8");
    for (const line of text.split("\n")) {
      if (line.trim() === "") continue;
      try {
        out.push(JSON.parse(line) as PersistRecord);
      } catch {
        console.warn("[mychat-dev-node] 跳过损坏的持久化记录行");
      }
    }
    return out;
  }

  close(): void {
    if (this.fd !== null) {
      try {
        closeSync(this.fd);
      } catch {
        /* 已关闭 */
      }
      this.fd = null;
    }
  }
}

export function createPersistence(dir: string | undefined): Persistence {
  return dir === undefined ? new NoopPersistence() : new FilePersistence(dir);
}

export function closePersistence(p: Persistence): void {
  if (p instanceof FilePersistence) p.close();
}
