/**
 * dev-node HTTP/WS 客户端封装。
 *
 * 客户端永远不因"节点接受了"而采信材料：UserNameRecord 与 PreKeyBundle
 * 均须本地验签（SR-5，验证在 messaging 编排层完成，本层只做传输）。
 */
import type { Envelope, UserNameRecord } from "@mychat/core";

import { fromBase64, toBase64 } from "./base64";

export class NodeApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

interface EnvelopeJson {
  version: string;
  epoch: number;
  toPseudonym: string;
  padClass: number;
  nonce: string;
  payload: string;
}

function envelopeToJson(e: Envelope): EnvelopeJson {
  return {
    version: e.version,
    epoch: e.epoch,
    toPseudonym: e.toPseudonym,
    padClass: e.padClass,
    nonce: toBase64(e.nonce),
    payload: toBase64(e.payload),
  };
}

function envelopeFromJson(j: EnvelopeJson): Envelope {
  return {
    version: j.version,
    epoch: j.epoch,
    toPseudonym: j.toPseudonym,
    padClass: j.padClass as 0 | 1 | 2 | 3,
    nonce: fromBase64(j.nonce),
    payload: fromBase64(j.payload),
  };
}

async function readError(res: Response): Promise<never> {
  let message = `HTTP ${res.status}`;
  try {
    const body = (await res.json()) as { error?: string };
    if (body.error) message = body.error;
  } catch {
    /* 保留状态码信息 */
  }
  throw new NodeApiError(res.status, message);
}

export class NodeApi {
  constructor(private baseUrl: string) {}

  // ----- Registry -----

  async register(record: UserNameRecord): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v0/registry/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ record: { ...record, signature: toBase64(record.signature) } }),
    });
    if (!res.ok) await readError(res);
  }

  async resolve(name: string): Promise<UserNameRecord | null> {
    const res = await fetch(`${this.baseUrl}/v0/registry/resolve/${encodeURIComponent(name)}`);
    if (res.status === 404) return null;
    if (!res.ok) await readError(res);
    const body = (await res.json()) as { record: { name: string; did: string; signature: string; ktIndex: number } };
    return {
      name: body.record.name,
      did: body.record.did,
      ktIndex: body.record.ktIndex,
      signature: fromBase64(body.record.signature),
    };
  }

  async putBundle(did: string, bundle: Uint8Array): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v0/registry/bundle/${encodeURIComponent(did)}`, {
      method: "PUT",
      headers: { "content-type": "application/octet-stream" },
      body: new Uint8Array(bundle),
    });
    if (!res.ok) await readError(res);
  }

  async getBundle(did: string): Promise<Uint8Array | null> {
    const res = await fetch(`${this.baseUrl}/v0/registry/bundle/${encodeURIComponent(did)}`);
    if (res.status === 404) return null;
    if (!res.ok) await readError(res);
    return new Uint8Array(await res.arrayBuffer());
  }

  // ----- Storage: 信箱 -----

  async mailboxAppend(mailboxId: string, envelope: Envelope): Promise<number> {
    const res = await fetch(
      `${this.baseUrl}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}/append`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ envelope: envelopeToJson(envelope) }),
      },
    );
    if (!res.ok) await readError(res);
    const body = (await res.json()) as { cursor: number };
    return body.cursor;
  }

  async mailboxFetch(
    mailboxId: string,
    cursor: number,
  ): Promise<{ envelopes: Envelope[]; cursor: number }> {
    const res = await fetch(
      `${this.baseUrl}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}?cursor=${cursor}`,
    );
    if (!res.ok) await readError(res);
    const body = (await res.json()) as { envelopes: EnvelopeJson[]; cursor: number };
    return { envelopes: body.envelopes.map(envelopeFromJson), cursor: body.cursor };
  }

  // ----- Relay: WS 唤醒订阅 -----

  /**
   * 为每个信箱建立一条 WS 订阅；任一信箱有新内容时触发 onActivity(mailboxId)。
   * 返回清理函数（关闭全部连接）。断线自动重连（2s 退避）。
   */
  subscribeMailboxes(mailboxIds: string[], onActivity: (mailboxId: string) => void): () => void {
    const sockets = new Set<WebSocket>();
    let closed = false;

    for (const mailboxId of mailboxIds) {
      const connect = () => {
        if (closed) return;
        const ws = new WebSocket(
          `${this.baseUrl.replace(/^http/, "ws")}/v0/relay/subscribe?mailbox=${encodeURIComponent(mailboxId)}`,
        );
        sockets.add(ws);
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data as string) as { type: string };
            if (msg.type === "mailbox-activity") onActivity(mailboxId);
          } catch {
            /* 忽略畸形帧 */
          }
        };
        ws.onclose = () => {
          sockets.delete(ws);
          if (!closed) setTimeout(connect, 2000);
        };
      };
      connect();
    }

    return () => {
      closed = true;
      for (const ws of sockets) ws.close();
      sockets.clear();
    };
  }
}
