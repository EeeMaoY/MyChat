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

/** 节点设备列表条目（节点视图；客户端须本地验签折叠后才可采信，SR-5）。 */
export interface DeviceRecordJson {
  certificate: {
    version: number;
    did: string;
    dkId: string;
    label: string;
    issuedAt: number;
    expiresAt: number;
    signature: string;
  };
  revoked: boolean;
  revokedAt: number | null;
  expired: boolean;
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

  async putBundle(did: string, bundle: Uint8Array, device: string): Promise<void> {
    const res = await fetch(
      `${this.baseUrl}/v0/registry/bundle/${encodeURIComponent(did)}?device=${encodeURIComponent(device)}`,
      {
        method: "PUT",
        headers: { "content-type": "application/octet-stream" },
        body: new Uint8Array(bundle),
      },
    );
    if (!res.ok) await readError(res);
  }

  async getBundle(did: string): Promise<Uint8Array | null> {
    const res = await fetch(`${this.baseUrl}/v0/registry/bundle/${encodeURIComponent(did)}`);
    if (res.status === 404) return null;
    if (!res.ok) await readError(res);
    return new Uint8Array(await res.arrayBuffer());
  }

  // ----- 设备注册表（M2-S10 FR-1.4） -----

  /** 登记设备凭证（IK 签名，节点验签准入 + KT 锚定）。 */
  async putDevice(did: string, certificate: Record<string, unknown>): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v0/registry/devices/${encodeURIComponent(did)}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ certificate }),
    });
    if (!res.ok) await readError(res);
  }

  /** 吊销设备（IK 签名吊销声明；节点停发该设备预密钥材料 + KT 锚定）。 */
  async revokeDevice(did: string, dkId: string, revocation: Record<string, unknown>): Promise<void> {
    const res = await fetch(
      `${this.baseUrl}/v0/registry/devices/${encodeURIComponent(did)}/${encodeURIComponent(dkId)}`,
      {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ revocation }),
      },
    );
    if (!res.ok) await readError(res);
  }

  /** 设备列表（节点视图；客户端须本地验签折叠后才可采信，SR-5）。 */
  async getDevices(did: string): Promise<DeviceRecordJson[]> {
    const res = await fetch(`${this.baseUrl}/v0/registry/devices/${encodeURIComponent(did)}`);
    if (!res.ok) await readError(res);
    const body = (await res.json()) as { devices: DeviceRecordJson[] };
    return body.devices;
  }

  // ----- OPK 池（M2-S9；M2-S10 起按设备分槽） -----

  async addOpks(did: string, opks: { id: number; public: string }[], device: string): Promise<void> {
    if (opks.length === 0) return;
    const res = await fetch(
      `${this.baseUrl}/v0/registry/bundle/${encodeURIComponent(did)}/opks?device=${encodeURIComponent(device)}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ opks }),
      },
    );
    if (!res.ok) await readError(res);
  }

  async consumeOpk(did: string, opkId: number, device: string): Promise<void> {
    const res = await fetch(
      `${this.baseUrl}/v0/registry/bundle/${encodeURIComponent(did)}/opk/${opkId}?device=${encodeURIComponent(device)}`,
      { method: "DELETE" },
    );
    if (!res.ok) await readError(res);
  }

  // ----- 恢复公告（社交恢复 FR-1.3） -----

  async putRecoveryAnnouncement(did: string, announcement: unknown): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v0/registry/recovery/${encodeURIComponent(did)}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ announcement }),
    });
    if (!res.ok) await readError(res);
  }

  async getRecoveryAnnouncement(did: string): Promise<Record<string, unknown> | null> {
    const res = await fetch(`${this.baseUrl}/v0/registry/recovery/${encodeURIComponent(did)}`);
    if (res.status === 404) return null;
    if (!res.ok) await readError(res);
    return (await res.json()) as Record<string, unknown>;
  }

  // ----- KT Log（设备集本地折叠的数据源，SR-5） -----

  /** 拉取某 DID 的 KT 事件流（全量；设备折叠与包含性验证在客户端本地完成）。 */
  async getKtEvents(did: string): Promise<{ did: string; type: string; index: number; payload: string }[]> {
    const res = await fetch(`${this.baseUrl}/v0/kt/list/${encodeURIComponent(did)}`);
    if (!res.ok) await readError(res);
    const body = (await res.json()) as { events: { did: string; type: string; index: number; payload: string }[] };
    return body.events;
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

  // ----- Storage: 块（附件/托管副本走 CAS，节点只见密文） -----

  async putBlock(cid: string, data: Uint8Array): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v0/storage/blocks/${encodeURIComponent(cid)}`, {
      method: "PUT",
      headers: { "content-type": "application/octet-stream" },
      body: new Uint8Array(data),
    });
    if (!res.ok) await readError(res);
  }

  async getBlock(cid: string): Promise<Uint8Array | null> {
    const res = await fetch(`${this.baseUrl}/v0/storage/blocks/${encodeURIComponent(cid)}`);
    if (res.status === 404) return null;
    if (!res.ok) await readError(res);
    return new Uint8Array(await res.arrayBuffer());
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
