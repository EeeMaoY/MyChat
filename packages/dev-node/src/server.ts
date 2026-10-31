/**
 * MyChat dev-node 单体服务装配（ADR-11）：HTTP（Storage/Registry/KT/Relay send）
 * + WebSocket（Relay 订阅）。
 *
 * 角色边界在代码结构上保持分离：relay/storage/registry/ktlog 各自独立模块，
 * 任何第三方可按 @mychat/core 四接口独立实现并部署自己的节点。
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { WebSocketServer, type WebSocket } from "ws";

import type { KTEvent, UserNameRecord } from "@mychat/core";
import {
  didToEd25519PublicKey,
  decodePreKeyBundle,
  verifyPreKeyBundle,
} from "@mychat/core";
import { envelopeFromJson, envelopeToJson, type EnvelopeJson } from "./wire.ts";
import { RelayHub, type RelayDelivery, type RelayNotification } from "./relay.ts";
import { appendEvent, createKTLogStore, ktLogInclusionProof, ktLogRoot, listEvents, type KTLogStore } from "./ktlog.ts";
import {
  createBundleStore,
  createRegistryStore,
  putBundle,
  registerRecord,
  resolveName,
  type BundleStore,
  type RegistryStore,
} from "./registry.ts";
import {
  createStorageStore,
  getBlock,
  mailboxAppend,
  mailboxFetch,
  putBlock,
  type StorageStore,
} from "./storage.ts";

const MAX_BODY = 16 * 1024 * 1024; // 块大小上限 16MB
const MAILBOX_MAX_ENTRIES = 1000;

export interface DevNode {
  port: number;
  close(): Promise<void>;
}

interface NodeState {
  storage: StorageStore;
  registry: RegistryStore;
  bundles: BundleStore;
  ktlog: KTLogStore;
  relay: RelayHub;
}

/** 启动 dev 节点（内存态；进程退出即清空——开发环境属性，如实呈现）。 */
export function startDevNode(opts: { port?: number; host?: string } = {}): Promise<DevNode> {
  const state: NodeState = {
    storage: createStorageStore(),
    registry: createRegistryStore(),
    bundles: createBundleStore(),
    ktlog: createKTLogStore(),
    relay: new RelayHub(),
  };

  const server = createServer((req, res) => {
    // CORS：dev 节点是零信任公共基础设施，浏览器客户端可从任意 origin 访问
    // （生产多节点部署时仍按本语义开放——节点不作鉴权裁决）
    res.setHeader("access-control-allow-origin", "*");
    res.setHeader("access-control-allow-methods", "GET, POST, PUT, OPTIONS");
    res.setHeader("access-control-allow-headers", "content-type");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    handleHttp(state, req, res).catch(() => {
      if (!res.headersSent) sendError(res, 500, "内部错误");
      res.end();
    });
  });

  const wss = new WebSocketServer({ noServer: true });
  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== "/v0/relay/subscribe") {
      socket.destroy();
      return;
    }
    const mailboxId = url.searchParams.get("mailbox");
    if (!mailboxId || mailboxId.length > 128) {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      state.relay.subscribe(mailboxId, ws as WebSocket);
      ws.send(JSON.stringify({ type: "mailbox-activity", mailboxId } satisfies RelayNotification));
    });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, opts.host ?? "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        port,
        close: () =>
          new Promise<void>((done) => {
            wss.close();
            server.close(() => done());
          }),
      });
    });
  });
}

async function handleHttp(state: NodeState, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const parts = url.pathname.split("/").filter(Boolean); // ["v0", domain, ...]
  if (parts[0] !== "v0") return sendError(res, 404, "未知路径");

  try {
    // ----- Registry -----
    if (req.method === "POST" && url.pathname === "/v0/registry/register") {
      const body = await readJson(req);
      const record = parseUserNameRecord(body);
      const result = registerRecord(state.registry, record);
      if (!result.ok) return sendError(res, 409, result.error);
      // KT 联动：注册历史锚定进透明日志（SR-5）
      appendEvent(state.ktlog, {
        did: record.did,
        type: "register",
        payload: new Uint8Array(Buffer.from(record.name, "utf8")),
      });
      return sendJson(res, 201, { ok: true, ktIndex: record.ktIndex });
    }
    if (req.method === "GET" && parts[1] === "registry" && parts[2] === "resolve" && typeof parts[3] === "string") {
      const record = resolveName(state.registry, decodeURIComponent(parts[3]));
      if (!record) return sendError(res, 404, "用户名不存在");
      return sendJson(res, 200, { record: serializeRecord(record) });
    }

    // ----- 预密钥束分发（Registry 角色扩展，设计报告 §5.2）-----
    if (parts[1] === "registry" && parts[2] === "bundle" && typeof parts[3] === "string") {
      const did = decodeURIComponent(parts[3]);
      // DID 格式校验（防任意键污染）
      try {
        didToEd25519PublicKey(did);
      } catch {
        return sendError(res, 400, "DID 格式非法");
      }
      if (req.method === "PUT") {
        const body = await readBody(req);
        // 节点侧验签准入：签名/有效期/DID 一致性不过即拒（客户端仍须自主验签）
        let bundle;
        try {
          bundle = decodePreKeyBundle(new Uint8Array(body));
        } catch {
          return sendError(res, 400, "bundle 编码非法");
        }
        if (bundle.did !== did || !verifyPreKeyBundle(bundle)) {
          return sendError(res, 400, "bundle 验签失败或 DID 不匹配");
        }
        putBundle(state.bundles, did, new Uint8Array(body));
        return sendJson(res, 201, { ok: true });
      }
      if (req.method === "GET") {
        const stored = state.bundles.bundles.get(did);
        if (!stored) return sendError(res, 404, "bundle 不存在");
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from(stored));
        return;
      }
    }

    // ----- KT Log -----
    if (req.method === "GET" && url.pathname === "/v0/kt/root") {
      return sendJson(res, 200, ktLogRoot(state.ktlog));
    }
    if (req.method === "GET" && parts[1] === "kt" && parts[2] === "proof" && typeof parts[3] === "string") {
      const index = Number(parts[3]);
      const proof = Number.isInteger(index) && index >= 0 ? ktLogInclusionProof(state.ktlog, index) : undefined;
      if (!proof) return sendError(res, 404, "证明不存在（序号越界）");
      return sendJson(res, 200, { proof });
    }
    if (req.method === "GET" && parts[1] === "kt" && parts[2] === "list" && typeof parts[3] === "string") {
      return sendJson(res, 200, { events: listEvents(state.ktlog, decodeURIComponent(parts[3])).map(serializeKTEvent) });
    }
    if (req.method === "POST" && url.pathname === "/v0/kt/append") {
      const body = await readJson(req);
      const event = appendEvent(state.ktlog, {
        did: String(body.did ?? ""),
        type: parseKTType(body.type),
        payload: new Uint8Array(Buffer.from(String(body.payload ?? ""), "base64")),
      });
      return sendJson(res, 201, { event: serializeKTEvent(event) });
    }

    // ----- Storage: blocks -----
    if (parts[1] === "storage" && parts[2] === "blocks" && typeof parts[3] === "string") {
      const cid = decodeURIComponent(parts[3]);
      if (req.method === "PUT") {
        const body = await readBody(req);
        if (body.length === 0) return sendError(res, 400, "空块");
        putBlock(state.storage, cid, new Uint8Array(body));
        return sendJson(res, 201, { ok: true });
      }
      if (req.method === "GET") {
        const block = getBlock(state.storage, cid);
        if (!block) return sendError(res, 404, "块不存在");
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from(block));
        return;
      }
    }

    // ----- Storage: mailboxes -----
    if (parts[1] === "storage" && parts[2] === "mailboxes" && typeof parts[3] === "string") {
      const mailboxId = decodeURIComponent(parts[3]);
      if (req.method === "POST" && parts[4] === "append") {
        const body = await readJson(req);
        let envelope;
        try {
          envelope = envelopeFromJson(body.envelope);
        } catch (err) {
          return sendError(res, 400, err instanceof Error ? err.message : "信封非法");
        }
        const box = state.storage.mailboxes.get(mailboxId);
        if (box && box.entries.length >= MAILBOX_MAX_ENTRIES) {
          return sendError(res, 429, "信箱已满（开发节点配额）");
        }
        const cursor = mailboxAppend(state.storage, mailboxId, envelope);
        state.relay.notifyActivity(mailboxId);
        return sendJson(res, 201, { cursor });
      }
      if (req.method === "GET" && parts[4] === undefined) {
        const cursor = Number(url.searchParams.get("cursor") ?? "0");
        const result = mailboxFetch(state.storage, mailboxId, Number.isInteger(cursor) && cursor >= 0 ? cursor : 0);
        return sendJson(res, 200, { envelopes: result.envelopes.map(envelopeToJson), cursor: result.cursor });
      }
    }

    // ----- Relay: 在线直投（协议边界保留；M0 客户端主路径走信箱） -----
    if (req.method === "POST" && url.pathname === "/v0/relay/send") {
      const body = await readJson(req);
      let envelope;
      try {
        envelope = envelopeFromJson(body.envelope);
      } catch (err) {
        return sendError(res, 400, err instanceof Error ? err.message : "信封非法");
      }
      const delivered = state.relay.deliver(envelope.toPseudonym, envelope);
      return sendJson(res, 202, { delivered });
    }

    return sendError(res, 404, "未知路径");
  } catch (err) {
    if (err instanceof BadRequestError) return sendError(res, 400, err.message);
    throw err;
  }
}

class BadRequestError extends Error {}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new BadRequestError("请求体过大");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const body = await readBody(req);
  try {
    return JSON.parse(body.toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new BadRequestError("JSON 解析失败");
  }
}

function sendJson(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(data));
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { error: message });
}

// ---------- 记录与事件的序列化（二进制字段 base64） ----------

function serializeRecord(r: UserNameRecord): Record<string, unknown> {
  return {
    name: r.name,
    did: r.did,
    signature: Buffer.from(r.signature).toString("base64"),
    ktIndex: r.ktIndex,
  };
}

function parseUserNameRecord(body: Record<string, unknown>): UserNameRecord {
  const record = body.record;
  if (typeof record !== "object" || record === null) throw new BadRequestError("记录格式非法");
  const r = record as Record<string, unknown>;
  if (typeof r.name !== "string" || typeof r.did !== "string" || typeof r.ktIndex !== "number") {
    throw new BadRequestError("记录字段非法");
  }
  return {
    name: r.name,
    did: r.did,
    ktIndex: r.ktIndex,
    signature: new Uint8Array(Buffer.from(String(r.signature ?? ""), "base64")),
  };
}

function serializeKTEvent(e: KTEvent): Record<string, unknown> {
  return { did: e.did, type: e.type, index: e.index, payload: Buffer.from(e.payload).toString("base64") };
}

function parseKTType(v: unknown): KTEvent["type"] {
  if (v === "register" || v === "revoke" || v === "device-add" || v === "device-revoke") return v;
  throw new BadRequestError("KT 事件类型非法");
}

export type { RelayDelivery };
