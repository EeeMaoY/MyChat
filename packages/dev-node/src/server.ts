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
  base58Encode,
  didToEd25519PublicKey,
  decodePreKeyBundle,
  verifyPreKeyBundle,
  verifyRecoveryAnnouncement,
} from "@mychat/core";
import { envelopeFromJson, envelopeToJson, type EnvelopeJson } from "./wire.ts";
import { RelayHub, type RelayDelivery, type RelayNotification } from "./relay.ts";
import { appendEvent, createKTLogStore, ktLogInclusionProof, ktLogRoot, listEvents, type KTLogStore } from "./ktlog.ts";
import {
  activeDeviceEntries,
  createDeviceRegistryStore,
  listDeviceEntries,
  registerDevice,
  revokeDevice,
  type DeviceRegistryStore,
} from "./devices.ts";
import {
  assembleBundle,
  consumeOpk,
  createBundleStore,
  createRegistryStore,
  dropDeviceMaterials,
  opkPoolStats,
  putBundle,
  putOpks,
  registerRecord,
  resolveName,
  type BundleStore,
  type RegistryStore,
} from "./registry.ts";
import {
  createStorageStore,
  deleteBlock,
  getBlock,
  mailboxAppend,
  mailboxFetch,
  putBlock,
  type StorageStore,
} from "./storage.ts";
import { closePersistence, createPersistence, type Persistence, type PersistRecord } from "./persistence.ts";
import { DEFAULT_LIMITS, RateLimiter, type Limits } from "./limits.ts";

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
  devices: DeviceRegistryStore;
  recovery: Map<string, string>;
  ktlog: KTLogStore;
  relay: RelayHub;
  persistence: Persistence;
  limits: Limits;
  limiters: {
    mailboxAppend: RateLimiter;
    blockPut: RateLimiter;
    register: RateLimiter;
  };
}

/**
 * 持久化重放（M3 修复）：按序落 store 重建内存态。记录均为已通过准入的操作事实，
 * 重放不再验签；KT 事件随 register/device-add/device-revoke 一并重建（根链延续）。
 * 信箱追加不触发 relay 通知（重放时无订阅者）。
 */
function replayPersisted(state: NodeState, records: PersistRecord[]): void {
  for (const r of records) {
    switch (r.t) {
      case "register": {
        const record = parseUserNameRecord({ record: r.record });
        registerRecord(state.registry, record);
        appendEvent(state.ktlog, {
          did: record.did,
          type: "register",
          payload: new Uint8Array(Buffer.from(record.name, "utf8")),
        });
        break;
      }
      case "device-add": {
        const result = registerDevice(state.devices, r.did, r.json);
        if (result.ok) {
          appendEvent(state.ktlog, { did: r.did, type: "device-add", payload: new Uint8Array(Buffer.from(r.json, "utf8")) });
        }
        break;
      }
      case "device-revoke": {
        const result = revokeDevice(state.devices, r.did, r.json);
        if (result.ok) {
          dropDeviceMaterials(state.bundles, r.did, r.dkId);
          appendEvent(state.ktlog, { did: r.did, type: "device-revoke", payload: new Uint8Array(Buffer.from(r.json, "utf8")) });
        }
        break;
      }
      case "bundle":
        putBundle(state.bundles, r.did, r.dkId, new Uint8Array(Buffer.from(r.bytes, "base64")));
        break;
      case "opks":
        try {
          putOpks(state.bundles, r.did, r.dkId, r.opks);
        } catch {
          /* 超限等：跳过（与写入路径的准入一致） */
        }
        break;
      case "opk-consume":
        consumeOpk(state.bundles, r.did, r.dkId, r.opkId);
        break;
      case "block":
        putBlock(state.storage, r.cid, new Uint8Array(Buffer.from(r.bytes, "base64")));
        break;
      case "block-delete":
        deleteBlock(state.storage, r.cid);
        break;
      case "envelope": {
        try {
          mailboxAppend(state.storage, r.mailboxId, envelopeFromJson(r.envelope as EnvelopeJson));
        } catch {
          /* 畸形记录跳过 */
        }
        break;
      }
      case "recovery":
        state.recovery.set(r.did, r.json);
        break;
    }
  }
}

/**
 * 当前内存态反推为等效记录序列（M4-S13 快照压缩）：重放逻辑复用，单一事实形态。
 * 已知边界：手动 POST /v0/kt/append 的事件不进快照（自动锚定的 register/device
 * 事件随记录重建；KT 根链由重放按序重建）。
 */
function exportStateAsRecords(state: NodeState): PersistRecord[] {
  const out: PersistRecord[] = [];
  for (const record of state.registry.records.values()) {
    out.push({ t: "register", record: serializeRecord(record) });
  }
  for (const [did, entries] of state.devices.devices) {
    for (const entry of entries.values()) {
      out.push({ t: "device-add", did, json: entry.certificate });
      if (entry.revokedAt !== null && entry.revokedJson !== undefined) {
        const revoked = JSON.parse(entry.certificate) as { dkId: string };
        out.push({ t: "device-revoke", did, dkId: revoked.dkId, json: entry.revokedJson });
      }
    }
  }
  for (const [did, byDevice] of state.bundles.bundles) {
    for (const [dkId, bytes] of byDevice) {
      out.push({ t: "bundle", did, dkId, bytes: Buffer.from(bytes).toString("base64") });
    }
  }
  for (const [did, byDevice] of state.bundles.opkPools) {
    for (const [dkId, pool] of byDevice) {
      out.push({ t: "opks", did, dkId, opks: [...pool.entries()].map(([id, publicKey]) => ({ id, public: publicKey })) });
    }
  }
  for (const [cid, bytes] of state.storage.blocks) {
    out.push({ t: "block", cid, bytes: Buffer.from(bytes).toString("base64") });
  }
  for (const [mailboxId, box] of state.storage.mailboxes) {
    for (const entry of box.entries) {
      out.push({ t: "envelope", mailboxId, envelope: envelopeToJson(entry.envelope) });
    }
  }
  for (const [did, json] of state.recovery) {
    out.push({ t: "recovery", did, json });
  }
  return out;
}

/** 启动 dev 节点（内存态；设置 MYCHAT_DATA_DIR / persistDir 后变更追加 JSONL 并在重启时重放）。 */
export function startDevNode(
  opts: {
    port?: number;
    host?: string;
    persistDir?: string;
    /** 快照压缩阈值（JSONL 记录数；默认 20000，测试注入小值） */
    compactThreshold?: number;
    limits?: Partial<Limits>;
  } = {},
): Promise<DevNode> {
  const limits: Limits = { ...DEFAULT_LIMITS, ...opts.limits };
  const state: NodeState = {
    storage: createStorageStore(),
    registry: createRegistryStore(),
    bundles: createBundleStore(),
    devices: createDeviceRegistryStore(),
    recovery: new Map(),
    ktlog: createKTLogStore(),
    relay: new RelayHub(),
    persistence: createPersistence(opts.persistDir ?? process.env.MYCHAT_DATA_DIR),
    limits,
    limiters: {
      mailboxAppend: new RateLimiter(limits.mailboxAppendPerMin, 60_000),
      blockPut: new RateLimiter(limits.blockPutPerMin, 60_000),
      register: new RateLimiter(limits.registerPerMin, 60_000),
    },
  };
  replayPersisted(state, state.persistence.load());

  // 快照压缩（M4-S13）：记录数超阈值时把内存态反推为快照并轮转 JSONL
  const compactThreshold = opts.compactThreshold ?? 20_000;
  if (state.persistence.lastLoadCount() >= compactThreshold) {
    state.persistence.compact(exportStateAsRecords(state));
    console.log(`[mychat-dev-node] 持久化快照压缩完成（${state.persistence.lastLoadCount()} 条记录）`);
  }

  const server = createServer((req, res) => {
    // CORS：dev 节点是零信任公共基础设施，浏览器客户端可从任意 origin 访问
    // （生产多节点部署时仍按本语义开放——节点不作鉴权裁决）
    res.setHeader("access-control-allow-origin", "*");
    res.setHeader("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS");
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
            server.close(() => {
              closePersistence(state.persistence);
              done();
            });
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
      if (!state.limiters.register.allow("global")) {
        return sendError(res, 429, "注册请求过于频繁（节点限流）");
      }
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
      state.persistence.append({ t: "register", record: serializeRecord(record) });
      return sendJson(res, 201, { ok: true, ktIndex: record.ktIndex });
    }
    if (req.method === "GET" && parts[1] === "registry" && parts[2] === "resolve" && typeof parts[3] === "string") {
      const record = resolveName(state.registry, decodeURIComponent(parts[3]));
      if (!record) return sendError(res, 404, "用户名不存在");
      return sendJson(res, 200, { record: serializeRecord(record) });
    }

    // ----- 设备注册表（M2-S10 FR-1.4：凭证登记/吊销/列表，设计报告 §4.2）-----
    if (parts[1] === "registry" && parts[2] === "devices" && typeof parts[3] === "string") {
      const did = decodeURIComponent(parts[3]);
      try {
        didToEd25519PublicKey(did);
      } catch {
        return sendError(res, 400, "DID 格式非法");
      }
      if (req.method === "PUT") {
        const body = await readJson(req);
        if (typeof body.certificate !== "object" || body.certificate === null) {
          return sendError(res, 400, "设备凭证格式非法");
        }
        const json = JSON.stringify(body.certificate);
        const result = registerDevice(state.devices, did, json);
        if (!result.ok) return sendError(res, 400, result.error);
        // KT 联动：设备生命周期锚定透明日志（联系人可本地折叠核验）
        appendEvent(state.ktlog, {
          did,
          type: "device-add",
          payload: new Uint8Array(Buffer.from(json, "utf8")),
        });
        state.persistence.append({ t: "device-add", did, json });
        return sendJson(res, 201, { ok: true, dkId: result.certificate.dkId });
      }
      if (req.method === "DELETE" && typeof parts[4] === "string") {
        const dkId = decodeURIComponent(parts[4]);
        const body = await readJson(req);
        if (typeof body.revocation !== "object" || body.revocation === null) {
          return sendError(res, 400, "吊销声明格式非法");
        }
        const json = JSON.stringify(body.revocation);
        const result = revokeDevice(state.devices, did, json);
        if (!result.ok) return sendError(res, 400, result.error);
        if (result.changed) {
          // 吊销即停发：删除该设备的 bundle 模板与 OPK 池 + KT 锚定
          dropDeviceMaterials(state.bundles, did, dkId);
          appendEvent(state.ktlog, {
            did,
            type: "device-revoke",
            payload: new Uint8Array(Buffer.from(json, "utf8")),
          });
          state.persistence.append({ t: "device-revoke", did, dkId, json });
        }
        return sendJson(res, 200, { ok: true, changed: result.changed });
      }
      if (req.method === "GET") {
        const now = Date.now();
        const devices = listDeviceEntries(state.devices, did).map((entry) => {
          const certificate = JSON.parse(entry.certificate) as Record<string, unknown>;
          return {
            certificate,
            revoked: entry.revokedAt !== null,
            revokedAt: entry.revokedAt,
            expired: typeof certificate.expiresAt === "number" && certificate.expiresAt <= now,
          };
        });
        return sendJson(res, 200, { devices });
      }
    }

    // ----- 预密钥束分发（Registry 角色扩展，设计报告 §5.2；M2-S10 起按设备分槽）-----
    if (parts[1] === "registry" && parts[2] === "bundle" && typeof parts[3] === "string") {
      const did = decodeURIComponent(parts[3]);
      // DID 格式校验（防任意键污染）
      try {
        didToEd25519PublicKey(did);
      } catch {
        return sendError(res, 400, "DID 格式非法");
      }
      // 写操作须指向有效设备（凭证已登记、未吊销、未过期）
      const requestedDevice = url.searchParams.get("device") ?? "";
      const activeDevices = activeDeviceEntries(state.devices, did, Date.now()).map((d) => d.dkId);
      if (
        (req.method === "PUT" || req.method === "POST" || req.method === "DELETE") &&
        !activeDevices.includes(requestedDevice)
      ) {
        return sendError(res, 403, "设备未登记或已失效（先登记设备凭证）");
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
        putBundle(state.bundles, did, requestedDevice, new Uint8Array(body));
        // bundle 上传同时把其中的 OPK 入该设备池（M2-S9 池化 + M2-S10 分槽）
        putOpks(state.bundles, did, requestedDevice, [
          { id: bundle.opkId, public: base58Encode(bundle.opkPublic) },
        ]);
        state.persistence.append({
          t: "bundle",
          did,
          dkId: requestedDevice,
          bytes: Buffer.from(new Uint8Array(body)).toString("base64"),
        });
        state.persistence.append({
          t: "opks",
          did,
          dkId: requestedDevice,
          opks: [{ id: bundle.opkId, public: base58Encode(bundle.opkPublic) }],
        });
        return sendJson(res, 201, { ok: true });
      }
      if (req.method === "POST" && parts[4] === "opks") {
        // OPK 池批量补充：{ opks: [{ id, public(base58) }] }
        const body = await readJson(req);
        if (!Array.isArray(body.opks)) return sendError(res, 400, "opks 字段非法");
        try {
          putOpks(
            state.bundles,
            did,
            requestedDevice,
            body.opks.map((o: { id: unknown; public: unknown }) => ({
              id: Number(o.id),
              public: String(o.public ?? ""),
            })),
          );
        } catch (err) {
          return sendError(res, 400, err instanceof Error ? err.message : "OPK 非法");
        }
        state.persistence.append({
          t: "opks",
          did,
          dkId: requestedDevice,
          opks: body.opks.map((o: { id: unknown; public: unknown }) => ({ id: Number(o.id), public: String(o.public ?? "") })),
        });
        return sendJson(res, 201, { ok: true, stats: opkPoolStats(state.bundles, did, requestedDevice) });
      }
      if (req.method === "DELETE" && parts[4] === "opk" && typeof parts[5] === "string") {
        const opkId = Number(parts[5]);
        const consumed = Number.isInteger(opkId) ? consumeOpk(state.bundles, did, requestedDevice, opkId) : false;
        if (consumed) {
          state.persistence.append({ t: "opk-consume", did, dkId: requestedDevice, opkId });
        }
        return sendJson(res, 200, { consumed, stats: opkPoolStats(state.bundles, did, requestedDevice) });
      }
      if (req.method === "GET" && parts[4] === "stats") {
        if (!activeDevices.includes(requestedDevice)) return sendError(res, 403, "设备未登记或已失效");
        return sendJson(res, 200, opkPoolStats(state.bundles, did, requestedDevice));
      }
      if (req.method === "GET") {
        // 分发：节点在有效设备集内确定性轮询（多设备自然负载均衡；吊销设备已出局）
        const assembled = assembleBundle(state.bundles, did, activeDevices);
        if (!assembled) return sendError(res, 404, "bundle 不存在（或无有效设备）");
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from(assembled.encoded));
        return;
      }
    }

    // ----- 恢复公告（社交恢复 FR-1.3，设计报告 §4.3：节点按 DID 存当前公告）-----
    if (parts[1] === "registry" && parts[2] === "recovery" && typeof parts[3] === "string") {
      const did = decodeURIComponent(parts[3]);
      try {
        didToEd25519PublicKey(did);
      } catch {
        return sendError(res, 400, "DID 格式非法");
      }
      if (req.method === "PUT") {
        const body = await readJson(req);
        const announcement = body.announcement;
        if (typeof announcement !== "object" || announcement === null) {
          return sendError(res, 400, "公告格式非法");
        }
        const a = announcement as Record<string, unknown>;
        if (a.did !== did || typeof a.wrapCid !== "string" || typeof a.threshold !== "number" || !Array.isArray(a.guardians)) {
          return sendError(res, 400, "公告字段非法");
        }
        const parsed = {
          did: a.did,
          wrapCid: a.wrapCid,
          threshold: a.threshold,
          guardians: a.guardians as string[],
          signature: new Uint8Array(Buffer.from(String(a.signature ?? ""), "base64")),
        };
        // 节点侧验签准入：公告必须由该 DID 的 IK 签名（客户端仍须自主验签）
        if (!verifyRecoveryAnnouncement(parsed)) {
          return sendError(res, 400, "公告验签失败");
        }
        state.recovery.set(did, JSON.stringify({ ...a }));
        state.persistence.append({ t: "recovery", did, json: JSON.stringify({ ...a }) });
        return sendJson(res, 201, { ok: true });
      }
      if (req.method === "GET") {
        const stored = state.recovery.get(did);
        if (!stored) return sendError(res, 404, "恢复公告不存在");
        res.writeHead(200, { "content-type": "application/json" });
        res.end(stored);
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
    if (req.method === "GET" && url.pathname === "/v0/kt/leaves") {
      // 前缀一致性材料（M3-S11 捎带）：index > after 的叶哈希（base58，日志顺序）
      const after = Number(url.searchParams.get("after") ?? "-1");
      const from = Number.isInteger(after) && after >= -1 ? after + 1 : 0;
      const leaves = state.ktlog.leaves.slice(from).map((l) => base58Encode(l));
      return sendJson(res, 200, { from, upTo: state.ktlog.leaves.length, leafHashes: leaves });
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
        if (!state.limiters.blockPut.allow("global")) {
          return sendError(res, 429, "块写入过于频繁（节点限流）");
        }
        const body = await readBody(req);
        if (body.length === 0) return sendError(res, 400, "空块");
        if (state.storage.blocks.size >= state.limits.maxBlocks) {
          return sendError(res, 429, "节点存储配额已满（maxBlocks）");
        }
        putBlock(state.storage, cid, new Uint8Array(body));
        state.persistence.append({ t: "block", cid, bytes: Buffer.from(new Uint8Array(body)).toString("base64") });
        return sendJson(res, 201, { ok: true });
      }
      if (req.method === "GET") {
        const block = getBlock(state.storage, cid);
        if (!block) return sendError(res, 404, "块不存在");
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from(block));
        return;
      }
      if (req.method === "DELETE") {
        // 物理删除（FR-4.4 动态删除的物理增强，M3-S12）：CAS 无归属，已知 cid 即可删
        // （cid 不可枚举，攻击者需已知 cid；开发节点属性，配额与审计为后续）
        const removed = deleteBlock(state.storage, cid);
        if (removed) {
          state.persistence.append({ t: "block-delete", cid });
        }
        return sendJson(res, 200, { deleted: removed });
      }
    }

    // ----- Storage: mailboxes -----
    if (parts[1] === "storage" && parts[2] === "mailboxes" && typeof parts[3] === "string") {
      const mailboxId = decodeURIComponent(parts[3]);
      if (req.method === "POST" && parts[4] === "append") {
        if (!state.limiters.mailboxAppend.allow(mailboxId)) {
          return sendError(res, 429, "信箱写入过于频繁（节点限流）");
        }
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
        state.persistence.append({ t: "envelope", mailboxId, envelope: envelopeToJson(envelope) });
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
