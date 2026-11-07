/**
 * S13 运维健壮化测试：限流（429 + 参数可注入）、快照压缩（阈值触发、
 * 数据完好、JSONL 轮转增量）、吊销状态跨快照保留。
 */
import { mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  createIdentity,
  encodePreKeyBundle,
  generateX25519KeyPair,
  issuePreKeyBundle,
  makeEnvelope,
  makeUserNameRecord,
  randomBytes,
  type Envelope,
} from "@mychat/core";
import { envelopeToJson } from "../wire";

import { startDevNode, type DevNode } from "../server";
import { registerDeviceCert } from "./helpers-device";

let node: DevNode;
let base: string;
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "mychat-ops-"));
});

afterEach(async () => {
  await node.close();
  rmSync(dataDir, { recursive: true, force: true });
});

function makeEnvelopeLocal(toPseudonym: string): Envelope {
  return { version: "1", epoch: 1, toPseudonym, padClass: 0, nonce: randomBytes(24), payload: randomBytes(200) };
}

describe("限流与资源配额（M4-S13）", () => {
  it("信箱 append 超速 429（参数注入小值）；正常速率不受影响", async () => {
    node = await startDevNode({ limits: { mailboxAppendPerMin: 3 } });
    base = `http://127.0.0.1:${node.port}`;
    const mailboxId = "rate-test-mailbox";
    const envelope = envelopeToJson(makeEnvelopeLocal(mailboxId));
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}/append`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ envelope }),
      });
      expect(res.status).toBe(201);
    }
    const fourth = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope }),
    });
    expect(fourth.status).toBe(429);
    // 不同信箱不受影响（限流按信箱键）
    const other = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent("another-mailbox")}/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope: envelopeToJson(makeEnvelopeLocal("another-mailbox")) }),
    });
    expect(other.status).toBe(201);
  });

  it("块总量配额：达到 maxBlocks 后 PUT 429", async () => {
    node = await startDevNode({ limits: { maxBlocks: 2 } });
    base = `http://127.0.0.1:${node.port}`;
    for (const cid of ["blk-1", "blk-2"]) {
      const res = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent(cid)}`, {
        method: "PUT",
        body: Buffer.from(randomBytes(32)),
      });
      expect(res.status).toBe(201);
    }
    const third = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent("blk-3")}`, {
      method: "PUT",
      body: Buffer.from(randomBytes(32)),
    });
    expect(third.status).toBe(429);
  });
});

describe("持久化快照与轮转（M4-S13）", () => {
  it("超阈值重启触发压缩：数据完好、JSONL 重置为增量、吊销状态保留", async () => {
    node = await startDevNode({ persistDir: dataDir, compactThreshold: 8 });
    base = `http://127.0.0.1:${node.port}`;

    // 第一代：alice 注册 + 设备 + bundle + OPK 池 + 吊销第二台设备 + 块 + 信箱
    const alice = createIdentity();
    const record = makeUserNameRecord(alice.ikEd.privateKey, "alice_ops", alice.did, 0);
    await fetch(`${base}/v0/registry/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
    });
    const dkA = await registerDeviceCert(base, alice, "主设备");
    const dkB = await registerDeviceCert(base, alice, "二手设备");
    const devQs = `?device=${encodeURIComponent(dkA)}`;
    const { deriveOpkId, makeDeviceRevocation, encodeDeviceRevocationJson } = await import("@mychat/core");
    const spk = generateX25519KeyPair();
    const opk1 = generateX25519KeyPair();
    const bundleOk = issuePreKeyBundle(alice, spk, { ...opk1, id: deriveOpkId(opk1.publicKey) }, 3_600_000);
    const put = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(alice.did)}${devQs}`, {
      method: "PUT",
      body: Buffer.from(encodePreKeyBundle(bundleOk)),
    });
    expect(put.status).toBe(201);
    // 吊销 dkB（跨快照保留吊销状态）
    const revocation = makeDeviceRevocation(alice.ikEd.privateKey, alice.did, dkB);
    const revoke = await fetch(`${base}/v0/registry/devices/${encodeURIComponent(alice.did)}/${encodeURIComponent(dkB)}`, {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ revocation: JSON.parse(encodeDeviceRevocationJson(revocation)) }),
    });
    expect(revoke.status).toBe(200);
    // 块 + 信封
    await fetch(`${base}/v0/storage/blocks/${encodeURIComponent("ops-blk")}`, {
      method: "PUT",
      body: Buffer.from(randomBytes(64)),
    });
    const mailboxId = "ops-mailbox";
    await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope: envelopeToJson(makeEnvelopeLocal(mailboxId)) }),
    });

    // 第二代启动：重放后记录数（>8）触发压缩（快照生成 + JSONL 轮转）
    await node.close();
    expect(existsSync(join(dataDir, "snapshot.json"))).toBe(false); // 压缩在启动时触发，尚未发生
    await startDevNode2();
    expect(existsSync(join(dataDir, "snapshot.json"))).toBe(true);
    // .bak 保留一代
    expect((await import("node:fs")).readdirSync(dataDir).some((f) => f.startsWith("node-log.jsonl."))).toBe(true);

    // 数据完好
    const resolved = await fetch(`${base}/v0/registry/resolve/alice_ops`);
    expect(resolved.status).toBe(200);
    const gotBlock = await fetch(`${base}/v0/storage/blocks/${encodeURIComponent("ops-blk")}`);
    expect(gotBlock.status).toBe(200);
    const gotMailbox = (await (await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}`)).json()) as { envelopes: unknown[] };
    expect(gotMailbox.envelopes).toHaveLength(1);
    // 吊销状态保留：dkB 上传材料被拒（设备已失效）
    const revivedBundle = issuePreKeyBundle(alice, generateX25519KeyPair(), { ...opk1, id: (await import("@mychat/core")).deriveOpkId(opk1.publicKey) }, 3_600_000);
    const roguePut = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(alice.did)}?device=${encodeURIComponent(dkB)}`, {
      method: "PUT",
      body: Buffer.from(encodePreKeyBundle(revivedBundle)),
    });
    expect(roguePut.status).toBe(403);
    // bundle/OPK 仍在主设备槽位
    const bundleRes = await fetch(`${base}/v0/registry/bundle/${encodeURIComponent(alice.did)}`);
    expect(bundleRes.status).toBe(200);

    // JSONL 已重置：压缩后无新增记录时文件不存在或为空（首次 append 才重建）
    const jsonlPath = join(dataDir, "node-log.jsonl");
    const newRecords = existsSync(jsonlPath) ? readFileSync(jsonlPath, "utf8").trim() : "";
    expect(newRecords).toBe(""); // 本次重启未写入任何新记录

    async function startDevNode2(): Promise<void> {
      node = await startDevNode({ persistDir: dataDir, compactThreshold: 8 });
      base = `http://127.0.0.1:${node.port}`;
    }
  });
});
