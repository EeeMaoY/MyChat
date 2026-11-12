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
  ktVerifyInclusion,
  makeEnvelope,
  makeUserNameRecord,
  randomBytes,
  utf8ToBytes,
  type Envelope,
  type KTEvent,
  type KtInclusionProof,
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

  it("compact 后旧 .bak 被清理（仅保留最新一个轮转备份）", async () => {
    const { readdirSync } = await import("node:fs");
    const bakFiles = () => readdirSync(dataDir).filter((f) => f.startsWith("node-log.jsonl.") && f.endsWith(".bak"));

    // 第一代：2 注册 + 2 设备 = 4 条记录（达到阈值）
    node = await startDevNode({ persistDir: dataDir, compactThreshold: 4 });
    base = `http://127.0.0.1:${node.port}`;
    for (const name of ["bak-u1", "bak-u2"]) {
      const identity = createIdentity();
      const record = makeUserNameRecord(identity.ikEd.privateKey, name, identity.did, 0);
      await fetch(`${base}/v0/registry/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
      });
      await registerDeviceCert(base, identity, `${name}-dev`);
    }
    await node.close();

    // 第二代启动：压缩 → 产生 .bak#1；再写 2 条新注册
    node = await startDevNode({ persistDir: dataDir, compactThreshold: 4 });
    base = `http://127.0.0.1:${node.port}`;
    expect(bakFiles().length).toBe(1);
    const firstBak = bakFiles()[0]!;
    for (const name of ["bak-u3", "bak-u4"]) {
      const identity = createIdentity();
      const record = makeUserNameRecord(identity.ikEd.privateKey, name, identity.did, 0);
      await fetch(`${base}/v0/registry/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
      });
    }
    await node.close();

    // 第三代启动：再次压缩 → .bak#2 产生，旧 .bak#1 被清理
    node = await startDevNode({ persistDir: dataDir, compactThreshold: 4 });
    base = `http://127.0.0.1:${node.port}`;
    expect(bakFiles().length).toBe(1);
    expect(bakFiles()[0]).not.toBe(firstBak); // 保留的是最新备份
    // 数据完好
    expect((await fetch(`${base}/v0/registry/resolve/bak-u1`)).status).toBe(200);
    expect((await fetch(`${base}/v0/registry/resolve/bak-u4`)).status).toBe(200);
  });

  it("交错注册/设备/手动事件后压缩：KT 根链不漂移，ktIndex/proof 仍可取证", async () => {
    // 第一代（不压缩）：交错操作制造与"按类型分组导出"不同的叶序
    node = await startDevNode({ persistDir: dataDir });
    base = `http://127.0.0.1:${node.port}`;
    const reg = async (name: string) => {
      const identity = createIdentity();
      const record = makeUserNameRecord(identity.ikEd.privateKey, name, identity.did, 0);
      const res = await fetch(`${base}/v0/registry/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ record: { ...record, signature: Buffer.from(record.signature).toString("base64") } }),
      });
      expect(res.status).toBe(201);
      return identity;
    };
    const alice = await reg("ord-alice"); // KT #0
    const bob = await reg("ord-bob"); // #1
    await registerDeviceCert(base, alice, "A1"); // #2
    const carol = await reg("ord-carol"); // #3
    await registerDeviceCert(base, bob, "B1"); // #4
    await registerDeviceCert(base, alice, "A2"); // #5
    // 手动 KT 事件（POST /v0/kt/append，同样须保序进快照）
    const manual = await fetch(`${base}/v0/kt/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ did: alice.did, type: "revoke", payload: Buffer.from("manual-note", "utf8").toString("base64") }),
    });
    expect(manual.status).toBe(201);
    const oldRoot = (await (await fetch(`${base}/v0/kt/root`)).json()) as { root: string; size: number };
    expect(oldRoot.size).toBe(7);
    await node.close();

    // 第二代：小阈值触发压缩（内存态由原始 JSONL 重放，此代根必然一致）
    node = await startDevNode({ persistDir: dataDir, compactThreshold: 5 });
    base = `http://127.0.0.1:${node.port}`;
    await node.close();

    // 第三代：从压缩快照重放——导出保序是根链不漂移的关键（分组导出会使叶序漂移）
    node = await startDevNode({ persistDir: dataDir, compactThreshold: 5 });
    base = `http://127.0.0.1:${node.port}`;
    const newRoot = (await (await fetch(`${base}/v0/kt/root`)).json()) as { root: string; size: number };
    expect(newRoot.root).toBe(oldRoot.root);
    expect(newRoot.size).toBe(7);

    // resolve 返回的 ktIndex 取包含性证明仍有效（客户端取证路径）
    const resolved = (await (await fetch(`${base}/v0/registry/resolve/ord-alice`)).json()) as {
      record: { ktIndex: number; did: string };
    };
    expect(resolved.record.ktIndex).toBe(0);
    const { proof } = (await (await fetch(`${base}/v0/kt/proof/${resolved.record.ktIndex}`)).json()) as { proof: KtInclusionProof };
    const event: KTEvent = { did: resolved.record.did, type: "register", index: resolved.record.ktIndex, payload: utf8ToBytes("ord-alice") };
    expect(ktVerifyInclusion(event, proof, newRoot.root)).toBe(true);
    // 手动事件的证明同样有效
    const manualProof = (await (await fetch(`${base}/v0/kt/proof/6`)).json()) as { proof: KtInclusionProof };
    expect(
      ktVerifyInclusion({ did: alice.did, type: "revoke", index: 6, payload: utf8ToBytes("manual-note") }, manualProof.proof, newRoot.root),
    ).toBe(true);
  });
});
