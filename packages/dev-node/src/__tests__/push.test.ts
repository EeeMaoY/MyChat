/**
 * S15 Web Push 网关测试：订阅登记/更新/注销、信箱 append 触发投递（注入 sender 桩）、
 * 410 自动移除、VAPID 密钥跨重启稳定。
 *
 * 说明：无 payload push 无法在单测中走真实推送服务（Chrome/Mozilla 端点），
 * 以 sender 注入桩验证发送行为；浏览器端到端推送属手动验收。
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PushStore } from "../push.ts";

import { startDevNode, type DevNode } from "../server";
import { randomBytes, type Envelope } from "@mychat/core";
import { envelopeToJson } from "../wire";

let node: DevNode;
let base: string;
let dataDir: string | undefined;

beforeEach(() => {
  dataDir = undefined;
});

afterEach(async () => {
  await node.close();
  if (dataDir !== undefined) rmSync(dataDir, { recursive: true, force: true });
});

function makeEnvelope(toPseudonym: string): Envelope {
  return { version: "1", epoch: 1, toPseudonym, padClass: 0, nonce: randomBytes(24), payload: randomBytes(200) };
}

const SUBSCRIPTION = {
  endpoint: "https://push.example.com/send/abc123",
  keys: { p256dh: "BPK", auth: "AUTH" },
};

async function subscribe(mailboxes: string[]): Promise<void> {
  const res = await fetch(`${base}/v0/push/subscribe`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subscription: SUBSCRIPTION, mailboxes }),
  });
  expect(res.status).toBe(201);
}

async function appendTo(mailboxId: string): Promise<void> {
  const res = await fetch(`${base}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}/append`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ envelope: envelopeToJson(makeEnvelope(mailboxId)) }),
  });
  expect(res.status).toBe(201);
}

describe("Web Push 网关（M4-S15）", () => {
  it("订阅登记 → 关注信箱 append 触发无 payload 投递；无关信箱不投递", async () => {
    node = await startDevNode({ persistDir: (dataDir = mkdtempSync(join(tmpdir(), "mychat-push-"))) });
    base = `http://127.0.0.1:${node.port}`;
    const sender = vi.fn<NonNullable<PushStore["sender"]>>(async () => undefined);
    node.push.sender = sender;

    const vapid = await fetch(`${base}/v0/push/vapid`);
    const { publicKey } = (await vapid.json()) as { publicKey: string };
    expect(publicKey.length).toBeGreaterThan(40); // 真实生成的 VAPID 公钥

    await subscribe(["mailbox-a", "mailbox-b"]);
    await appendTo("mailbox-a");
    await vi.waitFor(() => expect(sender).toHaveBeenCalledTimes(1));
    const [subscription, vapidDetails] = sender.mock.calls[0]!;
    expect(subscription.endpoint).toBe(SUBSCRIPTION.endpoint);
    expect(vapidDetails.publicKey).toBe(publicKey);

    await appendTo("mailbox-other"); // 未关注信箱
    await new Promise((r) => setTimeout(r, 150));
    expect(sender).toHaveBeenCalledTimes(1); // 不投递
  });

  it("mailboxes 覆盖更新与注销", async () => {
    node = await startDevNode({});
    base = `http://127.0.0.1:${node.port}`;
    const sender = vi.fn<NonNullable<PushStore["sender"]>>(async () => undefined);
    node.push.sender = sender;
    await subscribe(["mailbox-a"]);
    await subscribe(["mailbox-c"]); // 同 endpoint 覆盖
    await appendTo("mailbox-a");
    await new Promise((r) => setTimeout(r, 150));
    expect(sender).not.toHaveBeenCalled(); // 已被覆盖移除

    await appendTo("mailbox-c");
    await vi.waitFor(() => expect(sender).toHaveBeenCalledTimes(1));

    const del = await fetch(`${base}/v0/push/subscribe?endpoint=${encodeURIComponent(SUBSCRIPTION.endpoint)}`, { method: "DELETE" });
    expect(((await del.json()) as { removed: boolean }).removed).toBe(true);
    await appendTo("mailbox-c");
    await new Promise((r) => setTimeout(r, 150));
    expect(sender).toHaveBeenCalledTimes(1); // 已注销
  });

  it("推送 410（订阅过期）自动移除，后续信箱不再尝试", async () => {
    node = await startDevNode({});
    base = `http://127.0.0.1:${node.port}`;
    node.push.sender = vi.fn(async () => {
      throw Object.assign(new Error("gone"), { statusCode: 410 });
    });
    await subscribe(["mailbox-gone"]);
    await appendTo("mailbox-gone");
    await vi.waitFor(() => expect(node.push.sender).toHaveBeenCalledTimes(1));
    // node.push.sender 不可重赋值后清计数：直接以第二次 append 验证订阅已移除
    const senderFn = node.push.sender;
    await new Promise((r) => setTimeout(r, 100));
    (senderFn as ReturnType<typeof vi.fn>).mockClear!();
    await appendTo("mailbox-gone");
    await new Promise((r) => setTimeout(r, 150));
    expect(senderFn).toHaveBeenCalledTimes(0); // 已移除
  });

  it("VAPID 密钥跨重启稳定（持久化到数据目录）", async () => {
    dataDir = mkdtempSync(join(tmpdir(), "mychat-push2-"));
    node = await startDevNode({ persistDir: dataDir });
    base = `http://127.0.0.1:${node.port}`;
    const first = ((await (await fetch(`${base}/v0/push/vapid`)).json()) as { publicKey: string }).publicKey;
    await node.close();
    node = await startDevNode({ persistDir: dataDir });
    base = `http://127.0.0.1:${node.port}`;
    const second = ((await (await fetch(`${base}/v0/push/vapid`)).json()) as { publicKey: string }).publicKey;
    expect(second).toBe(first);
    expect(JSON.parse(readFileSync(join(dataDir, "vapid.json"), "utf8"))).toHaveProperty("privateKey");
  });
});

describe("Push 订阅加固", () => {
  /** 原始订阅 PUT（不断言 201），返回响应供状态码断言。 */
  function sub(base: string, subscription: unknown): Promise<Response> {
    return fetch(`${base}/v0/push/subscribe`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subscription, mailboxes: ["hard-mailbox"] }),
    });
  }

  it("endpoint scheme 校验：内网 http 拒绝；https/本机 http 放行", async () => {
    node = await startDevNode({});
    base = `http://127.0.0.1:${node.port}`;
    const keys = { p256dh: "BPK", auth: "AUTH" };
    expect((await sub(base, { endpoint: "http://192.168.1.10/send", keys })).status).toBe(400); // 内网
    expect((await sub(base, { endpoint: "http://10.0.0.5/send", keys })).status).toBe(400);
    expect((await sub(base, { endpoint: "ftp://push.example.com/send", keys })).status).toBe(400); // 非 http(s)
    expect((await sub(base, { endpoint: "https://push.example.com/send/abc", keys })).status).toBe(201);
    expect((await sub(base, { endpoint: "http://127.0.0.1:9099/send", keys })).status).toBe(201); // 本机放行
    expect((await sub(base, { endpoint: "http://localhost:9099/send", keys })).status).toBe(201);
  });

  it("keys 校验：空值/超长拒绝", async () => {
    node = await startDevNode({});
    base = `http://127.0.0.1:${node.port}`;
    const endpoint = "https://push.example.com/send/keys-test";
    expect((await sub(base, { endpoint, keys: { p256dh: "", auth: "AUTH" } })).status).toBe(400);
    expect((await sub(base, { endpoint, keys: { p256dh: "BPK", auth: "" } })).status).toBe(400);
    expect((await sub(base, { endpoint, keys: { p256dh: "BPK", auth: "x".repeat(513) } })).status).toBe(400);
    expect((await sub(base, { endpoint, keys: { p256dh: "x".repeat(512), auth: "AUTH" } })).status).toBe(201); // 边界内放行
  });

  it("订阅表上限：新端点触顶 429；既有端点更新放行", async () => {
    node = await startDevNode({ limits: { maxPushSubscriptions: 2 } });
    base = `http://127.0.0.1:${node.port}`;
    const keys = { p256dh: "BPK", auth: "AUTH" };
    const ep = (n: number) => `https://push.example.com/send/cap-${n}`;
    expect((await sub(base, { endpoint: ep(1), keys })).status).toBe(201);
    expect((await sub(base, { endpoint: ep(2), keys })).status).toBe(201);
    expect((await sub(base, { endpoint: ep(3), keys })).status).toBe(429); // 新端点触顶
    expect((await sub(base, { endpoint: ep(1), keys })).status).toBe(201); // 既有端点更新不受限
  });

  it("订阅限流：pushSubscribePerMin 触顶 429", async () => {
    node = await startDevNode({ limits: { pushSubscribePerMin: 1 } });
    base = `http://127.0.0.1:${node.port}`;
    const keys = { p256dh: "BPK", auth: "AUTH" };
    expect((await sub(base, { endpoint: "https://push.example.com/send/rl-1", keys })).status).toBe(201);
    expect((await sub(base, { endpoint: "https://push.example.com/send/rl-2", keys })).status).toBe(429);
  });
});
