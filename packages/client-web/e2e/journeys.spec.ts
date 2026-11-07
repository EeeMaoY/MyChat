/**
 * 核心旅程 e2e（M4-S14）：双浏览器页面驱动，替代 IAB 失稳的手动验收。
 * 覆盖：注册起名 → 好友申请确认流 → 1:1 聊天 → 群组 → 动态时间线 → 口令锁屏。
 * 每 test 独立 context（IndexedDB 天然隔离）与独立用户对，互不干扰。
 */
import { expect, test, type Browser, type Page } from "@playwright/test";

import { NODE_URL } from "../playwright.config";

const NAME_RE = /^[A-Za-z0-9_-]+$/;

/** 打开一个新用户页面（独立 context，指向测试 dev-node），完成无感创建 + 起名。 */
async function newUser(browser: Browser, name: string): Promise<Page> {
  const context = await browser.newContext();
  await context.addInitScript((url) => localStorage.setItem("mychat.node-url", url), NODE_URL);
  const page = await context.newPage();
  await page.goto("/");
  await expect(page.getByRole("button", { name: "开始使用" })).toBeVisible();
  await page.getByRole("button", { name: "开始使用" }).click();
  await expect(page.getByText("起个名字", { exact: false })).toBeVisible({ timeout: 15_000 });
  await page.locator("input.input").first().fill(name);
  await page.getByRole("button", { name: "注册并进入" }).click();
  // 主界面：侧栏出现动态入口与加好友按钮
  await expect(page.locator(".sidebar").getByRole("button", { name: "➕ 加好友" })).toBeVisible({ timeout: 15_000 });
  return page;
}

/** 打开"我"弹窗。 */
async function openProfile(page: Page): Promise<void> {
  await page.locator(".me-entry").click();
  await expect(page.getByText("我的 DID").first()).toBeVisible();
}

test.describe.configure({ mode: "serial" });

test("注册：无感创建 + 起名进入主界面", async ({ browser }) => {
  const page = await newUser(browser, "e2e_alice");
  await openProfile(page);
  await expect(page.locator(".profile-name")).toContainText("e2e_alice");
});

test("好友申请确认流：A 申请 → B 横幅通过 → 双向聊天", async ({ browser }) => {
  const alice = await newUser(browser, "e2e_alice2");
  const bob = await newUser(browser, "e2e_bob2");

  // A 加好友
  await alice.locator(".sidebar").getByRole("button", { name: "➕ 加好友" }).click();
  await alice.getByPlaceholder("对方的 MyChat 用户名").fill("e2e_bob2");
  await alice.getByRole("button", { name: "发送好友请求" }).click();
  // A 侧出现握手消息（会话已建立但等待对方确认语义：申请已发送提示）
  await expect(alice.getByText("（握手请求已发送）").first()).toBeVisible({ timeout: 10_000 });

  // B 侧横幅出现 → 通过
  await expect(bob.getByText("请求添加你为好友").first()).toBeVisible({ timeout: 15_000 });
  await bob.getByRole("button", { name: "通过", exact: true }).click();
  // B 进入与 A 的会话
  await expect(bob.locator(".chat-peer-name")).toContainText("e2e_alice2", { timeout: 10_000 });

  // 双向消息
  await bob.locator("textarea.chat-textarea").fill("你好 alice");
  await bob.getByRole("button", { name: "发送", exact: true }).click();
  await expect(alice.getByText("你好 alice").first()).toBeVisible({ timeout: 15_000 });
  await alice.locator("textarea.chat-textarea").fill("你好 bob");
  await alice.getByRole("button", { name: "发送", exact: true }).click();
  await expect(bob.getByText("你好 bob").first()).toBeVisible({ timeout: 15_000 });
});

test("群组流：A 建群（含 B/C）→ B 侧栏出现群 → 群消息互发", async ({ browser }) => {
  const alice = await newUser(browser, "e2e_alice3");
  const bob = await newUser(browser, "e2e_bob3");
  const cathy = await newUser(browser, "e2e_cathy3");
  // 先建立好友（群成员须为已建立会话的联系人，且建群入口要求 ≥2 位联系人）
  for (const [friendPage, friendName] of [[bob, "e2e_bob3"], [cathy, "e2e_cathy3"]] as const) {
    await alice.locator(".sidebar").getByRole("button", { name: "➕ 加好友" }).click();
    await alice.getByPlaceholder("对方的 MyChat 用户名").fill(friendName);
    await alice.getByRole("button", { name: "发送好友请求" }).click();
    await expect(friendPage.getByText("请求添加你为好友").first()).toBeVisible({ timeout: 15_000 });
    await friendPage.getByRole("button", { name: "通过", exact: true }).click();
  }

  // A 建群
  await alice.getByRole("button", { name: "👥 建群" }).click();
  await alice.locator("#group-name").fill("e2e 项目群");
  await alice.locator(".guardian-item").filter({ hasText: "e2e_bob3" }).locator("input[type=checkbox]").check();
  await alice.locator(".guardian-item").filter({ hasText: "e2e_cathy3" }).locator("input[type=checkbox]").check();
  await alice.getByRole("button", { name: "创建群聊" }).click();
  await expect(alice.getByText("群「e2e 项目群」已创建").first()).toBeVisible({ timeout: 10_000 });

  // 群聊窗打开（A 侧自动打开？建群后 appendLocalMessage；打开群会话）
  await alice.locator(".contact-item").filter({ hasText: "e2e 项目群" }).click();
  await alice.locator("textarea.chat-textarea").fill("群第一条消息");
  await alice.getByRole("button", { name: "发送", exact: true }).click();

  // B 侧栏出现群（group-keys 经 1:1 会话分发 + poll），点开可见消息
  await expect(bob.locator(".contact-item").filter({ hasText: "e2e 项目群" })).toBeVisible({ timeout: 20_000 });
  await bob.locator(".contact-item").filter({ hasText: "e2e 项目群" }).click();
  await expect(bob.getByText("群第一条消息").first()).toBeVisible({ timeout: 15_000 });
});

test("动态流：A 发布 → B 时间线可见", async ({ browser }) => {
  const alice = await newUser(browser, "e2e_alice4");
  const bob = await newUser(browser, "e2e_bob4");
  await alice.locator(".sidebar").getByRole("button", { name: "➕ 加好友" }).click();
  await alice.getByPlaceholder("对方的 MyChat 用户名").fill("e2e_bob4");
  await alice.getByRole("button", { name: "发送好友请求" }).click();
  await expect(bob.getByText("请求添加你为好友").first()).toBeVisible({ timeout: 15_000 });
  await bob.getByRole("button", { name: "通过", exact: true }).click();

  // A 发布动态
  await alice.getByRole("button", { name: "📱 动态" }).click();
  await alice.locator(".timeline-composer textarea").fill("e2e 的第一条动态");
  await alice.getByRole("button", { name: "发布", exact: true }).click();
  await expect(alice.getByText("e2e 的第一条动态").first()).toBeVisible({ timeout: 10_000 });

  // B 时间线可见（好友圈密钥分发 + poll 增量，留足重试窗口）
  await bob.getByRole("button", { name: "📱 动态" }).click();
  await expect(bob.getByText("e2e 的第一条动态").first()).toBeVisible({ timeout: 20_000 });
});

test("口令锁屏：设置口令 → 立即锁定 → 解锁恢复", async ({ browser }) => {
  const page = await newUser(browser, "e2e_alice5");
  await openProfile(page);

  // 设置口令（PassphraseModal：两次输入 + 提交；scrypt 需数百毫秒）
  await page.getByRole("button", { name: "设置访问口令" }).click();
  await page.locator("#vault-new").fill("e2e-pass-123");
  await page.locator("#vault-confirm").fill("e2e-pass-123");
  await page.getByRole("button", { name: "设置并加密本地数据" }).click();

  // 设置口令后 Profile 弹窗自动关闭：重开再点"立即锁定"
  await page.locator(".me-entry").click();
  await page.getByRole("button", { name: "立即锁定" }).click();
  await expect(page.getByText("MyChat 已锁定").first()).toBeVisible({ timeout: 10_000 });
  await page.getByPlaceholder("访问口令").fill("e2e-pass-123");
  await page.getByRole("button", { name: "解锁", exact: true }).click();
  // 主界面恢复，用户名仍在
  await expect(page.locator(".sidebar").getByRole("button", { name: "➕ 加好友" })).toBeVisible({ timeout: 15_000 });
  await openProfile(page);
  await expect(page.locator(".profile-name")).toContainText("e2e_alice5");
});

void NAME_RE;
