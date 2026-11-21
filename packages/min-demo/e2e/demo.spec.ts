/**
 * 课程演示最小实现的全流程验收：
 * 注册双身份 → Alice 加好友（X3DH）→ 端到端互发 → **节点视角无明文**（零信任核心断言）。
 */
import { expect, test } from "@playwright/test";

const MESSAGE_A = "Hello-E2EE-课程演示消息";
const MESSAGE_B = "Bob-回复-这条也是密文传输";

/** 第 index 个 persona 栏（0=Alice 左栏，1=Bob 右栏）。 */
function persona(page: import("@playwright/test").Page, index: 0 | 1) {
  return page.locator(".persona").nth(index);
}

test("端到端交流 + 中心（节点）只见密文", async ({ page }) => {
  await page.goto("/");

  // 两栏身份自动创建完成（DID 出现即 setup 完毕）
  await expect(persona(page, 0).locator(".status")).toContainText("DID", { timeout: 20_000 });
  await expect(persona(page, 1).locator(".status")).toContainText("DID", { timeout: 20_000 });

  // 注册用户名
  await persona(page, 0).getByPlaceholder("用户名", { exact: true }).fill("alice");
  await persona(page, 0).getByRole("button", { name: "① 注册" }).click();
  await expect(persona(page, 0).locator(".status")).toContainText("用户名「alice」");
  await persona(page, 1).getByPlaceholder("用户名", { exact: true }).fill("bob");
  await persona(page, 1).getByRole("button", { name: "① 注册" }).click();
  await expect(persona(page, 1).locator(".status")).toContainText("用户名「bob」");

  // Alice 对 bob 发起 X3DH 握手；Bob 侧自动接受（轮询发现信箱）
  await persona(page, 0).getByPlaceholder("对方用户名").fill("bob");
  await persona(page, 0).getByRole("button", { name: "② 加好友" }).click();
  await expect(persona(page, 1).locator(".chat-head")).toContainText("与「alice」的端到端加密会话", { timeout: 30_000 });
  await expect(persona(page, 0).locator(".chat-head")).toContainText("与「bob」的端到端加密会话", { timeout: 30_000 });

  // Alice → Bob 端到端消息（DR 加密；轮询解密）
  await persona(page, 0).getByPlaceholder("输入明文消息…").fill(MESSAGE_A);
  await persona(page, 0).getByRole("button", { name: "加密发送" }).click();
  await expect(persona(page, 0).locator(".bubble", { hasText: MESSAGE_A })).toBeVisible();
  await expect(persona(page, 1).locator(".bubble", { hasText: MESSAGE_A })).toBeVisible({ timeout: 30_000 });

  // Bob → Alice 回复
  await persona(page, 1).getByPlaceholder("输入明文消息…").fill(MESSAGE_B);
  await persona(page, 1).getByRole("button", { name: "加密发送" }).click();
  await expect(persona(page, 0).locator(".bubble", { hasText: MESSAGE_B })).toBeVisible({ timeout: 30_000 });

  // 核心断言：节点视角栏可见全部信封，但**任何一栏明文都不出现在中间栏**
  const nodeCol = page.locator(".nodecol");
  await expect(nodeCol.locator(".mailbox-card").first()).toBeVisible({ timeout: 15_000 });
  const nodeText = (await nodeCol.textContent()) ?? "";
  expect(nodeText).not.toContain(MESSAGE_A);
  expect(nodeText).not.toContain(MESSAGE_B);
  expect(nodeText).not.toContain("alice"); // 用户名不出现在节点信箱数据里（发现地址由 DID 派生，握手在密文内层）
  // 信封都是密文形态（version/epoch/padClass/payload 结构可见）
  await expect(nodeCol.locator(".envelope-json").first()).toBeVisible();
});
