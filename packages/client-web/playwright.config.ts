/**
 * Playwright 配置（M4-S14）：真实 dev-node + 双浏览器页面驱动核心旅程。
 * 端口固定 8801/5183（避开开发者本地常用端口）；客户端经 localStorage 指向该节点。
 * reuseExistingServer=true：本地已手动起服务时直接复用（开发友好）。
 */
import { defineConfig } from "@playwright/test";

export const NODE_PORT = 8801;
export const CLIENT_PORT = 5183;
export const NODE_URL = `http://127.0.0.1:${NODE_PORT}`;

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false, // 共享一个 dev-node，串行执行
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${CLIENT_PORT}`,
    trace: "retain-on-failure",
    viewport: { width: 1280, height: 800 },
  },
  webServer: [
    {
      command: "npm start -w @mychat/dev-node",
      cwd: "../..",
      port: NODE_PORT,
      reuseExistingServer: true,
      timeout: 30_000,
      env: { ...process.env, MYCHAT_PORT: String(NODE_PORT), MYCHAT_HOST: "127.0.0.1" } as Record<string, string>,
    },
    {
      command: `npm run dev -w @mychat/client-web -- --port ${CLIENT_PORT} --strictPort --host 127.0.0.1`,
      cwd: "../..",
      port: CLIENT_PORT,
      reuseExistingServer: true,
      timeout: 30_000,
      env: process.env as Record<string, string>,
    },
  ],
});
