import { defineConfig } from "@playwright/test";

/**
 * min-demo 演示验收（课程 demo 的可靠性保障）：
 * dev-node 8802（内存态）+ vite 5190，双端 + 节点视角三栏全流程。
 */
export default defineConfig({
  testDir: "e2e",
  timeout: 90_000,
  use: { headless: true, baseURL: "http://127.0.0.1:5190" },
  webServer: [
    {
      command: "npm start -w @mychat/dev-node",
      port: 8802,
      reuseExistingServer: false,
      timeout: 60_000,
      env: { MYCHAT_PORT: "8802" } as Record<string, string>,
    },
    {
      command: "npm run dev -w @mychat/min-demo",
      port: 5190,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
