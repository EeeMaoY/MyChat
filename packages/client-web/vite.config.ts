import react from "@vitejs/plugin-react";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    // e2e/ 是 Playwright 用例（npm run test:e2e），不属于 vitest 单测：
    // 不排除则被默认 glob（*.spec.ts）收集，加载 Playwright API 报错使 vitest run 失败
    exclude: [...configDefaults.exclude, "e2e/**"],
  },
});
