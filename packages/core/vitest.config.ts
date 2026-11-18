import { configDefaults, defineConfig } from "vitest/config";

// vitest 5 起默认 exclude 不再覆盖 dist/（npm run build 的 tsc 产物含
// __tests__ 编译出的 *.test.js，会被重复收集使计数翻倍）——显式排除。
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "dist/**"],
  },
});
