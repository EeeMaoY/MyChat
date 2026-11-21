import { defineConfig } from "vite";

export default defineConfig({
  // 演示页固定端口（e2e 与课程录制依赖）；绑定 IPv4 避免 vite 默认解析到 ::1
  server: { port: 5190, strictPort: true, host: "127.0.0.1" },
});
