/**
 * MyChat dev-node 入口：启动单体开发节点。
 *
 * 环境变量：
 *   MYCHAT_PORT      监听端口（默认 8629）
 *   MYCHAT_HOST      监听地址（默认 127.0.0.1）
 *   MYCHAT_DATA_DIR  持久化目录（可选；设置后变更追加 JSONL，重启重放恢复，
 *                    信箱历史/KT 根链跨重启延续；未设置保持纯内存）
 */
import { startDevNode } from "./server.ts";

const port = Number(process.env.MYCHAT_PORT ?? "8629");
const host = process.env.MYCHAT_HOST ?? "127.0.0.1";

const node = await startDevNode({ port, host });

console.log(`[mychat-dev-node] 监听 http://${host}:${node.port}`);
console.log("[mychat-dev-node] 角色：Relay / Storage / Registry / KTLog（协议接口分离，ADR-11）");
console.log("[mychat-dev-node] 开发环境属性：单点部署。仅见密文，无用户数据信任。");
if (process.env.MYCHAT_DATA_DIR) {
  console.log(`[mychat-dev-node] 持久化已启用：${process.env.MYCHAT_DATA_DIR}（JSONL 追加 + 启动重放）`);
} else {
  console.log("[mychat-dev-node] 提示：设置 MYCHAT_DATA_DIR 可启用持久化（重启不丢数据）");
}

process.on("SIGINT", () => {
  void node.close().then(() => process.exit(0));
});
