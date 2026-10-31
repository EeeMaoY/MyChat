/**
 * MyChat dev-node 入口：启动单体开发节点。
 *
 * 环境变量：
 *   MYCHAT_PORT  监听端口（默认 8629）
 *   MYCHAT_HOST  监听地址（默认 127.0.0.1）
 *
 * 注意：内存态，无持久化——开发/演示环境属性，生产多节点部署为后续里程碑。
 */
import { startDevNode } from "./server";

const port = Number(process.env.MYCHAT_PORT ?? "8629");
const host = process.env.MYCHAT_HOST ?? "127.0.0.1";

const node = await startDevNode({ port, host });

console.log(`[mychat-dev-node] 监听 http://${host}:${node.port}`);
console.log("[mychat-dev-node] 角色：Relay / Storage / Registry / KTLog（协议接口分离，ADR-11）");
console.log("[mychat-dev-node] 开发环境属性：内存态、单点部署。仅见密文，无用户数据信任。");

process.on("SIGINT", () => {
  void node.close().then(() => process.exit(0));
});
