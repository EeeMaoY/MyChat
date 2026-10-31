/**
 * MyChat dev-node —— 服务域单体开发节点（ADR-11）
 *
 * 单进程实现四类协议接口，协议边界自第一天分离
 * （接口定义见 @mychat/core `src/protocol/interfaces.ts`）：
 *
 *   Relay    中继池：在线密文包投递（计划于 S2 迭代实现）
 *   Storage  存储节点：信箱与加密块
 *   Registry 目录：用户名 → DID 映射
 *   KTLog    密钥透明日志：映射变更历史（v0: append-only）
 *
 * 注意：单体形态仅为开发/演示环境的部署属性，
 * 任何第三方可按四接口独立实现并部署自己的节点。
 */

const ROLES = ["Relay", "Storage", "Registry", "KTLog"] as const;

console.log(`[mychat-dev-node] 骨架就绪。待实现接口：${ROLES.join(" / ")}（S2 迭代）`);
