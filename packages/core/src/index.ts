/**
 * @mychat/core —— MyChat 协议与密码学核心
 *
 * 纯 TypeScript、浏览器/Node 同构（ADR-9）。
 * 密码原语：@noble 系列（经审计）；协议逻辑：按规范实现 + 测试向量保障。
 * 模块规划见 docs/MVP范围与里程碑计划.md §5.1。
 */
export const PROTOCOL_VERSION = "0.1.0";

export * from "./protocol/interfaces";
