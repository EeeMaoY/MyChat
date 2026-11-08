/**
 * @mychat/core —— MyChat 协议与密码学核心
 *
 * 纯 TypeScript、浏览器/Node 同构（ADR-9）。
 * 密码原语：@noble 系列（经审计）；协议逻辑：按规范实现 + 测试向量保障。
 *
 * 模块地图（docs/MVP范围与里程碑计划.md §5.1）：
 *   protocol  服务域四接口（IRelay/IStorage/IRegistry/IKTLog）—— client 与 node 的协议边界
 *   crypto    密码原语封装（全库唯一允许接触 @noble/* 的位置）
 *   codec     base58 / base64 / 字节工具
 *   identity  IK/DK 分层、DID、预密钥束、用户名签名记录
 *   signal    X3DH + Double Ratchet + 1:1 会话
 *   envelope  伪地址 / 填充 / 时间桶 / 信封编解码
 *   store     本地持久化抽象（IndexedDB / 内存）
 */
export const PROTOCOL_VERSION = "0.2.0";

export * from "./protocol/interfaces.ts";
export * from "./crypto/index.ts";
export * from "./codec/index.ts";
export * from "./identity/index.ts";
export * from "./signal/index.ts";
export * from "./envelope/index.ts";
export * from "./store/index.ts";
export * from "./attachment/index.ts";
export * from "./ssss/index.ts";
export * from "./ktmerkle/index.ts";
export * from "./recovery/index.ts";
export * from "./devices/index.ts";
export * from "./groups/index.ts";
export * from "./moments/index.ts";

