/**
 * 发现信箱（discovery inbox）—— 新会话握手的可达地址。
 *
 * 地址由 DID 公开材料派生，任何知道 DID 的人可投递握手请求。
 * 元数据边界（Level0 如实披露，TR-4/设计报告 Q1）：观察者可将
 * "握手投递"关联到该 DID；会话建立后的流量走伪地址轮换信箱（SR-2 覆盖）。
 * 发现路径的匿名化（sealed sender 化）为 M2 增强模式项。
 */
import { base58Encode, hkdfSha256, didToEd25519PublicKey } from "@mychat/core";

const DISCOVERY_INFO = "mychat:discovery:v1";

export function discoveryInboxId(did: string): string {
  const ikPublic = didToEd25519PublicKey(did);
  return base58Encode(hkdfSha256(ikPublic, new Uint8Array(32), DISCOVERY_INFO, 18));
}
