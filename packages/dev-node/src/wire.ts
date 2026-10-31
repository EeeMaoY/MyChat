/**
 * 节点线格式：Envelope 与 JSON 的互转（HTTP/WS 传输用，字段 base64）。
 * 二进制信封编解码（客户端侧）在 @mychat/core envelope 模块；
 * 节点只在线格式层做结构校验（见 validateEnvelopeJson）。
 */
import { AEAD_NONCE_LENGTH, type Envelope } from "@mychat/core";

export interface EnvelopeJson {
  version: string;
  epoch: number;
  toPseudonym: string;
  padClass: number;
  nonce: string;
  payload: string;
}

const MAX_PAYLOAD = 131_072; // 与填充最高档一致（防滥用上限）

export function envelopeToJson(e: Envelope): EnvelopeJson {
  return {
    version: e.version,
    epoch: e.epoch,
    toPseudonym: e.toPseudonym,
    padClass: e.padClass,
    nonce: Buffer.from(e.nonce).toString("base64"),
    payload: Buffer.from(e.payload).toString("base64"),
  };
}

/** 严格校验并转换；任何字段非法 throw（节点拒绝畸形信封，A3 防注入的基本面）。 */
export function envelopeFromJson(j: unknown): Envelope {
  if (typeof j !== "object" || j === null) throw new Error("信封格式非法");
  const e = j as Record<string, unknown>;
  if (typeof e.version !== "string" || e.version.length === 0) throw new Error("信封 version 非法");
  if (typeof e.epoch !== "number" || !Number.isInteger(e.epoch) || e.epoch < 0) throw new Error("信封 epoch 非法");
  if (typeof e.toPseudonym !== "string" || e.toPseudonym.length === 0 || e.toPseudonym.length > 128) {
    throw new Error("信封伪地址非法");
  }
  if (typeof e.padClass !== "number" || ![0, 1, 2, 3].includes(e.padClass)) throw new Error("信封填充档位非法");
  const nonce = Buffer.from(e.nonce as string, "base64");
  if (nonce.length !== AEAD_NONCE_LENGTH) throw new Error("信封 nonce 长度非法");
  const payload = Buffer.from(e.payload as string, "base64");
  if (payload.length === 0 || payload.length > MAX_PAYLOAD) throw new Error("信封负载长度非法");
  return {
    version: e.version,
    epoch: e.epoch,
    toPseudonym: e.toPseudonym,
    padClass: e.padClass as 0 | 1 | 2 | 3,
    nonce: new Uint8Array(nonce),
    payload: new Uint8Array(payload),
  };
}
