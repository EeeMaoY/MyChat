/**
 * 会话消息传输编码（信封 payload 的内层格式，设计报告 §11.1 Inner 层的 M0 子集）。
 *
 * 两种消息：
 *   initial（kind=1）：首条消息，携带 X3DH 初始头（响应方据此建立会话）
 *   regular（kind=2）：后续消息
 *
 * 时间戳按桶化处理由信封层负责（FR-3.3）；本层不携带任何明文可识别元数据。
 */
import { concatBytes } from "../codec";
import { type DrHeader, decodeHeader, encodeHeader } from "./ratchet";

export const KIND_INITIAL = 1;
export const KIND_REGULAR = 2;
export const X3DH_HEADER_LENGTH = 68; // ikx(32) + ek(32) + opkId(4)
export const NONCE_LENGTH = 24;

export interface InitialWire {
  kind: typeof KIND_INITIAL;
  x3dh: { ikxSenderPublic: Uint8Array; ekPublic: Uint8Array; opkId: number };
  header: DrHeader;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export interface RegularWire {
  kind: typeof KIND_REGULAR;
  header: DrHeader;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export type SessionWire = InitialWire | RegularWire;

function writeUint32(target: Uint8Array, offset: number, value: number): void {
  new DataView(target.buffer).setUint32(offset, value, false);
}

function readUint32(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}

export function encodeSessionWire(wire: SessionWire): Uint8Array {
  if (wire.kind === KIND_INITIAL) {
    const head = new Uint8Array(1 + X3DH_HEADER_LENGTH + 40 + NONCE_LENGTH + 4);
    head[0] = KIND_INITIAL;
    head.set(wire.x3dh.ikxSenderPublic, 1);
    head.set(wire.x3dh.ekPublic, 33);
    writeUint32(head, 65, wire.x3dh.opkId);
    head.set(encodeHeader(wire.header), 69);
    head.set(wire.nonce, 109);
    writeUint32(head, 133, wire.ciphertext.length);
    return concatBytes(head, wire.ciphertext);
  }
  const head = new Uint8Array(1 + 40 + NONCE_LENGTH + 4);
  head[0] = KIND_REGULAR;
  head.set(encodeHeader(wire.header), 1);
  head.set(wire.nonce, 41);
  writeUint32(head, 65, wire.ciphertext.length);
  return concatBytes(head, wire.ciphertext);
}

export function decodeSessionWire(bytes: Uint8Array): SessionWire {
  if (bytes.length < 1) throw new Error("wire: 空消息");
  const kind = bytes[0]!;
  const readTail = (offset: number): { header: DrHeader; nonce: Uint8Array; ciphertext: Uint8Array } => {
    if (bytes.length < offset + 40 + NONCE_LENGTH + 4) throw new Error("wire: 消息截断");
    const header = decodeHeader(bytes.slice(offset, offset + 40));
    const nonce = bytes.slice(offset + 40, offset + 40 + NONCE_LENGTH);
    const ctLen = readUint32(bytes, offset + 64);
    if (bytes.length !== offset + 68 + ctLen) throw new Error("wire: 密文长度不一致");
    return { header, nonce, ciphertext: bytes.slice(offset + 68) };
  };

  if (kind === KIND_INITIAL) {
    if (bytes.length < 1 + X3DH_HEADER_LENGTH) throw new Error("wire: 初始消息截断");
    const tail = readTail(1 + X3DH_HEADER_LENGTH);
    return {
      kind: KIND_INITIAL,
      x3dh: {
        ikxSenderPublic: bytes.slice(1, 33),
        ekPublic: bytes.slice(33, 65),
        opkId: readUint32(bytes, 65),
      },
      ...tail,
    };
  }
  if (kind === KIND_REGULAR) {
    return { kind: KIND_REGULAR, ...readTail(1) };
  }
  throw new Error(`wire: 未知消息类型 ${kind}`);
}
