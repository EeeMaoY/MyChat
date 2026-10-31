/**
 * signal 模块公共 API：X3DH 握手 + Double Ratchet + 1:1 会话（ADR-1、设计报告 §5.1/5.2）。
 */
export {
  MAX_SKIP,
  type DrHeader,
  type RatchetState,
  decodeHeader,
  encodeHeader,
  ratchetDecrypt,
  ratchetEncrypt,
  ratchetInitInitiator,
  ratchetInitResponder,
} from "./ratchet.ts";
export {
  EPOCH_MS,
  type Session,
  type SessionRole,
  acceptSession,
  deserializeSession,
  initiateSession,
  serializeSession,
  sessionMailbox,
  sessionReceive,
  sessionSend,
} from "./session.ts";
export {
  KIND_INITIAL,
  KIND_REGULAR,
  type InitialWire,
  type RegularWire,
  type SessionWire,
  decodeSessionWire,
  encodeSessionWire,
} from "./wire.ts";
export {
  type X3dhInitialHeader,
  type X3dhInitiateResult,
  x3dhAccept,
  x3dhAssociatedData,
  x3dhInitiate,
} from "./x3dh.ts";
