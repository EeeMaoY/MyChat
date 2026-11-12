/**
 * deserializeSession 输入校验测试（FR-7.1 持久化防线）：
 * 持久化记录与磁盘上的任何数据一样不可信——密钥字段长度、计数器、skipped
 * 结构、dhSelf 自洽性任一被篡改都必须 throw，不得以非法状态进入运行时。
 */
import { describe, expect, it } from "vitest";

import { base58Encode, utf8ToBytes } from "../../codec/index.ts";
import { generateX25519KeyPair, randomBytes } from "../../crypto/index.ts";
import { createIdentity, deriveOpkId, issuePreKeyBundle } from "../../identity/index.ts";
import { acceptSession, deserializeSession, initiateSession, serializeSession, sessionReceive, sessionSend } from "../session.ts";

/** 建立一个已推进链的会话并返回其序列化记录（Alice 视角）。 */
function makeSerializedSession(): string {
  const alice = createIdentity();
  const bob = createIdentity();
  const spk = generateX25519KeyPair();
  const opk = generateX25519KeyPair();
  const bundle = issuePreKeyBundle(bob, spk, { ...opk, id: deriveOpkId(opk.publicKey) }, 3_600_000);
  const { session, wire } = initiateSession(alice, bundle, utf8ToBytes("hello"));
  const { session: bobSession } = acceptSession(bob, spk, new Map([[deriveOpkId(opk.publicKey), opk]]), wire, alice.did);
  void sessionReceive(bobSession, sessionSend(session, utf8ToBytes("m1"))); // 推进链：计数器非零、根状态非初始
  sessionSend(session, utf8ToBytes("m2"));
  return serializeSession(session);
}

type Json = Record<string, unknown>;

/** 解析序列化记录，篡改指定字段后重新序列化（模拟被篡改的持久化记录）。 */
function tamper(json: string, mutate: (obj: Json) => void): string {
  const obj = JSON.parse(json) as Json;
  mutate(obj);
  return JSON.stringify(obj);
}

const ratchetOf = (obj: Json) => obj["ratchet"] as Json;

describe("deserializeSession 输入校验", () => {
  it("合法记录往返不受影响，恢复后仍可正常收发", () => {
    const restored = deserializeSession(makeSerializedSession());
    expect(() => sessionSend(restored, utf8ToBytes("still-works"))).not.toThrow();
  });

  it("role / peerDid 类型非法 throw", () => {
    const base = makeSerializedSession();
    expect(() => deserializeSession(tamper(base, (o) => { o["role"] = "peer"; }))).toThrow(/role/);
    expect(() => deserializeSession(tamper(base, (o) => { o["peerDid"] = 42; }))).toThrow(/peerDid/);
  });

  it("密钥字段解码长度非 32B（或非 base58）一律 throw", () => {
    const base = makeSerializedSession();
    const short31 = base58Encode(new Uint8Array(31));
    const long33 = base58Encode(new Uint8Array(33));

    expect(() => deserializeSession(tamper(base, (o) => { o["selfIkx"] = short31; }))).toThrow(/selfIkx/);
    expect(() => deserializeSession(tamper(base, (o) => { o["peerIkx"] = long33; }))).toThrow(/peerIkx/);
    expect(() => deserializeSession(tamper(base, (o) => { o["mailboxSecret"] = "abc"; }))).toThrow(/mailboxSecret/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["rootKey"] = short31; }))).toThrow(/rootKey/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["dhRemote"] = long33; }))).toThrow(/dhRemote/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["sendChainKey"] = short31; }))).toThrow(/sendChainKey/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["recvChainKey"] = short31; }))).toThrow(/recvChainKey/);
  });

  it("dhSelf 公钥与私钥推导不一致 throw（X25519 自洽不变量）", () => {
    const base = makeSerializedSession();
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["dhSelfPub"] = base58Encode(randomBytes(32)); }))).toThrow(/dhSelfPub/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["dhSelfPriv"] = base58Encode(randomBytes(32)); }))).toThrow(/dhSelf/);
  });

  it("计数器为负数/非整数/非数值一律 throw", () => {
    const base = makeSerializedSession();
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["sendCount"] = -1; }))).toThrow(/sendCount/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["recvCount"] = 1.5; }))).toThrow(/recvCount/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["prevSendCount"] = "2"; }))).toThrow(/prevSendCount/);
  });

  it("skipped 结构非法（非数组/条目形状/dh 长度/序号/密钥长度）一律 throw", () => {
    const base = makeSerializedSession();
    const goodDh = base58Encode(new Uint8Array(32));
    const goodKey = base58Encode(new Uint8Array(32));

    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["skipped"] = "nope"; }))).toThrow(/skipped/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["skipped"] = [["missing-separator", goodKey]]; }))).toThrow(/skipped/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["skipped"] = [[`${goodDh}:-1`, goodKey]]; }))).toThrow(/skipped/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["skipped"] = [[`${base58Encode(new Uint8Array(31))}:0`, goodKey]]; }))).toThrow(/skipped/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["skipped"] = [[`${goodDh}:0`, base58Encode(new Uint8Array(31))]]; }))).toThrow(/skipped/);
    expect(() => deserializeSession(tamper(base, (o) => { ratchetOf(o)["skipped"] = [[goodDh]]; }))).toThrow(/skipped/);
  });

  it("不是合法 JSON 时 throw", () => {
    expect(() => deserializeSession("{not-json")).toThrow(/JSON/);
  });
});
