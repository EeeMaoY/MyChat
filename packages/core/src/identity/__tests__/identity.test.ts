/**
 * identity 模块测试：DID、身份序列化、X3DH 预密钥束、用户名记录。
 * 覆盖 FR-1.1（无感身份创建）、SR-5（客户端验签）与设计报告 §4.1/§5.2。
 */
import { describe, expect, it } from "vitest";

import {
  decodePreKeyBundle,
  deriveOpkId,
  encodePreKeyBundle,
  issuePreKeyBundle,
  verifyPreKeyBundle,
} from "../bundle";
import {
  didFromEd25519PublicKey,
  didToEd25519PublicKey,
  isValidDid,
} from "../did";
import {
  createIdentity,
  deserializeIdentity,
  ikxBindingMessage,
  serializeIdentity,
} from "../identity";
import {
  makeUserNameRecord,
  signUserNameRecord,
  verifyUserNameRecord,
} from "../username";
import {
  ed25519Verify,
  generateEd25519KeyPair,
  generateX25519KeyPair,
} from "../../crypto";
import { base58Encode, bytesEqual } from "../../codec";

/** 翻转首字节（篡改辅助） */
function flipFirstByte(bytes: Uint8Array): Uint8Array {
  const copy = bytes.slice();
  copy[0] = copy[0]! ^ 0xff;
  return copy;
}

/** 生成一个 OPK：X25519 密钥对 + 公钥指纹编号 */
function makeOpk() {
  const opk = generateX25519KeyPair();
  return { ...opk, id: deriveOpkId(opk.publicKey) };
}

describe("did", () => {
  it("构造与解析往返", () => {
    const { publicKey } = generateEd25519KeyPair();
    const did = didFromEd25519PublicKey(publicKey);
    expect(did.startsWith("did:mychat:")).toBe(true);
    expect(bytesEqual(didToEd25519PublicKey(did), publicKey)).toBe(true);
    expect(isValidDid(did)).toBe(true);
  });

  it("不同公钥派生不同 DID（自认证唯一性）", () => {
    const a = didFromEd25519PublicKey(generateEd25519KeyPair().publicKey);
    const b = didFromEd25519PublicKey(generateEd25519KeyPair().publicKey);
    expect(a).not.toBe(b);
  });

  it("didToEd25519PublicKey：错误前缀、非法 base58、错误长度均 throw", () => {
    const validBody = base58Encode(generateEd25519KeyPair().publicKey);
    expect(() => didToEd25519PublicKey(`did:other:${validBody}`)).toThrow(); // 错误前缀
    expect(() => didToEd25519PublicKey("did:mychat:0OIl")).toThrow(); // 非法 base58 字符（0/O/I/l 不在字母表）
    expect(() => didToEd25519PublicKey("did:mychat:")).toThrow(); // 空主体
    expect(() => didToEd25519PublicKey(`did:mychat:${base58Encode(new Uint8Array(31))}`)).toThrow(); // 31B
    expect(() => didToEd25519PublicKey(`did:mychat:${base58Encode(new Uint8Array(33))}`)).toThrow(); // 33B
  });

  it("isValidDid：非法输入返回 false 而非 throw", () => {
    expect(isValidDid("hello")).toBe(false);
    expect(isValidDid("did:mychat:0OIl")).toBe(false);
    expect(isValidDid(`did:mychat:${base58Encode(new Uint8Array(31))}`)).toBe(false);
  });
});

describe("createIdentity", () => {
  it("两次生成的 DID 不同（随机性，FR-1.1 无参数创建）", () => {
    const a = createIdentity();
    const b = createIdentity();
    expect(a.did).not.toBe(b.did);
    expect(a.did.startsWith("did:mychat:")).toBe(true);
  });

  it("DID 可由 ikEd 公钥重算，且 ikxBindingSig 验签通过", () => {
    const identity = createIdentity();
    expect(identity.did).toBe(didFromEd25519PublicKey(identity.ikEd.publicKey));
    expect(
      ed25519Verify(
        identity.ikxBindingSig,
        ikxBindingMessage(identity.ikX.publicKey),
        identity.ikEd.publicKey,
      ),
    ).toBe(true);
  });
});

describe("serializeIdentity / deserializeIdentity", () => {
  it("往返后各字段相等", () => {
    const identity = createIdentity();
    const restored = deserializeIdentity(serializeIdentity(identity));
    expect(restored.did).toBe(identity.did);
    expect(restored.ikEd).toEqual(identity.ikEd);
    expect(restored.ikX).toEqual(identity.ikX);
    expect(restored.dkEd).toEqual(identity.dkEd);
    expect(restored.ikxBindingSig).toEqual(identity.ikxBindingSig);
  });

  it("篡改 JSON 任一字节后 deserialize throw（全位置遍历）", () => {
    const json = serializeIdentity(createIdentity());
    expect(json).not.toMatch(/\s/); // 紧凑序列化：每个字节都语义有效
    for (let i = 0; i < json.length; i++) {
      const original = json.charAt(i);
      const tamperedChar = original === "0" ? "1" : "0";
      const tampered = json.slice(0, i) + tamperedChar + json.slice(i + 1);
      expect(() => deserializeIdentity(tampered), `位置 ${i}（'${original}'→'${tamperedChar}'）未被检出`).toThrow();
    }
  });

  it("非 JSON 输入 throw", () => {
    expect(() => deserializeIdentity("not json")).toThrow();
  });
});

describe("PreKeyBundle（设计报告 §5.2）", () => {
  it("issue 后 verify 通过", () => {
    const identity = createIdentity();
    const bundle = issuePreKeyBundle(identity, generateX25519KeyPair(), makeOpk(), 60_000);
    expect(verifyPreKeyBundle(bundle)).toBe(true);
  });

  it("篡改 ikxPublic / spkPublic / opkPublic / did 任一字节后 verify 返回 false", () => {
    const identity = createIdentity();
    const other = createIdentity();
    const bundle = issuePreKeyBundle(identity, generateX25519KeyPair(), makeOpk(), 60_000);
    expect(verifyPreKeyBundle({ ...bundle, ikxPublic: flipFirstByte(bundle.ikxPublic) })).toBe(false);
    expect(verifyPreKeyBundle({ ...bundle, spkPublic: flipFirstByte(bundle.spkPublic) })).toBe(false);
    expect(verifyPreKeyBundle({ ...bundle, opkPublic: flipFirstByte(bundle.opkPublic) })).toBe(false);
    expect(verifyPreKeyBundle({ ...bundle, did: other.did })).toBe(false); // 换属主
  });

  it("过期或时间被改小的 bundle verify 返回 false", () => {
    const identity = createIdentity();
    const expired = issuePreKeyBundle(identity, generateX25519KeyPair(), makeOpk(), -1_000);
    expect(expired.spkExpiresAt).toBeLessThanOrEqual(Date.now());
    expect(verifyPreKeyBundle(expired)).toBe(false);
    const bundle = issuePreKeyBundle(identity, generateX25519KeyPair(), makeOpk(), 60_000);
    expect(verifyPreKeyBundle({ ...bundle, spkExpiresAt: Date.now() - 1_000 })).toBe(false);
  });

  it("opk.id 与公钥指纹不一致时 issue throw", () => {
    const identity = createIdentity();
    const opk = makeOpk();
    expect(() => issuePreKeyBundle(identity, generateX25519KeyPair(), { ...opk, id: opk.id + 1 }, 60_000)).toThrow();
  });
});

describe("encodePreKeyBundle / decodePreKeyBundle", () => {
  it("编码解码往返相等，且编码确定性", () => {
    const identity = createIdentity();
    const bundle = issuePreKeyBundle(identity, generateX25519KeyPair(), makeOpk(), 60_000);
    const decoded = decodePreKeyBundle(encodePreKeyBundle(bundle));
    expect(decoded.did).toBe(bundle.did);
    expect(decoded.ikxPublic).toEqual(bundle.ikxPublic);
    expect(decoded.ikxSignature).toEqual(bundle.ikxSignature);
    expect(decoded.spkPublic).toEqual(bundle.spkPublic);
    expect(decoded.spkSignature).toEqual(bundle.spkSignature);
    expect(decoded.spkExpiresAt).toBe(bundle.spkExpiresAt);
    expect(decoded.opkId).toBe(bundle.opkId);
    expect(decoded.opkPublic).toEqual(bundle.opkPublic);
    // 确定性：同一 bundle 两次编码逐字节一致
    expect(encodePreKeyBundle(bundle)).toEqual(encodePreKeyBundle(bundle));
  });

  it("截断输入 throw", () => {
    const identity = createIdentity();
    const bytes = encodePreKeyBundle(issuePreKeyBundle(identity, generateX25519KeyPair(), makeOpk(), 60_000));
    for (const length of [0, 3, 5, 10, bytes.length - 1]) {
      expect(() => decodePreKeyBundle(bytes.slice(0, length)), `截断到 ${length} 字节未被拒绝`).toThrow();
    }
  });

  it("脏字节（magic/版本/长度前缀/尾部）throw", () => {
    const identity = createIdentity();
    const bytes = encodePreKeyBundle(issuePreKeyBundle(identity, generateX25519KeyPair(), makeOpk(), 60_000));
    expect(() => decodePreKeyBundle(flipFirstByte(bytes))).toThrow(); // magic 被破坏
    const badVersion = bytes.slice();
    badVersion[4] = 0x02; // 版本字段
    expect(() => decodePreKeyBundle(badVersion)).toThrow();
    const badLength = bytes.slice();
    badLength[7] = badLength[7]! ^ 0x01; // did 字段的 2B 长度前缀
    expect(() => decodePreKeyBundle(badLength)).toThrow();
    expect(() => decodePreKeyBundle(new Uint8Array([...bytes, 0x00]))).toThrow(); // 尾部多余字节
    expect(() => decodePreKeyBundle(new Uint8Array(64).fill(0x41))).toThrow(); // 纯垃圾
  });
});

describe("UserNameRecord（SR-5 客户端验签）", () => {
  it("makeUserNameRecord 后 verifyUserNameRecord 通过", () => {
    const identity = createIdentity();
    const record = makeUserNameRecord(identity.ikEd.privateKey, "alice", identity.did, 7);
    expect(verifyUserNameRecord(record)).toBe(true);
  });

  it("篡改 name / did / ktIndex 后 verify 返回 false", () => {
    const identity = createIdentity();
    const other = createIdentity();
    const record = makeUserNameRecord(identity.ikEd.privateKey, "alice", identity.did, 7);
    expect(verifyUserNameRecord({ ...record, name: "bob" })).toBe(false);
    expect(verifyUserNameRecord({ ...record, name: "" })).toBe(false); // name 非空
    expect(verifyUserNameRecord({ ...record, did: other.did })).toBe(false); // did 格式合法但非签名人
    expect(verifyUserNameRecord({ ...record, did: "not-a-did" })).toBe(false); // did 格式非法
    expect(verifyUserNameRecord({ ...record, ktIndex: 8 })).toBe(false);
  });

  it("不同 ktIndex 签名不同（签名覆盖 ktIndex）", () => {
    const identity = createIdentity();
    const sig7 = signUserNameRecord(identity.ikEd.privateKey, "alice", identity.did, 7);
    const sig8 = signUserNameRecord(identity.ikEd.privateKey, "alice", identity.did, 8);
    expect(bytesEqual(sig7, sig8)).toBe(false);
  });
});
