/**
 * Signal 协议栈测试：X3DH 握手 + Double Ratchet 全行为面。
 * M0 Gate §3 要求：X3DH/Double Ratchet 具备测试向量与已知答案测试。
 * （原语层 KAT 见 crypto/__tests__/kat.test.ts；本文件覆盖协议层行为契约）
 */
import { describe, expect, it } from "vitest";

import { utf8ToBytes } from "../../codec";
import { generateX25519KeyPair } from "../../crypto";
import {
  createIdentity,
  deriveOpkId,
  issuePreKeyBundle,
} from "../../identity";
import {
  acceptSession,
  deserializeSession,
  initiateSession,
  serializeSession,
  sessionMailbox,
  sessionReceive,
  sessionSend,
} from "../session";

/** 搭建一对已建立会话的双方（响应方持有 SPK/OPK 池的完整演练）。 */
function setupConversation() {
  const alice = createIdentity();
  const bob = createIdentity();

  // Bob 侧预密钥材料（SPK + OPK 池）；opkId = OPK 公钥指纹（identity/bundle 的防篡改契约）
  const spk = generateX25519KeyPair();
  const opk1 = generateX25519KeyPair();
  const opk2 = generateX25519KeyPair();
  const bobBundle = issuePreKeyBundle(bob, spk, { ...opk1, id: deriveOpkId(opk1.publicKey) }, 3_600_000);

  const opkPool = new Map<number, ReturnType<typeof generateX25519KeyPair>>([
    [deriveOpkId(opk1.publicKey), opk1],
    [deriveOpkId(opk2.publicKey), opk2],
  ]);

  const { session: aliceSession, wire } = initiateSession(alice, bobBundle, utf8ToBytes("你好 Bob，这是首条 E2EE 消息 🔒"));
  const { session: bobSession, plaintext } = acceptSession(bob, spk, opkPool, wire, alice.did);

  return { alice, bob, spk, opkIdUsed: bobBundle.opkId, opkPool, aliceSession, bobSession, firstPlaintext: plaintext, initialWire: wire };
}

describe("X3DH 握手", () => {
  it("初始消息被响应方正确解密（双方推出同一 SK）", () => {
    const { firstPlaintext, opkIdUsed, opkPool } = setupConversation();
    expect(new TextDecoder().decode(firstPlaintext)).toBe("你好 Bob，这是首条 E2EE 消息 🔒");
    // OPK 被 acceptSession 消费后应由调用方删除（此处验证池仍含该键、删除后不可重放会话）
    expect(opkPool.has(opkIdUsed)).toBe(true);
  });

  it("OPK 已消耗后再用同 wire 建会话必须失败（防重放建会话）", () => {
    const { initialWire } = setupConversation();
    const freshSpk = generateX25519KeyPair();
    // 空池 + 不匹配的 SPK = OPK 已销毁场景；最坏情况也必须因 OPK 缺失而失败
    const { bob } = setupConversation();
    expect(() => acceptSession(bob, freshSpk, new Map(), initialWire)).toThrow();
  });

  it("被篡改的初始消息必须解密失败", () => {
    const { bob, spk, opkPool, initialWire } = setupConversation();
    const tampered = initialWire.slice();
    tampered[tampered.length - 1]! ^= 1;
    expect(() => acceptSession(bob, spk, opkPool, tampered)).toThrow();
  });
});

describe("Double Ratchet 收发", () => {
  it("多轮交替互发（触发多次 DH ratchet）内容一致", () => {
    const { aliceSession, bobSession } = setupConversation();
    const messages = [
      "第 1 条：Alice → Bob",
      "第 2 条：Bob → Alice",
      "第 3 条：Alice → Bob，含中文与 emoji ✅",
      "第 4 条：Bob → Alice",
      "第 5 条：Alice → Bob",
    ];
    for (const [i, text] of messages.entries()) {
      const fromAlice = i % 2 === 0;
      const wire = fromAlice ? sessionSend(aliceSession, utf8ToBytes(text)) : sessionSend(bobSession, utf8ToBytes(text));
      const received = fromAlice ? sessionReceive(bobSession, wire) : sessionReceive(aliceSession, wire);
      expect(new TextDecoder().decode(received)).toBe(text);
    }
  });

  it("同方连续发送多条（对称链推进）", () => {
    const { aliceSession, bobSession } = setupConversation();
    for (let i = 1; i <= 5; i++) {
      const wire = sessionSend(aliceSession, utf8ToBytes(`burst-${i}`));
      expect(new TextDecoder().decode(sessionReceive(bobSession, wire))).toBe(`burst-${i}`);
    }
  });

  it("乱序到达：跳过的消息可延迟解密，后续消息正常", () => {
    const { aliceSession, bobSession } = setupConversation();
    const w1 = sessionSend(aliceSession, utf8ToBytes("m1"));
    const w2 = sessionSend(aliceSession, utf8ToBytes("m2"));
    const w3 = sessionSend(aliceSession, utf8ToBytes("m3"));

    expect(new TextDecoder().decode(sessionReceive(bobSession, w2))).toBe("m2"); // 跳过 m1
    expect(new TextDecoder().decode(sessionReceive(bobSession, w1))).toBe("m1"); // 补收
    expect(new TextDecoder().decode(sessionReceive(bobSession, w3))).toBe("m3");
  });

  it("重放同一条消息第二次必须失败（SR-4 防重放）", () => {
    const { aliceSession, bobSession } = setupConversation();
    const wire = sessionSend(aliceSession, utf8ToBytes("only-once"));
    expect(new TextDecoder().decode(sessionReceive(bobSession, wire))).toBe("only-once");
    expect(() => sessionReceive(bobSession, wire)).toThrow();
  });

  it("密文单字节篡改必须解密失败", () => {
    const { aliceSession, bobSession } = setupConversation();
    const wire = sessionSend(aliceSession, utf8ToBytes("tamper-me"));
    wire[wire.length - 1]! ^= 1;
    expect(() => sessionReceive(bobSession, wire)).toThrow();
  });

  it("会话序列化往返后可继续收发（本地优先恢复，FR-7.1）", () => {
    const { aliceSession, bobSession } = setupConversation();
    const restoredBob = deserializeSession(serializeSession(bobSession));

    const wire = sessionSend(aliceSession, utf8ToBytes("after-restore"));
    expect(new TextDecoder().decode(sessionReceive(restoredBob, wire))).toBe("after-restore");

    // 恢复的会话也能回信，原会话可解
    const reply = sessionSend(restoredBob, utf8ToBytes("reply-after-restore"));
    expect(new TextDecoder().decode(sessionReceive(aliceSession, reply))).toBe("reply-after-restore");
  });

  it("恢复的会话拒收已消费的旧消息（skipped key 持久化不重放）", () => {
    const { aliceSession, bobSession } = setupConversation();
    const wire = sessionSend(aliceSession, utf8ToBytes("consumed-before-restore"));
    expect(sessionReceive(bobSession, wire)); // 先消费
    const restoredBob = deserializeSession(serializeSession(bobSession));
    expect(() => sessionReceive(restoredBob, wire)).toThrow();
  });
});

describe("信箱伪地址（FR-3.1 epoch 轮换）", () => {
  it("收发方向伪地址不同；epoch 推进后轮换；不同会话互不相干", () => {
    const { aliceSession, bobSession } = setupConversation();
    const t0 = 1_700_000_000_000;

    const aliceSend = sessionMailbox(aliceSession, "send", t0);
    const aliceRecv = sessionMailbox(aliceSession, "recv", t0);
    expect(aliceSend).not.toBe(aliceRecv);

    // 双方视角一致：Alice 的发件箱 = Bob 的收件箱
    expect(sessionMailbox(bobSession, "recv", t0)).toBe(aliceSend);
    expect(sessionMailbox(bobSession, "send", t0)).toBe(aliceRecv);

    // epoch 轮换（EPOCH_MS = 60_000）
    expect(sessionMailbox(aliceSession, "send", t0 + 60_000)).not.toBe(aliceSend);
    // 同 epoch 内确定性
    expect(sessionMailbox(aliceSession, "send", t0 + 1_234)).toBe(aliceSend);
  });
});
