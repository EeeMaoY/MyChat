/**
 * Double Ratchet 事务回滚测试：解密失败不得污染会话状态。
 *
 * 覆盖三类攻击面（修复前均会不可逆破坏会话）：
 * - 旧代消息重放 → 错误方向的 DH ratchet → 双方 rootKey 永久分叉；
 * - 伪造 header（随机 dh + 大 n）→ skipped 存储膨胀 + recvCount 被推到伪造位置；
 * - 恶意 dh 为 X25519 低阶点（全零）→ dhRatchet 中途抛错、状态半写。
 */
import { describe, expect, it } from "vitest";

import { bytesToUtf8, utf8ToBytes } from "../../codec/index.ts";
import { generateX25519KeyPair, randomBytes } from "../../crypto/index.ts";
import { createIdentity, deriveOpkId, issuePreKeyBundle } from "../../identity/index.ts";
import {
  acceptSession,
  initiateSession,
  sessionReceive,
  sessionSend,
} from "../session.ts";
import { type RatchetState, ratchetDecrypt } from "../ratchet.ts";

/** 搭建一对已建立会话的双方（与 signal.test.ts 同款演练）。 */
function setupConversation() {
  const alice = createIdentity();
  const bob = createIdentity();

  const spk = generateX25519KeyPair();
  const opk1 = generateX25519KeyPair();
  const bobBundle = issuePreKeyBundle(bob, spk, { ...opk1, id: deriveOpkId(opk1.publicKey) }, 3_600_000);
  const opkPool = new Map<number, ReturnType<typeof generateX25519KeyPair>>([
    [deriveOpkId(opk1.publicKey), opk1],
  ]);

  const { session: aliceSession, wire } = initiateSession(alice, bobBundle, utf8ToBytes("首条消息"));
  const { session: bobSession } = acceptSession(bob, spk, opkPool, wire, alice.did);
  return { aliceSession, bobSession };
}

/** 关键状态字段快照（用于攻击前后完整性比对）。 */
function snapshotRatchet(state: RatchetState) {
  return {
    rootKey: state.rootKey.slice(),
    dhSelfPub: state.dhSelf.publicKey.slice(),
    dhSelfPriv: state.dhSelf.privateKey.slice(),
    dhRemote: state.dhRemote === null ? null : state.dhRemote.slice(),
    sendChainKey: state.sendChainKey === null ? null : state.sendChainKey.slice(),
    recvChainKey: state.recvChainKey === null ? null : state.recvChainKey.slice(),
    sendCount: state.sendCount,
    recvCount: state.recvCount,
    prevSendCount: state.prevSendCount,
    skippedSize: state.skipped.size,
  };
}

describe("ratchet 事务回滚（解密失败不污染状态）", () => {
  it("三轮正常通信后重放旧代历史消息：throw 且双方继续正常收发（会话未坏）", () => {
    const { aliceSession, bobSession } = setupConversation();

    // 三轮完整通信（每轮双向，触发多次 DH ratchet 代际推进）；保留首轮原始字节
    const firstA2b = sessionSend(aliceSession, utf8ToBytes("round1-a"));
    expect(bytesToUtf8(sessionReceive(bobSession, firstA2b))).toBe("round1-a");
    expect(bytesToUtf8(sessionReceive(aliceSession, sessionSend(bobSession, utf8ToBytes("round1-b"))))).toBe("round1-b");
    for (let i = 2; i <= 3; i++) {
      expect(bytesToUtf8(sessionReceive(bobSession, sessionSend(aliceSession, utf8ToBytes(`round${i}-a`))))).toBe(`round${i}-a`);
      expect(bytesToUtf8(sessionReceive(aliceSession, sessionSend(bobSession, utf8ToBytes(`round${i}-b`))))).toBe(`round${i}-b`);
    }

    // 跨代重放首轮原始字节：此时 Bob 的 dhRemote 已是更新的代际，重放会把
    // DH ratchet 推向错误方向（修复前 rootKey 永久分叉，会话死亡）
    expect(() => sessionReceive(bobSession, firstA2b)).toThrow();

    // 会话回滚成功：双方继续正常收发
    expect(bytesToUtf8(sessionReceive(bobSession, sessionSend(aliceSession, utf8ToBytes("after-attack"))))).toBe("after-attack");
    expect(bytesToUtf8(sessionReceive(aliceSession, sessionSend(bobSession, utf8ToBytes("after-attack-reply"))))).toBe("after-attack-reply");
  });

  it("伪造 header（随机 dh + 大 n）：throw 后 skipped 与 recvCount 回滚，紧随的真实消息可解", () => {
    const { aliceSession, bobSession } = setupConversation();
    const beforeSize = bobSession.ratchet.skipped.size;
    const beforeRecv = bobSession.ratchet.recvCount;

    // 伪造 header：随机 32B dh、n = recvCount + 900（绕过 MAX_SKIP 但膨胀 skipped）
    const forged = { dh: randomBytes(32), pn: 0, n: bobSession.ratchet.recvCount + 900 };
    expect(() =>
      ratchetDecrypt(bobSession.ratchet, forged, randomBytes(24), randomBytes(64), utf8ToBytes("ad")),
    ).toThrow();

    // skipped 键与 recvCount 均回滚到攻击前（修复前会新增 900 个伪造键并推进计数）
    expect(bobSession.ratchet.skipped.size).toBe(beforeSize);
    expect(bobSession.ratchet.recvCount).toBe(beforeRecv);

    // 紧随的真实消息可解
    const wire = sessionSend(aliceSession, utf8ToBytes("real-after-forged"));
    expect(bytesToUtf8(sessionReceive(bobSession, wire))).toBe("real-after-forged");
  });

  it("dh 为全零低阶点：dhRatchet 抛错后状态完整回滚（快照逐字段比对）", () => {
    const { aliceSession, bobSession } = setupConversation();
    void aliceSession;
    const before = snapshotRatchet(bobSession.ratchet);

    // 全零 32B 是 X25519 低阶点：x25519SharedSecret 在 dhRatchet 中途抛错
    const zeroDh = new Uint8Array(32);
    expect(() =>
      ratchetDecrypt(bobSession.ratchet, { dh: zeroDh, pn: 0, n: 0 }, randomBytes(24), randomBytes(64), utf8ToBytes("ad")),
    ).toThrow();

    // 半写状态被整体回滚：关键字段与攻击前逐字段一致
    expect(snapshotRatchet(bobSession.ratchet)).toEqual(before);
  });
});
