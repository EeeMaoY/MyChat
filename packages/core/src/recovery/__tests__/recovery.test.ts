/**
 * 社交恢复全流程测试（FR-1.3 / M1 Gate 5 的密码学面）：
 * 设置 → 分片封装分发 → 守护者开启 → 3/5 重组 RK → 解开身份包裹。
 * 守护者不可读、非守护者无法解、公告不可伪造均被覆盖。
 */
import { describe, expect, it } from "vitest";

import { randomBytes } from "../../crypto/index.ts";
import { createIdentity, deserializeIdentity, didToEd25519PublicKey } from "../../identity/index.ts";
import {
  createRecoverySetup,
  makeRecoveryAnnouncement,
  openGuardianShare,
  openIdentityWrap,
  recoverRk,
  recoveryMessage,
  sealGuardianShare,
  sealIdentityWrap,
  verifyRecoveryAnnouncement,
} from "../recovery.ts";

describe("社交恢复全流程（3-of-5）", () => {
  it("端到端：设置 → 守护者回传分片 → 重组 RK → 解开身份包裹", () => {
    const owner = createIdentity();
    const guardians = [createIdentity(), createIdentity(), createIdentity(), createIdentity(), createIdentity()];
    const guardianDids = guardians.map((g) => g.did);

    // —— 原机设置 ——
    const setup = createRecoverySetup(owner, guardianDids, 3);
    expect(verifyRecoveryAnnouncement(setup.announcement)).toBe(true);

    // wrap 上传节点（CID 校验在 putBlock 侧由调用方做，此处验证引用一致）
    const sealedPacks = guardianDids.map((did) => sealGuardianShare(setup, did));

    // —— 恢复：任选 3 位守护者各自开启分片（用各自私钥）并回传 ——
    const collected = sealedPacks.slice(0, 3).map((pack, i) => {
      const share = openGuardianShare(guardians[i]!.ikEd.privateKey, pack);
      return share;
    });
    const rk = recoverRk(collected, 32);

    // 新设备从节点取 wrap 块（此处直接用内存 wrap），用重组 RK 解开身份（v2：含用户名）
    const restoredPayload = openIdentityWrap(rk, setup.wrap);
    expect(restoredPayload.myName).toBe(null);
    const restored = deserializeIdentity(restoredPayload.identityJson);
    expect(restored.did).toBe(owner.did);
    expect(restored.ikEd.privateKey).toEqual(owner.ikEd.privateKey);
    expect(restored.ikX.privateKey).toEqual(owner.ikX.privateKey);
  });

  it("守护者只能开自己的分片包；非守护者无法解任何包", () => {
    const owner = createIdentity();
    const guardians = [createIdentity(), createIdentity()];
    const setup = createRecoverySetup(owner, guardians.map((g) => g.did), 2);
    const packs = guardians.map((g) => sealGuardianShare(setup, g.did));

    // 守护者 A 开自己的包 ✓
    expect(openGuardianShare(guardians[0]!.ikEd.privateKey, packs[0]!)).toBeDefined();
    // 守护者 A 开守护者 B 的包 ✗（收件方不匹配）
    expect(() => openGuardianShare(guardians[0]!.ikEd.privateKey, packs[1]!)).toThrow();
    // 陌生人 ✗
    expect(() => openGuardianShare(createIdentity().ikEd.privateKey, packs[0]!)).toThrow();
  });

  it("公告不可伪造：第三方签名/DID 不匹配均拒绝", () => {
    const owner = createIdentity();
    const guardians = [createIdentity(), createIdentity(), createIdentity()];
    const dids = guardians.map((g) => g.did);

    const unsigned = { did: owner.did, wrapCid: "FakeCid", threshold: 2, guardians: dids };
    // 第三方签名
    const forged = { ...unsigned, signature: randomBytes(64) };
    expect(verifyRecoveryAnnouncement(forged as never)).toBe(false);
    // 攻击者换掉 wrapCid 后以受害者名义重签——无 IK 私钥做不到；这里验证签名覆盖字段：
    const legit = makeRecoveryAnnouncement(owner, "RealCid", 2, dids);
    const tampered = { ...legit, wrapCid: "EvilCid" };
    expect(verifyRecoveryAnnouncement(tampered)).toBe(false);
    void unsigned;
  });

  it("守护者分片数量不足门限时不能重组出可用 RK（非原像）", () => {
    const owner = createIdentity();
    const guardians = [createIdentity(), createIdentity(), createIdentity()];
    const setup = createRecoverySetup(owner, guardians.map((g) => g.did), 3);
    const shares = guardians.map((g, i) => openGuardianShare(g.ikEd.privateKey, sealGuardianShare(setup, guardians[i]!.did)));
    const onlyTwo = recoverRk(shares.slice(0, 2));
    expect(() => openIdentityWrap(onlyTwo, setup.wrap)).toThrow();
  });

  it("身份包裹的 RK 错误必被 AEAD 认证拒绝", () => {
    const owner = createIdentity();
    const wrap = sealIdentityWrap(randomBytes(32), { identityJson: JSON.stringify({ did: owner.did }), myName: null });
    expect(() => openIdentityWrap(randomBytes(32), wrap)).toThrow();
  });

  it("公告被签消息对各字段敏感", () => {
    const owner = createIdentity();
    const g = [createIdentity().did, createIdentity().did];
    const m1 = recoveryMessage({ did: owner.did, wrapCid: "C", threshold: 2, guardians: g });
    const m2 = recoveryMessage({ did: owner.did, wrapCid: "D", threshold: 2, guardians: g });
    const m3 = recoveryMessage({ did: owner.did, wrapCid: "C", threshold: 2, guardians: [g[1]!, g[0]!] });
    expect(m1.toString()).not.toBe(m2.toString());
    expect(m1.toString()).not.toBe(m3.toString());
    void didToEd25519PublicKey;
  });
});
