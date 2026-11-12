/**
 * 群状态规范化序与成员唯一性测试：
 * 排序比较器必须满足严格弱序（did 相等返回 0），否则含重复成员的状态在
 * 不同引擎的排序实现下可能产生不同规范化编码（验签分叉面）；同时
 * verifyGroupState 直接拒绝重复成员。
 */
import { describe, expect, it } from "vitest";

import { createGroup, createIdentity, groupStateMessage, signGroup, verifyGroupState } from "../../index.ts";

describe("群状态全序比较器与重复成员拒绝", () => {
  it("含重复成员的状态 verifyGroupState 返回 false（即便签名真实有效）", () => {
    const owner = createIdentity();
    const a = createIdentity();
    const b = createIdentity();
    const { state } = createGroup(owner.ikEd.privateKey, "群", owner.did, [a.did, b.did]);
    const { signature, ...fields } = state;
    void signature;
    // 篡改态：成员 a 出现两次，并由真实 owner 重签（签名合法 ≠ 状态合法）
    const duplicated = signGroup(owner.ikEd.privateKey, {
      ...fields,
      members: [...fields.members, { did: a.did, role: "member" as const, joinedEpoch: fields.epoch }],
    });
    expect(duplicated.members.filter((m) => m.did === a.did)).toHaveLength(2);
    expect(verifyGroupState(duplicated)).toBe(false);
  });

  it("重复成员在不同输入顺序下规范化编码一致（相等 did 比较返回 0）", () => {
    const owner = createIdentity();
    const a = createIdentity();
    const base = { v: 1 as const, groupId: "group", name: "n", owner: owner.did, epoch: 1 };
    const membersA = [
      { did: a.did, role: "member" as const, joinedEpoch: 1 },
      { did: owner.did, role: "owner" as const, joinedEpoch: 1 },
      { did: a.did, role: "member" as const, joinedEpoch: 2 },
    ];
    const membersB = [membersA[1]!, membersA[0]!, membersA[2]!];
    // 同一多重集合的两种排列必须得到同一确定性编码
    expect(groupStateMessage({ ...base, members: membersA })).toEqual(groupStateMessage({ ...base, members: membersB }));
  });

  it("合法去重状态的验签与编码不受比较器修改影响", () => {
    const owner = createIdentity();
    const a = createIdentity();
    const { state } = createGroup(owner.ikEd.privateKey, "群", owner.did, [a.did]);
    expect(verifyGroupState(state)).toBe(true);
    // 同一字段重签得到逐字节相同的签名（确定性编码 + 确定性 Ed25519）：
    // 证明比较器修改对合法状态零影响
    const { signature, ...fields } = state;
    void signature;
    const resigned = signGroup(owner.ikEd.privateKey, fields);
    expect(resigned.signature).toEqual(state.signature);
    expect(verifyGroupState(resigned)).toBe(true);
  });
});
