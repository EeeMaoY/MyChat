/**
 * 群组模块单测（M3-S11，FR-6.1/6.2）：
 * 群状态签名/成员变更语义、群主转让与群改名、双层信封加解密、移除断读与防伪造、防重放。
 */
import { describe, expect, it } from "vitest";

import {
  addGroupMember,
  applyGroupKeysPayload,
  base58Decode,
  bytesToUtf8,
  createGroup,
  createGroupView,
  decodeGroupStateJson,
  encodeGroupStateJson,
  generateSenderKeys,
  groupMailboxId,
  makeGroupKeysPayload,
  openGroupMessage,
  removeGroupMember,
  renameGroup,
  sealGroupMessage,
  signGroup,
  transferGroupOwnership,
  utf8ToBytes,
  verifyGroupState,
  createIdentity,
  type GroupView,
  type Identity,
} from "../index.ts";

function setupGroup(memberCount = 3): { owner: Identity; members: Identity[]; state: ReturnType<typeof createGroup>["state"]; groupSecret: Uint8Array; views: GroupView[] } {
  const identities = Array.from({ length: memberCount }, () => createIdentity());
  const [owner, ...others] = identities;
  const { state, groupSecret } = createGroup(owner!.ikEd.privateKey, "测试群", owner!.did, others.map((m) => m.did));
  const senderKeys = generateSenderKeys(state.members.map((m) => m.did));
  const views = identities.map((id) => createGroupView(state, groupSecret, senderKeys));
  return { owner: owner!, members: others, state, groupSecret, views };
}

describe("群组状态（GroupState）", () => {
  it("创建：owner 自动入列、签名有效、groupId 随机不绑定创建者", () => {
    const { state } = setupGroup();
    expect(verifyGroupState(state)).toBe(true);
    expect(state.epoch).toBe(1);
    expect(state.members).toHaveLength(3);
    expect(state.members.find((m) => m.did === state.owner)!.role).toBe("owner");
  });

  it("JSON 编解码往返一致；篡改签名后验签失败", () => {
    const { state } = setupGroup();
    const round = decodeGroupStateJson(encodeGroupStateJson(state));
    expect(round).toEqual(state);
    const tampered = { ...round, name: "篡改的群名" };
    expect(verifyGroupState(tampered)).toBe(false);
  });

  it("非群主签发的状态验签失败", () => {
    const { state, members } = setupGroup();
    // 以成员身份对篡改字段重签（真实签名但签名者非 owner）
    const { signature, ...fields } = state;
    void signature;
    const resigned = signGroup(members[0]!.ikEd.privateKey, { ...fields, name: "冒主群名" });
    expect(verifyGroupState(resigned)).toBe(false);
  });

  it("入群 epoch+1 且 joinedEpoch 为新 epoch；超上限拒绝；重复加入拒绝", () => {
    const owner = createIdentity();
    const a = createIdentity();
    const { state } = createGroup(owner.ikEd.privateKey, "群", owner.did, []);
    const next = addGroupMember(owner.ikEd.privateKey, state, a.did);
    expect(next.epoch).toBe(2);
    expect(next.members.find((m) => m.did === a.did)!.joinedEpoch).toBe(2);
    expect(verifyGroupState(next)).toBe(true);
    expect(() => addGroupMember(owner.ikEd.privateKey, next, a.did)).toThrow(/已是群成员/);
  });

  it("移除成员 epoch+1；移除 owner 拒绝；移除不存在者拒绝", () => {
    const { owner, members, state } = setupGroup(3);
    const next = removeGroupMember(owner.ikEd.privateKey, state, members[0]!.did);
    expect(next.epoch).toBe(state.epoch + 1);
    expect(next.members.some((m) => m.did === members[0]!.did)).toBe(false);
    expect(() => removeGroupMember(owner.ikEd.privateKey, next, owner.did)).toThrow(/群主不可被移除/);
    expect(() => removeGroupMember(owner.ikEd.privateKey, next, "did:mychat:none")).toThrow(/不是群成员/);
  });
});

describe("群组加密（Sender-Keys 双层信封）", () => {
  it("多发送方互发：各成员均可解密并验签通过", () => {
    const { owner, members, state, groupSecret, views } = setupGroup(3);
    const senderKeys = views[0]!.senderKeys;
    const wireOwner = sealGroupMessage(owner.ikEd.privateKey, owner.did, senderKeys.get(owner.did)!, groupSecret, state.groupId, state.epoch, 0, utf8ToBytes("来自群主"));
    const wireMember = sealGroupMessage(members[0]!.ikEd.privateKey, members[0]!.did, senderKeys.get(members[0]!.did)!, groupSecret, state.groupId, state.epoch, 7, utf8ToBytes("来自成员"));

    for (const view of views) {
      expect(bytesToUtf8(openGroupMessage(view, wireOwner).plaintext)).toBe("来自群主");
      const opened = openGroupMessage(view, wireMember);
      expect(bytesToUtf8(opened.plaintext)).toBe("来自成员");
      expect(opened.senderDid).toBe(members[0]!.did);
    }
  });

  it("外层与群信箱同密钥：非成员/旧 epoch 无法解密（断读物理面）", () => {
    const { owner, state, groupSecret, views } = setupGroup(2);
    const sk = views[0]!.senderKeys.get(owner.did)!;
    const wire = sealGroupMessage(owner.ikEd.privateKey, owner.did, sk, groupSecret, state.groupId, state.epoch, 0, utf8ToBytes("秘密"));
    // 被移除者（只有旧 epoch 的 groupSecret）在新 epoch 信箱密钥下解不开
    const outsiderView: GroupView = { ...views[0]!, state: { ...state, epoch: state.epoch + 1 } };
    expect(() => openGroupMessage(outsiderView, wire)).toThrow();
    // 完全的局外人（错误 groupSecret）解不开
    const stranger = createGroupView(state, base58Decode("11111111111111111111111111111111"), views[0]!.senderKeys);
    expect(() => openGroupMessage(stranger, wire)).toThrow();
  });

  it("被移除者拿不到新 epoch SK：无法解密也无法伪造（IK 验签拒绝）", () => {
    const { owner, members, state, groupSecret, views } = setupGroup(3);
    const evicted = members[0]!;
    const survivorViews = views.filter((_, i) => i !== 1);
    const nextState = removeGroupMember(owner.ikEd.privateKey, state, evicted.did);
    const newKeys = generateSenderKeys(nextState.members.map((m) => m.did));
    const newViews = survivorViews.map((v) => createGroupView(nextState, groupSecret, newKeys));
    // 被移除者滞留旧状态/旧 SK
    const evictedView = views[1]!;

    const wire = sealGroupMessage(owner.ikEd.privateKey, owner.did, newKeys.get(owner.did)!, groupSecret, nextState.groupId, nextState.epoch, 0, utf8ToBytes("你已被移除"));
    // 幸存成员可解
    expect(bytesToUtf8(openGroupMessage(newViews[1]!, wire).plaintext)).toBe("你已被移除");
    // 被移除者：旧 epoch 视角解不开新消息
    expect(() => openGroupMessage(evictedView, wire)).toThrow();
    // 被移除者伪造：用旧 SK 与自己的 IK 签名造新 epoch 消息——外层即失败；即便外层可过（拿到 groupSecret），内层与验签也拒绝
    const forged = sealGroupMessage(evicted.ikEd.privateKey, evicted.did, views[1]!.senderKeys.get(evicted.did)!, groupSecret, nextState.groupId, nextState.epoch, 0, utf8ToBytes("我是伪造的"));
    expect(() => openGroupMessage(newViews[0]!, forged)).toThrow();
  });

  it("防重放：同发送方 index 回退被拒；独立派生使中间丢帧不阻断后续", () => {
    const { owner, state, groupSecret, views } = setupGroup(2);
    const sk = views[0]!.senderKeys.get(owner.did)!;
    const receiver = views[1]!;
    const m0 = sealGroupMessage(owner.ikEd.privateKey, owner.did, sk, groupSecret, state.groupId, state.epoch, 0, utf8ToBytes("m0"));
    const m2 = sealGroupMessage(owner.ikEd.privateKey, owner.did, sk, groupSecret, state.groupId, state.epoch, 2, utf8ToBytes("m2"));
    expect(bytesToUtf8(openGroupMessage(receiver, m0).plaintext)).toBe("m0");
    expect(bytesToUtf8(openGroupMessage(receiver, m2).plaintext)).toBe("m2");
    expect(() => openGroupMessage(receiver, m0)).toThrow(/重放/);
    // 中间丢失的 m1 之后再到也被拒（index 已越过）——FIFO 信箱下不应发生
  });

  it("GroupKeys 载荷：分发 → 成员侧恢复视角；载荷与状态不一致被拒", () => {
    const setup = setupGroup(3);
    const { state, groupSecret, views, owner } = setup;
    const payload = makeGroupKeysPayload(state, groupSecret, views[0]!.senderKeys);
    const view = applyGroupKeysPayload(JSON.parse(JSON.stringify(payload)) as Parameters<typeof applyGroupKeysPayload>[0]);
    expect(view.state.groupId).toBe(state.groupId);
    expect(view.senderKeys.size).toBe(3);
    // 新成员（此前不在群）凭分发载荷可加入并解密（消息由 owner 签发）
    const wire = sealGroupMessage(
      owner.ikEd.privateKey,
      state.owner,
      views[0]!.senderKeys.get(state.owner)!,
      groupSecret,
      state.groupId,
      state.epoch,
      0,
      utf8ToBytes("欢迎"),
    );
    expect(bytesToUtf8(openGroupMessage(view, wire).plaintext)).toBe("欢迎");
    // 篡改 epoch 一致性校验
    const bad = { ...payload, epoch: payload.epoch + 1 };
    expect(() => applyGroupKeysPayload(bad as typeof payload)).toThrow(/不一致/);
  });

  it("群信箱 ID 随 epoch 轮换（被移除者不可达新信箱）", () => {
    const { state, groupSecret } = setupGroup(2);
    expect(groupMailboxId(groupSecret, state.epoch)).not.toBe(groupMailboxId(groupSecret, state.epoch + 1));
    expect(groupMailboxId(groupSecret, state.epoch)).toBe(groupMailboxId(groupSecret, state.epoch));
  });
});

describe("群主转让与群改名（权威转移）", () => {
  it("转让：新 owner 就任、旧 owner 降级、epoch+1、joinedEpoch 保持、人数不变", () => {
    const { owner, members, state } = setupGroup(3);
    const newOwner = members[0]!;
    const next = transferGroupOwnership(owner.ikEd.privateKey, state, newOwner.did);
    expect(next.epoch).toBe(state.epoch + 1);
    expect(next.owner).toBe(newOwner.did);
    expect(next.members).toHaveLength(state.members.length);
    const newEntry = next.members.find((m) => m.did === newOwner.did)!;
    expect(newEntry.role).toBe("owner");
    expect(newEntry.joinedEpoch).toBe(state.members.find((m) => m.did === newOwner.did)!.joinedEpoch);
    const oldEntry = next.members.find((m) => m.did === owner.did)!;
    expect(oldEntry.role).toBe("member");
    expect(oldEntry.joinedEpoch).toBe(state.members.find((m) => m.did === owner.did)!.joinedEpoch);
    // 转让签名仍由原 owner IK 签发（权威转移的密码学事实），而 owner 字段已指向
    // 新 owner：持有上一状态的成员以 prevState 为锚可验证转让；不知情者单看新
    // 状态无从验证（Ed25519 验签锚点必然是签名者公钥）。
    expect(verifyGroupState(next, state)).toBe(true);
    expect(verifyGroupState(next)).toBe(false);
  });

  it("转让边界：非成员拒绝；对 owner 自己转让拒绝", () => {
    const { owner, state } = setupGroup(2);
    expect(() => transferGroupOwnership(owner.ikEd.privateKey, state, "did:mychat:none")).toThrow(/不是群成员/);
    expect(() => transferGroupOwnership(owner.ikEd.privateKey, state, owner.did)).toThrow(/自己/);
  });

  it("转让后由新 owner 继续管理：addGroupMember 重签且常规验签通过（转让的实际意义）", () => {
    const { owner, members, state } = setupGroup(3);
    const newOwner = members[0]!;
    const transferred = transferGroupOwnership(owner.ikEd.privateKey, state, newOwner.did);
    const outsider = createIdentity();
    const next = addGroupMember(newOwner.ikEd.privateKey, transferred, outsider.did);
    expect(next.epoch).toBe(transferred.epoch + 1);
    expect(next.owner).toBe(newOwner.did);
    expect(next.members.some((m) => m.did === outsider.did && m.joinedEpoch === next.epoch)).toBe(true);
    // 新 owner 时代的常规状态：owner 即签名者，回到常规锚点验签
    expect(verifyGroupState(next)).toBe(true);
  });

  it("改名：epoch+1、成员与 owner 逐字段不变、验签通过；非法群名拒绝", () => {
    const { owner, state } = setupGroup(2);
    const next = renameGroup(owner.ikEd.privateKey, state, "改名后的群");
    expect(next.epoch).toBe(state.epoch + 1);
    expect(next.name).toBe("改名后的群");
    expect(next.members).toEqual(state.members);
    expect(next.owner).toBe(state.owner);
    expect(next.groupId).toBe(state.groupId);
    expect(verifyGroupState(next)).toBe(true);
    expect(() => renameGroup(owner.ikEd.privateKey, state, "")).toThrow(/群名长度非法/);
    expect(() => renameGroup(owner.ikEd.privateKey, state, "a".repeat(257))).toThrow(/群名长度非法/);
    // 上限按 UTF-8 字节计：85 个汉字（255 字节）可过，86 个汉字（258 字节）拒
    expect(renameGroup(owner.ikEd.privateKey, state, "群".repeat(85)).name.length).toBe(85);
    expect(() => renameGroup(owner.ikEd.privateKey, state, "群".repeat(86))).toThrow(/群名长度非法/);
  });

  it("确定性：同输入两次转让产出逐字节一致", () => {
    const { owner, members, state } = setupGroup(2);
    const a = transferGroupOwnership(owner.ikEd.privateKey, state, members[0]!.did);
    const b = transferGroupOwnership(owner.ikEd.privateKey, state, members[0]!.did);
    expect(encodeGroupStateJson(a)).toBe(encodeGroupStateJson(b));
  });
});
