/**
 * 群组加密不可信输入守卫测试（SR-5：分发通道可信 ≠ 内容免验）：
 * applyGroupKeysPayload 的载荷形状/条目合法性守卫，与 openGroupMessage
 * 内层信封字段类型守卫——畸形输入一律 throw，不得进入密码学运算。
 */
import { describe, expect, it } from "vitest";

import {
  aeadDecrypt,
  aeadEncrypt,
  applyGroupKeysPayload,
  base58Encode,
  bytesToUtf8,
  concatBytes,
  createGroup,
  createGroupView,
  createIdentity,
  generateSenderKeys,
  groupMailboxKey,
  makeGroupKeysPayload,
  openGroupMessage,
  randomBytes,
  sealGroupMessage,
  utf8ToBytes,
  type GroupKeysPayload,
  type GroupView,
  type Identity,
} from "../../index.ts";

const AEAD_NONCE_LENGTH = 24;

function setupGroup(memberCount = 3): { owner: Identity; state: ReturnType<typeof createGroup>["state"]; groupSecret: Uint8Array; views: GroupView[] } {
  const identities = Array.from({ length: memberCount }, () => createIdentity());
  const [owner, ...others] = identities;
  const { state, groupSecret } = createGroup(owner!.ikEd.privateKey, "测试群", owner!.did, others.map((m) => m.did));
  const senderKeys = generateSenderKeys(state.members.map((m) => m.did));
  const views = identities.map((id) => createGroupView(state, groupSecret, senderKeys));
  return { owner: owner!, state, groupSecret, views };
}

/** 构造外层信封（与 sealAead 同布局：nonce(24B) || XChaCha(mailboxKey)）。 */
function sealOuter(mailboxKey: Uint8Array, plaintextJson: string): Uint8Array {
  const nonce = randomBytes(AEAD_NONCE_LENGTH);
  return concatBytes(nonce, aeadEncrypt(mailboxKey, nonce, utf8ToBytes(plaintextJson)));
}

function openOuter(mailboxKey: Uint8Array, blob: Uint8Array): string {
  return bytesToUtf8(aeadDecrypt(mailboxKey, blob.slice(0, AEAD_NONCE_LENGTH), blob.slice(AEAD_NONCE_LENGTH)));
}

describe("applyGroupKeysPayload 不可信输入守卫", () => {
  it("senderKeys 非数组（字符串迭代会产生 undefined 键）整载荷拒绝", () => {
    const { state, groupSecret, views } = setupGroup();
    const payload = makeGroupKeysPayload(state, groupSecret, views[0]!.senderKeys) as unknown as Record<string, unknown>;
    payload["senderKeys"] = "owner-did";
    expect(() => applyGroupKeysPayload(payload as unknown as GroupKeysPayload)).toThrow(/senderKeys/);
  });

  it("条目 key 解码长度非 32B 拒绝（过短与超长）", () => {
    const { owner, state, groupSecret, views } = setupGroup();
    const payload = makeGroupKeysPayload(state, groupSecret, views[0]!.senderKeys) as unknown as Record<string, unknown>;
    payload["senderKeys"] = [
      { did: owner.did, key: base58Encode(new Uint8Array(31)) },
      { did: state.members[1]!.did, key: base58Encode(new Uint8Array(33)) },
    ];
    expect(() => applyGroupKeysPayload(payload as unknown as GroupKeysPayload)).toThrow(/32 字节/);
  });

  it("越权 did（不在群状态成员清单中）拒绝", () => {
    const { state, groupSecret, views } = setupGroup();
    const payload = makeGroupKeysPayload(state, groupSecret, views[0]!.senderKeys) as unknown as Record<string, unknown>;
    payload["senderKeys"] = [{ did: "did:mychat:outsider", key: base58Encode(new Uint8Array(32)) }];
    expect(() => applyGroupKeysPayload(payload as unknown as GroupKeysPayload)).toThrow(/非群成员/);
  });

  it("条目形状畸形（null / 缺字段 / 非对象）拒绝", () => {
    const { state, groupSecret, views } = setupGroup();
    const goodKey = base58Encode(new Uint8Array(32));
    for (const bad of [null, "str", 42, { did: state.owner }, { key: goodKey }]) {
      const payload = makeGroupKeysPayload(state, groupSecret, views[0]!.senderKeys) as unknown as Record<string, unknown>;
      payload["senderKeys"] = [bad];
      expect(() => applyGroupKeysPayload(payload as unknown as GroupKeysPayload)).toThrow(/条目/);
    }
  });

  it("groupSecret 解码长度非 32B 拒绝", () => {
    const { state, groupSecret, views } = setupGroup();
    const payload = makeGroupKeysPayload(state, groupSecret, views[0]!.senderKeys) as unknown as Record<string, unknown>;
    payload["groupSecret"] = base58Encode(new Uint8Array(31));
    expect(() => applyGroupKeysPayload(payload as unknown as GroupKeysPayload)).toThrow(/groupSecret/);
  });
});

describe("openGroupMessage 内层信封字段守卫", () => {
  /** 把已封装消息的内层信封 JSON 做字段改写后重新封装（外层密钥合法，内容可任意伪造）。 */
  function rewrap(view: GroupView, wire: Uint8Array, mutate: (envelope: Record<string, unknown>) => void): Uint8Array {
    const outerKey = groupMailboxKey(view.groupSecret, view.state.epoch);
    const envelope = JSON.parse(openOuter(outerKey, wire)) as Record<string, unknown>;
    mutate(envelope);
    return sealOuter(outerKey, JSON.stringify(envelope));
  }

  it("合法信封重封装后仍可解（证明测试构造本身有效）", () => {
    const { owner, state, groupSecret, views } = setupGroup(2);
    const wire = sealGroupMessage(owner.ikEd.privateKey, owner.did, views[0]!.senderKeys.get(owner.did)!, groupSecret, state.groupId, state.epoch, 0, utf8ToBytes("原文"));
    const resealed = rewrap(views[0]!, wire, () => {});
    expect(bytesToUtf8(openGroupMessage(views[1]!, resealed).plaintext)).toBe("原文");
  });

  it("index 为字符串（可经 ToUint32 折叠通过验签）被守卫拒绝", () => {
    const { owner, state, groupSecret, views } = setupGroup(2);
    const wire = sealGroupMessage(owner.ikEd.privateKey, owner.did, views[0]!.senderKeys.get(owner.did)!, groupSecret, state.groupId, state.epoch, 0, utf8ToBytes("原文"));
    // index:"0" 经 setUint32 的 ToUint32 折叠与数字 0 验签结果相同——正是守卫要堵的类型混淆
    const forged = rewrap(views[0]!, wire, (envelope) => { envelope["index"] = "0"; });
    expect(() => openGroupMessage(views[1]!, forged)).toThrow(/index/);
  });

  it("sender / epoch 类型非法被守卫拒绝", () => {
    const { owner, state, groupSecret, views } = setupGroup(2);
    const wire = sealGroupMessage(owner.ikEd.privateKey, owner.did, views[0]!.senderKeys.get(owner.did)!, groupSecret, state.groupId, state.epoch, 0, utf8ToBytes("原文"));
    const badSender = rewrap(views[0]!, wire, (envelope) => { envelope["sender"] = 42; });
    expect(() => openGroupMessage(views[1]!, badSender)).toThrow(/sender/);
    const badEpoch = rewrap(views[0]!, wire, (envelope) => { envelope["epoch"] = "0"; });
    expect(() => openGroupMessage(views[1]!, badEpoch)).toThrow(/epoch/);
  });
});
