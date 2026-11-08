/**
 * 群组状态（GroupState，FR-6.1，M3 计划 §3.2）—— 群主权威、IK 签名的成员清单。
 *
 * 信任模型：群主签发权威清单，经群信箱广播与 1:1 会话同步；成员客户端
 * 本地验签后才采信（SR-5 惯例：节点存储与转发不代表可信）。
 * **任何状态变更即 epoch+1**（v1 设计决定：编排层复用统一的 SK 重分发路径）：
 * 入群（history: new-only，新成员不见加入前消息）、移除/退群（断读：被移除者
 * 拿不到新 epoch 的群秘密与发送密钥，FR-6.2）、群主转让与群改名，统一由
 * epoch 推进表达。
 *
 * 签名覆盖确定性编码（与 username/certificate 同一惯例）：
 *   "mychat:group-state-v1:" || len(groupId)||groupId || len(name)||name
 *     || len(owner)||owner || epoch(4B) || memberCount(2B)
 *     || 各成员（按 did 排序）: len(did)||did || role(1B) || joinedEpoch(4B)
 */
import { base58Decode, base58Encode, base64Decode, base64Encode, concatBytes, utf8ToBytes } from "../codec/index.ts";
import { randomBytes } from "../crypto/index.ts";
import { ed25519Sign, ed25519Verify } from "../crypto/index.ts";
import { didToEd25519PublicKey } from "../identity/did.ts";

const STATE_SIGNING_PREFIX = "mychat:group-state-v1:";
const SIGNATURE_LENGTH = 64;
/** 群名 UTF-8 上限 */
const NAME_MAX_BYTES = 256;
/** FR-6.1：3–50 人私群（v1 硬上限） */
export const GROUP_MEMBER_LIMIT = 50;

export interface GroupMember {
  did: string;
  role: "owner" | "member";
  /** 加入时所在的 epoch（新成员从此 epoch 起可读） */
  joinedEpoch: number;
}

export interface GroupState {
  v: 1;
  /** 群标识 = base58(random 32B)，不绑定创建者 DID（降低群-人关联） */
  groupId: string;
  name: string;
  owner: string;
  /** 从 1 起单调递增；每次状态变更（成员变更/群主转让/群改名）+1 */
  epoch: number;
  /** 按 did 排序（签名一致性的规范化序） */
  members: GroupMember[];
  /** owner IK 签名（64B） */
  signature: Uint8Array;
}

/** 防拼接歧义的确定性编码（导出供测试与审计复核）。 */
export function groupStateMessage(fields: Omit<GroupState, "signature">): Uint8Array {
  const parts: Uint8Array[] = [utf8ToBytes(STATE_SIGNING_PREFIX), prefixed(fields.groupId), prefixed(fields.name), prefixed(fields.owner), uint32(fields.epoch), uint16(fields.members.length)];
  const sorted = [...fields.members].sort((a, b) => (a.did < b.did ? -1 : 1));
  for (const m of sorted) {
    parts.push(prefixed(m.did), new Uint8Array([m.role === "owner" ? 0 : 1]), uint32(m.joinedEpoch));
  }
  return concatBytes(...parts);
}

function prefixed(text: string): Uint8Array {
  const bytes = utf8ToBytes(text);
  const out = new Uint8Array(2 + bytes.length);
  new DataView(out.buffer).setUint16(0, bytes.length, false);
  out.set(bytes, 2);
  return out;
}

function uint32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function uint16(n: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, n, false);
  return out;
}

export interface CreateGroupResult {
  state: GroupState;
  /** 群对称秘密（32B）：派生群信箱与信箱密钥；仅成员经 1:1 会话获得 */
  groupSecret: Uint8Array;
}

/**
 * 创建群组：groupId/groupSecret 随机生成，owner 与初始成员同为 epoch 1 成员
 * （owner 需出现在 memberDids 中或自动并入）。初始成员为空亦可（单人群）。
 */
export function createGroup(ikEdPrivateKey: Uint8Array, name: string, ownerDid: string, memberDids: string[]): CreateGroupResult {
  if (name.length === 0 || utf8ToBytes(name).length > NAME_MAX_BYTES) {
    throw new Error("群名长度非法（1-256 字节）");
  }
  const unique = new Set(memberDids);
  unique.add(ownerDid);
  if (unique.size > GROUP_MEMBER_LIMIT) {
    throw new Error(`群成员数超上限（${GROUP_MEMBER_LIMIT}）`);
  }
  const members: GroupMember[] = [...unique].map((did) => ({
    did,
    role: did === ownerDid ? ("owner" as const) : ("member" as const),
    joinedEpoch: 1,
  }));
  const state = signGroup(ikEdPrivateKey, {
    v: 1,
    groupId: base58Encode(randomBytes(32)),
    name,
    owner: ownerDid,
    epoch: 1,
    members,
  });
  return { state, groupSecret: randomBytes(32) };
}

/** 以新字段重签（成员变更/群主转让/群名变更的内部原语）。 */
export function signGroup(ikEdPrivateKey: Uint8Array, fields: Omit<GroupState, "signature">): GroupState {
  return { ...fields, signature: ed25519Sign(ikEdPrivateKey, groupStateMessage(fields)) };
}

/**
 * 验证群状态：结构校验 + IK 验签全部通过才有效。
 *
 * 常规路径：签名锚定 state.owner（权威即签名者）。
 * 权威转移路径（可选 prevState）：转让状态的签名仍由原 owner 签发——这是权威
 * 转移的密码学事实，而 state.owner 已指向新 owner，故单看新状态无法自证
 * （Ed25519 验签锚点必然是签名者公钥）；持有上一个状态的成员以 prevState 为锚
 * 验证：同群、epoch 连续 +1、原 owner 已降级为 member、签名出自原 owner IK。
 * prevState 须为验证方本地已采信的上一个状态（不递归重验，以兼容连续转让链）。
 */
export function verifyGroupState(state: GroupState, prevState?: GroupState): boolean {
  if (state.v !== 1) return false;
  if (!Number.isSafeInteger(state.epoch) || state.epoch < 1) return false;
  if (state.name.length === 0 || utf8ToBytes(state.name).length > NAME_MAX_BYTES) return false;
  if (state.members.length === 0 || state.members.length > GROUP_MEMBER_LIMIT) return false;
  if (!state.members.some((m) => m.role === "owner" && m.did === state.owner)) return false;
  try {
    base58Decode(state.groupId);
    didToEd25519PublicKey(state.owner);
  } catch {
    return false;
  }
  if (state.signature.length !== SIGNATURE_LENGTH) return false;
  const { signature, ...fields } = state;
  if (ed25519Verify(signature, groupStateMessage(fields), didToEd25519PublicKey(state.owner))) return true;
  // 常规验签未过且提供了上一个状态时，尝试权威转移路径
  if (prevState === undefined || prevState.v !== 1) return false;
  if (!Number.isSafeInteger(prevState.epoch) || prevState.epoch < 1) return false;
  if (state.groupId !== prevState.groupId) return false;
  if (state.epoch !== prevState.epoch + 1) return false;
  if (state.owner === prevState.owner) return false;
  // 原 owner 须仍在新清单中且已降级为 member（转让完整性的结构证据）
  const previous = state.members.find((m) => m.did === prevState.owner);
  if (!previous || previous.role !== "member") return false;
  try {
    didToEd25519PublicKey(prevState.owner);
  } catch {
    return false;
  }
  return ed25519Verify(signature, groupStateMessage(fields), didToEd25519PublicKey(prevState.owner));
}

export function isGroupMember(state: GroupState, did: string): boolean {
  return state.members.some((m) => m.did === did);
}

/**
 * 邀请成员：epoch+1（入群即前向隔离——新成员仅见加入后消息，history: new-only 默认）。
 * 返回重签的新状态；超限 throw。
 */
export function addGroupMember(ikEdPrivateKey: Uint8Array, state: GroupState, newMemberDid: string): GroupState {
  if (isGroupMember(state, newMemberDid)) throw new Error("该用户已是群成员");
  if (state.members.length + 1 > GROUP_MEMBER_LIMIT) throw new Error(`群成员数超上限（${GROUP_MEMBER_LIMIT}）`);
  const { signature, ...fields } = state;
  void signature;
  return signGroup(ikEdPrivateKey, {
    ...fields,
    epoch: state.epoch + 1,
    members: [
      ...state.members,
      { did: newMemberDid, role: "member" as const, joinedEpoch: state.epoch + 1 },
    ],
  });
}

/** 移除成员（FR-6.2 断读）：epoch+1；owner 不可被移除（转让走 transferGroupOwnership）。 */
export function removeGroupMember(ikEdPrivateKey: Uint8Array, state: GroupState, targetDid: string): GroupState {
  if (targetDid === state.owner) throw new Error("群主不可被移除");
  if (!isGroupMember(state, targetDid)) throw new Error("该用户不是群成员");
  const { signature, ...fields } = state;
  void signature;
  return signGroup(ikEdPrivateKey, {
    ...fields,
    epoch: state.epoch + 1,
    members: state.members.filter((m) => m.did !== targetDid),
  });
}

/**
 * 群主转让：newOwnerDid 须为现有成员且非当前 owner。旧 owner 降级为 role:"member"，
 * 新 owner 升为 role:"owner"（双方 joinedEpoch 均保持不变），epoch+1（v1 设计决定：
 * 任何状态变更都推进 epoch，编排层复用统一的 SK 重分发路径），群成员总数不变。
 *
 * 签名仍由调用方 IK（原 owner）签发——这是权威转移的密码学事实：转让授权本身
 * 必须出自现任权威。因此转让状态的验证锚点是原 owner（借助上一状态，见
 * verifyGroupState 的权威转移路径）；新 owner 后续签发的状态回到常规 owner 锚点。
 */
export function transferGroupOwnership(ikEdPrivateKey: Uint8Array, state: GroupState, newOwnerDid: string): GroupState {
  if (!isGroupMember(state, newOwnerDid)) throw new Error("该用户不是群成员");
  if (newOwnerDid === state.owner) throw new Error("不能将群主转让给自己");
  const { signature, ...fields } = state;
  void signature;
  return signGroup(ikEdPrivateKey, {
    ...fields,
    owner: newOwnerDid,
    epoch: state.epoch + 1,
    members: state.members.map((m) => {
      if (m.did === newOwnerDid) return { ...m, role: "owner" as const };
      if (m.did === state.owner) return { ...m, role: "member" as const };
      return m;
    }),
  });
}

/**
 * 群改名：群名校验与 createGroup 一致（1-256 UTF-8 字节）；epoch+1（与转让同一
 * 设计决定：统一"状态变更=epoch 推进"，编排层无需区分处理）；owner 与成员列表
 * 逐字段不变，签名由调用方 IK（owner）重签，常规 owner 锚点验签即可通过。
 */
export function renameGroup(ikEdPrivateKey: Uint8Array, state: GroupState, newName: string): GroupState {
  if (newName.length === 0 || utf8ToBytes(newName).length > NAME_MAX_BYTES) {
    throw new Error("群名长度非法（1-256 字节）");
  }
  const { signature, ...fields } = state;
  void signature;
  return signGroup(ikEdPrivateKey, { ...fields, name: newName, epoch: state.epoch + 1 });
}

// ----- JSON 编解码（群信箱广播与 1:1 分发统一形态；signature 为 base64） -----

export function encodeGroupStateJson(state: GroupState): string {
  return JSON.stringify({
    v: state.v,
    groupId: state.groupId,
    name: state.name,
    owner: state.owner,
    epoch: state.epoch,
    members: state.members,
    signature: base64Encode(state.signature),
  });
}

export function decodeGroupStateJson(text: string): GroupState {
  const raw = JSON.parse(text) as Record<string, unknown>;
  if (raw.v !== 1) throw new Error("群状态版本不识别");
  if (typeof raw.groupId !== "string" || typeof raw.name !== "string" || typeof raw.owner !== "string") {
    throw new Error("群状态字段非法");
  }
  if (typeof raw.epoch !== "number" || !Array.isArray(raw.members)) throw new Error("群状态字段非法");
  if (typeof raw.signature !== "string") throw new Error("群状态签名字段缺失");
  const members: GroupMember[] = (raw.members as { did: unknown; role: unknown; joinedEpoch: unknown }[]).map((m) => {
    if (typeof m.did !== "string" || (m.role !== "owner" && m.role !== "member") || typeof m.joinedEpoch !== "number") {
      throw new Error("群成员条目非法");
    }
    return { did: m.did, role: m.role, joinedEpoch: m.joinedEpoch };
  });
  return {
    v: 1,
    groupId: raw.groupId,
    name: raw.name,
    owner: raw.owner,
    epoch: raw.epoch,
    members,
    signature: base64Decode(raw.signature),
  };
}
