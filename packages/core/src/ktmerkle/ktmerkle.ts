/**
 * KT 日志 Merkle 树（FR-1.6 的 M1 形态）。
 *
 * 结构：叶子 = BLAKE3(事件确定性序列化)；树用空叶子补齐到 2^k 后逐层两两拼接
 * 哈希（实现简单、路径长度固定 log2(size)，与节点侧同构实现互验）。
 *
 * M1 边界（如实披露）：提供包含性证明（"我的注册事件在日志中"）与节点侧
 * append-only 根链；RFC 6962 一致性证明与多副本交叉比对（防节点分叉）为 M2。
 */
import { base58Decode, base58Encode, concatBytes, utf8ToBytes } from "../codec/index.ts";
import { blake3Hash } from "../crypto/index.ts";
import type { KTEvent } from "../protocol/interfaces.ts";

/** 事件确定性序列化（节点与客户端共用，任何字段变动都会破坏证明）。 */
export function ktEventLeafBytes(event: KTEvent): Uint8Array {
  return concatBytes(
    utf8ToBytes(event.did),
    utf8ToBytes(event.type),
    event.payload,
    new Uint8Array([event.index & 0xff, (event.index >>> 8) & 0xff, (event.index >>> 16) & 0xff, (event.index >>> 24) & 0xff]),
  );
}

export function ktLeafHash(event: KTEvent): Uint8Array {
  return blake3Hash(ktEventLeafBytes(event));
}

interface MerkleLevels {
  /** levels[0] = 叶层（已补齐到 2^k），levels[k] = [root] */
  levels: Uint8Array[][];
}

function buildLevels(leaves: Uint8Array[]): MerkleLevels {
  if (leaves.length === 0) throw new Error("空叶子集");
  let width = 1;
  while (width < leaves.length) width <<= 1;
  const bottom: Uint8Array[] = leaves.map((l) => l);
  const zeroLeaf = blake3Hash(new Uint8Array(0));
  while (bottom.length < width) bottom.push(zeroLeaf);
  const levels: Uint8Array[][] = [bottom];
  while (levels[levels.length - 1]!.length > 1) {
    const prev = levels[levels.length - 1]!;
    const next: Uint8Array[] = [];
    for (let i = 0; i < prev.length; i += 2) {
      next.push(blake3Hash(concatBytes(prev[i]!, prev[i + 1]!)));
    }
    levels.push(next);
  }
  return { levels };
}

/** 当前根（base58）。 */
export function ktMerkleRoot(leaves: Uint8Array[]): string {
  const { levels } = buildLevels(leaves);
  return base58Encode(levels[levels.length - 1]![0]!);
}

export interface KtInclusionProof {
  /** 叶子序号（0 起） */
  index: number;
  /** 树大小（未补齐的真实叶子数） */
  size: number;
  /** 叶哈希（base58） */
  leaf: string;
  /** 自叶向根的兄弟哈希路径；isLeft = 兄弟是否在当前节点左侧 */
  path: { sibling: string; isLeft: boolean }[];
  /** 证明对应的根（base58） */
  root: string;
}

export function ktInclusionProof(leaves: Uint8Array[], index: number): KtInclusionProof {
  if (index < 0 || index >= leaves.length) throw new Error("叶子序号越界");
  const { levels } = buildLevels(leaves);
  const path: { sibling: string; isLeft: boolean }[] = [];
  let pos = index;
  for (let level = 0; level < levels.length - 1; level++) {
    const layer = levels[level]!;
    const siblingPos = pos % 2 === 0 ? pos + 1 : pos - 1;
    path.push({ sibling: base58Encode(layer[siblingPos]!), isLeft: pos % 2 === 1 });
    pos = pos >> 1;
  }
  return {
    index,
    size: leaves.length,
    leaf: base58Encode(leaves[index]!),
    path,
    root: base58Encode(levels[levels.length - 1]![0]!),
  };
}

/** 验证包含性证明（事件由调用方提供，重算叶哈希，防证明伪造）。 */
export function ktVerifyInclusion(event: KTEvent, proof: KtInclusionProof, expectedRoot: string): boolean {
  if (proof.index >= proof.size || proof.size === 0) return false;
  let current = blake3Hash(ktEventLeafBytes(event));
  if (base58Encode(current) !== proof.leaf) return false;
  for (const step of proof.path) {
    const sibling = base58Decode(step.sibling);
    current = step.isLeft ? blake3Hash(concatBytes(sibling, current)) : blake3Hash(concatBytes(current, sibling));
  }
  return base58Encode(current) === expectedRoot && base58Encode(current) === proof.root;
}

// ---------------------------------------------------------------------------
// 前缀一致性验证（SR-5 完整化，M3-S11 捎带）
//
// 边界（如实披露）：本树的 pad-to-2^k 形态与 RFC 6962 的 left-aligned 不同，
// 标准一致性证明需迁移树结构（协议 v0.2 评估）；此处提供**语义等价**的前缀
// 一致性——节点给出两个时点间的叶哈希增量，客户端重算两个时点的根并与本地
// 记录（或另一副本的根链）比对。任何历史篡改/分叉都会导致根不匹配，安全语义
// 与 RFC 6962 一致性证明相同；开销 O(n) 与客户端事件流折叠同阶。
// ---------------------------------------------------------------------------

/** 树从 size(oldPrefix) 增长到 size(oldPrefix)+appended 的一致性材料（两时点根）。 */
export function ktConsistencyUpdate(oldPrefixLeafHashes: Uint8Array[], appendedLeafHashes: Uint8Array[]): { oldRoot: string; newRoot: string } {
  if (oldPrefixLeafHashes.length === 0 && appendedLeafHashes.length === 0) throw new Error("空叶子集");
  return {
    oldRoot: oldPrefixLeafHashes.length === 0 ? "" : ktMerkleRoot(oldPrefixLeafHashes),
    newRoot: ktMerkleRoot([...oldPrefixLeafHashes, ...appendedLeafHashes]),
  };
}

/**
 * 验证前缀一致性：旧前缀叶哈希重算根必须等于 oldRoot，
 * 追加增量后重算根必须等于 newRoot。任一不匹配 = 节点历史被篡改或副本分叉。
 */
export function ktVerifyConsistency(oldPrefixLeafHashes: Uint8Array[], appendedLeafHashes: Uint8Array[], oldRoot: string, newRoot: string): boolean {
  try {
    const computed = ktConsistencyUpdate(oldPrefixLeafHashes, appendedLeafHashes);
    return computed.oldRoot === oldRoot && computed.newRoot === newRoot;
  } catch {
    return false;
  }
}
