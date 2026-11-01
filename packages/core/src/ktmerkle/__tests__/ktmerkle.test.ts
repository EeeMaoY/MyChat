import { describe, expect, it } from "vitest";

import { utf8ToBytes } from "../../codec/index.ts";
import type { KTEvent } from "../../protocol/interfaces.ts";
import {
  ktConsistencyUpdate,
  ktInclusionProof,
  ktLeafHash,
  ktMerkleRoot,
  ktVerifyConsistency,
  ktVerifyInclusion,
} from "../ktmerkle.ts";

function makeEvent(index: number, did = `did:mychat:test${index}`): KTEvent {
  return { did, type: "register", payload: utf8ToBytes(`user-${index}`), index };
}

describe("KT Merkle 树（FR-1.6 M1）", () => {
  it("各规模（1..9 个事件）下每个事件的包含性证明均验证通过", () => {
    for (const size of [1, 2, 3, 4, 5, 7, 8, 9]) {
      const leaves = Array.from({ length: size }, (_, i) => ktLeafHash(makeEvent(i)));
      const root = ktMerkleRoot(leaves);
      for (let i = 0; i < size; i++) {
        const proof = ktInclusionProof(leaves, i);
        expect(ktVerifyInclusion(makeEvent(i), proof, root)).toBe(true);
      }
    }
  });

  it("事件被篡改后验证失败（证明与事件绑定）", () => {
    const leaves = Array.from({ length: 5 }, (_, i) => ktLeafHash(makeEvent(i)));
    const root = ktMerkleRoot(leaves);
    const proof = ktInclusionProof(leaves, 2);
    expect(ktVerifyInclusion(makeEvent(2), proof, root)).toBe(true);
    expect(ktVerifyInclusion(makeEvent(3), proof, root)).toBe(false);
    expect(ktVerifyInclusion({ ...makeEvent(2), payload: utf8ToBytes("tampered") }, proof, root)).toBe(false);
  });

  it("路径或根被篡改后验证失败", () => {
    const leaves = Array.from({ length: 6 }, (_, i) => ktLeafHash(makeEvent(i)));
    const root = ktMerkleRoot(leaves);
    const proof = ktInclusionProof(leaves, 4);
    const badPath = { ...proof, path: proof.path.map((s, i) => (i === 0 ? { ...s, sibling: "1111111" } : s)) };
    expect(ktVerifyInclusion(makeEvent(4), badPath, root)).toBe(false);
    expect(ktVerifyInclusion(makeEvent(4), proof, "2KEFebt7r89fsVfAePVR5pSwB8XzYz6VyhjXQ")).toBe(false);
  });

  it("叶哈希对事件全部字段敏感（did/type/payload/index）", () => {
    const base = makeEvent(7);
    const variants: KTEvent[] = [
      { ...base, did: "did:mychat:other" },
      { ...base, type: "revoke" },
      { ...base, payload: utf8ToBytes("user-8") },
      { ...base, index: 8 },
    ];
    const baseHash = ktLeafHash(base).toString();
    for (const v of variants) {
      expect(ktLeafHash(v).toString()).not.toBe(baseHash);
    }
  });
});

describe("KT 前缀一致性（M3-S11 捎带，SR-5 完整化）", () => {
  it("日志增长后：前缀重算双根与两时点根一致（各规模交叉）", () => {
    const all = Array.from({ length: 9 }, (_, i) => ktLeafHash(makeEvent(i)));
    for (const m of [0, 1, 3, 5, 9]) {
      for (const n of new Set([Math.max(1, m), m + 1, 9])) {
        if (n < m) continue;
        const oldPrefix = all.slice(0, m);
        const appended = all.slice(m, n);
        const oldRoot = m === 0 ? "" : ktMerkleRoot(oldPrefix);
        const newRoot = ktMerkleRoot(all.slice(0, n));
        expect(ktVerifyConsistency(oldPrefix, appended, oldRoot, newRoot)).toBe(true);
        // ktConsistencyUpdate 与验证器自洽
        const updated = ktConsistencyUpdate(oldPrefix, appended);
        expect(updated.oldRoot).toBe(oldRoot);
        expect(updated.newRoot).toBe(newRoot);
      }
    }
  });

  it("历史被篡改 / 分叉 / 根不匹配时验证失败", () => {
    const all = Array.from({ length: 6 }, (_, i) => ktLeafHash(makeEvent(i)));
    const oldRoot = ktMerkleRoot(all.slice(0, 3));
    const newRoot = ktMerkleRoot(all);
    // 篡改旧前缀中的一个叶哈希
    const tampered = [...all.slice(0, 3)];
    tampered[1] = ktLeafHash(makeEvent(99));
    expect(ktVerifyConsistency(tampered, all.slice(3), oldRoot, newRoot)).toBe(false);
    // 增量替换（分叉：节点给了不同的"新增"叶子）
    const forked = [ktLeafHash(makeEvent(100))];
    expect(ktVerifyConsistency(all.slice(0, 3), forked, oldRoot, newRoot)).toBe(false);
    // 根不匹配
    expect(ktVerifyConsistency(all.slice(0, 3), all.slice(3), ktMerkleRoot(all.slice(0, 2)), newRoot)).toBe(false);
    expect(ktVerifyConsistency(all.slice(0, 3), all.slice(3), oldRoot, ktMerkleRoot([...all, ktLeafHash(makeEvent(50))]))).toBe(false);
  });
});
