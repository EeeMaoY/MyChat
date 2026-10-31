import { describe, expect, it } from "vitest";

import { utf8ToBytes } from "../../codec/index.ts";
import type { KTEvent } from "../../protocol/interfaces.ts";
import {
  ktInclusionProof,
  ktLeafHash,
  ktMerkleRoot,
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
