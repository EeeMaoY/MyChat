import { describe, expect, it } from "vitest";

import { base58Decode } from "../../codec/index.ts";
import { randomBytes } from "../../crypto/index.ts";
import { decryptAttachment, encryptAttachment, verifyAttachmentCid } from "../attachment.ts";

/** 分块生成大缓冲（@noble randomBytes 单次上限 65536）。 */
function randomLarge(size: number): Uint8Array {
  const out = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65536) {
    out.set(randomBytes(Math.min(65536, size - offset)), offset);
  }
  return out;
}

describe("附件端到端加密（M1-S5）", () => {
  it("加密-解密往返（小文本与随机大内容）", () => {
    for (const size of [1, 1024, 256 * 1024]) {
      const data = randomLarge(size);
      const att = encryptAttachment(data);
      expect(decryptAttachment(att)).toEqual(data);
    }
  });

  it("CID = base58(BLAKE3(密文))，且 verifyAttachmentCid 通过；密文篡改后 CID 校验失败", () => {
    const att = encryptAttachment(randomBytes(2048));
    expect(verifyAttachmentCid(att)).toBe(true);
    expect(base58Decode(att.cid).length).toBe(32);

    const tampered = att.ciphertext.slice();
    tampered[tampered.length - 1]! ^= 1;
    expect(verifyAttachmentCid({ cid: att.cid, ciphertext: tampered })).toBe(false);
  });

  it("不同内容得到不同 CID；同内容重复加密因随机 nonce 产生独立密文与 CID（语义安全）", () => {
    const a = encryptAttachment(new Uint8Array([1, 2, 3]));
    const b = encryptAttachment(new Uint8Array([1, 2, 4]));
    expect(a.cid).not.toBe(b.cid);

    const c1 = encryptAttachment(new Uint8Array([9]));
    const c2 = encryptAttachment(new Uint8Array([9]));
    // 随机 nonce ⇒ 密文不同 ⇒ CID 不同：CAS 幂等不适用于附件（同文件重复发送各存一份，可接受）
    expect(c1.cid).not.toBe(c2.cid);
    expect(c1.contentKey).not.toEqual(c2.contentKey);
    expect(decryptAttachment(c1)).toEqual(new Uint8Array([9]));
    expect(decryptAttachment(c2)).toEqual(new Uint8Array([9]));
  });

  it("错误 CK / 篡改密文解密失败", () => {
    const att = encryptAttachment(randomBytes(128));
    expect(() =>
      decryptAttachment({ ...att, contentKey: randomBytes(32) }),
    ).toThrow();
    const bad = att.ciphertext.slice();
    bad[0]! ^= 1;
    expect(() => decryptAttachment({ ...att, ciphertext: bad })).toThrow();
  });

  it("空内容拒绝", () => {
    expect(() => encryptAttachment(new Uint8Array(0))).toThrow();
  });
});
