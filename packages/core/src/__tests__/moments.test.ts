/**
 * 动态模块单测（M3-S12，FR-4.1/4.2/4.4）：密钥/信箱派生、日志条目加密、
 * 动态内容块往返、墓碑语义。
 */
import { describe, expect, it } from "vitest";

import {
  createMomentBlock,
  decryptAttachment,
  encryptAttachment,
  generateMomentKey,
  momentFeedId,
  openFeedEntry,
  openMomentBlock,
  sealFeedEntry,
  utf8ToBytes,
  base58Encode,
  type FeedEntry,
} from "../index.ts";

describe("好友圈密钥与动态信箱", () => {
  it("momentKey 随机生成；feedId 确定性派生且不同密钥不同信箱", () => {
    const a = generateMomentKey();
    const b = generateMomentKey();
    expect(a).not.toEqual(b);
    expect(momentFeedId(a)).toBe(momentFeedId(a));
    expect(momentFeedId(a)).not.toBe(momentFeedId(b));
  });
});

describe("动态日志条目（FeedEntry）", () => {
  it("post 条目加解密封往返；非好友密钥解不开", () => {
    const key = generateMomentKey();
    const entry: FeedEntry = { v: 1, type: "post", cid: "bafk-abc", contentKey: "CK1", nonce: "N1", at: 1700000000000 };
    const sealed = sealFeedEntry(key, entry);
    expect(openFeedEntry(key, sealed)).toEqual(entry);

    expect(() => openFeedEntry(generateMomentKey(), sealed)).toThrow();
  });

  it("delete 墓碑条目往返；篡改密文被 AEAD 拒绝", () => {
    const key = generateMomentKey();
    const tombstone: FeedEntry = { v: 1, type: "delete", cid: "bafk-abc", at: 1700000000001 };
    expect(openFeedEntry(key, sealFeedEntry(key, tombstone))).toEqual(tombstone);

    const sealed = sealFeedEntry(key, { v: 1, type: "post", cid: "x", contentKey: "c", nonce: "n", at: 1 });
    sealed[10]! ^= 1;
    expect(() => openFeedEntry(key, sealed)).toThrow();
  });

  it("字段缺失/类型非法的明文被拒绝", () => {
    const key = generateMomentKey();
    const bogus = sealFeedEntry(key, { v: 2, type: "post", cid: "x", at: 1 } as unknown as FeedEntry);
    expect(() => openFeedEntry(key, bogus)).toThrow(/字段非法/);
  });
});

describe("动态内容块", () => {
  it("文字动态往返：create → put 块 → open", () => {
    const created = createMomentBlock({ v: 1, text: "第一条动态" });
    const opened = openMomentBlock(created.block, created.contentKey, created.nonce);
    expect(opened.text).toBe("第一条动态");
    expect(opened.attachment).toBeUndefined();
  });

  it("图片动态往返：动态块引用独立图片块（两层密钥）", () => {
    const imageBytes = utf8ToBytes("fake-png-bytes");
    const img = encryptAttachment(imageBytes);
    const created = createMomentBlock({
      v: 1,
      text: "看图",
      attachment: { cid: img.cid, contentKey: base58Encode(img.contentKey), nonce: base58Encode(img.nonce), name: "pic.png", size: imageBytes.length, mime: "image/png" },
    });
    const opened = openMomentBlock(created.block, created.contentKey, created.nonce);
    expect(opened.text).toBe("看图");
    expect(opened.attachment?.cid).toBe(img.cid);
    // 图片块本身可独立解密（模拟好友取回）
    expect(decryptAttachment({ ciphertext: img.ciphertext, contentKey: img.contentKey, nonce: img.nonce })).toEqual(imageBytes);
  });
});
