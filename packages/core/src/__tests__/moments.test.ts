/**
 * 动态模块单测（M3-S12 + 加固批次 ②，FR-4.1/4.2/4.4）：密钥/信箱派生、
 * 日志条目加密与 **IK 作者性验签**、动态内容块往返、墓碑语义。
 */
import { describe, expect, it } from "vitest";

import {
  createIdentity,
  createMomentBlock,
  decryptAttachment,
  feedEntryMessage,
  generateMomentKey,
  makeMomentEntry,
  momentFeedId,
  openFeedEntry,
  openMomentBlock,
  sealFeedEntry,
  utf8ToBytes,
  base58Encode,
  encryptAttachment,
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

describe("动态日志条目（FeedEntry，带 IK 签名）", () => {
  it("post 条目签发加密封往返；非好友密钥解不开", () => {
    const key = generateMomentKey();
    const author = createIdentity();
    const entry = makeMomentEntry(author.ikEd.privateKey, {
      v: 1,
      type: "post",
      cid: "bafk-abc",
      authorDid: author.did,
      contentKey: "CK1",
      nonce: "N1",
      at: 1700000000000,
    });
    const sealed = sealFeedEntry(key, entry);
    expect(openFeedEntry(key, sealed)).toEqual(entry);

    expect(() => openFeedEntry(generateMomentKey(), sealed)).toThrow();
  });

  it("delete 墓碑条目往返；篡改密文被 AEAD 拒绝", () => {
    const key = generateMomentKey();
    const author = createIdentity();
    const tombstone = makeMomentEntry(author.ikEd.privateKey, { v: 1, type: "delete", cid: "bafk-abc", authorDid: author.did, at: 1700000000001 });
    expect(openFeedEntry(key, sealFeedEntry(key, tombstone))).toEqual(tombstone);

    const sealed = sealFeedEntry(
      key,
      makeMomentEntry(author.ikEd.privateKey, { v: 1, type: "post", cid: "x", authorDid: author.did, contentKey: "c", nonce: "n", at: 1 }),
    );
    sealed[10]! ^= 1;
    expect(() => openFeedEntry(key, sealed)).toThrow();
  });

  it("被签消息确定性；字段缺失/类型非法拒绝", () => {
    const author = createIdentity();
    const fields = { v: 1 as const, type: "post" as const, cid: "x", authorDid: author.did, contentKey: "c", nonce: "n", at: 7 };
    expect(feedEntryMessage(fields)).toEqual(feedEntryMessage(fields));
    // 内容指针有无影响签名域（1B 标志位）
    expect(feedEntryMessage(fields)).not.toEqual(feedEntryMessage({ ...fields, contentKey: undefined, nonce: undefined }));

    const key = generateMomentKey();
    const bogus = sealFeedEntry(key, makeMomentEntry(author.ikEd.privateKey, { ...fields, v: 2 as never }));
    expect(() => openFeedEntry(key, bogus)).toThrow(/字段非法/);
  });
});

describe("条目作者性（加固批次 ②：好友伪造被验签拒绝）", () => {
  it("冒名作者（签名者≠声明作者）的条目被拒绝", () => {
    const key = generateMomentKey();
    const realAuthor = createIdentity();
    const mallory = createIdentity();
    // mallory 签名但声明 authorDid 为 realAuthor
    const forged = makeMomentEntry(mallory.ikEd.privateKey, {
      v: 1,
      type: "post",
      cid: "bafk-forged",
      authorDid: realAuthor.did,
      contentKey: "CK",
      nonce: "N",
      at: 1,
    });
    const sealed = sealFeedEntry(key, forged);
    expect(() => openFeedEntry(key, sealed)).toThrow(/签名验证失败/);
  });

  it("篡改条目任一业务字段（cid/at/指针）验签失败", () => {
    const key = generateMomentKey();
    const author = createIdentity();
    const entry = makeMomentEntry(author.ikEd.privateKey, {
      v: 1,
      type: "post",
      cid: "bafk-real",
      authorDid: author.did,
      contentKey: "CK",
      nonce: "N",
      at: 42,
    });
    // 以真实签名 + 篡改字段重封（攻击者拿到条目明文可重组密文——对称层拦不住，签名层必须拦）
    const tampered: FeedEntry = { ...entry, cid: "bafk-evil" };
    expect(() => openFeedEntry(key, sealFeedEntry(key, tampered))).toThrow(/签名验证失败/);
    expect(() => openFeedEntry(key, sealFeedEntry(key, { ...entry, at: entry.at + 1 }))).toThrow(/签名验证失败/);
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
    expect(decryptAttachment({ ciphertext: img.ciphertext, contentKey: img.contentKey, nonce: img.nonce })).toEqual(imageBytes);
  });
});
