/**
 * 附件 objectURL 缓存（模块级，cid → objectURL）：
 * 同一附件只取块解密一次（图片与下载共享）；锁定（lockApp 丢弃 KEK）时
 * 统一 revoke 回收——已解密的明文图片不再以 blob URL 存活内存。
 *
 * 独立成 lib 模块的原因：app.ts（lib）需在 lockApp 中清理，而组件层
 * MessageAttachment 依赖 app.ts，直接 import 组件会成环。
 */

/** cid → objectURL。 */
const objectUrlCache = new Map<string, string>();

/** 命中缓存则返回 objectURL（未命中返回 undefined）。 */
export function getCachedObjectUrl(cid: string): string | undefined {
  return objectUrlCache.get(cid);
}

/** 存入 objectURL（同一 cid 以首次为准，重复生成直接丢弃）。 */
export function cacheObjectUrl(cid: string, url: string): void {
  if (!objectUrlCache.has(cid)) objectUrlCache.set(cid, url);
}

/** 全量回收：revoke 全部 objectURL 并清空缓存（锁定时调用）。 */
export function clearAttachmentCache(): void {
  for (const url of objectUrlCache.values()) URL.revokeObjectURL(url);
  objectUrlCache.clear();
}
