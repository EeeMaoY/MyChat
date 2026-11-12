/**
 * 对端会话载荷的运行时校验（防远程白屏，安全加固批次）。
 *
 * 会话明文由对端任意构造：解密成功只证明"确为对端所发"，不证明字段类型合法。
 * 未校验的 text:null、fromName:{} 等一旦落库，渲染层抛 TypeError → React 卸载整棵树（白屏），
 * 且消息已持久化，之后每次启动都复现。故所有入站载荷先过本模块：
 * JSON 解析失败或任一所用字段类型非法即整体返回 null（调用方丢弃、不落库）。
 *
 * 约定：只校验并保留本端实际使用的字段（多余字段宽容、不透传）；
 * 深层语义校验（群状态验签、分片封装开启等）仍由 core 在各消费点承担。
 */
import type { GroupKeysPayloadJson, ReplyQuote, SessionPayload } from "./messaging";

/** 附件声明大小上限（16 MiB = 节点单块上限；发送侧 8MB 上限在其内）。 */
const MAX_ATTACHMENT_SIZE = 16 * 1024 * 1024;
/** 回执 / 撤回 id 列表长度上限（防超大数组拖垮逐条匹配）。 */
const MAX_ID_LIST = 1000;

/** 宽松对象形态：仅排除 null 与数组（数组按字段单独校验）。 */
type Fields = Record<string, unknown>;

function isFields(value: unknown): value is Fields {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

/** 可选字符串：缺省或 string 合法；显式 null / 其他类型一律非法。 */
function isOptionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === "string";
}

/** 受限长度的字符串数组（元素非法即整体非法）。 */
function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= MAX_ID_LIST && value.every(isString);
}

/** GroupKeysPayloadJson 的浅形状判定；深层（群状态验签、密钥材料）由 core 与 handleGroupKeys 承担。 */
function isGroupKeysPayload(value: unknown): value is GroupKeysPayloadJson {
  return isFields(value);
}

/** 引用快照（S17）校验：text 必填，mid/authorName 可选字符串。 */
function parseReplyQuote(value: unknown): ReplyQuote | null {
  if (!isFields(value)) return null;
  const { mid, authorName, text } = value;
  if (!isString(text) || !isOptionalString(mid) || !isOptionalString(authorName)) return null;
  return {
    text,
    ...(mid !== undefined ? { mid } : {}),
    ...(authorName !== undefined ? { authorName } : {}),
  };
}

/** 附件字段（image/file 共用）校验：五个字符串 + 受限数值 size。 */
function isAttachmentFields(o: Fields): boolean {
  const { cid, contentKey, nonce, name, mime, size } = o;
  return (
    isString(cid) &&
    isString(contentKey) &&
    isString(nonce) &&
    isString(name) &&
    isString(mime) &&
    typeof size === "number" &&
    Number.isFinite(size) &&
    size >= 0 &&
    size <= MAX_ATTACHMENT_SIZE
  );
}

/**
 * 解析对端载荷并做逐 type 的严格形状校验；不合法返回 null（不落库）。
 * 兼容注意：M0 时期的纯文本消息（非 JSON）不会得到合法输出，
 * 调用方以 isStructuredPayload 区分后按纯文本落库。
 */
export function parseSessionPayload(raw: string): SessionPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isFields(parsed) || parsed.v !== 1) return null;
  const o = parsed;
  const type = o.type;
  switch (type) {
    case "chat": {
      const { text, mid, replyTo } = o;
      if (!isString(text) || !isOptionalString(mid)) return null;
      let quote: ReplyQuote | undefined;
      if (replyTo !== undefined) {
        const parsedQuote = parseReplyQuote(replyTo);
        if (parsedQuote === null) return null;
        quote = parsedQuote;
      }
      return {
        v: 1,
        type: "chat",
        text,
        ...(mid !== undefined ? { mid } : {}),
        ...(quote !== undefined ? { replyTo: quote } : {}),
      };
    }
    case "image":
    case "file": {
      const { mid } = o;
      if (!isAttachmentFields(o) || !isOptionalString(mid)) return null;
      return {
        v: 1,
        type,
        cid: o.cid as string,
        contentKey: o.contentKey as string,
        nonce: o.nonce as string,
        name: o.name as string,
        mime: o.mime as string,
        size: o.size as number,
        ...(mid !== undefined ? { mid } : {}),
      };
    }
    case "receipt": {
      const { delivered, read } = o;
      if (!isStringList(delivered) || !isStringList(read)) return null;
      return { v: 1, type: "receipt", delivered, read };
    }
    case "recall": {
      const { ids } = o;
      if (!isStringList(ids)) return null;
      return { v: 1, type: "recall", ids };
    }
    case "custody-request": {
      // 仅 v/type 被消费（forName 未使用，归一为 null 以满足类型）
      return { v: 1, type: "custody-request", forName: isString(o.forName) ? o.forName : null };
    }
    case "custody-reply": {
      const { cid, wrappedKey } = o;
      if (!isString(cid) || !isString(wrappedKey)) return null;
      return { v: 1, type: "custody-reply", cid, wrappedKey };
    }
    case "guardian-invite": {
      const { wrapCid, sealedShare } = o;
      if (!isString(wrapCid) || !isString(sealedShare)) return null;
      // 载荷自报的 did 不透传：归属一律以会话对端 did 为准（见 handleSessionPayload）
      return { v: 1, type: "guardian-invite", wrapCid, sealedShare };
    }
    case "recovery-request": {
      const { did } = o;
      if (!isString(did)) return null;
      return { v: 1, type: "recovery-request", did };
    }
    case "recovery-share": {
      const { did, shareX, shareY } = o;
      if (!isString(did) || !isString(shareY) || typeof shareX !== "number" || !Number.isInteger(shareX)) return null;
      return { v: 1, type: "recovery-share", did, shareX, shareY };
    }
    case "group-keys": {
      const { payload } = o;
      if (!isGroupKeysPayload(payload)) return null;
      return { v: 1, type: "group-keys", payload };
    }
    case "group-leave": {
      const { groupId } = o;
      if (!isString(groupId)) return null;
      return { v: 1, type: "group-leave", groupId };
    }
    case "circle-keys": {
      const { momentKey } = o;
      if (!isString(momentKey)) return null;
      return { v: 1, type: "circle-keys", momentKey };
    }
    case "moment-comment": {
      const { cid, text } = o;
      if (!isString(cid) || !isString(text)) return null;
      return { v: 1, type: "moment-comment", cid, text };
    }
    default:
      return null; // type 不在清单内
  }
}

/**
 * raw 是否具备 v1 结构化载荷的外形（合法 JSON 对象，v===1 且 type 为 string）。
 * 用于区分"M0 纯文本消息"与"外形是结构化载荷但字段非法"：前者按文本落库，后者丢弃。
 */
export function isStructuredPayload(raw: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return false;
  }
  return isFields(parsed) && parsed.v === 1 && isString(parsed.type);
}
