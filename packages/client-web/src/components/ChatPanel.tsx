/** 聊天面板：会话头部、消息列表（气泡/系统条/附件）、自适应输入区（含附件发送）。 */
import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ChangeEvent,
  type KeyboardEvent,
  type ReactElement,
} from "react";

import { markChatOpened, sendAttachment, sendMessage, setNotice, useAppState } from "../lib/app";
import type { ChatMessage } from "../lib/messaging";

import { FileBubble, ImageBubble } from "./MessageAttachment";
import { formatClock, shortDid } from "./format";

interface Props {
  /** 窄屏返回会话列表。 */
  onBack: () => void;
  /** 空态引导里的加好友入口。 */
  onAddFriend: () => void;
}

/** 输入框自适应高度上限（与 CSS max-height 一致）。 */
const TEXTAREA_MAX_PX = 160;

/** 附件大小上限 8MB（发送前拦截，避免读入大文件）。 */
const ATTACHMENT_MAX_BYTES = 8 * 1024 * 1024;

/** 文件选择框 accept 提示（不强制；其余类型按文件消息发送）。 */
const ATTACHMENT_ACCEPT = "image/*,.pdf,.txt,.md,.zip,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.mp3,.mp4";

/** 回执 title 提示（FR-5.2 三态）。 */
const RECEIPT_TITLE = { sent: "已发送", delivered: "已送达", read: "已读" } as const;

/** 回执三态（仅 out 消息）：单勾灰=已发送，双勾灰=已送达，双勾蓝=已读。 */
function ReceiptBadge({ status }: { status: ChatMessage["status"] }) {
  const s = status ?? "sent";
  const title = RECEIPT_TITLE[s];
  const stroke = { fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round" } as const;
  return (
    <span className={`msg-receipt${s === "read" ? " read" : ""}`} title={title} aria-label={title}>
      {s === "sent" ? (
        <svg viewBox="0 0 15 12" width="14" height="12" aria-hidden="true">
          <path d="M1.5 6.5 5 10 13.5 1.5" {...stroke} />
        </svg>
      ) : (
        <svg viewBox="0 0 18 12" width="17" height="12" aria-hidden="true">
          <path d="M1.5 6.5 5 10 12.5 1.5" {...stroke} />
          <path d="M6 6.5 9.5 10 17 1.5" {...stroke} />
        </svg>
      )}
    </span>
  );
}

export default function ChatPanel({ onBack, onAddFriend }: Props) {
  const state = useAppState();
  const did = state.activeDid;

  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const listRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  /** did → 待触发定时器（markChatOpened 500ms 去抖，同一会话合并为一次）。 */
  const openTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const list = did !== null ? state.messages[did] : undefined;
  const contact = did !== null ? state.contacts.find((c) => c.did === did) : undefined;
  // 群会话（M3-S11）：activeDid = group:<groupId>
  const isGroupChat = did !== null && did.startsWith("group:");
  const group = isGroupChat && did !== null ? state.groups.find((g) => `group:${g.groupId}` === did) : undefined;

  function scrollToBottom(): void {
    const el = listRef.current;
    if (el !== null) el.scrollTop = el.scrollHeight;
  }

  /** 同一会话 500ms 内的多次触发合并为一次 markChatOpened（打开会话 + 新到消息）。 */
  function markOpenedDebounced(chatDid: string): void {
    const timers = openTimersRef.current;
    const prev = timers.get(chatDid);
    if (prev !== undefined) clearTimeout(prev);
    timers.set(
      chatDid,
      setTimeout(() => {
        timers.delete(chatDid);
        markChatOpened(chatDid);
      }, 500),
    );
  }

  // 切换会话：清空草稿、复位输入框高度、滚到底部
  useEffect(() => {
    setDraft("");
    setSending(false);
    if (inputRef.current !== null) inputRef.current.style.height = "auto";
    scrollToBottom();
  }, [did]);

  // 打开/切换会话、当前会话收到新消息：去抖上报"已打开"（触发对端 read 回执）
  useEffect(() => {
    if (did !== null) markOpenedDebounced(did);
  }, [did, list?.length]);

  // 卸载：清掉未触发的去抖定时器
  useEffect(
    () => () => {
      for (const timer of openTimersRef.current.values()) clearTimeout(timer);
      openTimersRef.current.clear();
    },
    [],
  );

  // 消息增减（收/发）后滚到底部
  useLayoutEffect(() => {
    scrollToBottom();
  }, [list?.length]);

  /** 空态：未选择会话。 */
  if (did === null) {
    return (
      <section className="chat-panel">
        <div className="chat-empty">
          <p className="chat-empty-title">添加好友开始聊天</p>
          <p className="chat-empty-sub">
            通过对方用户名发送加密好友请求，握手完成后，消息只存在于你们两人的设备上。
          </p>
          <button className="btn-primary" onClick={onAddFriend}>
            ➕ 加好友
          </button>
        </div>
      </section>
    );
  }

  // 早退后的非空别名（嵌套函数内不继承 did 的 narrowing）
  const activeDid: string = did;

  async function handleSend(): Promise<void> {
    const text = draft.trim();
    if (text === "" || sending) return;
    setSending(true);
    try {
      await sendMessage(activeDid, text);
      setDraft("");
      if (inputRef.current !== null) inputRef.current.style.height = "auto";
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "发送失败");
    } finally {
      setSending(false);
    }
  }

  /** 附件发送：mime 以 image/ 开头按图片，否则按文件；超限不发。 */
  async function handleFileSelected(e: ChangeEvent<HTMLInputElement>): Promise<void> {
    const input = e.target;
    const file = input.files?.[0];
    input.value = ""; // 复位，允许重复选择同一文件
    if (file === undefined || sending) return;
    if (file.size > ATTACHMENT_MAX_BYTES) {
      setNotice("附件超过 8MB 上限");
      return;
    }
    setSending(true);
    try {
      const data = new Uint8Array(await file.arrayBuffer());
      const kind = file.type.startsWith("image/") ? "image" : "file";
      await sendAttachment(activeDid, { data, name: file.name, mime: file.type || "application/octet-stream" }, kind);
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "发送失败");
    } finally {
      setSending(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>): void {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void handleSend();
    }
  }

  function handleChange(e: ChangeEvent<HTMLTextAreaElement>): void {
    setDraft(e.target.value);
    const el = e.target;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, TEXTAREA_MAX_PX)}px`;
  }

  /** 单条消息体：图片/文件渲染附件气泡，其余按文本。 */
  function renderBody(m: ChatMessage, dir: "in" | "out"): ReactElement {
    if (m.kind === "image" && m.attachment !== undefined) {
      return (
        <div className={`chat-bubble-${dir} media-bubble`}>
          <ImageBubble attachment={m.attachment} />
        </div>
      );
    }
    if (m.kind === "file" && m.attachment !== undefined) {
      return (
        <div className={`chat-bubble-${dir} media-bubble`}>
          <FileBubble attachment={m.attachment} />
        </div>
      );
    }
    return <div className={`chat-bubble-${dir}`}>{m.text}</div>;
  }

  return (
    <section className="chat-panel">
      <header className="chat-head">
        <button className="chat-back" onClick={onBack} aria-label="返回会话列表">
          ←
        </button>
        <div className="chat-peer">
          <span className="chat-peer-name">
            {isGroupChat ? `👥 ${group?.name ?? "群聊"}` : (contact?.name ?? shortDid(did ?? ""))}
          </span>
          <span className="chat-peer-did">
            {isGroupChat ? `${group?.memberCount ?? 0} 位成员 · 端到端群加密` : shortDid(did ?? "")}
          </span>
        </div>
        <span className="chat-e2ee">🔒 端到端加密</span>
      </header>

      <div className="msg-list" ref={listRef}>
        {(list ?? []).map((m) => {
          if (m.kind === "handshake") {
            return (
              <div key={m.id} className="msg-system">
                {m.text}
              </div>
            );
          }
          const dir = m.direction === "in" ? "in" : "out";
          const senderName =
            isGroupChat && m.direction === "in" && m.senderDid !== undefined
              ? (state.contacts.find((c) => c.did === m.senderDid)?.name ?? `${m.senderDid.slice(0, 10)}…`)
              : null;
          return (
            <div key={m.id} className={`msg-row msg-${dir}`}>
              {senderName !== null && <span className="msg-sender">{senderName}</span>}
              {renderBody(m, dir)}
              <span className="msg-meta">
                <span className="msg-time">{formatClock(m.at)}</span>
                {m.direction === "out" && <ReceiptBadge status={m.status} />}
              </span>
            </div>
          );
        })}
      </div>

      <footer className="chat-input">
        {/* 隐藏文件选择框：选中即发送 */}
        <input
          ref={fileInputRef}
          type="file"
          className="chat-file-input"
          accept={ATTACHMENT_ACCEPT}
          onChange={(e) => void handleFileSelected(e)}
          aria-hidden="true"
          tabIndex={-1}
        />
        <button
          className="chat-attach"
          onClick={() => fileInputRef.current?.click()}
          disabled={sending}
          title="发送图片或文件"
          aria-label="发送图片或文件"
        >
          📎
        </button>
        <textarea
          ref={inputRef}
          className="chat-textarea"
          value={draft}
          rows={1}
          placeholder="输入消息，Enter 发送，Shift+Enter 换行"
          disabled={sending}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
        />
        <button
          className="btn-primary chat-send"
          onClick={() => void handleSend()}
          disabled={sending || draft.trim() === ""}
        >
          {sending ? "发送中…" : "发送"}
        </button>
      </footer>
    </section>
  );
}
