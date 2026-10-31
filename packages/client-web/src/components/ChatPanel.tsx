/** 聊天面板：会话头部、消息列表（气泡/系统条）、自适应输入区。 */
import { useEffect, useLayoutEffect, useRef, useState, type ChangeEvent, type KeyboardEvent } from "react";

import { openChat, sendMessage, setNotice, useAppState } from "../lib/app";

import { formatClock, shortDid } from "./format";

interface Props {
  /** 窄屏返回会话列表。 */
  onBack: () => void;
  /** 空态引导里的加好友入口。 */
  onAddFriend: () => void;
}

/** 输入框自适应高度上限（与 CSS max-height 一致）。 */
const TEXTAREA_MAX_PX = 160;

export default function ChatPanel({ onBack, onAddFriend }: Props) {
  const state = useAppState();
  const did = state.activeDid;

  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const listRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  const list = did !== null ? state.messages[did] : undefined;
  const contact = did !== null ? state.contacts.find((c) => c.did === did) : undefined;

  function scrollToBottom(): void {
    const el = listRef.current;
    if (el !== null) el.scrollTop = el.scrollHeight;
  }

  // 切换会话：清空草稿、复位输入框高度、滚到底部
  useEffect(() => {
    setDraft("");
    setSending(false);
    if (inputRef.current !== null) inputRef.current.style.height = "auto";
    scrollToBottom();
  }, [did]);

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

  return (
    <section className="chat-panel">
      <header className="chat-head">
        <button className="chat-back" onClick={onBack} aria-label="返回会话列表">
          ←
        </button>
        <div className="chat-peer">
          <span className="chat-peer-name">{contact?.name ?? shortDid(did)}</span>
          <span className="chat-peer-did">{shortDid(did)}</span>
        </div>
        <span className="chat-e2ee">🔒 端到端加密</span>
      </header>

      <div className="msg-list" ref={listRef}>
        {(list ?? []).map((m) =>
          m.kind === "handshake" ? (
            <div key={m.id} className="msg-system">
              {m.text}
            </div>
          ) : (
            <div key={m.id} className={`msg-row ${m.direction === "in" ? "msg-in" : "msg-out"}`}>
              <div className={`chat-bubble-${m.direction === "in" ? "in" : "out"}`}>{m.text}</div>
              <span className="msg-time">{formatClock(m.at)}</span>
            </div>
          ),
        )}
      </div>

      <footer className="chat-input">
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
