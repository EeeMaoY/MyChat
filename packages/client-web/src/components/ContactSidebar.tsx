/** 会话列表侧栏：我的状态、联系人列表、加好友与"我"入口。 */
import { openChat, useAppState } from "../lib/app";
import type { ChatMessage } from "../lib/messaging";

import { formatListTime, shortDid, truncate } from "./format";

interface Props {
  onAddFriend: () => void;
  onOpenProfile: () => void;
}

/** 取某会话最后一条消息（noUncheckedIndexedAccess 下需判空）。 */
function lastMessage(messages: Record<string, ChatMessage[]>, did: string): ChatMessage | undefined {
  const list = messages[did];
  if (list === undefined || list.length === 0) return undefined;
  return list[list.length - 1];
}

export default function ContactSidebar({ onAddFriend, onOpenProfile }: Props) {
  const state = useAppState();

  return (
    <aside className="sidebar">
      <header className="sidebar-head">
        <span className="app-logo">MyChat</span>
        <button className="me-entry" onClick={onOpenProfile} title="我的身份与数据">
          <span className={`online-dot ${state.online ? "on" : "off"}`} aria-hidden="true" />
          <span className="me-name">{state.myName ?? "未命名"}</span>
        </button>
      </header>

      <nav className="contact-list">
        {state.contacts.length === 0 && (
          <p className="contact-empty">
            还没有联系人。
            <br />
            点击下方"➕ 加好友"，用对方用户名发起加密会话。
          </p>
        )}
        {state.contacts.map((c) => {
          const last = lastMessage(state.messages, c.did);
          const active = state.activeDid === c.did;
          return (
            <button
              key={c.did}
              className={`contact-item${active ? " active" : ""}`}
              onClick={() => openChat(c.did)}
            >
              <span className="contact-row">
                <span className="contact-name">{c.name ?? shortDid(c.did)}</span>
                <span className="contact-time">{last !== undefined ? formatListTime(last.at) : ""}</span>
              </span>
              <span className="contact-preview">
                {last !== undefined ? truncate(last.text, 30) : "（暂无消息）"}
              </span>
            </button>
          );
        })}
      </nav>

      <footer className="sidebar-foot">
        <button className="btn-primary btn-block" onClick={onAddFriend}>
          ➕ 加好友
        </button>
      </footer>
    </aside>
  );
}
