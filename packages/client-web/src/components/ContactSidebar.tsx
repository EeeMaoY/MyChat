/** 会话列表侧栏：我的状态、联系人/群组列表、加好友/建群与"我"入口。 */
import { openChat, useAppState } from "../lib/app";
import type { ChatMessage } from "../lib/messaging";

import { formatListTime, shortDid, truncate } from "./format";

interface Props {
  onAddFriend: () => void;
  onOpenProfile: () => void;
  onCreateGroup: () => void;
  onOpenTimeline: () => void;
}

/** 取某会话最后一条消息（noUncheckedIndexedAccess 下需判空）。 */
function lastMessage(messages: Record<string, ChatMessage[]>, did: string): ChatMessage | undefined {
  const list = messages[did];
  if (list === undefined || list.length === 0) return undefined;
  return list[list.length - 1];
}

export default function ContactSidebar({ onAddFriend, onOpenProfile, onCreateGroup, onOpenTimeline }: Props) {
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
        <button
          className={`contact-item${state.view === "timeline" ? " active" : ""}`}
          onClick={onOpenTimeline}
        >
          <span className="contact-row">
            <span className="contact-name">📱 动态</span>
            <span className="contact-time">{state.moments.length > 0 ? `${state.moments.length}` : ""}</span>
          </span>
          <span className="contact-preview">好友圈时间线（端到端加密）</span>
        </button>
        {/* 群组（M3-S11）：键 group:<groupId>，与联系人统一会话路由 */}
        {state.groups.map((g) => {
          const chatKey = `group:${g.groupId}`;
          const last = lastMessage(state.messages, chatKey);
          const active = state.activeDid === chatKey;
          return (
            <button key={chatKey} className={`contact-item${active ? " active" : ""}`} onClick={() => openChat(chatKey)}>
              <span className="contact-row">
                <span className="contact-name">👥 {g.name}</span>
                <span className="contact-time">{last !== undefined ? formatListTime(last.at) : ""}</span>
              </span>
              <span className="contact-preview">
                {last !== undefined ? truncate(last.text, 30) : `（${g.memberCount} 位成员）`}
              </span>
            </button>
          );
        })}
        {state.contacts.length === 0 && state.groups.length === 0 && (
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
        <div className="sidebar-foot-row">
          <button className="btn-primary btn-block" onClick={onAddFriend}>
            ➕ 加好友
          </button>
          <button className="btn-ghost btn-block" onClick={onCreateGroup} disabled={state.contacts.length < 2}>
            👥 建群
          </button>
        </div>
      </footer>
    </aside>
  );
}
