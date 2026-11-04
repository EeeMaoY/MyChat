/**
 * 好友申请横幅（M3 修复 FR-8.1：申请 → 通过/拒绝）。
 * 数据随全局状态同步（handleHandshake 入队即 emit），通过后自动成为联系人。
 */
import { useState } from "react";

import { acceptFriendRequest, openChat, rejectFriendRequest, setNotice, useAppState } from "../lib/app";

import { shortDid } from "./format";

export default function FriendRequestBanner() {
  const state = useAppState();
  const [busyFrom, setBusyFrom] = useState<string | null>(null);

  async function handleAccept(fromDid: string): Promise<void> {
    if (busyFrom !== null) return;
    setBusyFrom(fromDid);
    try {
      await acceptFriendRequest(fromDid);
      setNotice("已通过好友申请，现在可以开始聊天");
      openChat(fromDid);
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "通过失败");
    } finally {
      setBusyFrom(null);
    }
  }

  async function handleReject(fromDid: string): Promise<void> {
    if (busyFrom !== null) return;
    setBusyFrom(fromDid);
    try {
      await rejectFriendRequest(fromDid);
      setNotice("已拒绝该好友申请（对方不会收到通知）");
    } finally {
      setBusyFrom(null);
    }
  }

  if (state.friendRequests.length === 0) return null;

  return (
    <div className="recovery-banner" role="alert">
      <span className="recovery-banner-icon" aria-hidden="true">
        👋
      </span>
      <div className="recovery-banner-body">
        {state.friendRequests.map((req) => {
          const label = req.name ?? shortDid(req.fromDid);
          return (
            <div key={req.fromDid} className="recovery-banner-row">
              <p className="recovery-banner-text">
                <b>{label}</b>（<code>{shortDid(req.fromDid)}</code>）请求添加你为好友
                {req.note !== "" ? <>：「{req.note}」</> : null}
                ——通过后你们才能互发消息。
              </p>
              <div className="recovery-banner-actions">
                <button className="btn-primary" disabled={busyFrom !== null} onClick={() => void handleAccept(req.fromDid)}>
                  {busyFrom === req.fromDid ? "处理中…" : "通过"}
                </button>
                <button className="btn-ghost" disabled={busyFrom !== null} onClick={() => void handleReject(req.fromDid)}>
                  拒绝
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
