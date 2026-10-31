/**
 * 守护者侧恢复请求横幅（FR-1.3）：每 3s 轮询待确认恢复请求与我持有的守护身份。
 * 有请求时顶部显著横幅 + 确认/拒绝（UX-2 防社工：确认前醒目警示）；新增守护身份一次性 notice。
 */
import { useEffect, useRef, useState } from "react";

import {
  confirmRecoveryRequest,
  listGuardianships,
  listRecoveryRequests,
  rejectRecoveryRequest,
  setNotice,
  useAppState,
} from "../lib/app";

import { shortDid } from "./format";

interface RecoveryRequest {
  ownerDid: string;
  fromDid: string;
}

/** sessionStorage 去重前缀：同一守护身份每浏览器会话只提示一次。 */
const GUARDIAN_NOTICE_PREFIX = "mychat.guardian-notice:";

export default function RecoveryRequestBanner() {
  const state = useAppState();
  const [requests, setRequests] = useState<RecoveryRequest[]>([]);
  /** 处理中的请求方（确认/拒绝按钮防重入）。 */
  const [busyFrom, setBusyFrom] = useState<string | null>(null);
  /** 已见过的守护身份（首次轮询为基线，不触发提示）。 */
  const seenGuardiansRef = useRef<Set<string> | null>(null);
  /** tick 内读最新联系人（避免闭包捕获初始空列表）。 */
  const contactsRef = useRef(state.contacts);
  contactsRef.current = state.contacts;

  useEffect(() => {
    let alive = true;
    async function tick(): Promise<void> {
      const [reqs, ships] = await Promise.all([listRecoveryRequests(), listGuardianships()]);
      if (!alive) return;
      setRequests(reqs);
      const seen = seenGuardiansRef.current;
      if (seen === null) {
        seenGuardiansRef.current = new Set(ships.map((s) => s.ownerDid));
        return;
      }
      for (const s of ships) {
        if (seen.has(s.ownerDid)) continue;
        seen.add(s.ownerDid);
        const key = `${GUARDIAN_NOTICE_PREFIX}${s.ownerDid}`;
        if (sessionStorage.getItem(key) !== null) continue;
        sessionStorage.setItem(key, "1");
        const label = contactsRef.current.find((c) => c.did === s.ownerDid)?.name ?? shortDid(s.ownerDid);
        setNotice(`你已成为 ${label} 的紧急联系人（守护者）：若对方请求恢复账户，你会在此收到确认请求`);
      }
    }
    void tick();
    const timer = window.setInterval(() => {
      void tick();
    }, 3000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  async function handleConfirm(req: RecoveryRequest): Promise<void> {
    if (busyFrom !== null) return;
    setBusyFrom(req.fromDid);
    const res = await confirmRecoveryRequest(req.fromDid, req.ownerDid);
    setBusyFrom(null);
    if (res.ok) {
      // lib 已回传分片并删除请求记录，本地同步移除
      setRequests((prev) => prev.filter((r) => r.fromDid !== req.fromDid));
      setNotice("已确认协助恢复：分片已回传给请求者");
    } else {
      setNotice(res.error ?? "确认失败");
    }
  }

  async function handleReject(req: RecoveryRequest): Promise<void> {
    if (busyFrom !== null) return;
    setBusyFrom(req.fromDid);
    try {
      await rejectRecoveryRequest(req.fromDid);
      setRequests((prev) => prev.filter((r) => r.fromDid !== req.fromDid));
      setNotice("已拒绝该恢复请求");
    } finally {
      setBusyFrom(null);
    }
  }

  if (requests.length === 0) return null;

  return (
    <div className="recovery-banner" role="alert">
      <span className="recovery-banner-icon" aria-hidden="true">
        ⚠️
      </span>
      <div className="recovery-banner-body">
        {requests.map((req) => {
          const label = state.contacts.find((c) => c.did === req.fromDid)?.name ?? shortDid(req.fromDid);
          return (
            <div key={req.fromDid} className="recovery-banner-row">
              <p className="recovery-banner-text">
                <b>{label}</b>（<code>{shortDid(req.fromDid)}</code>）请求恢复其账户——请确认对方确为本人，且你本人的设备未丢失。
              </p>
              <div className="recovery-banner-actions">
                <button className="btn-primary" disabled={busyFrom !== null} onClick={() => void handleConfirm(req)}>
                  确认协助
                </button>
                <button className="btn-ghost" disabled={busyFrom !== null} onClick={() => void handleReject(req)}>
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
