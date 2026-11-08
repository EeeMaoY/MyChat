/**
 * 群成员管理面板（M4-S15 后续批次，FR-6.4 UX 完整化）：
 * 成员列表 + 群主操作（移除/转让）+ 成员侧退出入口——替代 prompt 交互。
 */
import { useState } from "react";

import { removeGroupMember, setNotice, transferGroupOwnership, useAppState } from "../lib/app";

import { shortDid } from "./format";
import Modal from "./Modal";

interface Props {
  groupId: string;
  onClose: () => void;
}

export default function GroupMembersModal({ groupId, onClose }: Props) {
  const state = useAppState();
  const group = state.groups.find((g) => g.groupId === groupId);
  const [busyDid, setBusyDid] = useState<string | null>(null);

  if (group === undefined) {
    return (
      <Modal title="群成员" onClose={onClose}>
        <p className="field-hint">群不存在或已退出。</p>
      </Modal>
    );
  }

  function contactName(did: string): string {
    return state.contacts.find((c) => c.did === did)?.name ?? shortDid(did);
  }

  async function handleRemove(memberDid: string): Promise<void> {
    if (busyDid !== null) return;
    if (!window.confirm(`确定将 ${contactName(memberDid)} 移出群聊？对方将无法读取任何新消息。`)) return;
    setBusyDid(memberDid);
    const err = await removeGroupMember(groupId, memberDid);
    setBusyDid(null);
    setNotice(err ?? "已移除该成员（对方不可达新消息）");
  }

  async function handleTransfer(memberDid: string): Promise<void> {
    if (busyDid !== null) return;
    if (!window.confirm(`确定将群主转让给 ${contactName(memberDid)}？你将变为普通成员。`)) return;
    setBusyDid(memberDid);
    const err = await transferGroupOwnership(groupId, memberDid);
    setBusyDid(null);
    if (err === null) {
      setNotice("群主已转让");
      onClose();
    } else setNotice(err);
  }

  return (
    <Modal title={`群成员 · ${group.name}`} onClose={onClose}>
      <GroupMemberList
        groupId={groupId}
        busyDid={busyDid}
        onRemove={(did) => void handleRemove(did)}
        onTransfer={(did) => void handleTransfer(did)}
        contactName={contactName}
      />
      <p className="field-hint">
        移除与转让即时生效：被移除者不可达新消息（端到端断读）；转让后你变为普通成员。
      </p>
    </Modal>
  );
}

/** 成员列表（从全局消息路由读取群成员明细——由 lib/messaging 的快照提供）。 */
function GroupMemberList(props: {
  groupId: string;
  busyDid: string | null;
  onRemove: (did: string) => void;
  onTransfer: (did: string) => void;
  contactName: (did: string) => string;
}) {
  const state = useAppState();
  // 成员明细经全局状态下发（app.ts 的 groups 快照扩展 members）
  const group = state.groups.find((g) => g.groupId === props.groupId);
  const members = (group as unknown as { members?: { did: string; role: string }[] })?.members ?? [];
  const myDid = state.did;
  const amOwner = group?.amOwner === true;

  if (members.length === 0) {
    return <p className="field-hint">成员明细加载中…（需要 v0.2 群快照扩展）</p>;
  }
  return (
    <div className="guardian-list">
      {members.map((m) => (
        <div key={m.did} className="guardian-item">
          <span className="guardian-item-name">
            {props.contactName(m.did)}
            {m.role === "owner" ? " · 群主" : ""}
            {m.did === myDid ? " · 我" : ""}
          </span>
          <span className="guardian-item-did">{shortDid(m.did)}</span>
          {amOwner && m.role !== "owner" && m.did !== myDid && (
            <span className="recovery-banner-actions">
              <button className="btn-ghost" disabled={props.busyDid !== null} onClick={() => props.onTransfer(m.did)}>
                转让
              </button>
              <button className="btn-ghost" disabled={props.busyDid !== null} onClick={() => props.onRemove(m.did)}>
                移除
              </button>
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
