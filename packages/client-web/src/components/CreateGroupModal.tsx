/**
 * 建群弹窗（FR-6.1，M3-S11）：从已有联系人多选成员，创建 3–50 人私群。
 * 群密钥经各成员 1:1 加密会话分发；群成员列表对节点不可见。
 */
import { useState, type FormEvent } from "react";

import { createGroupAndInvite, setNotice, useAppState } from "../lib/app";

import { shortDid } from "./format";
import Modal from "./Modal";

interface Props {
  onClose: () => void;
}

export default function CreateGroupModal({ onClose }: Props) {
  const state = useAppState();
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function toggle(did: string): void {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(did)) next.delete(did);
      else next.add(did);
      return next;
    });
  }

  async function handleSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (pending) return;
    if (name.trim() === "") {
      setError("给群起个名字");
      return;
    }
    if (selected.size < 2) {
      setError("至少选择 2 位联系人（含你共 3 人成群）");
      return;
    }
    setPending(true);
    setError(null);
    const err = await createGroupAndInvite(name.trim(), [...selected]);
    setPending(false);
    if (err !== null) {
      setError(err);
      return;
    }
    setNotice("群已创建，邀请已通过加密会话发送");
    onClose();
  }

  return (
    <Modal title="发起群聊" onClose={onClose}>
      <form onSubmit={(e) => void handleSubmit(e)}>
        <label className="field-label" htmlFor="group-name">
          群名称
        </label>
        <input
          id="group-name"
          className="input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="例如：项目小组"
          maxLength={30}
          disabled={pending}
        />
        <label className="field-label">选择成员（{selected.size} 已选）</label>
        {state.contacts.length === 0 ? (
          <p className="field-hint">暂无联系人：请先添加好友再建群。</p>
        ) : (
          <div className="guardian-list">
            {state.contacts.map((c) => (
              <label key={c.did} className="guardian-item">
                <input type="checkbox" checked={selected.has(c.did)} onChange={() => toggle(c.did)} disabled={pending} />
                <span className="guardian-item-name">{c.name ?? shortDid(c.did)}</span>
                <span className="guardian-item-did">{shortDid(c.did)}</span>
              </label>
            ))}
          </div>
        )}
        {error !== null && <p className="field-error">{error}</p>}
        <div className="modal-actions">
          <button type="button" className="btn-ghost" onClick={onClose} disabled={pending}>
            取消
          </button>
          <button type="submit" className="btn-primary" disabled={pending || selected.size < 2 || name.trim() === ""}>
            {pending ? "创建中…" : "创建群聊"}
          </button>
        </div>
        <p className="field-hint">群密钥经各自加密会话分发；被移除的成员无法读取移除后的任何新消息。</p>
      </form>
    </Modal>
  );
}
