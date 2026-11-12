/** 加好友弹窗：对方用户名 + 附言（选填）。错误内联；成功后用返回的 did 打开该会话。 */
import { useState, type FormEvent } from "react";

import { addFriend, openChat } from "../lib/app";

import Modal from "./Modal";

interface Props {
  onClose: () => void;
}

const NOTE_PLACEHOLDER = "希望与你建立端到端加密聊天";

export default function AddFriendModal({ onClose }: Props) {
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function handleSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    const trimmed = name.trim();
    if (trimmed === "") {
      setError("请输入对方用户名");
      return;
    }
    setPending(true);
    setError(null);
    const res = await addFriend(trimmed, note.trim());
    setPending(false);
    if (res.error !== null) {
      setError(res.error);
      return;
    }
    // 用返回的新联系人 did 直接打开会话（旧实现按名字在 await 前的陈旧快照里 find，必 undefined 不跳转）
    if (res.did !== null) openChat(res.did);
    onClose();
  }

  return (
    <Modal title="➕ 加好友" onClose={onClose}>
      <form onSubmit={(e) => void handleSubmit(e)}>
        <label className="field-label" htmlFor="friend-name">
          对方用户名
        </label>
        <input
          id="friend-name"
          className="input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="对方的 MyChat 用户名"
          autoFocus
          disabled={pending}
        />
        <label className="field-label" htmlFor="friend-note">
          附言（选填）
        </label>
        <input
          id="friend-note"
          className="input"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder={NOTE_PLACEHOLDER}
          maxLength={100}
          disabled={pending}
        />
        <p className="field-hint">好友请求经加密握手送达，对方通过后即可开始聊天。</p>
        {error !== null && <p className="field-error">{error}</p>}
        <div className="modal-actions">
          <button className="btn-ghost" type="button" onClick={onClose} disabled={pending}>
            取消
          </button>
          <button className="btn-primary" type="submit" disabled={pending || name.trim() === ""}>
            {pending ? "发送请求中…" : "发送好友请求"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
