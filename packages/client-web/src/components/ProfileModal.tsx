/** "我"弹窗：用户名/DID 管理、已读回执开关、数据与边界诚实披露（UX-6/UX-7）、节点连接设置。 */
import { useEffect, useState, type ChangeEvent, type FormEvent } from "react";

import { getReadReceiptsEnabled, setNotice, setReadReceiptsEnabled, submitUsername, useAppState } from "../lib/app";

import { NAME_RE } from "./format";
import Modal from "./Modal";

interface Props {
  onClose: () => void;
}

const NODE_URL_KEY = "mychat.node-url";

export default function ProfileModal({ onClose }: Props) {
  const state = useAppState();
  const did = state.did;

  const [name, setName] = useState("");
  const [nameError, setNameError] = useState<string | null>(null);
  const [namePending, setNamePending] = useState(false);

  const [nodeUrl, setNodeUrl] = useState<string>(() => localStorage.getItem(NODE_URL_KEY) ?? "");
  const [didCopied, setDidCopied] = useState(false);

  /** 已读回执开关初始值（异步读取，null=加载中）。 */
  const [readReceipts, setReadReceipts] = useState<boolean | null>(null);

  useEffect(() => {
    let alive = true;
    void getReadReceiptsEnabled().then((enabled) => {
      if (alive) setReadReceipts(enabled);
    });
    return () => {
      alive = false;
    };
  }, []);

  /** 切换已读回执：UI 先行，写库失败则回滚。 */
  async function handleToggleReadReceipts(e: ChangeEvent<HTMLInputElement>): Promise<void> {
    const prev = readReceipts === true;
    const next = e.target.checked;
    setReadReceipts(next);
    try {
      await setReadReceiptsEnabled(next);
    } catch {
      setReadReceipts(prev);
      setNotice("设置保存失败");
    }
  }

  async function handleSetName(e: FormEvent): Promise<void> {
    e.preventDefault();
    const trimmed = name.trim();
    if (!NAME_RE.test(trimmed)) {
      setNameError("用户名需为 3-20 位字母、数字、下划线或连字符");
      return;
    }
    setNamePending(true);
    setNameError(null);
    const err = await submitUsername(trimmed);
    setNamePending(false);
    if (err !== null) {
      setNameError(err);
      return;
    }
    setName("");
    setNotice("用户名已设置");
  }

  async function copyDid(): Promise<void> {
    if (did === null || navigator.clipboard === undefined) {
      setNotice("复制失败，请手动复制");
      return;
    }
    try {
      await navigator.clipboard.writeText(did);
      setDidCopied(true);
      window.setTimeout(() => setDidCopied(false), 1500);
    } catch {
      setNotice("复制失败，请手动复制");
    }
  }

  function handleSaveNode(e: FormEvent): void {
    e.preventDefault();
    const url = nodeUrl.trim();
    if (url === "") localStorage.removeItem(NODE_URL_KEY);
    else localStorage.setItem(NODE_URL_KEY, url);
    setNotice("节点地址已保存，刷新页面后生效");
  }

  return (
    <Modal title="我" onClose={onClose}>
      {/* 用户名 */}
      {state.myName !== null ? (
        <p className="profile-name">
          <span className="online-dot on" aria-hidden="true" />
          <b>{state.myName}</b>
          <span className="profile-name-tag">已注册</span>
        </p>
      ) : (
        <form onSubmit={(e) => void handleSetName(e)}>
          <label className="field-label" htmlFor="profile-name">
            设置用户名
          </label>
          <div className="inline-row">
            <input
              id="profile-name"
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="3-20 位字母、数字、下划线或连字符"
              maxLength={20}
              disabled={namePending}
            />
            <button className="btn-primary" type="submit" disabled={namePending || name.trim() === ""}>
              {namePending ? "保存中…" : "保存"}
            </button>
          </div>
          {nameError !== null && <p className="field-error">{nameError}</p>}
        </form>
      )}

      {/* DID */}
      <label className="field-label">我的 DID</label>
      <div className="inline-row">
        <code className="did-value" title={did ?? ""}>
          {did ?? "—"}
        </code>
        <button className="btn-ghost" onClick={() => void copyDid()} disabled={did === null}>
          {didCopied ? "已复制" : "复制"}
        </button>
      </div>

      {/* 已读回执隐私开关（FR-5.2），立即生效 */}
      <label className="setting-row">
        <input
          type="checkbox"
          checked={readReceipts === true}
          disabled={readReceipts === null}
          onChange={(e) => void handleToggleReadReceipts(e)}
        />
        已读回执（对方能看到你是否已读）
      </label>

      {/* 能力边界诚实披露（UX-7） */}
      <details className="disclosure">
        <summary>数据与边界</summary>
        <ul className="boundary-list">
          <li>
            私钥只保存在本浏览器的 IndexedDB 中；清除浏览器数据会导致身份丢失且无法找回（社交恢复功能将在后续版本提供）。
          </li>
          <li>消息只存在你的设备与对方的设备上，服务节点只能看到加密后的密文。</li>
          <li>开发预览版：当前节点为单点部署；删除与匿名的完整能力边界见项目文档。</li>
        </ul>
      </details>

      {/* 连接设置 */}
      <form className="node-form" onSubmit={handleSaveNode}>
        <label className="field-label" htmlFor="node-url">
          节点地址
        </label>
        <div className="inline-row">
          <input
            id="node-url"
            className="input"
            value={nodeUrl}
            onChange={(e) => setNodeUrl(e.target.value)}
            placeholder="http://127.0.0.1:8629"
          />
          <button className="btn-ghost" type="submit">
            保存
          </button>
        </div>
        <p className="field-hint">留空恢复默认节点；修改后需刷新页面生效。</p>
      </form>
    </Modal>
  );
}
