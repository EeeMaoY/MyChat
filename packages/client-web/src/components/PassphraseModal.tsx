/**
 * 口令密钥库弹窗（W1 密钥存储保护，加固批次 ①）：首次设置与修改口令。
 * 设置/修改会立即全量迁移本地敏感数据为加密形态（scrypt 派生 KEK 包裹）。
 */
import { useState, type FormEvent } from "react";

import { changeVaultPassphrase, setupVaultPassphrase } from "../lib/app";

import Modal from "./Modal";

interface Props {
  /** false = 修改模式（需旧口令） */
  initialSetup: boolean;
  onClose: () => void;
}

export default function PassphraseModal({ initialSetup, onClose }: Props) {
  const [oldPass, setOldPass] = useState("");
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (pending) return;
    if (pass.length < 8) {
      setError("口令至少 8 位（建议混合大小写、数字与符号）");
      return;
    }
    if (pass !== confirm) {
      setError("两次输入的口令不一致");
      return;
    }
    setPending(true);
    setError(null);
    const err = initialSetup ? await setupVaultPassphrase(pass) : await changeVaultPassphrase(oldPass, pass);
    setPending(false);
    if (err !== null) {
      setError(err);
      return;
    }
    onClose();
  }

  return (
    <Modal title={initialSetup ? "设置访问口令" : "修改访问口令"} onClose={onClose}>
      <form onSubmit={(e) => void handleSubmit(e)}>
        {!initialSetup && (
          <>
            <label className="field-label" htmlFor="vault-old">
              当前口令
            </label>
            <input id="vault-old" className="input" type="password" value={oldPass} onChange={(e) => setOldPass(e.target.value)} disabled={pending} />
          </>
        )}
        <label className="field-label" htmlFor="vault-new">
          {initialSetup ? "设置口令（至少 8 位）" : "新口令"}
        </label>
        <input id="vault-new" className="input" type="password" value={pass} onChange={(e) => setPass(e.target.value)} disabled={pending} />
        <label className="field-label" htmlFor="vault-confirm">
          确认新口令
        </label>
        <input id="vault-confirm" className="input" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} disabled={pending} />
        {error !== null && <p className="field-error">{error}</p>}
        <div className="modal-actions">
          <button type="button" className="btn-ghost" onClick={onClose} disabled={pending}>
            取消
          </button>
          <button type="submit" className="btn-primary" disabled={pending || pass === "" || confirm !== pass}>
            {pending ? "处理中…（首次加密约需数秒）" : initialSetup ? "设置并加密本地数据" : "修改口令"}
          </button>
        </div>
        <p className="field-hint warn-hint">
          口令用于加密本机的私钥材料（scrypt 派生，不外发）。<b>忘记口令将无法解密本地数据</b>——
          请务必备份导出并牢记口令。
        </p>
      </form>
    </Modal>
  );
}
