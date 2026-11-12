/**
 * 锁屏（W1 密钥存储保护，加固批次 ①）：口令解锁本地密钥库。
 * 忘记口令本地数据无法解密；唯一出路是欢迎页的社交恢复向导（需先前设置过紧急联系人）。
 */
import { useState, type FormEvent } from "react";

import { unlockApp } from "../lib/app";

export default function LockedPage() {
  const [passphrase, setPassphrase] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleUnlock(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (pending || passphrase === "") return;
    setPending(true);
    setError(null);
    const ok = await unlockApp(passphrase);
    setPending(false);
    if (!ok) setError("口令不正确，请重试");
  }

  return (
    <main className="page page-center">
      <form className="locked-card" onSubmit={(e) => void handleUnlock(e)}>
        <h1 className="locked-title">🔒 MyChat 已锁定</h1>
        <p className="field-hint">输入访问口令解锁本地加密数据。私钥始终只在本机，口令不外发。</p>
        <input
          className="input"
          type="password"
          value={passphrase}
          autoFocus
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="访问口令"
          disabled={pending}
        />
        {error !== null && <p className="field-error">{error}</p>}
        <button className="btn-primary btn-block" type="submit" disabled={pending || passphrase === ""}>
          {pending ? "解锁中…" : "解锁"}
        </button>
        <p className="field-hint warn-hint">
          忘记口令？本地数据无法解密。若已设置紧急联系人，可在欢迎页通过「已丢失访问权限？用紧急联系人恢复」使用社交恢复向导重建身份；否则本地数据无法解密。
        </p>
      </form>
    </main>
  );
}
