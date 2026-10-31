/** 起名页：注册用户名（可跳过，稍后在"我"里设置）。错误内联显示。 */
import { useState, type FormEvent } from "react";

import { skipUsername, submitUsername } from "../lib/app";
import { NAME_RE } from "../components/format";

export default function SetNamePage() {
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function handleSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    const trimmed = name.trim();
    if (!NAME_RE.test(trimmed)) {
      setError("用户名需为 3-20 位字母、数字、下划线或连字符");
      return;
    }
    setPending(true);
    setError(null);
    const err = await submitUsername(trimmed);
    setPending(false);
    if (err !== null) setError(err);
  }

  return (
    <main className="page page-center setname">
      <form className="setname-card" onSubmit={(e) => void handleSubmit(e)}>
        <h1 className="setname-title">起个名字</h1>
        <p className="setname-sub">这是你在 MyChat 上的唯一标识，好友将通过它找到你。</p>
        <input
          className="input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="例如：alice_01"
          autoFocus
          maxLength={20}
          disabled={pending}
        />
        <p className="field-hint">3-20 位字母、数字、下划线或连字符</p>
        {error !== null && <p className="field-error">{error}</p>}
        <button className="btn-primary btn-block" type="submit" disabled={pending || name.trim() === ""}>
          {pending ? "注册中…" : "注册并进入"}
        </button>
        <button className="skip-link" type="button" onClick={skipUsername} disabled={pending}>
          稍后再说
        </button>
      </form>
    </main>
  );
}
