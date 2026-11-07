/**
 * 安全引导横幅（加固批次 ①）：未设置访问口令时常驻提醒（UX 显著、可关闭单次）。
 */
import { useState } from "react";

import { useAppState } from "../lib/app";

export default function SecurityBanner({ onSetup }: { onSetup: () => void }) {
  const state = useAppState();
  const [dismissed, setDismissed] = useState(false);
  if (state.vaultConfigured || dismissed || state.phase !== "main") return null;

  return (
    <div className="recovery-banner" role="alert">
      <span className="recovery-banner-icon" aria-hidden="true">
        🔐
      </span>
      <div className="recovery-banner-body">
        <p className="recovery-banner-text">
          本机私钥目前<b>未加密存储</b>——设置访问口令以保护身份（他人使用此浏览器将无法冒用你的账号）。
        </p>
        <div className="recovery-banner-actions">
          <button className="btn-primary" onClick={onSetup}>
            设置口令
          </button>
          <button className="btn-ghost" onClick={() => setDismissed(true)}>
            稍后
          </button>
        </div>
      </div>
    </div>
  );
}
