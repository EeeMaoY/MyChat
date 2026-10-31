/**
 * 紧急联系人恢复向导（FR-1.3，M1 计划 §2 S7；UX-2 分步降低困惑）。
 * 无身份状态下的 4 步流程：验证账户 → 添加紧急联系人 → 发送请求 → 等待分片收集。
 * lib 侧内部维护临时身份；done 后已完成导入并切到 main，向导只负责引导与展示。
 */
import { useEffect, useRef, useState, type FormEvent } from "react";

import { recoveryAddGuardian, recoveryPollCollect, recoveryRequestShares, recoveryStart } from "../lib/app";

import { NAME_RE } from "../components/format";

interface Props {
  /** 恢复成功后回调：关闭向导进入主界面（App 侧提示创建托管备份）。 */
  onFinished: () => void;
  /** recoveryStart 成功后回调：App 记录已进入恢复模式（取消时需重载页面回欢迎页）。 */
  onActivated: () => void;
  /** 用户取消恢复。 */
  onCancel: () => void;
}

const STEP_LABELS = ["验证账户", "添加联系人", "发送请求", "等待分片"] as const;

/** 成功页停留时长：让用户看清"恢复成功"与后续建议再进主界面。 */
const SUCCESS_HOLD_MS = 2000;

/** 分片收集轮询间隔。 */
const COLLECT_INTERVAL_MS = 2000;

export default function RecoveryWizard({ onFinished, onActivated, onCancel }: Props) {
  // step 5 = 恢复成功页
  const [step, setStep] = useState<1 | 2 | 3 | 4 | 5>(1);

  // 步骤 1：验证账户
  const [ownerName, setOwnerName] = useState("");
  const [startError, setStartError] = useState<string | null>(null);
  const [startPending, setStartPending] = useState(false);

  // 步骤 2：添加紧急联系人
  const [guardians, setGuardians] = useState<string[]>([]);
  const [guardianName, setGuardianName] = useState("");
  const [guardianError, setGuardianError] = useState<string | null>(null);
  const [guardianPending, setGuardianPending] = useState(false);

  // 步骤 3/4：发送请求与分片收集
  const [requestPending, setRequestPending] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [collect, setCollect] = useState<{ progress: number; needed: number }>({ progress: 0, needed: 0 });

  /** onFinished 经 ref 转发，避免 App 重渲染重置成功页定时器。 */
  const finishedRef = useRef(onFinished);
  finishedRef.current = onFinished;

  async function handleStart(e: FormEvent): Promise<void> {
    e.preventDefault();
    const trimmed = ownerName.trim();
    if (!NAME_RE.test(trimmed)) {
      setStartError("请输入要恢复的账户用户名（3-20 位字母、数字、下划线或连字符）");
      return;
    }
    setStartPending(true);
    setStartError(null);
    const res = await recoveryStart(trimmed);
    setStartPending(false);
    if (!res.ok) {
      setStartError(res.error ?? "恢复启动失败");
      return;
    }
    onActivated();
    setStep(2);
  }

  async function handleAddGuardian(e: FormEvent): Promise<void> {
    e.preventDefault();
    const trimmed = guardianName.trim();
    if (!NAME_RE.test(trimmed)) {
      setGuardianError("请输入紧急联系人的用户名");
      return;
    }
    if (guardians.includes(trimmed)) {
      setGuardianError("该联系人已在列表中");
      return;
    }
    setGuardianPending(true);
    setGuardianError(null);
    const res = await recoveryAddGuardian(trimmed);
    setGuardianPending(false);
    if (!res.ok) {
      setGuardianError(res.error ?? "添加失败");
      return;
    }
    setGuardians((prev) => [...prev, trimmed]);
    setGuardianName("");
  }

  async function handleSendRequest(): Promise<void> {
    if (requestPending) return;
    setRequestPending(true);
    setRequestError(null);
    const res = await recoveryRequestShares();
    setRequestPending(false);
    if (!res.ok) {
      setRequestError(res.error ?? "发送失败");
      return;
    }
    setCollect({ progress: 0, needed: 0 });
    setStep(4);
  }

  // 步骤 4：每 2s 轮询收集进度；done 时 lib 已完成导入并切到 main
  useEffect(() => {
    if (step !== 4) return;
    let alive = true;
    async function tick(): Promise<void> {
      const r = await recoveryPollCollect();
      if (!alive) return;
      setCollect({ progress: r.progress, needed: r.needed });
      if (r.done) setStep(5);
    }
    void tick();
    const timer = window.setInterval(() => {
      void tick();
    }, COLLECT_INTERVAL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [step]);

  // 步骤 5：短暂停留后自动进入主界面
  useEffect(() => {
    if (step !== 5) return;
    const timer = window.setTimeout(() => finishedRef.current(), SUCCESS_HOLD_MS);
    return () => window.clearTimeout(timer);
  }, [step]);

  const percent = collect.needed > 0 ? Math.min(100, Math.round((collect.progress / collect.needed) * 100)) : 0;

  return (
    <main className="page page-center wizard">
      <div className="wizard-card">
        <header className="wizard-head">
          <h1 className="wizard-title">恢复账户访问</h1>
          {step !== 5 && (
            <button className="wizard-cancel" onClick={onCancel}>
              取消恢复
            </button>
          )}
        </header>

        <ol className="wizard-steps">
          {STEP_LABELS.map((label, i) => {
            const n = i + 1;
            const cls = n === step ? " current" : n < step ? " done" : "";
            return (
              <li key={label} className={`wizard-step${cls}`} aria-current={n === step ? "step" : undefined}>
                <span className="wizard-step-dot" aria-hidden="true">
                  {n < step ? "✓" : n}
                </span>
                <span>{label}</span>
              </li>
            );
          })}
        </ol>

        {step === 1 && (
          <form onSubmit={(e) => void handleStart(e)}>
            <label className="field-label" htmlFor="recovery-owner">
              要恢复的账户用户名
            </label>
            <input
              id="recovery-owner"
              className="input"
              value={ownerName}
              onChange={(e) => setOwnerName(e.target.value)}
              placeholder="例如：alice_01"
              autoFocus
              maxLength={20}
              disabled={startPending}
            />
            <p className="field-hint">输入你之前注册的用户名，系统将核对该账户的恢复公告。</p>
            {startError !== null && <p className="field-error">{startError}</p>}
            <button className="btn-primary btn-block wizard-primary" type="submit" disabled={startPending || ownerName.trim() === ""}>
              {startPending ? "验证中…" : "下一步"}
            </button>
          </form>
        )}

        {step === 2 && (
          <div>
            <form className="inline-row" onSubmit={(e) => void handleAddGuardian(e)}>
              <input
                className="input"
                value={guardianName}
                onChange={(e) => setGuardianName(e.target.value)}
                placeholder="紧急联系人的 MyChat 用户名"
                aria-label="紧急联系人的 MyChat 用户名"
                maxLength={20}
                disabled={guardianPending}
              />
              <button className="btn-ghost" type="submit" disabled={guardianPending || guardianName.trim() === ""}>
                {guardianPending ? "添加中…" : "添加"}
              </button>
            </form>
            <p className="field-hint">
              逐个添加你的紧急联系人（需对方也在 MyChat）。至少 2 位；门限通常为 3 位，添加越多越稳妥（建议 5 位）。
            </p>
            {guardians.length > 0 && (
              <ul className="wizard-chip-list">
                {guardians.map((g) => (
                  <li key={g} className="wizard-chip">
                    {g}
                  </li>
                ))}
              </ul>
            )}
            {guardianError !== null && <p className="field-error">{guardianError}</p>}
            <div className="modal-actions">
              <button className="btn-ghost" type="button" onClick={() => setStep(1)} disabled={guardianPending}>
                上一步
              </button>
              <button className="btn-primary" type="button" onClick={() => setStep(3)} disabled={guardians.length < 2 || guardianPending}>
                下一步
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div>
            <p className="wizard-desc">
              将向以下 {guardians.length} 位紧急联系人发送恢复请求，他们会各自回传一份加密分片；
              集齐门限数量后即可在本机重建你的身份。
            </p>
            <ul className="wizard-chip-list">
              {guardians.map((g) => (
                <li key={g} className="wizard-chip">
                  {g}
                </li>
              ))}
            </ul>
            {requestError !== null && <p className="field-error">{requestError}</p>}
            <div className="modal-actions">
              <button className="btn-ghost" type="button" onClick={() => setStep(2)} disabled={requestPending}>
                上一步
              </button>
              <button className="btn-primary" type="button" onClick={() => void handleSendRequest()} disabled={requestPending}>
                {requestPending ? "发送中…" : "发送恢复请求"}
              </button>
            </div>
          </div>
        )}

        {step === 4 && (
          <div>
            <p className="wizard-desc">等待紧急联系人确认协助。请保持页面打开，对方确认后分片会自动收集。</p>
            <div
              className="recovery-progress"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={collect.needed}
              aria-valuenow={collect.progress}
            >
              <div className="recovery-progress-fill" style={{ width: `${percent}%` }} />
            </div>
            <p className="field-hint">
              已收集 {collect.progress} / {collect.needed > 0 ? collect.needed : "…"} 位联系人的分片
            </p>
            <div className="modal-actions">
              <button className="btn-ghost" type="button" onClick={() => setStep(3)}>
                返回
              </button>
            </div>
          </div>
        )}

        {step === 5 && (
          <div className="wizard-success">
            <p className="wizard-success-title">✓ 恢复成功</p>
            <p className="field-hint">身份已在本机重建，正在进入 MyChat…</p>
            <p className="field-hint">强烈建议：进入后立即在「我的」中点击「立即创建托管备份」。</p>
            <button className="btn-primary btn-block wizard-primary" type="button" onClick={() => finishedRef.current()}>
              立即进入
            </button>
          </div>
        )}
      </div>
    </main>
  );
}
