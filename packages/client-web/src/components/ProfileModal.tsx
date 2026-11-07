/**
 * "我"弹窗：用户名/DID 管理、已读回执开关、数据安全（导出/导入/托管备份，FR-7.2/7.3）、
 * 紧急联系人（社交恢复，FR-1.3）、数据与边界诚实披露（UX-6/UX-7）、节点连接设置。
 */
import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from "react";

import {
  createCustodyBackup,
  exportAllData,
  getMyDevice,
  getReadReceiptsEnabled,
  getRecoverySelf,
  importAllData,
  listCustodyCopies,
  listMyDevices,
  resetMomentCircle,
  revokeMyDevice,
  setNotice,
  setReadReceiptsEnabled,
  setupGuardians,
  submitUsername,
  useAppState,
  rehearseRecovery,
} from "../lib/app";

import { NAME_RE, shortDid } from "./format";
import Modal from "./Modal";

interface Props {
  onClose: () => void;
}

const NODE_URL_KEY = "mychat.node-url";

/** 恢复门限固定 3（FR-1.3 默认 3-of-5；展示随已选人数收敛）。 */
const GUARDIAN_THRESHOLD = 3;

/** 已设置的社交恢复信息（getRecoverySelf 返回）。 */
interface RecoverySelfInfo {
  wrapCid: string;
  threshold: number;
  guardians: string[];
}

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

  // —— 数据安全（各操作独立防重入）——
  const [exportPending, setExportPending] = useState(false);
  const [importPending, setImportPending] = useState(false);
  const [custodyPending, setCustodyPending] = useState(false);
  /** 我为他人保管的托管副本数（null=加载中）。 */
  const [custodyCount, setCustodyCount] = useState<number | null>(null);
  const importInputRef = useRef<HTMLInputElement | null>(null);

  // —— 紧急联系人 ——
  const [recoverySelf, setRecoverySelf] = useState<RecoverySelfInfo | null>(null);
  const [selfLoaded, setSelfLoaded] = useState(false);
  /** 恢复演练进行中与结果。 */
  const [rehearsePending, setRehearsePending] = useState(false);
  const [rehearseResult, setRehearseResult] = useState<{ ok: boolean; checks: { name: string; ok: boolean; detail: string }[] } | null>(null);
  /** 重新设置模式（选择列表覆盖已设置状态）。 */
  const [editingGuardians, setEditingGuardians] = useState(false);
  const [selectedDids, setSelectedDids] = useState<ReadonlySet<string>>(new Set());
  const [guardiansPending, setGuardiansPending] = useState(false);
  const [guardiansError, setGuardiansError] = useState<string | null>(null);

  // —— 设备管理（M2-S10 FR-1.4）——
  interface DeviceRow {
    dkId: string;
    label: string;
    issuedAt: number;
    expiresAt: number;
    revoked: boolean;
    expired: boolean;
  }
  const [myDevice, setMyDevice] = useState<{ dkId: string; label: string; expiresAt: number } | null>(null);
  const [devices, setDevices] = useState<DeviceRow[] | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);
  const [revokePending, setRevokePending] = useState(false);
  const [circleResetPending, setCircleResetPending] = useState(false);

  useEffect(() => {
    let alive = true;
    void getReadReceiptsEnabled().then((enabled) => {
      if (alive) setReadReceipts(enabled);
    });
    void listCustodyCopies().then((copies) => {
      if (alive) setCustodyCount(copies.length);
    });
    void getRecoverySelf().then((self) => {
      if (alive) {
        setRecoverySelf(self);
        setSelfLoaded(true);
      }
    });
    setMyDevice(getMyDevice());
    void listMyDevices().then((rows) => {
      if (alive) {
        setDevices(
          rows.map((d) => ({
            dkId: d.certificate.dkId,
            label: d.certificate.label,
            issuedAt: d.certificate.issuedAt,
            expiresAt: d.certificate.expiresAt,
            revoked: d.revoked,
            expired: d.expired,
          })),
        );
      }
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

  // —— 数据安全 ——

  /** 导出全部数据：明文 JSON 备份包，触发浏览器下载（UX-7 提示保管责任）。 */
  async function handleExport(): Promise<void> {
    if (exportPending) return;
    setExportPending(true);
    try {
      const json = await exportAllData();
      const date = new Date().toISOString().slice(0, 10);
      const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `mychat-backup-${date}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice("备份已导出，请妥善保管");
    } catch (err) {
      setNotice(err instanceof Error ? `导出失败：${err.message}` : "导出失败");
    } finally {
      setExportPending(false);
    }
  }

  /** 从备份文件导入：成功后 lib 已切回 main，关闭弹窗即可见恢复后的数据。 */
  async function handleImportFile(e: ChangeEvent<HTMLInputElement>): Promise<void> {
    const input = e.target;
    const file = input.files?.[0];
    input.value = ""; // 复位，允许重复选择同一文件
    if (file === undefined || importPending) return;
    setImportPending(true);
    try {
      const text = await file.text();
      const ok = await importAllData(text);
      if (ok) {
        setNotice("已从备份导入全部数据");
        onClose();
      } else {
        setNotice("导入失败：备份文件无效");
      }
    } catch (err) {
      setNotice(err instanceof Error ? `导入失败：${err.message}` : "导入失败：备份文件无效");
    } finally {
      setImportPending(false);
    }
  }

  /** 托管备份：把加密备份发给前 2 位联系人保管（对方不可读）。 */
  async function handleCustody(): Promise<void> {
    if (custodyPending) return;
    setCustodyPending(true);
    try {
      const { hosts } = await createCustodyBackup();
      setNotice(`托管副本已发送给 ${hosts.length} 位联系人`);
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "托管备份创建失败");
    } finally {
      setCustodyPending(false);
    }
  }

  // —— 紧急联系人 ——

  function toggleGuardian(contactDid: string): void {
    setSelectedDids((prev) => {
      const next = new Set(prev);
      if (next.has(contactDid)) next.delete(contactDid);
      else next.add(contactDid);
      return next;
    });
  }

  /** 提交守护者设置：分片经会话分发给所选联系人。 */
  async function handleSetupGuardians(): Promise<void> {
    if (guardiansPending) return;
    const dids = [...selectedDids];
    if (dids.length < 2) {
      setGuardiansError("至少选择 2 位紧急联系人");
      return;
    }
    setGuardiansPending(true);
    setGuardiansError(null);
    const res = await setupGuardians(dids, Math.min(GUARDIAN_THRESHOLD, dids.length));
    setGuardiansPending(false);
    if (!res.ok) {
      setGuardiansError(res.error ?? "设置失败");
      return;
    }
    const self = await getRecoverySelf();
    setRecoverySelf(self);
    setEditingGuardians(false);
    setSelectedDids(new Set());
    const effectiveThreshold = Math.min(GUARDIAN_THRESHOLD, dids.length);
    setNotice(`紧急联系人已设置：${dids.length} 位守护者，任意 ${effectiveThreshold} 位可帮你找回账号`);
  }

  /** 联系人展示名（无名字时退回短 DID）。 */
  function contactLabel(targetDid: string): string {
    return state.contacts.find((c) => c.did === targetDid)?.name ?? shortDid(targetDid);
  }

  // —— 设备管理 ——

  /** 吊销一台设备（两段确认：revokeTarget 记录待吊销目标，再次点击执行）。 */
  async function handleRevoke(dkId: string): Promise<void> {
    if (revokePending) return;
    if (revokeTarget !== dkId) {
      setRevokeTarget(dkId);
      return;
    }
    setRevokePending(true);
    try {
      await revokeMyDevice(dkId);
      setDevices((prev) => prev?.map((d) => (d.dkId === dkId ? { ...d, revoked: true } : d)) ?? null);
      setNotice(dkId === myDevice?.dkId ? "本设备已被吊销：请导出备份后停止使用此浏览器收发消息" : "设备已吊销，对方将自动轮换会话");
    } catch (err) {
      setNotice(err instanceof Error ? `吊销失败：${err.message}` : "吊销失败");
    } finally {
      setRevokePending(false);
      setRevokeTarget(null);
    }
  }

  function deviceStatus(d: DeviceRow): { text: string; cls: string } {
    if (d.revoked) return { text: "已吊销", cls: "off" };
    if (d.expired) return { text: "已过期", cls: "off" };
    return { text: "活跃", cls: "on" };
  }

  const showGuardianSetup = !selfLoaded || recoverySelf === null || editingGuardians;

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

      {/* 设备管理（M2-S10 FR-1.4） */}
      <label className="field-label">设备管理</label>
      {myDevice !== null && (
        <p className="field-hint">
          本设备：<b>{myDevice.label}</b>（{shortDid(myDevice.dkId)}），凭证有效期至{" "}
          {new Date(myDevice.expiresAt).toLocaleDateString()}，到期自动续签。
        </p>
      )}
      {devices === null ? (
        <p className="field-hint">设备列表加载中…</p>
      ) : devices.length === 0 ? (
        <p className="field-hint">暂无已登记设备（首次发送消息后会自动登记）。</p>
      ) : (
        <div className="guardian-list">
          {devices.map((d) => {
            const status = deviceStatus(d);
            const isSelf = d.dkId === myDevice?.dkId;
            return (
              <div key={d.dkId} className="guardian-item">
                <span className={`online-dot ${status.cls}`} aria-hidden="true" />
                <span className="guardian-item-name">{d.label}</span>
                <span className="guardian-item-did">{shortDid(d.dkId)}{isSelf ? " · 本设备" : ""}</span>
                {!d.revoked && !d.expired && (
                  <button
                    className="btn-ghost"
                    disabled={revokePending}
                    onClick={() => void handleRevoke(d.dkId)}
                  >
                    {revokeTarget === d.dkId ? (revokePending ? "吊销中…" : "确认吊销？") : "吊销"}
                  </button>
                )}
                {(d.revoked || d.expired) && <span className="custody-meta">{status.text}</span>}
              </div>
            );
          })}
        </div>
      )}
      <p className="field-hint">
        吊销后该设备的预密钥材料立即停发，联系人会自动重建会话；被吊销设备需从备份重新导入才能恢复使用。
      </p>

      {/* 好友圈安全（加固批次 ③） */}
      <label className="field-label">好友圈安全</label>
      <div className="inline-row data-row">
        <button
          className="btn-ghost"
          disabled={circleResetPending}
          onClick={async () => {
            if (circleResetPending) return;
            if (!window.confirm("重置将换发全新好友圈密钥：新动态不再可用旧密钥解密（适用于怀疑密钥泄露）。好友将自动收到新密钥。确认重置？")) return;
            setCircleResetPending(true);
            try {
              await resetMomentCircle();
              setNotice("好友圈密钥已重置并通知全部联系人");
            } catch (err) {
              setNotice(err instanceof Error ? err.message : "重置失败");
            } finally {
              setCircleResetPending(false);
            }
          }}
        >
          {circleResetPending ? "重置中…" : "重置好友圈密钥"}
        </button>
      </div>
      <p className="field-hint">
        怀疑好友圈密钥泄露（如共用设备被他人使用）时重置：新动态只有持有新密钥的好友可读；已缓存的旧动态不受影响。
      </p>

      {/* 数据安全：导出/导入（FR-7.2）与好友托管备份（FR-7.3） */}
      <label className="field-label">数据安全</label>
      <div className="inline-row data-row">
        <button className="btn-ghost" onClick={() => void handleExport()} disabled={exportPending}>
          {exportPending ? "导出中…" : "导出全部数据"}
        </button>
        <button className="btn-ghost" onClick={() => importInputRef.current?.click()} disabled={importPending}>
          {importPending ? "导入中…" : "从备份文件导入"}
        </button>
        <input
          ref={importInputRef}
          type="file"
          accept=".json,application/json"
          className="hidden-file-input"
          tabIndex={-1}
          onChange={(e) => void handleImportFile(e)}
        />
      </div>
      <p className="field-hint warn-hint">备份文件为明文，请妥善保管。</p>
      <div className="inline-row data-row">
        <button className="btn-ghost" onClick={() => void handleCustody()} disabled={custodyPending}>
          {custodyPending ? "发送中…" : "立即创建托管备份"}
        </button>
        <span className="custody-meta">
          {custodyCount !== null ? `你为 ${custodyCount} 位联系人保管副本` : ""}
        </span>
      </div>
      <p className="field-hint">托管副本会把加密备份发给前 2 位联系人保管，对方无法读取内容。</p>

      {/* 紧急联系人（社交恢复，FR-1.3） */}
      <label className="field-label">紧急联系人（社交恢复）</label>
      {showGuardianSetup ? (
        <div className="guardian-setup">
          <p className="field-hint">
            选择 ≥2 位联系人，其中任意 {GUARDIAN_THRESHOLD} 位可帮你找回账号（建议 5 位）。
          </p>
          {state.contacts.length === 0 ? (
            <p className="field-hint">暂无联系人：请先添加好友，再从中选择紧急联系人。</p>
          ) : (
            <div className="guardian-list">
              {state.contacts.map((c) => (
                <label key={c.did} className="guardian-item">
                  <input
                    type="checkbox"
                    checked={selectedDids.has(c.did)}
                    onChange={() => toggleGuardian(c.did)}
                    disabled={guardiansPending}
                  />
                  <span className="guardian-item-name">{c.name ?? shortDid(c.did)}</span>
                  <span className="guardian-item-did">{shortDid(c.did)}</span>
                </label>
              ))}
            </div>
          )}
          <p className="field-hint">
            {selectedDids.size === 0
              ? `门限 ${GUARDIAN_THRESHOLD}：任意 ${GUARDIAN_THRESHOLD} 位守护者确认即可找回`
              : `已选 ${selectedDids.size} 位，任意 ${Math.min(GUARDIAN_THRESHOLD, selectedDids.size)} 位可帮你找回账号`}
          </p>
          {guardiansError !== null && <p className="field-error">{guardiansError}</p>}
          <div className="modal-actions">
            {editingGuardians && (
              <button
                className="btn-ghost"
                onClick={() => {
                  setEditingGuardians(false);
                  setSelectedDids(new Set());
                  setGuardiansError(null);
                }}
                disabled={guardiansPending}
              >
                取消
              </button>
            )}
            <button
              className="btn-primary"
              onClick={() => void handleSetupGuardians()}
              disabled={guardiansPending || selectedDids.size < 2}
            >
              {guardiansPending ? "设置中…" : editingGuardians ? "保存新设置" : "设置紧急联系人"}
            </button>
          </div>
        </div>
      ) : (
        recoverySelf !== null && (
          <div className="guardian-status">
            <p className="field-hint">
              已设置 <b>{recoverySelf.guardians.length}</b> 位守护者（
              {recoverySelf.guardians.map(contactLabel).join("、")}
              ），任意 <b>{recoverySelf.threshold}</b> 位确认即可帮你找回账号。恢复公告已发布到节点。
            </p>
            <div className="modal-actions">
              <button
                className="btn-ghost"
                disabled={rehearsePending}
                onClick={async () => {
                  setRehearsePending(true);
                  try {
                    setRehearseResult(await rehearseRecovery());
                  } finally {
                    setRehearsePending(false);
                  }
                }}
              >
                {rehearsePending ? "演练中…" : "恢复演练"}
              </button>
              <button
                className="btn-ghost"
                onClick={() => {
                  setSelectedDids(new Set(recoverySelf.guardians));
                  setEditingGuardians(true);
                }}
              >
                重新设置
              </button>
            </div>
            {rehearseResult !== null && (
              <ul className="boundary-list">
                {rehearseResult.checks.map((c) => (
                  <li key={c.name}>
                    {c.ok ? "✅" : "⚠️"} {c.name}
                    {c.detail ? `——${c.detail}` : ""}
                  </li>
                ))}
                <li>{rehearseResult.ok ? "✅ 演练通过：恢复所需的公告、包裹与守护者会话均就绪。" : "⚠️ 存在未就绪项，请先处理后再依赖社交恢复。"}</li>
              </ul>
            )}
          </div>
        )
      )}

      {/* 能力边界诚实披露（UX-7） */}
      <details className="disclosure">
        <summary>数据与边界</summary>
        <ul className="boundary-list">
          <li>私钥只保存在本浏览器的 IndexedDB 中；清除浏览器数据会导致身份丢失，可通过紧急联系人、托管副本或备份文件找回。</li>
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
