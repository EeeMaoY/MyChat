/**
 * 应用装配与状态（React 绑定：useSyncExternalStore）。
 *
 * 状态流转（设计报告 §10.3 首启流程，UX-1：全程 0 次密钥操作）：
 *   loading → welcome（无身份）→ creating（无感创建中，动画）
 *           → set-name（起个名字，可跳过）→ main
 */
import { useSyncExternalStore } from "react";

import { base58Decode, createIdbKVStore, decryptAttachment, type KVStore } from "@mychat/core";

import { Messaging, type ChatMessage, type Contact } from "./messaging";
import { NodeApi } from "./node-api";

export type Phase = "loading" | "welcome" | "creating" | "set-name" | "main";

export interface AppState {
  phase: Phase;
  did: string | null;
  myName: string | null;
  contacts: Contact[];
  messages: Record<string, ChatMessage[]>;
  online: boolean;
  notice: string | null;
  activeDid: string | null; // 当前打开的会话
}

let kv: KVStore | null = null;
let messaging: Messaging | null = null;
let pendingName: string | null = null;

let state: AppState = {
  phase: "loading",
  did: null,
  myName: null,
  contacts: [],
  messages: {},
  online: true,
  notice: null,
  activeDid: null,
};

const listeners = new Set<() => void>();

/**
 * 不可变快照更新：useSyncExternalStore 以 Object.is 比较 getSnapshot 结果，
 * 就地 mutate 同一引用会导致 React 判定无变化而不重渲染（集成期已踩坑）。
 */
function setState(patch: Partial<AppState>): void {
  state = { ...state, ...patch };
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useAppState(): AppState {
  return useSyncExternalStore(subscribe, () => state);
}

/** 由 UI 或测试注入的节点地址（默认本地 dev-node）。 */
export function nodeBaseUrl(): string {
  return localStorage.getItem("mychat.node-url") ?? "http://127.0.0.1:8629";
}

function syncFromMessaging(): void {
  if (!messaging) return;
  setState({
    myName: messaging.myName,
    contacts: [...messaging.contacts.values()].sort((a, b) => b.addedAt - a.addedAt),
    messages: Object.fromEntries([...messaging.messages.entries()]),
    online: messaging.online,
  });
}

/** 启动：加载身份或进入欢迎流程。 */
export async function bootstrap(): Promise<void> {
  kv = await createIdbKVStore("mychat");
  const api = new NodeApi(nodeBaseUrl());
  messaging = await Messaging.load({ api, kv });
  if (!messaging) {
    setState({ phase: "welcome" });
    return;
  }
  messaging.onStateChange = syncFromMessaging;
  bindNotifications();
  setState({ phase: "main", did: messaging.identity.did });
  syncFromMessaging();
  messaging.startRealtime();
  void messaging.poll();
}

/** FR-1.1：无感身份创建（UI 仅显示进度动画，无任何用户输入）。 */
export async function createMyIdentity(): Promise<void> {
  if (!kv) return;
  setState({ phase: "creating" });
  const api = new NodeApi(nodeBaseUrl());
  messaging = await Messaging.createNew({ api, kv });
  messaging.onStateChange = syncFromMessaging;
  bindNotifications();
  pendingName = null;
  setState({ phase: "set-name", did: messaging.identity.did });
}

/** FR-1.2：用户名注册（set-name 阶段提交；跳过则稍后在"我的"页设置）。 */
export async function submitUsername(name: string): Promise<string | null> {
  if (!messaging) return "应用尚未就绪";
  try {
    await messaging.setUsername(name);
    setState({ phase: "main" });
    messaging.startRealtime();
    void messaging.poll();
    return null;
  } catch (err) {
    return err instanceof Error ? err.message : "注册失败";
  }
}

export function skipUsername(): void {
  setState({ phase: "main" });
  messaging?.startRealtime();
  void messaging?.poll();
}

export async function addFriend(name: string, note: string): Promise<string | null> {
  if (!messaging) return "应用尚未就绪";
  const error = await messaging.addFriend(name, note);
  if (error === null) setState({ activeDid: messaging!.contacts.get(messaging!.contacts.keys().next().value as string)?.did ?? state.activeDid });
  return error;
}

export async function sendMessage(did: string, text: string): Promise<void> {
  await messaging?.sendMessage(did, text);
}

/** 发送图片/文件（≤8MB，端到端加密后走 CAS 块）。 */
export async function sendAttachment(
  did: string,
  file: { data: Uint8Array; name: string; mime: string },
  kind: "image" | "file",
): Promise<void> {
  await messaging?.sendAttachment(did, file, kind);
}

/** UI 打开会话时调用：触发对端的 read 回执（受隐私开关控制）。 */
export function markChatOpened(did: string): void {
  void messaging?.markChatOpened(did);
}

export async function getReadReceiptsEnabled(): Promise<boolean> {
  return (await messaging?.readReceiptsEnabled()) ?? true;
}

export async function setReadReceiptsEnabled(enabled: boolean): Promise<void> {
  await messaging?.setReadReceiptsEnabled(enabled);
}

/** 取回并解密附件（图片渲染/文件下载用；objectURL 缓存由 UI 层管理）。 */
export async function fetchAttachment(
  meta: { cid: string; contentKey: string; nonce: string },
): Promise<Uint8Array> {
  const m = messaging;
  if (!m) throw new Error("应用尚未就绪");
  const ciphertext = await m.getNodeApi().getBlock(meta.cid);
  if (!ciphertext) throw new Error("附件块不存在（节点无此数据）");
  return decryptAttachment({
    ciphertext,
    contentKey: base58Decode(meta.contentKey),
    nonce: base58Decode(meta.nonce),
  });
}

export function openChat(did: string | null): void {
  setState({ activeDid: did });
}

export function setNotice(notice: string | null): void {
  setState({ notice });
}

/** 供"我的"页展示与设置页跳转。 */
export function getMessaging(): Messaging | null {
  return messaging;
}

// ---------- 设备管理（FR-1.4 多设备，M2-S10 UI 接入用） ----------

/** 本机设备信息（null=应用未就绪）。 */
export function getMyDevice(): { dkId: string; label: string; issuedAt: number; expiresAt: number } | null {
  if (!messaging) return null;
  return {
    dkId: messaging.deviceDkId,
    label: messaging.deviceCert.label,
    issuedAt: messaging.deviceCert.issuedAt,
    expiresAt: messaging.deviceCert.expiresAt,
  };
}

/** 我名下的全部设备（KT 事件流本地折叠，含已吊销/已过期）。 */
export async function listMyDevices() {
  return (await messaging?.listMyDevices()) ?? [];
}

/** 吊销一台设备（本设备吊销后将无法再收发消息，UI 侧确认）。 */
export async function revokeMyDevice(dkId: string): Promise<void> {
  if (!messaging) throw new Error("应用尚未就绪");
  await messaging.revokeMyDevice(dkId);
}

// ---------- 数据导出与托管（FR-7.2/7.3，UI 接入用） ----------

export async function exportAllData(): Promise<string> {
  if (!messaging) throw new Error("应用尚未就绪");
  return messaging.exportAll();
}

/** 导入恢复：成功后返回 true（内部已重建会话与实时通道）。 */
export async function importAllData(json: string): Promise<boolean> {
  if (!messaging) return false;
  await messaging.importAll(json);
  setState({ phase: "main", did: messaging.identity.did });
  syncFromMessaging();
  return true;
}

export async function createCustodyBackup(): Promise<{ hosts: string[] }> {
  if (!messaging) throw new Error("应用尚未就绪");
  return messaging.createCustodyBackup();
}

export async function listCustodyCopies(): Promise<
  { fromDid: string; cid: string; contentKey: string; nonce: string }[]
> {
  return (await messaging?.listCustodyCopies()) ?? [];
}

export async function decryptCustodyCopy(copy: {
  cid: string;
  contentKey: string;
  nonce: string;
}): Promise<string> {
  if (!messaging) throw new Error("应用尚未就绪");
  return messaging.decryptCustodyCopy(copy);
}

// ---------- 社交恢复向导（FR-1.3，无身份状态下的独立流程） ----------

/**
 * 恢复流程状态：以临时身份（内存库，不落盘）与守护者建立会话并收集分片。
 * 分片达门限后解开身份包裹，把恢复出的身份写入本机，随后由调用方引导托管副本恢复。
 */
let recoveryCtx: { messaging: Messaging; ownerDid: string; wrapCid: string; threshold: number } | null = null;

export interface RecoveryStepResult {
  ok: boolean;
  error?: string;
}

/** 第 1 步：输入被恢复账户的用户名，拉取并验证恢复公告，建立恢复上下文。 */
export async function recoveryStart(ownerName: string): Promise<RecoveryStepResult> {
  try {
    const { createMemoryKVStore } = await import("@mychat/core");
    const api = new NodeApi(nodeBaseUrl());
    const record = await api.resolve(ownerName);
    if (!record) return { ok: false, error: "用户名不存在" };
    const announcement = await api.getRecoveryAnnouncement(record.did);
    if (!announcement) return { ok: false, error: "该账户未设置社交恢复" };

    const kv = await createMemoryKVStore();
    const messaging = await Messaging.createNew({ api, kv });
    recoveryCtx = {
      messaging,
      ownerDid: record.did,
      wrapCid: String(announcement.wrapCid ?? ""),
      threshold: Number(announcement.threshold ?? 3),
    };
    setState({ phase: "main", did: messaging.identity.did, notice: "恢复模式：请添加全部紧急联系人并发起请求" });
    syncFromMessaging();
    messaging.startRealtime();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "恢复启动失败" };
  }
}

/** 第 2 步：以临时身份添加守护者（复用加好友握手；守护者侧将看到恢复请求说明）。 */
export async function recoveryAddGuardian(name: string): Promise<RecoveryStepResult> {
  if (!recoveryCtx) return { ok: false, error: "请先启动恢复流程" };
  const err = await recoveryCtx.messaging.addFriend(name, `我是账户 ${recoveryCtx.ownerDid} 的所有者，正在通过紧急联系人恢复访问权限`);
  return err === null ? { ok: true } : { ok: false, error: err };
}

/** 第 3 步：向全部守护者广播恢复请求（触发对方的分片回传）。 */
export async function recoveryRequestShares(): Promise<RecoveryStepResult> {
  if (!recoveryCtx) return { ok: false, error: "请先启动恢复流程" };
  await recoveryCtx.messaging.sendRecoveryRequest(recoveryCtx.ownerDid);
  return { ok: true };
}

/** 第 4 步：轮询收集；达标后返回恢复出的身份 JSON（调用方完成导入）。 */
export async function recoveryPollCollect(): Promise<{ done: boolean; progress: number; needed: number }> {
  if (!recoveryCtx) return { done: false, progress: 0, needed: 0 };
  await recoveryCtx.messaging.poll();
  const { collectedShares } = recoveryCtx.messaging;
  if (collectedShares.length >= recoveryCtx.threshold) {
    const payload = await recoveryCtx.messaging.tryFinishRecovery(
      recoveryCtx.ownerDid,
      recoveryCtx.wrapCid,
      recoveryCtx.threshold,
    );
    if (payload && kv) {
      // 写入本机并重建真实会话（wrap v2：身份 + 用户名一起回填，KI-2）
      const { deserializeIdentity, utf8ToBytes } = await import("@mychat/core");
      const identity = deserializeIdentity(payload.identityJson);
      await kv.put("identity", utf8ToBytes(payload.identityJson));
      if (payload.myName !== null) {
        await kv.put("my-name", utf8ToBytes(payload.myName));
      }
      const api = new NodeApi(nodeBaseUrl());
      messaging = await Messaging.load({ api, kv });
      if (messaging) {
        messaging.onStateChange = syncFromMessaging;
        bindNotifications();
        setState({ phase: "main", did: identity.did, notice: "身份已通过紧急联系人恢复" });
        syncFromMessaging();
        messaging.startRealtime();
        void messaging.poll();
        recoveryCtx = null;
        return { done: true, progress: 1, needed: 1 };
      }
    }
  }
  return {
    done: false,
    progress: collectedShares.length,
    needed: recoveryCtx.threshold,
  };
}

// ---------- 守护者与恢复请求（守护者侧 UI 接入） ----------

export async function setupGuardians(guardianDids: string[], threshold = 3): Promise<RecoveryStepResult> {
  if (!messaging) return { ok: false, error: "应用尚未就绪" };
  try {
    await messaging.setupGuardians(guardianDids, threshold);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "设置失败" };
  }
}

export async function getRecoverySelf(): Promise<{ wrapCid: string; threshold: number; guardians: string[] } | null> {
  return (await messaging?.getRecoverySelf()) ?? null;
}

export async function listGuardianships(): Promise<{ ownerDid: string; wrapCid: string }[]> {
  return (await messaging?.listGuardianships()) ?? [];
}

export async function listRecoveryRequests(): Promise<{ ownerDid: string; fromDid: string }[]> {
  return (await messaging?.listRecoveryRequests()) ?? [];
}

export async function confirmRecoveryRequest(fromDid: string, ownerDid: string): Promise<RecoveryStepResult> {
  try {
    await messaging?.confirmRecoveryRequest(fromDid, ownerDid);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "确认失败" };
  }
}

export async function rejectRecoveryRequest(fromDid: string): Promise<void> {
  await messaging?.rejectRecoveryRequest(fromDid);
}

/** 通知开关（kv 持久化；浏览器授权由调用方触发 requestPermission，S8/W2）。 */
export async function getNotificationsEnabled(): Promise<boolean> {
  const raw = await kv?.get("setting:notifications");
  return raw === undefined ? true : new TextDecoder().decode(raw) === "on";
}

export async function setNotificationsEnabled(enabled: boolean): Promise<void> {
  await kv?.put("setting:notifications", new TextEncoder().encode(enabled ? "on" : "off"));
  if (enabled && typeof Notification !== "undefined" && Notification.permission === "default") {
    void Notification.requestPermission();
  }
}

/** 注册新消息系统通知（页面隐藏时才打扰；点击聚焦并打开会话）。 */
function bindNotifications(): void {
  if (!messaging) return;
  messaging.onSessionRebuilt = (did) => {
    if (state.phase === "main") setNotice("联系人更换了设备，加密会话已自动重建");
    void did;
  };
  messaging.onIncomingMessage = (message) => {
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
    if (!document.hidden) return;
    void getNotificationsEnabled().then((enabled) => {
      if (!enabled) return;
      const contact = messaging?.contacts.get(message.did);
      const notification = new Notification(`MyChat · ${contact?.name ?? "新消息"}`, {
        body: message.text.slice(0, 80),
        tag: message.did,
      });
      notification.onclick = () => {
        window.focus();
        openChat(message.did);
        notification.close();
      };
    });
  };
}

export async function rehearseRecovery(): Promise<{ ok: boolean; checks: { name: string; ok: boolean; detail: string }[] }> {
  return (await messaging?.rehearseRecovery()) ?? { ok: false, checks: [] };
}

export function bindSessionRebuilt(handler: (did: string) => void): void {
  if (messaging) messaging.onSessionRebuilt = handler;
}

export type { ChatMessage, Contact };
