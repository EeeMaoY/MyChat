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

export type { ChatMessage, Contact };
