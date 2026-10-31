/**
 * 根组件：phase 路由 + 全局提示条 + 首启创建编排。
 * 流转（§10.3，UX-1）：loading → welcome → creating（≥1.2s 动画）→ set-name → main。
 */
import { useEffect, useRef, useState, type ReactNode } from "react";

import { bootstrap, createMyIdentity, setNotice, useAppState } from "./lib/app";

import CreatingPage from "./pages/CreatingPage";
import MainPage from "./pages/MainPage";
import SetNamePage from "./pages/SetNamePage";
import WelcomePage from "./pages/WelcomePage";

/** 身份创建动画的最短展示时长（createMyIdentity 本身很快，动画属体验设计）。 */
const CREATE_ANIM_MS = 1200;

export default function App() {
  const state = useAppState();

  // —— 首启创建引导：点击"开始使用"进入动画页，创建与动画并行，二者都完成才进 set-name ——
  const [creatingRequested, setCreatingRequested] = useState(false);
  const [animDone, setAnimDone] = useState(false);
  const bootstrapStartedRef = useRef(false);
  const createStartedRef = useRef(false);

  // 启动：加载已有身份或进入欢迎页（StrictMode 下防重复执行）
  useEffect(() => {
    if (bootstrapStartedRef.current) return;
    bootstrapStartedRef.current = true;
    bootstrap().catch((err: unknown) => {
      setNotice(err instanceof Error ? err.message : "启动失败，请刷新重试");
    });
  }, []);

  const startCreate = (): void => {
    if (creatingRequested) return;
    setCreatingRequested(true);
    setAnimDone(false);
    // 最短动画计时（组件常驻，无需清理）
    window.setTimeout(() => setAnimDone(true), CREATE_ANIM_MS);
  };

  // 进入动画页后才真正发起身份创建（ref 记 pending，防 StrictMode 重复调用）
  useEffect(() => {
    if (!creatingRequested || createStartedRef.current) return;
    createStartedRef.current = true;
    createMyIdentity().catch((err: unknown) => {
      createStartedRef.current = false;
      setCreatingRequested(false); // 失败退回欢迎页，可重试
      setNotice(err instanceof Error ? err.message : "身份创建失败");
    });
  }, [creatingRequested]);

  // —— 全局提示：5s 自动清除 ——
  const notice = state.notice;
  useEffect(() => {
    if (notice === null) return;
    const timer = window.setTimeout(() => setNotice(null), 5000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  // 创建页退出条件：已请求创建，且（创建完成切到 set-name && 动画计时结束）
  const creating = creatingRequested && !(state.phase === "set-name" && animDone);

  let page: ReactNode;
  if (state.phase === "loading" && !creatingRequested) {
    page = (
      <main className="page page-center page-loading">
        <span className="spinner" role="status" aria-label="加载中" />
      </main>
    );
  } else if (creating) {
    page = <CreatingPage />;
  } else if (state.phase === "welcome") {
    page = <WelcomePage onStart={startCreate} />;
  } else if (state.phase === "set-name") {
    page = <SetNamePage />;
  } else {
    page = <MainPage />;
  }

  return (
    <>
      {notice !== null && (
        <div className="notice-bar" role="status">
          <span className="notice-text">{notice}</span>
          <button className="notice-close" onClick={() => setNotice(null)} aria-label="关闭提示">
            ✕
          </button>
        </div>
      )}
      {page}
    </>
  );
}
