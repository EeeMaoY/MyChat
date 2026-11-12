/**
 * 渲染错误边界（防远程白屏，安全加固批次）：捕获子树渲染期异常，显示兜底界面而非卸载整棵树。
 * 与 lib/validate.ts 分工：入站校验拦截新的畸形载荷；本组件兜底已落库的历史脏数据与未预见的渲染错误。
 */
import { Component, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  failed: boolean;
}

export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch(error: unknown, info: ErrorInfo): void {
    // 留控制台线索便于定位（不向用户展示错误细节）
    console.error("界面渲染异常", error, info.componentStack);
  }

  render(): ReactNode {
    if (this.state.failed) {
      return (
        <main className="page page-center" role="alert">
          <h1>界面出现异常</h1>
          <p className="field-hint">显示内容时遇到无法处理的错误，刷新页面可尝试恢复。</p>
          <button className="btn-primary" onClick={() => location.reload()}>
            刷新
          </button>
        </main>
      );
    }
    return this.props.children;
  }
}
