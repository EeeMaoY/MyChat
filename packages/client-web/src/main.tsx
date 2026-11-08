import { createRoot } from "react-dom/client";

import App from "./App";
import "./index.css";

/**
 * 不用 StrictMode：其 dev 模式的 double-mount 会让 bootstrap（全局单例装配：
 * IndexedDB/实时通道/节点对账）执行两次，产生两个 Messaging 实例与轮询/状态
 * 分裂竞态（M4-S15 e2e 实测定位）。生产构建本无 StrictMode，移除后 dev/e2e
 * 与生产行为一致。
 */
createRoot(document.getElementById("root")!).render(<App />);
