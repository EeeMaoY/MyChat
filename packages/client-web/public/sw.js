/**
 * MyChat Service Worker（M4-S15 Web Push）：
 * 收到 push（节点发送的无 payload 唤醒）→ 展示本地静态通知——内容永不出密文层。
 * 点击通知聚焦/打开应用。
 */
self.addEventListener("install", () => {
  // 不做内容缓存：本地权威数据语义（设备副本即权威），离线壳会与真实状态分叉。
  // 本 SW 仅承载 Web Push 唤醒与 PWA 安装形态。立即生效新版本。
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  event.waitUntil(
    self.registration.showNotification("MyChat", {
      body: "有新消息",
      tag: "mychat-activity",
      renotify: true,
      // 点击行为在 notificationclick 中处理；badge/icon 留空使用浏览器默认
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if ("focus" in client) return client.focus();
      }
      return self.clients.openWindow("/");
    }),
  );
});
