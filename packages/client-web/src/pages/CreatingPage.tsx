/** 身份创建动画页：纯视觉。phase 由 lib 层推进，最短展示时长由 App 控制。 */

export default function CreatingPage() {
  return (
    <main className="page page-center creating">
      <div className="creating-ring" aria-hidden="true" />
      <h1 className="creating-title">正在为你创建专属身份…</h1>
      <p className="creating-sub">密钥在你的设备上本地生成，任何人（包括我们）都无法看到。</p>
    </main>
  );
}
