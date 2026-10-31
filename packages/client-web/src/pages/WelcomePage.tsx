/** 产品首页：一句话定位 + 特性点 + 开始使用（UX-1：全程无密钥/节点操作）。 */

interface Props {
  onStart: () => void;
}

const FEATURES = [
  { name: "端到端加密", desc: "消息只有你和对方能解开，任何中间方都只是转发密文" },
  { name: "元数据保护", desc: "伪地址信封与填充档位，抑制「谁知道在和谁聊天、发了多大」的推断" },
  { name: "数据所有权", desc: "身份与聊天记录都在你自己的设备上，不依赖任何平台账号" },
] as const;

export default function WelcomePage({ onStart }: Props) {
  return (
    <main className="page page-center welcome">
      <h1 className="welcome-title">MyChat</h1>
      <p className="welcome-tagline">数据完全属于你的社交网络</p>
      <ul className="welcome-features">
        {FEATURES.map((f) => (
          <li key={f.name}>
            <span className="feature-dot" aria-hidden="true" />
            <div>
              <span className="feature-name">{f.name}</span>
              <span className="feature-desc">{f.desc}</span>
            </div>
          </li>
        ))}
      </ul>
      <button className="btn-primary btn-lg" onClick={onStart}>
        开始使用
      </button>
      <p className="welcome-hint">无需注册手机号或邮箱，身份将自动在你的设备上创建</p>
    </main>
  );
}
