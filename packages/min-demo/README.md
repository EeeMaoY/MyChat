# MyChat 最小演示（minE2E 分支）

课程演示用的**最小实现**：一个页面三栏，直观展示「去中心化安全社交网络」的两个核心事实——

1. **端到端加密交流正常**：左（Alice）右（Bob）两栏互发消息，只有双方能解密；
2. **中心（节点）只见密文**：中间栏直接渲染节点信箱端点返回的**原始 JSON**——没有明文、没有消息内容、没有身份关联。

## 演示拓扑

```
Alice 客户端 ─┐                    ┌─ Bob 客户端
              │   ┌────────────┐   │
              ├──►│ dev-node   │◄──┤   零信任中继：验签准入、按伪地址投递
              │   │ (8802)     │   │   它能看到的全部数据 = 中间栏展示的密文信封
              │   └────────────┘   │
  密码学在两端本地执行（X3DH + Double Ratchet + XChaCha20-Poly1305）
```

- **packages/core**：协议与密码学核心（演示客户端复用的全部原语都在这里，是讲解的主角之一）
- **packages/dev-node**：零信任节点（不做鉴权裁决、无法解密任何消息——"去中心化"在单节点部署形态下的诚实边界见协议规范 §10）
- **packages/min-demo**（本包）：三栏演示页，客户端主线约 300 行，逐段可讲

## 启动

```bash
npm run build -w @mychat/core     # core 产物（min-demo 与 dev-node 依赖）
npm start -w @mychat/dev-node &   # 节点 :8802（默认 8629，演示脚本用 8802）
npm run dev -w @mychat/min-demo   # 演示页 :5190
```

浏览器打开 `http://127.0.0.1:5190`（节点地址可用 `?node=` 参数覆盖）。

## 课程演示脚本（约 3 分钟）

| 步骤 | 操作 | 讲解要点 |
| --- | --- | --- |
| 1 | 打开页面，Alice/Bob 两栏自动出现 DID | **无感身份创建**：Ed25519（签名）+ X25519（协商）密钥对本地生成，`did:mychat:` 自认证，无需注册机构 |
| 2 | Alice 栏注册 `alice`、Bob 栏注册 `bob` | 用户名记录是 **IK 签名**的 (name, did)——节点验签准入但无法冒名改绑；DID 才是身份本体 |
| 3 | Alice 输入 `bob` 点「② 加好友」 | **X3DH 握手**（DH1-DH4 → 会话密钥）：取对方预密钥束（SPK+OPK 公钥）→ 密文投其发现信箱；握手载荷带 `ikxSig` 身份绑定签名（防冒名，协议规范 §5） |
| 4 | 观察 Bob 栏日志与中间栏 | Bob 轮询发现信箱 → 响应方推导**同一会话密钥** → **OPK 一次性消耗**并轮换（一次性语义是抗未来泄露的关键） |
| 5 | Alice 发消息，Bob 收到 | **Double Ratchet**：每条消息一次性棘轮密钥 + XChaCha20-Poly1305；四档定长填充抑制长度侧信道 |
| 6 | **重点：看中间栏** | 节点信箱里的信封只有 `version/epoch/padClass/payload(密文)`——对着左右栏明文讲"服务器存的是什么" |
| 7 | Bob 回复，双向通信成立 | 双向棘轮各自推进；会话信箱地址随时间桶轮换（元数据保护） |
| 8 | 中间栏对比两人的"会话信箱" | **同一伪地址**：Alice 的发送信箱与 Bob 的接收信箱是同一个地址（`sessionMailbox(send) == 对端 sessionMailbox(recv)`）——双向流量共用伪地址，节点无法区分收发方向 |

## 最小实现与完整版的对应关系

| 演示概念 | 本包位置 | 完整实现（对照讲解） |
| --- | --- | --- |
| 身份与 DID | `client.ts` setup/publishPreKeys | `packages/core/src/identity/` |
| X3DH | `client.ts` addFriend/onEnvelopeDiscovery | `packages/core/src/signal/x3dh.ts` |
| Double Ratchet | `client.ts` send/onEnvelopeChat | `packages/core/src/signal/ratchet.ts` |
| 信封/填充/时间桶 | `client.ts` seal/poll | `packages/core/src/envelope/` |
| 节点协议（7 端点） | `node-client.ts` | `packages/dev-node/src/server.ts` |
| 完整客户端（群组/动态/恢复/多设备…） | — | `packages/client-web/`（工业版参考） |

## 验收

```bash
npx playwright test --config packages/min-demo/playwright.config.ts
```

用例覆盖：双身份注册 → X3DH 建会话 → 双向端到端消息 → **节点视角无明文**（把演示消息文本作为毒物断言中间栏不含）。
