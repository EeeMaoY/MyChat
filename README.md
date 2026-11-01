# MyChat

去中心化安全社交网络（Decentralized Secure Social Network）。

个人计算机网络课程期末项目，以实现可交付 Web 端为初期目标，期末提交。

> 核心命题：内容端到端加密、元数据被架构性保护、数据完全属于用户，同时拥有中心化平台的使用便利。

## 文档

- [需求分析报告](./docs/需求分析报告.md) — 需求基线
- [产品设计报告](./docs/产品设计报告.md) — 架构与 ADR（含 Web-first 增补 ADR-9~12）
- [MVP 范围与里程碑计划](./docs/MVP范围与里程碑计划.md) — 执行基线

## 仓库结构（npm workspaces）

| 包 | 职责 |
| --- | --- |
| `packages/core` | 协议与密码学核心（纯 TS，浏览器/Node 同构）：身份、X3DH + Double Ratchet、信封、EDS、服务域接口定义 |
| `packages/dev-node` | 服务域单体开发节点（Relay / Storage / Registry / KT Log，协议接口分离，ADR-11） |
| `packages/client-web` | React + Vite Web 客户端 |

依赖方向：`client-web → core ← dev-node`；客户端与节点之间只经协议（信封 + 四接口）通信。

## 快速开始

```bash
npm install        # 安装依赖（Node >= 24）
npm run build      # 构建全部包
npm test           # 运行全部测试
npm run dev:client # 启动 Web 客户端开发服务器
```
