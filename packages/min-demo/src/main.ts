/**
 * 演示页装配：三栏 = Alice | 节点视角 | Bob。
 *
 * 中间栏展示"节点可见的一切"——直接渲染节点信箱端点返回的原始 JSON
 * （version/epoch/padClass/nonce/payload），不经过任何客户端解密：
 * 课程中现场对比左右两栏的明文与中间栏的密文，即端到端加密 + 零信任节点的直观证明。
 */
import { DemoClient } from "./client";
import { NodeClient } from "./node-client";

const nodeBase = new URLSearchParams(location.search).get("node") ?? `${location.protocol}//${location.hostname}:8802`;

const alice = new DemoClient("Alice", nodeBase);
const bob = new DemoClient("Bob", nodeBase);
const node = new NodeClient(nodeBase);

// ---------- DOM 工具 ----------

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls !== undefined) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

/** 单人栏：状态 + 操作 + 会话 + 操作日志。 */
function buildPersona(parent: HTMLElement, client: DemoClient, title: string): void {
  const col = el("div", "col persona");
  col.append(el("h2", undefined, title));

  const status = el("div", "status");
  col.append(status);

  const actions = el("div", "actions");
  const nameInput = el("input") as HTMLInputElement;
  nameInput.placeholder = "用户名";
  nameInput.className = "input";
  const btnRegister = el("button", "btn", "① 注册");
  btnRegister.disabled = true;
  const friendInput = el("input") as HTMLInputElement;
  friendInput.placeholder = "对方用户名";
  friendInput.className = "input";
  const btnFriend = el("button", "btn", "② 加好友");
  btnFriend.disabled = true;
  actions.append(nameInput, btnRegister, friendInput, btnFriend);
  col.append(actions);

  const chat = el("div", "chat");
  const chatHead = el("div", "chat-head");
  const msgList = el("div", "msgs");
  const chatRow = el("div", "chat-row");
  const chatInput = el("input") as HTMLInputElement;
  chatInput.placeholder = "输入明文消息…";
  chatInput.className = "input";
  const btnSend = el("button", "btn", "加密发送");
  btnSend.disabled = true;
  chatRow.append(chatInput, btnSend);
  chat.append(chatHead, msgList, chatRow);
  col.append(chat);

  const logBox = el("div", "log");
  col.append(logBox);
  parent.append(col);

  btnRegister.addEventListener("click", () => {
    void (async () => {
      try {
        btnRegister.disabled = true;
        await client.register(nameInput.value.trim());
      } catch (err) {
        alert(err instanceof Error ? err.message : "注册失败");
        btnRegister.disabled = false;
      }
    })();
  });
  btnFriend.addEventListener("click", () => {
    void (async () => {
      try {
        btnFriend.disabled = true;
        await client.addFriend(friendInput.value.trim());
      } catch (err) {
        alert(err instanceof Error ? err.message : "加好友失败");
        btnFriend.disabled = false;
      }
    })();
  });
  const doSend = (): void => {
    void (async () => {
      const did = client.getState().contacts[0]?.did;
      if (did === undefined || chatInput.value.trim() === "") return;
      try {
        await client.send(did, chatInput.value.trim());
        chatInput.value = "";
      } catch (err) {
        alert(err instanceof Error ? err.message : "发送失败");
      }
    })();
  };
  btnSend.addEventListener("click", doSend);
  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") doSend();
  });

  client.onChange = () => renderPersona(client, { status, nameInput, btnRegister, btnFriend, chatHead, msgList, btnSend });
}

function renderPersona(
  client: DemoClient,
  ui: {
    status: HTMLElement;
    nameInput: HTMLInputElement;
    btnRegister: HTMLButtonElement;
    btnFriend: HTMLButtonElement;
    chatHead: HTMLElement;
    msgList: HTMLElement;
    btnSend: HTMLButtonElement;
  },
): void {
  const s = client.getState();
  if (s.did !== null) {
    ui.status.textContent = `DID ${s.did.slice(0, 24)}…${s.userName !== null ? ` · 用户名「${s.userName}」` : ""}`;
    ui.btnRegister.disabled = s.userName !== null;
    // 演示单会话：注册后才能加好友，已有联系人后关闭入口
    ui.btnFriend.disabled = s.userName === null || s.contacts.length >= 1;
    ui.btnSend.disabled = s.contacts.length === 0;
  }
  ui.chatHead.textContent = s.contacts[0] !== undefined ? `与「${s.contacts[0].name}」的端到端加密会话` : "（尚无会话）";
  ui.msgList.replaceChildren();
  for (const group of s.messages) {
    for (const item of group.items) {
      const row = el("div", `msg ${item.dir === "out" ? "out" : "in"}`);
      const bubble = el("div", "bubble", item.text);
      bubble.title = "本地看到的明文；网络上传输的是密文（见中间栏）";
      row.append(bubble);
      ui.msgList.append(row);
    }
  }
  ui.msgList.scrollTop = ui.msgList.scrollHeight;
}

// ---------- 节点视角栏 ----------

const nodeCol = document.querySelector(".nodecol") as HTMLElement | null;

function buildNodeCol(parent: HTMLElement): void {
  const col = nodeCol ?? el("div", "col nodecol");
  col.replaceChildren();
  col.append(el("h2", undefined, "🔍 节点视角（零信任中继）"));
  const nodeStatus = el("div", "status");
  col.append(nodeStatus);
  col.append(el("p", "hint", "下面是节点信箱端点返回的原始数据——只有密文信封，没有明文、没有身份关联。"));
  const mailboxList = el("div", "mailbox-list");
  col.append(mailboxList);
  parent.append(col);

  void (async () => {
    try {
      const root = await node.ktRoot();
      nodeStatus.textContent = `节点 ${nodeBase} · KT 透明日志 ${root.size} 条 · 根 ${root.root.slice(0, 12)}…`;
    } catch {
      nodeStatus.textContent = `节点 ${nodeBase} 不可达（先启动 dev-node）`;
    }
  })();

  const refresh = (): void => {
    void renderNodeMailboxes(mailboxList);
  };
  setInterval(refresh, 2000);
}

async function renderNodeMailboxes(container: HTMLElement): Promise<void> {
  const mailboxes = [...alice.mailboxes(), ...bob.mailboxes()];
  if (mailboxes.length === 0) return;
  container.replaceChildren();
  for (const mb of mailboxes) {
    const card = el("div", "mailbox-card");
    card.append(el("div", "mailbox-id", `${mb.label} · ${mb.id.slice(0, 14)}…`));
    try {
      const { envelopes } = await node.mailboxFetchRaw(mb.id, 0);
      if (envelopes.length === 0) {
        card.append(el("div", "mailbox-empty", "（空）"));
      }
      for (const e of envelopes.slice(-3)) {
        const line = el("code", "envelope-json", JSON.stringify({ version: e.version, epoch: e.epoch, padClass: e.padClass, payload: String(e.payload).slice(0, 26) + "…" }));
        line.title = JSON.stringify(e, null, 2);
        card.append(line);
      }
    } catch {
      card.append(el("div", "mailbox-empty", "（拉取失败）"));
    }
    container.append(card);
  }
}

// ---------- 装配 ----------

const root = document.querySelector(".cols") as HTMLElement;
buildPersona(root, alice, "👤 Alice");
buildNodeCol(root);
buildPersona(root, bob, "👤 Bob");

// 身份创建：进入页面即自动（无感创建，FR-1.1 语义；刷新自动恢复），随后启动轮询
void (async () => {
  await alice.setup();
  await bob.setup();
  (document.querySelector(".topbar") as HTMLElement).textContent = `MyChat 最小演示 · 节点 ${nodeBase} · 双栏为端到端加密客户端，中间栏为节点可见的全部数据`;
  setInterval(() => {
    void alice.poll();
    void bob.poll();
  }, 1500);
})();
