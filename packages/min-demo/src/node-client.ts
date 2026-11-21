/**
 * 节点 HTTP 客户端（课程演示最小版）——只封装演示用到的 7 个端点。
 *
 * 刻意保持"裸 fetch + 逐端点一个方法"的形态：课程中可逐行讲解客户端与
 * 节点（零信任中继）的原始协议交互。字段编码与 packages/client-web/src/lib/node-api.ts
 * 一致（UserNameRecord 签名 base64、信封 JSON 的 nonce/payload base64）。
 */
import type { Envelope, UserNameRecord } from "@mychat/core";

/** 信封 → JSON（节点信箱 append/fetch 的传输形态；与 dev-node wire.ts 对齐）。 */
export function envelopeToJson(e: Envelope): Record<string, unknown> {
  return {
    version: e.version,
    epoch: e.epoch,
    toPseudonym: e.toPseudonym,
    padClass: e.padClass,
    nonce: toBase64(e.nonce),
    payload: toBase64(e.payload),
  };
}

/** JSON → 信封（fetch 返回形态）。 */
export function envelopeFromJson(raw: Record<string, unknown>): Envelope {
  return {
    version: raw.version as string,
    epoch: raw.epoch as number,
    toPseudonym: raw.toPseudonym as string,
    padClass: raw.padClass as 0 | 1 | 2 | 3,
    nonce: fromBase64(raw.nonce as string),
    payload: fromBase64(raw.payload as string),
  };
}

export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(text: string): Uint8Array {
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export class NodeClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private async assertOk(res: Response): Promise<void> {
    if (!res.ok) throw new Error(`节点返回 ${res.status}：${await res.text().catch(() => "")}`);
  }

  /** 注册用户名（record.signature 为 base64 字符串的 JSON 形态）。 */
  async register(record: UserNameRecord): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v0/registry/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ record: { ...record, signature: toBase64(record.signature) } }),
    });
    await this.assertOk(res);
  }

  /** 查用户名 → DID（404 返回 null）。 */
  async resolve(name: string): Promise<UserNameRecord | null> {
    const res = await fetch(`${this.baseUrl}/v0/registry/resolve/${encodeURIComponent(name)}`);
    if (res.status === 404) return null;
    await this.assertOk(res);
    const body = (await res.json()) as { record: { name: string; did: string; signature: string; ktIndex: number } };
    return { name: body.record.name, did: body.record.did, ktIndex: body.record.ktIndex, signature: fromBase64(body.record.signature) };
  }

  /** 登记设备凭证（IK 签名；节点验签准入，bundle 上传的前置）。 */
  async putDevice(did: string, certificate: Record<string, unknown>): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v0/registry/devices/${encodeURIComponent(did)}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ certificate }),
    });
    await this.assertOk(res);
  }

  /** 上传预密钥束（二进制；节点验签后入库，OPK 随 bundle 入池）。 */
  async putBundle(did: string, bundle: Uint8Array, device: string): Promise<void> {
    const res = await fetch(
      `${this.baseUrl}/v0/registry/bundle/${encodeURIComponent(did)}?device=${encodeURIComponent(device)}`,
      { method: "PUT", headers: { "content-type": "application/octet-stream" }, body: new Uint8Array(bundle) },
    );
    await this.assertOk(res);
  }

  /** 取对方预密钥束（公共名片语义：任何知道 DID 的人可取）。 */
  async getBundle(did: string): Promise<Uint8Array | null> {
    const res = await fetch(`${this.baseUrl}/v0/registry/bundle/${encodeURIComponent(did)}`);
    if (res.status === 404) return null;
    await this.assertOk(res);
    return new Uint8Array(await res.arrayBuffer());
  }

  /** 消耗一个 OPK（一次性语义：X3DH 响应方接受握手后必须销毁）。 */
  async consumeOpk(did: string, opkId: number, device: string): Promise<void> {
    const res = await fetch(
      `${this.baseUrl}/v0/registry/bundle/${encodeURIComponent(did)}/opk/${opkId}?device=${encodeURIComponent(device)}`,
      { method: "DELETE" },
    );
    await this.assertOk(res);
  }

  /** 投递信封到信箱（节点只见伪地址与密文）。 */
  async mailboxAppend(mailboxId: string, envelope: Envelope): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}/append`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope: envelopeToJson(envelope) }),
    });
    await this.assertOk(res);
  }

  /** 拉取信箱增量（cursor 之后；返回节点原始 JSON 供节点视角展示）。 */
  async mailboxFetchRaw(mailboxId: string, cursor: number): Promise<{ envelopes: Record<string, unknown>[]; cursor: number }> {
    const res = await fetch(`${this.baseUrl}/v0/storage/mailboxes/${encodeURIComponent(mailboxId)}?cursor=${cursor}`);
    await this.assertOk(res);
    return (await res.json()) as { envelopes: Record<string, unknown>[]; cursor: number };
  }

  /** 节点健康检查（取 KT 根——顺带可在演示中展示透明日志）。 */
  async ktRoot(): Promise<{ size: number; root: string }> {
    const res = await fetch(`${this.baseUrl}/v0/kt/root`);
    await this.assertOk(res);
    return (await res.json()) as { size: number; root: string };
  }
}
