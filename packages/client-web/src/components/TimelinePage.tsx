/**
 * 动态时间线（FR-4.1/4.2/4.4，M3-S12）：发布框 + 好友圈动态流。
 * 排序仅按时间（无算法推荐，Non-Goals）；删除为墓碑语义——已缓存副本
 * 无法物理强制删除，UI 如实告知（FR-4.4 固有边界）。
 */
import { useEffect, useRef, useState, type ChangeEvent } from "react";

import { commentMoment, deleteMoment, publishMoment, setNotice, useAppState } from "../lib/app";
import type { MomentItem } from "../lib/messaging";

import { formatListTime, shortDid } from "./format";
import { ImageBubble } from "./MessageAttachment";

const ATTACHMENT_MAX_BYTES = 8 * 1024 * 1024;

export default function TimelinePage({ onBack }: { onBack: () => void }) {
  const state = useAppState();
  const did = state.did;

  const [draft, setDraft] = useState("");
  const [file, setFile] = useState<{ data: Uint8Array; name: string; mime: string } | null>(null);
  const [pending, setPending] = useState(false);
  const [commentDraft, setCommentDraft] = useState<{ cid: string; text: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // 图片选择后立即读入（≤8MB）
  useEffect(() => () => setFile(null), []);

  async function handleFile(e: ChangeEvent<HTMLInputElement>): Promise<void> {
    const input = e.target;
    const f = input.files?.[0];
    input.value = "";
    if (f === undefined) return;
    if (f.size > ATTACHMENT_MAX_BYTES) {
      setNotice("图片超过 8MB 上限");
      return;
    }
    setFile({ data: new Uint8Array(await f.arrayBuffer()), name: f.name, mime: f.type || "image/png" });
  }

  async function handlePublish(): Promise<void> {
    if (pending) return;
    if (draft.trim() === "" && file === null) return;
    setPending(true);
    try {
      await publishMoment(draft.trim(), file ?? undefined);
      setDraft("");
      setFile(null);
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "发布失败");
    } finally {
      setPending(false);
    }
  }

  async function handleDelete(cid: string): Promise<void> {
    try {
      await deleteMoment(cid);
      setNotice("已删除：好友端将以墓碑隐藏；已缓存的副本无法强制删除");
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "删除失败");
    }
  }

  async function handleComment(item: MomentItem): Promise<void> {
    if (commentDraft === null || commentDraft.cid !== item.cid || commentDraft.text.trim() === "") return;
    try {
      await commentMoment(item.authorDid, item.cid, commentDraft.text.trim());
      setCommentDraft(null);
      setNotice("留言已发送（仅对方可见）");
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "留言失败");
    }
  }

  function authorName(authorDid: string): string {
    if (authorDid === did) return "我";
    return state.contacts.find((c) => c.did === authorDid)?.name ?? shortDid(authorDid);
  }

  return (
    <section className="chat-panel timeline">
      <header className="chat-head">
        <button className="chat-back" onClick={onBack} aria-label="返回会话列表">
          ←
        </button>
        <div className="chat-peer">
          <span className="chat-peer-name">📱 动态</span>
          <span className="chat-peer-did">好友圈 · 端到端加密 · 仅好友可见</span>
        </div>
      </header>

      {/* 发布框（FR-4.1） */}
      <div className="timeline-composer">
        <textarea
          className="chat-textarea"
          value={draft}
          rows={2}
          placeholder="分享点什么…（仅好友可见）"
          disabled={pending}
          onChange={(e) => setDraft(e.target.value)}
        />
        {file !== null && (
          <p className="field-hint">
            已选图片：{file.name}（{Math.ceil(file.data.length / 1024)}KB）·{" "}
            <button className="btn-ghost" onClick={() => setFile(null)} disabled={pending}>
              移除
            </button>
          </p>
        )}
        <div className="inline-row">
          <input ref={fileInputRef} type="file" accept="image/*" className="hidden-file-input" tabIndex={-1} onChange={(e) => void handleFile(e)} />
          <button className="btn-ghost" onClick={() => fileInputRef.current?.click()} disabled={pending}>
            🖼 图片
          </button>
          <button className="btn-primary" onClick={() => void handlePublish()} disabled={pending || (draft.trim() === "" && file === null)}>
            {pending ? "发布中…" : "发布"}
          </button>
        </div>
      </div>

      {/* 动态流（FR-4.2，按时间倒序） */}
      <div className="msg-list timeline-list">
        {state.moments.length === 0 && (
          <p className="field-hint">暂无动态。发布一条，或等好友的动态同步到本地。</p>
        )}
        {state.moments.map((m) => (
          <article key={`${m.authorDid}:${m.cid}`} className={`moment-card${m.deleted === true ? " deleted" : ""}`}>
            <header className="moment-head">
              <b>{authorName(m.authorDid)}</b>
              <span className="contact-time">{formatListTime(m.at)}</span>
              {m.authorDid === did && m.deleted !== true && (
                <button className="btn-ghost" onClick={() => void handleDelete(m.cid)}>
                  删除
                </button>
              )}
            </header>
            {m.deleted === true ? (
              <p className="field-hint">该动态已由作者删除（本地缓存内容已隐藏）。</p>
            ) : (
              <>
                {m.text !== "" && <p className="moment-text">{m.text}</p>}
                {m.attachment !== undefined && m.attachment.mime.startsWith("image/") && <ImageBubble attachment={m.attachment} />}
                <footer className="moment-foot">
                  <span className="contact-time">{m.comments.length > 0 ? `${m.comments.length} 条留言` : ""}</span>
                  {m.authorDid !== did && (
                    <button
                      className="btn-ghost"
                      onClick={() => setCommentDraft({ cid: m.cid, text: "" })}
                    >
                      留言
                    </button>
                  )}
                </footer>
                {m.comments.map((c, i) => (
                  <p key={i} className="moment-comment">
                    <b>{authorName(c.fromDid)}</b>：{c.text}
                  </p>
                ))}
                {commentDraft !== null && commentDraft.cid === m.cid && (
                  <div className="inline-row">
                    <input
                      className="input"
                      value={commentDraft.text}
                      placeholder="留言（仅作者可见）"
                      autoFocus
                      onChange={(e) => setCommentDraft({ cid: m.cid, text: e.target.value })}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void handleComment(m);
                      }}
                    />
                    <button className="btn-primary" onClick={() => void handleComment(m)}>
                      发送
                    </button>
                    <button className="btn-ghost" onClick={() => setCommentDraft(null)}>
                      取消
                    </button>
                  </div>
                )}
              </>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}
