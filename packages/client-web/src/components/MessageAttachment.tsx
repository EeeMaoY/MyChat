/** 附件气泡：图片解密渲染（objectURL 缓存）与文件下载。 */
import { useEffect, useState } from "react";

import { fetchAttachment, setNotice } from "../lib/app";
import type { AttachmentMeta } from "../lib/messaging";

import { formatBytes } from "./format";

/** cid → objectURL 模块级缓存：同一附件只取块解密一次（图片与下载共享）。 */
const objectUrlCache = new Map<string, string>();

/** Uint8Array → Blob（复制进独立 ArrayBuffer，兼容 BlobPart 的类型约束）。 */
function toBlob(data: Uint8Array, mime: string): Blob {
  return new Blob([new Uint8Array(data)], { type: mime });
}

type ImageLoadState =
  | { phase: "loading" }
  | { phase: "ready"; url: string }
  | { phase: "error" };

/** 取附件字节并生成 objectURL（命中缓存则直接复用）。 */
async function loadObjectUrl(att: AttachmentMeta): Promise<string> {
  const cached = objectUrlCache.get(att.cid);
  if (cached !== undefined) return cached;
  const data = await fetchAttachment({
    cid: att.cid,
    contentKey: att.contentKey,
    nonce: att.nonce,
  });
  const url = URL.createObjectURL(toBlob(data, att.mime));
  objectUrlCache.set(att.cid, url);
  return url;
}

/** 图片气泡：挂载时取块解密，加载中骨架占位，点击新标签页打开原图。 */
export function ImageBubble({ attachment }: { attachment: AttachmentMeta }) {
  const [state, setState] = useState<ImageLoadState>({ phase: "loading" });

  useEffect(() => {
    let alive = true;
    setState({ phase: "loading" });
    loadObjectUrl(attachment)
      .then((url) => {
        if (alive) setState({ phase: "ready", url });
      })
      .catch(() => {
        if (alive) setState({ phase: "error" });
      });
    return () => {
      alive = false;
    };
  }, [attachment]);

  if (state.phase === "loading") {
    return <div className="img-skeleton" role="status" aria-label="图片加载中" />;
  }
  if (state.phase === "error") {
    return <div className="img-failed">图片无法加载</div>;
  }
  return (
    <img
      className="msg-image"
      src={state.url}
      alt={attachment.name}
      title={attachment.name}
      onClick={() => window.open(state.url, "_blank", "noopener")}
    />
  );
}

/** 文件气泡：📄 图标 + 文件名 + 大小，点击下载（取块解密 → <a download> 保存）。 */
export function FileBubble({ attachment }: { attachment: AttachmentMeta }) {
  const [downloading, setDownloading] = useState(false);

  async function handleDownload(): Promise<void> {
    if (downloading) return;
    setDownloading(true);
    try {
      const data = await fetchAttachment({
        cid: attachment.cid,
        contentKey: attachment.contentKey,
        nonce: attachment.nonce,
      });
      const url = URL.createObjectURL(toBlob(data, attachment.mime));
      const a = document.createElement("a");
      a.href = url;
      a.download = attachment.name;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setNotice("文件下载失败");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <div className="file-bubble">
      <span className="file-icon" aria-hidden="true">
        📄
      </span>
      <span className="file-info">
        <span className="file-name" title={attachment.name}>
          {attachment.name}
        </span>
        <span className="file-size">{formatBytes(attachment.size)}</span>
      </span>
      <button className="file-download" onClick={() => void handleDownload()} disabled={downloading}>
        {downloading ? "下载中…" : "下载"}
      </button>
    </div>
  );
}
