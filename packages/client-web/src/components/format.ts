/** 共享 UI 纯函数与常量（时间 / 文本 / DID 展示、用户名规则）。 */

/** 用户名规则：3-20 位字母、数字、下划线或连字符（FR-1.2）。 */
export const NAME_RE = /^[A-Za-z0-9_-]{3,20}$/;

/** 时钟时间 HH:mm（聊天气泡）。 */
export function formatClock(at: number): string {
  const d = new Date(at);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

/** 会话列表时间：今天显示 HH:mm，更早显示 MM-DD。 */
export function formatListTime(at: number): string {
  const d = new Date(at);
  const now = new Date();
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  if (sameDay) return formatClock(at);
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${mo}-${day}`;
}

/** 摘要截断：超长加省略号。 */
export function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** 人类可读大小：B / KB / MB（KB 起保留一位小数）。 */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** 短 DID：保留可读前缀 + 主体前几位（did:mychat: 共 11 字符）。 */
export function shortDid(did: string): string {
  return did.length > 18 ? `${did.slice(0, 18)}…` : did;
}
