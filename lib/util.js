// Small helpers shared by the shortcode ports and feed builders.

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Hugo's `truncate n`: character budget including the appended ellipsis,
// breaking on the last word boundary inside the budget.
function truncate(s, n) {
  const str = String(s ?? "");
  if (str.length <= n) return str;
  let cut = str.slice(0, n - 1);
  const lastSpace = cut.lastIndexOf(" ");
  if (lastSpace > 0) cut = cut.slice(0, lastSpace);
  return `${cut} …`;
}

// Rough .Plain for raw markdown: strips code fences markers, inline markup,
// links, and shortcode delimiters, keeping the visible text.
function plainifyMarkdown(md) {
  return String(md ?? "")
    .replace(/\{\{[<%][\s\S]*?[>%]\}\}/g, " ")
    .replace(/```[^\n]*\n/g, "")
    .replace(/`([^`]*)`/g, "$1")
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/[*_]{1,3}([^*_]+)[*_]{1,3}/g, "$1")
    .replace(/^\s*[-+>]\s+/gm, "")
    .replace(/\s+/g, " ")
    .trim();
}

// Strip markup repeatedly until no tag-shaped fragments remain, so nested
// fragments like "<scr<script>ipt>" can't reassemble into a tag.
function stripTags(s) {
  let out = String(s ?? "");
  let prev;
  do {
    prev = out;
    out = out.replace(/<[^>]*>?/g, "");
  } while (out !== prev);
  return out;
}

// Hugo-style date formatting for the "2006-01-02" layout used site-wide.
function isoDate(d) {
  if (!d) return "";
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().slice(0, 10);
}

// Local calendar date (YYYY-MM-DD), matching Hugo's now.Format which used
// the build machine's timezone rather than UTC.
function localDate(d = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

module.exports = { escapeHtml, truncate, plainifyMarkdown, stripTags, isoDate, localDate };
