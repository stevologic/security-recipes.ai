// Translates the Hugo shortcode dialect used across content/*.md into
// HTML (or markdown-it container syntax) before markdown rendering, so
// the 2,500+ content files migrate to Eleventy without a single edit.
//
// Handles:
//   {{< relref "/path#anchor" >}}          -> resolved site-relative URL
//   {{< callout type="info" >}} ... {{< /callout >}} -> ::: callout containers
//   {{< tabs >}} {{< tab name="X" >}} md {{< /tab >}} {{< /tabs >}} -> containers
//   {{< cards >}} {{< card ... >}} {{< /cards >}}    -> hextra-card HTML
//   {{< prompt-toc >}} {{< cve-toc >}} {{< recipe-browser >}} {{< cve-database >}}
//   {{< remediation-tool domain="..." >}} {{< playbook-workflow >}}
//   {{< marketplace-gallery >}}
//   ```mermaid fences                      -> <pre class="mermaid">
//
// Code fences are masked first so documentation about shortcodes is never
// rewritten.

const { resolveRelref } = require("./content-index");
const { escapeHtml } = require("./util");
const promptToc = require("./shortcodes/prompt-toc");
const cveToc = require("./shortcodes/cve-toc");
const recipeBrowser = require("./shortcodes/recipe-browser");
const cveDatabase = require("./shortcodes/cve-database");
const remediationTool = require("./shortcodes/remediation-tool");
const playbookWorkflow = require("./shortcodes/playbook-workflow");
const marketplaceGallery = require("./shortcodes/marketplace-gallery");
const searchIndexableCount = require("./shortcodes/search-indexable-count");

// Private-use delimiters survive string processing but cannot be mistaken for
// user-authored Markdown. Both ends are required so inline-code masks are
// restored before markdown-it sees them.
const FENCE_TOKEN = "\uE000SRFENCE";
const FENCE_END = "\uE001";

// Parse `key="value"` pairs from a shortcode argument string.
function parseAttrs(argString) {
  const attrs = {};
  const re = /([\w-]+)\s*=\s*"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(argString))) {
    attrs[m[1]] = m[2].replace(/\\"/g, '"');
  }
  return attrs;
}

function maskInlineCode(content, store) {
  // Inline code spans documenting shortcode syntax must survive verbatim.
  return content.replace(/`[^`\n]*\{\{[<%][^`\n]*`/g, (span) => {
    store.push(span);
    return `${FENCE_TOKEN}${store.length - 1}${FENCE_END}`;
  });
}

function maskFences(content, store) {
  return content.replace(/^(```|~~~)[^\n]*\n[\s\S]*?^\1[ \t]*$/gm, (block) => {
    // Mermaid fences become client-rendered <pre class="mermaid"> blocks,
    // matching how Hextra shipped diagrams to the vendored mermaid.min.js.
    const mermaid = block.match(/^(?:```|~~~)\s*mermaid[^\n]*\n([\s\S]*?)\n?(?:```|~~~)[ \t]*$/);
    const stored = mermaid
      ? `<pre class="mermaid">${escapeHtml(mermaid[1])}</pre>`
      : block;
    store.push(stored);
    return `${FENCE_TOKEN}${store.length - 1}${FENCE_END}`;
  });
}

function unmaskFences(content, store) {
  return content.replace(
    new RegExp(`${FENCE_TOKEN}(\\d+)${FENCE_END}`, "g"),
    (_, i) => store[Number(i)],
  );
}

// {{< cards >}} ... {{< /cards >}} regions collapse to one compact HTML
// block (no blank lines) so CommonMark treats the grid as a single raw
// HTML block instead of paragraph-wrapping the anchors.
function renderCards(inner, md) {
  const cards = [];
  const re = /\{\{<\s*card\s+([^>]*?)\s*>\}\}/g;
  let m;
  while ((m = re.exec(inner))) {
    const a = parseAttrs(m[1]);
    const title = escapeHtml(a.title || "");
    const subtitle = a.subtitle ? md.renderInline(a.subtitle) : "";
    cards.push(
      `<a class="hextra-card hextra-feature-card" href="${escapeHtml(a.link || "#")}">` +
        `<span class="hextra-card-icon">${title}</span>` +
        (subtitle ? `<span class="hextra-card-subtitle">${subtitle}</span>` : "") +
        `</a>`
    );
  }
  return `<div class="hextra-cards">${cards.join("")}</div>`;
}

// mdInline: a markdown-it instance used for inline rendering inside card
// subtitles. Injected from eleventy.config.js to keep one pipeline.
function createPreprocessor(mdInline) {
  return function preprocess(content, sourcePath) {
    if (!content.includes("{{<") && !content.includes("{{%") && !content.includes("```mermaid")) {
      return content;
    }

    const fences = [];
    let out = maskFences(content, fences);
    out = maskInlineCode(out, fences);

    // relref
    out = out.replace(/\{\{[<%]\s*relref\s+"([^"]+)"\s*[>%]\}\}/g, (_, target) =>
      resolveRelref(target, sourcePath)
    );

    // Self-closing custom shortcodes (site-specific components).
    out = out.replace(/\{\{[<%]\s*(prompt-toc|cve-toc|recipe-browser|cve-database|marketplace-gallery|remediation-tool|playbook-workflow|search-indexable-count)(\s[^>%]*)?[>%]\}\}/g, (_, name, args) => {
      const attrs = parseAttrs(args || "");
      switch (name) {
        case "prompt-toc": return promptToc(sourcePath);
        case "cve-toc": return cveToc(sourcePath);
        case "recipe-browser": return recipeBrowser();
        case "cve-database": return cveDatabase();
        case "marketplace-gallery": return marketplaceGallery();
        case "remediation-tool": return remediationTool(attrs.domain);
        case "playbook-workflow": return playbookWorkflow(sourcePath);
        case "search-indexable-count": return searchIndexableCount(attrs.field);
        default: return "";
      }
    });

    // cards / card
    out = out.replace(/\{\{<\s*cards\s*>\}\}([\s\S]*?)\{\{<\s*\/cards\s*>\}\}/g, (_, inner) =>
      renderCards(inner, mdInline)
    );

    // callout -> markdown-it container (inner markdown still renders)
    out = out
      .replace(/\{\{[<%]\s*callout(\s[^>%]*)?[>%]\}\}/g, (_, args) => {
        const type = parseAttrs(args || "").type || "default";
        return `\n\n::: callout ${type}\n`;
      })
      .replace(/\{\{[<%]\s*\/callout\s*[>%]\}\}/g, "\n:::\n");

    // tabs / tab -> nested containers (:::: outer, ::: inner)
    out = out
      .replace(/\{\{[<%]\s*tabs(\s[^>%]*)?[>%]\}\}/g, "\n\n:::: tabs\n")
      .replace(/\{\{[<%]\s*\/tabs\s*[>%]\}\}/g, "\n::::\n")
      .replace(/\{\{[<%]\s*tab(\s[^>%]*)?[>%]\}\}/g, (_, args) => {
        const name = parseAttrs(args || "").name || "Tab";
        // Container params survive as the info string; the renderer reads it.
        return `\n\n::: tab ${name.replace(/\n/g, " ")}\n`;
      })
      .replace(/\{\{[<%]\s*\/tab\s*[>%]\}\}/g, "\n:::\n");

    const leftover = out.match(/\{\{[<%]\s*[\w/-]+/);
    if (leftover) {
      console.warn(`[shortcodes] unhandled shortcode in ${sourcePath}: ${leftover[0]}`);
    }
    return unmaskFences(out, fences);
  };
}

module.exports = { createPreprocessor, parseAttrs };
