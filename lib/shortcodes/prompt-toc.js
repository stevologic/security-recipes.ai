// Port of layouts/shortcodes/prompt-toc.html: browsable card list of the
// prompt entries that are direct children of the section invoking it.

const { childrenOf } = require("../content-index");
const { escapeHtml, truncate, isoDate } = require("../util");
const { renderAiProvenance } = require("../ai-provenance");

module.exports = function promptToc(sourcePath) {
  const pages = childrenOf(sourcePath);
  if (!pages.length) {
    return (
      `<div class="prompt-toc prompt-toc--empty"><p><em>No entries here yet.</em> ` +
      `<a href="/contribute/#contributing-a-prompt">Be the first to contribute one →</a></p></div>`
    );
  }

  const cards = pages.map((p) => {
    const fm = p.fm;
    const maturity = fm.maturity || "";
    const desc = p.description || truncate(p.summary, 180);
    const model = fm.model || fm.model_used || "";
    const date = isoDate(p.date);
    const meta = [
      fm.author && `<span class="prompt-toc__meta-item"><span class="prompt-toc__meta-label">author</span> ${escapeHtml(fm.author)}</span>`,
      fm.team && `<span class="prompt-toc__meta-item"><span class="prompt-toc__meta-label">team</span> ${escapeHtml(fm.team)}</span>`,
      renderAiProvenance(model, {
        label: fm.ai_assisted === true ? "AI-enriched" : "Tested with",
      }),
      date && `<span class="prompt-toc__meta-item"><span class="prompt-toc__meta-label">updated</span> ${date}</span>`,
    ].filter(Boolean).join("");
    const tags = p.tags.length
      ? `<div class="prompt-toc__tags">${p.tags.map((t) => `<span class="prompt-toc__tag">${escapeHtml(t)}</span>`).join("")}</div>`
      : "";
    return (
      `<a class="prompt-toc__card" href="${escapeHtml(p.url)}">` +
      `<div class="prompt-toc__head"><h3 class="prompt-toc__title">${escapeHtml(p.title)}</h3>` +
      (maturity ? `<span class="prompt-toc__maturity prompt-toc__maturity--${escapeHtml(maturity.toLowerCase())}">${escapeHtml(maturity)}</span>` : "") +
      `</div>` +
      (desc ? `<p class="prompt-toc__desc">${escapeHtml(desc)}</p>` : "") +
      `<div class="prompt-toc__meta">${meta}</div>` +
      tags +
      `</a>`
    );
  });

  return `<div class="prompt-toc">${cards.join("")}</div>`;
};
