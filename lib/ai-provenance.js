const { escapeHtml } = require("./util");

function renderAiProvenance(model, options = {}) {
  const normalizedModel = String(model || "").trim();
  if (!normalizedModel) return "";
  const label = String(options.label || "AI-assisted").trim() || "AI-assisted";
  const title = /\bwith$/i.test(label)
    ? `${label} ${normalizedModel}`
    : `${label} with ${normalizedModel}`;
  return (
    `<span class="sr-ai-provenance" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}">` +
    `<span class="sr-ai-provenance__icon" aria-hidden="true">✦</span>` +
    `<span class="sr-ai-provenance__label">${escapeHtml(label)}</span>` +
    `<code>${escapeHtml(normalizedModel)}</code>` +
    `</span>`
  );
}

module.exports = { renderAiProvenance };
