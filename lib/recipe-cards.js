// Single source of truth for the /recipes/ catalogue cards. Both the slim
// /recipes-browser.json feed (lib/feeds.js) and the server-rendered first page
// (lib/shortcodes/recipe-browser.js) consume browserCardObjects() so their data
// can never drift. renderCardHtml() is the server-side markup; the client
// mirror lives in assets/js/recipe-browser.js and must match it byte-for-byte.

const { regularPagesUnder, isDiscoveryPage } = require("./content-index");
const { recipeModel } = require("./recipe-model");
const { escapeHtml, localDate } = require("./util");
const { renderAiProvenance } = require("./ai-provenance");

// The catalogue's short category labels, in display order.
const CATEGORIES = [
  { slug: "general", label: "General", description: "Reusable prompts, toolsets, and review patterns" },
  { slug: "classic-defaults", label: "Defaults", description: "Recurring unsafe defaults and hardening prompts" },
  { slug: "compliance-standards", label: "Compliance", description: "Audit evidence and standards-readiness checks" },
  { slug: "code-hygiene", label: "Code Hygiene", description: "Language-specific maintainability and correctness workflows" },
  { slug: "crypto-defi", label: "Crypto/DeFi", description: "Blockchain, wallet, bridge, and payment recipes" },
];

function workflowArchetypeLabel(value) {
  if (value === "*") return "All CVEs";
  return String(value || "")
    .split("_")
    .filter(Boolean)
    .map((part) => ["ssrf", "xxe", "idor", "dos", "sql", "http"].includes(part)
      ? part.toUpperCase()
      : part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function workflowRelationshipText(card) {
  const archetypes = Array.isArray(card.cveArchetypes) ? card.cveArchetypes : [];
  if (!archetypes.length) return "";
  const shown = archetypes.slice(0, 2).map(workflowArchetypeLabel).join(", ");
  const remaining = archetypes.length - 2;
  const roleText = String(card.cveWorkflowRole || "remediate").replace(/-/g, " ");
  const role = roleText.charAt(0).toUpperCase() + roleText.slice(1);
  return `CVE ${role} · ${shown}${remaining > 0 ? ` +${remaining}` : ""}`;
}

// Plain card objects for every recipes recipe, sorted newest-first
// (matching the catalogue's default "Newest" sort).
function browserCardObjects() {
  const models = regularPagesUnder("recipes/")
    .filter((page) => isDiscoveryPage(page) && !page.sourcePath.startsWith("recipes/cve/"))
    .map(recipeModel)
    .sort((a, b) => b.date.localeCompare(a.date) || a.page.title.localeCompare(b.page.title, "en"));

  // 7-day zero-day window anchored to today.
  const since = localDate(new Date(Date.now() - 6 * 86400000));

  return models.map((m) => {
    const cat = m.browserCategory;
    const severity = m.severity || "unspecified";
    const maturity = m.maturity || "unspecified";
    const published = cat.slug === "cve" ? m.disclosed || m.date : "";
    const zeroDayDate = m.disclosed || m.date;
    const zeroDay = cat.slug === "cve" && !!zeroDayDate && zeroDayDate >= since;
    const identity = m.cve || m.ghsa || m.framework || m.recipeId || m.tool || m.agent || cat.label;
    const searchParts = [
      m.page.title, m.browserSummary, identity, cat.label, severity, maturity,
      m.tagText, m.facets.join(" "), m.ecosystem, m.author, m.team, m.model,
      m.cve, m.ghsa, m.recipeId, m.framework, m.frameworkVersion,
      m.jurisdiction, m.industry.join(" "), published,
      m.cveArchetypes.join(" "), m.cveWorkflowRole,
    ];
    if (zeroDay) searchParts.push("0-day zero-day recent latest");
    searchParts.push(...m.knownAs);
    const search = searchParts.filter(Boolean).join(" ").toLowerCase();
    return {
      slug: m.slug,
      title: m.page.title,
      url: m.page.url,
      category: cat.slug,
      categoryLabel: cat.label,
      severity,
      maturity,
      quality: m.quality.score,
      tier: m.quality.tier,
      facets: m.facets,
      date: m.date,
      published,
      ecosystem: m.ecosystem,
      identity,
      cve: m.cve,
      summary: m.browserSummary,
      model: m.model,
      aiAssisted: m.aiAssisted,
      generatedBy: m.generatedBy,
      zeroDay,
      cveArchetypes: m.cveArchetypes,
      cveWorkflowRole: m.cveWorkflowRole,
      search,
    };
  });
}

// Library-wide counters shown in the catalogue hero.
function browserStats(cards) {
  const categoryCounts = {};
  let cve = 0;
  let highImpact = 0;
  let zeroDay = 0;
  let worldClass = 0;
  let aiAssisted = 0;
  let modelAttributed = 0;
  const outcomes = new Set();
  for (const c of cards) {
    categoryCounts[c.category] = (categoryCounts[c.category] || 0) + 1;
    if (c.category === "cve") cve += 1;
    if (c.zeroDay) zeroDay += 1;
    if (c.severity === "critical" || c.severity === "high") highImpact += 1;
    if (c.tier === "world-class") worldClass += 1;
    if (c.aiAssisted && c.model) aiAssisted += 1;
    if (c.model) modelAttributed += 1;
    c.facets.forEach((facet) => outcomes.add(facet));
  }
  return {
    total: cards.length,
    cve,
    highImpact,
    zeroDay,
    worldClass,
    aiAssisted,
    modelAttributed,
    outcomeCount: outcomes.size,
    categoryCounts,
  };
}

// Server-side markup for one card. Kept lean: the client filters over the feed
// array, not DOM attributes, so a card only needs its slug (for the download
// button) plus the visible content. MUST stay identical to buildCardHtml() in
// assets/js/recipe-browser.js.
function renderCardHtml(card) {
  const severity = card.severity || "unspecified";
  const displayTier = card.tier === "world-class" ? "complete" : card.tier;
  const topline =
    `<span>${escapeHtml(card.categoryLabel)}</span>` +
    (card.zeroDay ? `<span class="recipe-browser-card__fresh">0-Day</span>` : "") +
    (severity !== "unspecified"
      ? `<span class="recipe-browser-card__severity recipe-browser-card__severity--${escapeHtml(severity)}">${escapeHtml(severity)}</span>`
      : `<span>${escapeHtml(card.maturity)}</span>`) +
    `<span class="recipe-browser-card__quality recipe-browser-card__quality--${escapeHtml(card.tier)}">${escapeHtml(displayTier)} ${card.quality}</span>`;

  const meta =
    (card.identity ? `<span>${escapeHtml(card.identity)}</span>` : "") +
    (card.published ? `<span>Published ${escapeHtml(card.published)}</span>` : "") +
    (card.ecosystem ? `<span>${escapeHtml(card.ecosystem)}</span>` : "") +
    renderAiProvenance(card.model, {
      label: card.aiAssisted ? "AI-enriched" : "Tested with",
    });
  const evidenceLink = card.cve
    ? `<a class="recipe-browser-card__evidence" href="/cve/${encodeURIComponent(card.cve.toUpperCase())}/" ` +
      `aria-describedby="recipe-card-${escapeHtml(card.slug)}">CVE evidence</a>`
    : "";
  const workflowRelationship = workflowRelationshipText(card);

  return (
    `<article class="recipe-browser-card recipe-browser-card--${escapeHtml(card.category)}${card.zeroDay ? " recipe-browser-card--zero-day" : ""}" data-recipe-card data-recipe-slug="${escapeHtml(card.slug)}" data-recipe-path="${escapeHtml(card.url)}" aria-labelledby="recipe-card-${escapeHtml(card.slug)}">` +
    `<div class="recipe-browser-card__visual" aria-hidden="true"><span>${escapeHtml(card.categoryLabel.slice(0, 2).toUpperCase())}</span></div>` +
    `<div class="recipe-browser-card__content">` +
    `<div class="recipe-browser-card__topline">${topline}</div>` +
    `<h3 id="recipe-card-${escapeHtml(card.slug)}">${escapeHtml(card.title)}</h3>` +
    (card.summary ? `<p>${escapeHtml(card.summary)}</p>` : "") +
    `<ul class="recipe-browser-card__facets" aria-label="Recipe outcomes">${card.facets.map((f) => `<li>${escapeHtml(f.replace(/-/g, " "))}</li>`).join("")}</ul>` +
    `<div class="recipe-browser-card__meta">${meta}` +
    (workflowRelationship
      ? `<span class="recipe-browser-card__cve-linkage">${escapeHtml(workflowRelationship)}</span>`
      : "") +
    `</div>` +
    `<div class="recipe-browser-card__actions">` +
    `<a class="recipe-browser-card__open" href="${escapeHtml(card.url)}" aria-describedby="recipe-card-${escapeHtml(card.slug)}">Open</a>` +
    evidenceLink +
    `<button type="button" class="recipe-browser-card__download" data-recipe-download aria-label="Download ${escapeHtml(card.title)} recipe JSON">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v10m0 0 4-4m-4 4-4-4M5 19h14"/></svg>` +
    `<span>Download</span></button></div>` +
    `</div></article>`
  );
}

module.exports = {
  CATEGORIES,
  browserCardObjects,
  browserStats,
  renderCardHtml,
  workflowRelationshipText,
};
