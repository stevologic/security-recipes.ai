// Port of layouts/shortcodes/recipe-browser.html: the /recipes/ browser.
// Static card grid over every prompt-library recipe; filtering, search,
// and downloads stay client-side in assets/js/recipe-browser.js.

const { regularPagesUnder } = require("../content-index");
const { recipeModel } = require("../recipe-model");
const { escapeHtml } = require("../util");

const CATEGORIES = [
  { slug: "cve", label: "CVE", description: "Named advisory and vulnerability recipes" },
  { slug: "general", label: "General", description: "Reusable prompts, toolsets, and review patterns" },
  { slug: "classic-defaults", label: "Defaults", description: "Recurring unsafe defaults and hardening prompts" },
  { slug: "compliance-standards", label: "Compliance", description: "Audit evidence and standards-readiness checks" },
  { slug: "crypto-defi", label: "Crypto/DeFi", description: "Blockchain, wallet, bridge, and payment recipes" },
];

module.exports = function recipeBrowser() {
  // Sort by date desc like Hugo's `sort $pages "Date" "desc"`.
  const models = regularPagesUnder("prompt-library/")
    .map(recipeModel)
    .sort((a, b) => b.date.localeCompare(a.date) || a.page.title.localeCompare(b.page.title, "en"));

  // 7-day zero-day window anchored to today (browser variant of the rule).
  const { localDate } = require("../util");
  const since = localDate(new Date(Date.now() - 6 * 86400000));

  const categoryCounts = {};
  let cveCount = 0;
  let highImpactCount = 0;
  let zeroDayCount = 0;
  for (const m of models) {
    const cat = m.browserCategory.slug;
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
    if (cat === "cve") cveCount += 1;
    const zeroDayDate = m.disclosed || m.date;
    if (cat === "cve" && zeroDayDate && zeroDayDate >= since) zeroDayCount += 1;
    if (m.severity === "critical" || m.severity === "high") highImpactCount += 1;
  }

  const plural = (n) => (n === 1 ? "" : "s");

  const cards = models.map((m) => {
    const cat = m.browserCategory;
    const severity = m.severity || "unspecified";
    const maturity = m.maturity || "unspecified";
    const publishedDate = cat.slug === "cve" ? m.disclosed || m.date : "";
    const zeroDayDate = m.disclosed || m.date;
    const isZeroDay = cat.slug === "cve" && !!zeroDayDate && zeroDayDate >= since;
    const identity = m.cve || m.ghsa || m.tool || m.agent || cat.label;
    const facetString = m.facets.join(" ");
    const searchParts = [
      m.page.title, m.browserSummary, identity, cat.label, severity, maturity,
      m.tagText, facetString, m.ecosystem, m.author, m.team, m.model,
      m.cve, m.ghsa, publishedDate,
    ];
    if (isZeroDay) searchParts.push("0-day zero-day recent latest");
    searchParts.push(...m.knownAs);
    const searchIndex = searchParts.filter(Boolean).join(" ");

    const topline =
      `<span>${escapeHtml(cat.label)}</span>` +
      (isZeroDay ? `<span class="recipe-browser-card__fresh">0-Day</span>` : "") +
      (severity !== "unspecified"
        ? `<span class="recipe-browser-card__severity recipe-browser-card__severity--${escapeHtml(severity)}">${escapeHtml(severity)}</span>`
        : `<span>${escapeHtml(maturity)}</span>`) +
      `<span class="recipe-browser-card__quality recipe-browser-card__quality--${m.quality.tier}">${m.quality.tier} ${m.quality.score}</span>`;

    const meta =
      (identity ? `<span>${escapeHtml(identity)}</span>` : "") +
      (publishedDate ? `<span>Published ${escapeHtml(publishedDate)}</span>` : "") +
      (m.ecosystem ? `<span>${escapeHtml(m.ecosystem)}</span>` : "") +
      (m.page.fm.model ? `<span>${escapeHtml(m.page.fm.model)}</span>` : "");

    return (
      `<article class="recipe-browser-card recipe-browser-card--${cat.slug}${isZeroDay ? " recipe-browser-card--zero-day" : ""}"` +
      ` data-recipe-card data-recipe-category="${cat.slug}" data-recipe-zero-day="${isZeroDay}"` +
      ` data-recipe-severity="${escapeHtml(severity)}" data-recipe-facets="${facetString}"` +
      ` data-recipe-quality="${m.quality.score}" data-recipe-readiness="${m.quality.tier}"` +
      ` data-recipe-maturity="${escapeHtml(maturity)}" data-recipe-date="${m.date}"` +
      ` data-recipe-published="${escapeHtml(publishedDate)}" data-recipe-title="${escapeHtml(m.page.title)}"` +
      ` data-recipe-summary="${escapeHtml(m.browserSummary)}" data-recipe-slug="${escapeHtml(m.slug)}"` +
      ` data-recipe-path="${escapeHtml(m.page.url)}" data-recipe-source="${escapeHtml(m.source)}"` +
      ` data-recipe-index="${escapeHtml(searchIndex)}">` +
      `<div class="recipe-browser-card__visual" aria-hidden="true"><span>${escapeHtml(cat.label.slice(0, 2).toUpperCase())}</span></div>` +
      `<div class="recipe-browser-card__content">` +
      `<div class="recipe-browser-card__topline">${topline}</div>` +
      `<h3><a href="${escapeHtml(m.page.url)}">${escapeHtml(m.page.title)}</a></h3>` +
      (m.browserSummary ? `<p>${escapeHtml(m.browserSummary)}</p>` : "") +
      `<div class="recipe-browser-card__facets" aria-label="Recipe facets">${m.facets.map((f) => `<span>${f.replace(/-/g, " ")}</span>`).join("")}</div>` +
      `<div class="recipe-browser-card__meta">${meta}</div>` +
      `<div class="recipe-browser-card__actions">` +
      `<a class="recipe-browser-card__open" href="${escapeHtml(m.page.url)}">Open recipe</a>` +
      `<button type="button" class="recipe-browser-card__download" data-recipe-download aria-label="Download ${escapeHtml(m.page.title)} recipe JSON">` +
      `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v10m0 0 4-4m-4 4-4-4M5 19h14"/></svg>` +
      `<span>Download</span></button></div>` +
      `</div></article>`
    );
  });

  const categoryButtons = CATEGORIES.filter((c) => (categoryCounts[c.slug] || 0) > 0)
    .map((c) => {
      const count = categoryCounts[c.slug];
      return (
        `<button type="button" class="recipe-browser__category recipe-browser__category--${c.slug}" data-recipe-filter="${c.slug}" data-recipe-filter-label="${escapeHtml(c.label)}">` +
        `<span class="recipe-browser__category-mark"></span><strong>${escapeHtml(c.label)}</strong>` +
        `<small>${count} recipe${plural(count)}</small></button>`
      );
    })
    .join("");

  return (
    `<section class="recipe-browser" data-recipe-browser data-recipe-api="/api/recipes.json" data-recipe-legacy-api="/recipes-index.json" data-recipe-mcp="/mcp">` +
    `<div class="recipe-browser__hero">` +
    `<div class="recipe-browser__intro"><h2>Recipes</h2>` +
    `<p>Search the working shelf of reusable security recipes, filter by the problem surface, open the full recipe, or download a portable JSON copy for downstream review, MCP context, and agent handoff.</p></div>` +
    `<div class="recipe-browser__agent-endpoint"><div>` +
    `<span class="recipe-browser__eyeline">Agent endpoints</span>` +
    `<div class="recipe-browser__endpoint-list">` +
    `<div><span>JSON feed</span><code>/api/recipes.json</code></div>` +
    `<div><span>MCP server</span><code>/mcp</code></div>` +
    `</div></div>` +
    `<div class="recipe-browser__endpoint-actions">` +
    `<button type="button" class="recipe-browser__icon-button" data-recipe-copy-endpoint aria-label="Copy agent endpoint">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 8V6.6A2.6 2.6 0 0 1 10.6 4h6.8A2.6 2.6 0 0 1 20 6.6v6.8a2.6 2.6 0 0 1-2.6 2.6H16M6.6 8h6.8A2.6 2.6 0 0 1 16 10.6v6.8a2.6 2.6 0 0 1-2.6 2.6H6.6A2.6 2.6 0 0 1 4 17.4v-6.8A2.6 2.6 0 0 1 6.6 8Z"/></svg>` +
    `<span>Copy</span></button>` +
    `<button type="button" class="recipe-browser__icon-button" data-recipe-copy-agent-prompt aria-label="Copy agent recipe instructions">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 7h8M8 11h8M8 15h5M5.8 3.8h12.4A1.8 1.8 0 0 1 20 5.6v12.8a1.8 1.8 0 0 1-1.8 1.8H5.8A1.8 1.8 0 0 1 4 18.4V5.6a1.8 1.8 0 0 1 1.8-1.8Z"/></svg>` +
    `<span>Prompt</span></button>` +
    `<button type="button" class="recipe-browser__icon-button" data-recipe-download-all aria-label="Download recipe endpoint JSON">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v10m0 0 4-4m-4 4-4-4M5 19h14"/></svg>` +
    `<span>JSON</span></button>` +
    `</div></div></div>` +
    `<div class="recipe-browser__stats" aria-label="Recipe library summary">` +
    `<article><strong>${models.length}</strong><span>Total recipes</span></article>` +
    `<article><strong>${CATEGORIES.length + 1}</strong><span>Browse lanes</span></article>` +
    `<article><strong>${cveCount}</strong><span>CVE recipes</span></article>` +
    `<article><strong>${highImpactCount}</strong><span>High-impact advisories</span></article>` +
    `</div>` +
    `<div class="recipe-browser__controls">` +
    `<div class="recipe-browser__search" role="search">` +
    `<label for="recipe-browser-search">Search every recipe</label>` +
    `<div class="recipe-browser__search-field">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m21 21-4.3-4.3M10.8 18a7.2 7.2 0 1 1 0-14.4 7.2 7.2 0 0 1 0 14.4Z"/></svg>` +
    `<input id="recipe-browser-search" type="search" autocomplete="off" spellcheck="false" data-recipe-search placeholder="Search by title, CVE, tag, ecosystem, severity, toolset..." aria-describedby="recipe-browser-summary" aria-autocomplete="list" aria-haspopup="listbox" aria-expanded="false">` +
    `<button type="button" class="recipe-browser__search-clear" data-recipe-clear-search hidden aria-label="Clear recipe search">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>` +
    `</button></div></div>` +
    `<div class="recipe-browser__selects">` +
    `<label><span>Severity</span><select data-recipe-severity-filter>` +
    `<option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unspecified">Unspecified</option>` +
    `</select></label>` +
    `<label><span>Facet</span><select data-recipe-facet-filter>` +
    `<option value="all">All facets</option><option value="remediation">Remediation</option><option value="risk">Risk</option><option value="audit">Audit</option><option value="compliance">Compliance</option><option value="code-hygiene">Code hygiene</option>` +
    `</select></label>` +
    `<label><span>Quality</span><select data-recipe-quality-filter>` +
    `<option value="0">All quality</option><option value="85">World-class</option><option value="70">Strong+</option><option value="50">Usable+</option>` +
    `</select></label>` +
    `<label><span>Sort</span><select data-recipe-sort>` +
    `<option value="newest">Newest</option><option value="title">Title</option><option value="severity">Severity</option><option value="quality">Quality</option>` +
    `</select></label>` +
    `</div></div>` +
    `<div class="recipe-browser__categories" aria-label="Category filters">` +
    `<button type="button" class="recipe-browser__category recipe-browser__category--all is-active" data-recipe-filter="all" data-recipe-filter-label="All">` +
    `<span class="recipe-browser__category-mark"></span><strong>All</strong><small>${models.length} recipes</small></button>` +
    `<button type="button" class="recipe-browser__category recipe-browser__category--zero-day" data-recipe-filter="zero-day" data-recipe-filter-label="0-Day">` +
    `<span class="recipe-browser__category-mark"></span><strong>0-Day</strong><small>${zeroDayCount} CVE recipe${plural(zeroDayCount)}</small></button>` +
    categoryButtons +
    `</div>` +
    `<p id="recipe-browser-summary" class="recipe-browser__summary" data-recipe-summary>Showing ${models.length} recipe${plural(models.length)}.</p>` +
    `<div class="recipe-browser__grid" data-recipe-grid>${cards.join("")}</div>` +
    `<p class="recipe-browser__empty" data-recipe-empty hidden>No recipes match those filters.</p>` +
    `<p class="recipe-browser__status" data-recipe-status aria-live="polite"></p>` +
    `</section>`
  );
};
