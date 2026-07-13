// Federated /recipes/ library shell. Curated recipes remain a small, fast
// browser feed while the complete CVE collection stays on its worker/shard
// path. The page presents both as first-class collections without merging
// incomparable rankings or moving hundreds of thousands of records onto the main thread.

const fs = require("node:fs");
const path = require("node:path");
const { escapeHtml } = require("../util");
const {
  CATEGORIES,
  browserCardObjects,
  browserStats,
  renderCardHtml,
} = require("../recipe-cards");

const SSR_PAGE_SIZE = 18;
const SEED_PER_CATEGORY = 36;
const RUNTIME_SUMMARY = path.join(
  __dirname,
  "..",
  "..",
  "static",
  "api",
  "cve-catalog",
  "runtime-summary.json",
);

function readCveStats() {
  try {
    const summary = JSON.parse(fs.readFileSync(RUNTIME_SUMMARY, "utf8"));
    return {
      total: Number(summary?.totals?.catalog_records) || 0,
      critical: Number(summary?.by_severity?.critical) || 0,
      high: Number(summary?.by_severity?.high) || 0,
      medium: Number(summary?.by_severity?.medium) || 0,
      kev: Number(summary?.totals?.in_scope_kev) || 0,
      stableOverrides: Number(summary?.totals?.stable_markdown_overrides) || 0,
    };
  } catch {
    return { total: 0, critical: 0, high: 0, medium: 0, kev: 0, stableOverrides: 0 };
  }
}

function seedCards(cards) {
  const seen = new Set();
  const seed = [];
  const add = (card) => {
    if (!seen.has(card.url)) {
      seen.add(card.url);
      seed.push(card);
    }
  };
  cards.slice(0, SSR_PAGE_SIZE).forEach(add);
  const perCategory = {};
  for (const card of cards) {
    perCategory[card.category] = (perCategory[card.category] || 0) + 1;
    if (card.category !== "cve" && perCategory[card.category] <= SEED_PER_CATEGORY) add(card);
  }
  return seed;
}

function count(value) {
  return Number(value || 0).toLocaleString("en-US");
}

function categoryButton(slug, label, description, itemCount, active = false) {
  return (
    `<button type="button" class="recipe-browser__category recipe-browser__category--${slug}${active ? " is-active" : ""}" ` +
    `data-recipe-filter="${slug}" data-recipe-filter-label="${escapeHtml(label)}" aria-pressed="${active}">` +
    `<span class="recipe-browser__category-mark" aria-hidden="true"></span>` +
    `<span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(description)}</small></span>` +
    `<b>${count(itemCount)}</b></button>`
  );
}

module.exports = function recipeBrowser() {
  const cards = browserCardObjects();
  const stats = browserStats(cards);
  const cve = readCveStats();
  const uniqueTotal = Math.max(cards.length, cards.length + cve.total - cve.stableOverrides);
  const firstPage = cards.slice(0, SSR_PAGE_SIZE).map(renderCardHtml).join("");
  const seedJson = JSON.stringify(seedCards(cards)).replace(/</g, "\\u003c");

  const categoryButtons = CATEGORIES.filter((category) => (stats.categoryCounts[category.slug] || 0) > 0)
    .map((category) => categoryButton(
      category.slug,
      category.label,
      category.description,
      stats.categoryCounts[category.slug],
    ))
    .join("");

  const weeklyButton = stats.zeroDay > 0
    ? categoryButton("zero-day", "New this week", "Recently disclosed CVE overrides", stats.zeroDay)
    : "";

  return (
    `<section class="recipe-browser recipe-library" data-recipe-browser data-recipe-api="/api/recipes.json" ` +
    `data-recipe-legacy-api="/recipes-index.json" data-recipe-feed="/recipes-browser.json" ` +
    `data-recipe-mcp="/mcp" data-recipe-total="${stats.total}" data-cve-total="${cve.total}" ` +
    `data-recipe-ssr-count="${Math.min(SSR_PAGE_SIZE, stats.total)}" data-recipe-page-size="24">` +
    `<script type="application/json" data-recipe-seed>${seedJson}</script>` +

    `<header class="recipe-library__hero" aria-labelledby="recipe-library-heading">` +
    `<div class="recipe-library__hero-copy">` +
    `<span class="recipe-library__eyebrow">Federated security knowledge</span>` +
    `<h2 id="recipe-library-heading">One library. Two purpose-built indexes.</h2>` +
    `<p>Choose reviewed workflow guidance for a security task, or search the complete medium, high, and critical CVE catalog. Each collection keeps the ranking, filters, and retrieval path that fit its scale.</p>` +
    `<div class="recipe-library__hero-actions">` +
    `<button type="button" class="recipe-library__utility" data-recipe-copy-agent-prompt>Copy agent instructions</button>` +
    `<a class="recipe-library__utility recipe-library__utility--quiet" href="/mcp-servers/">Connect through MCP</a>` +
    `</div></div>` +
    `<dl class="recipe-library__metrics" aria-label="Library coverage">` +
    `<div><dt>Unique entries</dt><dd>${count(uniqueTotal)}</dd></div>` +
    `<div><dt>Curated workflows</dt><dd>${count(stats.total)}</dd></div>` +
    `<div><dt>Scored CVEs</dt><dd>${count(cve.total)}</dd></div>` +
    `<div><dt>CISA known exploited</dt><dd>${count(cve.kev)}</dd></div>` +
    `</dl></header>` +

    `<div class="recipe-library__scope" role="tablist" aria-label="Recipe collections">` +
    `<button id="recipe-library-curated-tab" type="button" role="tab" aria-selected="true" ` +
    `aria-controls="recipe-library-curated" tabindex="0" data-library-tab="curated">` +
    `<span>Curated workflows</span><strong>${count(stats.total)}</strong><small>Reviewed instructions, evidence checks, and agent context</small></button>` +
    `<button id="recipe-library-cve-tab" type="button" role="tab" aria-selected="false" ` +
    `aria-controls="recipe-library-cve" tabindex="-1" data-library-tab="cve">` +
    `<span>CVE catalog</span><strong>${count(cve.total)}</strong><small>${count(cve.critical)} critical · ${count(cve.high)} high · ${count(cve.medium)} medium · ${count(cve.kev)} KEV</small></button>` +
    `</div>` +
    `<noscript><p class="recipe-library__noscript">JavaScript is required for in-page filtering. ` +
    `<a href="/recipes/cve/">Open the complete CVE catalog</a>, or browse the first curated results below.</p></noscript>` +

    `<section id="recipe-library-curated" class="recipe-library__panel" role="tabpanel" ` +
    `aria-labelledby="recipe-library-curated-tab" data-library-panel="curated">` +
    `<aside id="recipe-library-facets" class="recipe-library__facets" aria-labelledby="recipe-library-filter-heading" aria-hidden="false">` +
    `<div class="recipe-library__facet-heading"><span class="recipe-library__eyebrow">Curated collection</span>` +
    `<h3 id="recipe-library-filter-heading">Browse by outcome</h3>` +
    `<p>Use filters to narrow the reviewed collection. CVE-scale search lives in its own tab.</p>` +
    `<button type="button" class="recipe-library__filter-close" data-recipe-filter-close>Close filters</button></div>` +
    `<div class="recipe-browser__categories" role="group" aria-label="Curated recipe categories">` +
    categoryButton("all", "All curated", "Every reviewed workflow", stats.total, true) +
    weeklyButton + categoryButtons + `</div>` +
    `<fieldset class="recipe-library__filter-group"><legend>Refine results</legend>` +
    `<label><span>Severity</span><select data-recipe-severity-filter>` +
    `<option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unspecified">Unspecified</option>` +
    `</select></label>` +
    `<label><span>Outcome</span><select data-recipe-facet-filter>` +
    `<option value="all">All outcomes</option><option value="remediation">Remediation</option><option value="risk">Risk analysis</option><option value="audit">Audit evidence</option><option value="compliance">Compliance</option><option value="code-hygiene">Code hygiene</option>` +
    `</select></label>` +
    `<label><span>Review quality</span><select data-recipe-quality-filter>` +
    `<option value="0">Any review score</option><option value="85">World-class</option><option value="70">Strong+</option><option value="50">Usable+</option>` +
    `</select></label>` +
    `<button type="button" class="recipe-library__reset" data-recipe-reset-filters>Clear all filters</button>` +
    `</fieldset>` +
    `<details class="recipe-library__agent-access"><summary>Agent and data access</summary>` +
    `<div><p>Use the curated JSON feed for workflow recipes. Use dedicated CVE tools for the complete catalog.</p>` +
    `<code>/api/recipes.json</code><code>/mcp</code>` +
    `<div class="recipe-library__agent-actions">` +
    `<button type="button" data-recipe-copy-endpoint>Copy feed URL</button>` +
    `<button type="button" data-recipe-download-all>Download curated feed</button>` +
    `</div></div></details>` +
    `</aside>` +

    `<div class="recipe-library__results">` +
    `<div class="recipe-library__toolbar">` +
    `<button type="button" class="recipe-library__filter-toggle" data-recipe-filter-toggle ` +
    `aria-expanded="false" aria-controls="recipe-library-facets">Filters <span data-recipe-filter-count>0</span></button>` +
    `<div class="recipe-browser__search" role="search">` +
    `<label for="recipe-browser-search">Search curated workflows</label>` +
    `<div class="recipe-browser__search-field">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m21 21-4.3-4.3M10.8 18a7.2 7.2 0 1 1 0-14.4 7.2 7.2 0 0 1 0 14.4Z"/></svg>` +
    `<input id="recipe-browser-search" type="search" maxlength="160" autocomplete="off" spellcheck="false" ` +
    `data-recipe-search placeholder="Title, finding type, framework, ecosystem…" ` +
    `aria-describedby="recipe-browser-summary" aria-autocomplete="list" aria-haspopup="listbox" aria-expanded="false">` +
    `<button type="button" class="recipe-browser__search-clear" data-recipe-clear-search hidden aria-label="Clear recipe search">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg></button>` +
    `</div></div>` +
    `<label class="recipe-library__sort"><span>Sort</span><select data-recipe-sort>` +
    `<option value="newest">Recently updated</option><option value="title">Title</option>` +
    `<option value="severity">Severity</option><option value="quality">Review quality</option>` +
    `</select></label>` +
    `</div>` +
    `<div class="recipe-library__active-filters" data-recipe-active-filters aria-label="Active filters"></div>` +
    `<div class="recipe-library__result-heading">` +
    `<p id="recipe-browser-summary" class="recipe-browser__summary" data-recipe-summary role="status" aria-live="polite" aria-atomic="true">` +
    `Showing ${Math.min(SSR_PAGE_SIZE, stats.total)} of ${count(stats.total)} curated recipes.</p>` +
    `<span>Dense list view</span></div>` +
    `<div class="recipe-browser__grid" data-recipe-grid>${firstPage}</div>` +
    `<div class="recipe-browser__empty" data-recipe-empty hidden>` +
    `<strong>No curated workflows match those filters.</strong>` +
    `<p>Try clearing a filter, or send this query to the complete CVE catalog.</p>` +
    `<button type="button" data-recipe-search-cve>Search the CVE catalog</button></div>` +
    `<div class="recipe-browser__more"><button type="button" class="recipe-browser__more-button" data-recipe-load-more hidden>Load more</button></div>` +
    `<p class="recipe-browser__status" data-recipe-status aria-live="polite"></p>` +
    `</div></section>` +

    `<section id="recipe-library-cve" class="recipe-library__panel recipe-library__panel--cve" role="tabpanel" ` +
    `aria-labelledby="recipe-library-cve-tab" data-library-panel="cve" hidden>` +
    `<div class="recipe-library__cve-guide">` +
    `<div><span class="recipe-library__eyebrow">Complete generated coverage</span>` +
    `<h3>Search 10 years of medium, high, and critical CVEs</h3>` +
    `<p>Paste any complete CVE ID to open its record immediately. Or search words from a vulnerability title, then narrow every in-scope record by severity, year, or CISA KEV status.</p></div>` +
    `<div class="recipe-library__cve-paths" aria-label="Common CVE paths">` +
    `<button type="button" data-cve-shortcut="kev">Known exploited <strong>${count(cve.kev)}</strong></button>` +
    `<button type="button" data-cve-shortcut="critical">Critical <strong>${count(cve.critical)}</strong></button>` +
    `<button type="button" data-cve-shortcut="high">High <strong>${count(cve.high)}</strong></button>` +
    `<button type="button" data-cve-shortcut="medium">Medium <strong>${count(cve.medium)}</strong></button>` +
    `<a href="/recipes/cve/">Catalog methodology</a>` +
    `</div></div>` +
    `<div data-cve-catalog data-cve-catalog-deferred data-cve-catalog-base="/api/cve-catalog/"></div>` +
    `</section>` +
    `</section>`
  );
};
