// Standalone /recipes/ product surface for curated, bounded security workflows.
// The continuously synchronized CVE corpus has its own /cve-database/ product.

const { escapeHtml } = require("../util");
const {
  CATEGORIES,
  browserCardObjects,
  browserStats,
  renderCardHtml,
} = require("../recipe-cards");

const SSR_PAGE_SIZE = 18;
const SEED_PER_CATEGORY = 36;

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
    if (perCategory[card.category] <= SEED_PER_CATEGORY) add(card);
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

  return (
    `<section class="recipe-browser recipe-library" data-recipe-browser data-recipe-api="/api/curated-recipes.json" ` +
    `data-recipe-feed="/recipes-browser.json" ` +
    `data-recipe-mcp="/mcp" data-recipe-total="${stats.total}" ` +
    `data-recipe-ssr-count="${Math.min(SSR_PAGE_SIZE, stats.total)}" data-recipe-page-size="24">` +
    `<script type="application/json" data-recipe-seed>${seedJson}</script>` +

    `<header class="recipe-library__hero" aria-labelledby="recipe-library-heading">` +
    `<div class="recipe-library__hero-copy">` +
    `<span class="recipe-library__eyebrow">Human-reviewed · agent-ready</span>` +
    `<h2 id="recipe-library-heading">Turn a finding into bounded, reviewable work.</h2>` +
    `<p>Choose the smallest recipe that matches the outcome you need. Every workflow is structured for people to inspect and agents to retrieve, with explicit inputs, guardrails, evidence, and stop conditions.</p>` +
    `<div class="recipe-library__hero-actions">` +
    `<button type="button" class="recipe-library__utility" data-recipe-copy-agent-prompt>Copy agent instructions</button>` +
    `<a class="recipe-library__utility recipe-library__utility--quiet" href="/mcp-servers/">Connect through MCP</a>` +
    `<a class="recipe-library__utility recipe-library__utility--quiet" href="/cve-database/">Open CVE Database</a>` +
    `</div></div>` +
    `<dl class="recipe-library__metrics" aria-label="Recipe library coverage">` +
    `<div><dt>Curated workflows</dt><dd>${count(stats.total)}</dd></div>` +
    `<div><dt>High completeness</dt><dd>${count(stats.worldClass)}</dd></div>` +
    `<div><dt>Model-attributed</dt><dd>${count(stats.modelAttributed)}</dd></div>` +
    `<div><dt>Outcome lanes</dt><dd>${count(stats.outcomeCount)}</dd></div>` +
    `</dl></header>` +
    `<noscript><p class="recipe-library__noscript">JavaScript is required for in-page filtering. ` +
    `The first curated results remain available below, and the full feed is available at <code>/api/curated-recipes.json</code>.</p></noscript>` +

    `<section id="recipe-library-curated" class="recipe-library__panel" aria-label="Curated security recipes">` +
    `<aside id="recipe-library-facets" class="recipe-library__facets" aria-labelledby="recipe-library-filter-heading" aria-hidden="false">` +
    `<div class="recipe-library__facet-heading"><span class="recipe-library__eyebrow">Curated collection</span>` +
    `<h3 id="recipe-library-filter-heading">Browse by outcome</h3>` +
    `<p>Start with intent, then refine by severity, outcome, and review quality. CVE-linked workflows also appear inside matching CVE records.</p>` +
    `<button type="button" class="recipe-library__filter-close" data-recipe-filter-close>Close filters</button></div>` +
    `<div class="recipe-browser__categories" role="group" aria-label="Curated recipe categories">` +
    categoryButton("all", "All curated", "Every reviewed workflow", stats.total, true) +
    categoryButtons + `</div>` +
    `<fieldset class="recipe-library__filter-group"><legend>Refine results</legend>` +
    `<label><span>Severity</span><select data-recipe-severity-filter>` +
    `<option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unspecified">Unspecified</option>` +
    `</select></label>` +
    `<label><span>Outcome</span><select data-recipe-facet-filter>` +
    `<option value="all">All outcomes</option><option value="remediation">Remediation</option><option value="risk">Risk analysis</option><option value="audit">Audit evidence</option><option value="compliance">Compliance</option><option value="code-hygiene">Code hygiene</option>` +
    `</select></label>` +
    `<label><span>Review quality</span><select data-recipe-quality-filter>` +
    `<option value="0">Any review score</option><option value="85">Complete (85+)</option><option value="70">Strong (70+)</option><option value="50">Usable (50+)</option>` +
    `</select></label>` +
    `<button type="button" class="recipe-library__reset" data-recipe-reset-filters>Clear all filters</button>` +
    `</fieldset>` +
    `<details class="recipe-library__agent-access"><summary>Agent and data access</summary>` +
    `<div><p>Retrieve the same curated workflows as structured JSON or through read-only MCP tools.</p>` +
    `<code>/api/curated-recipes.json</code><code>/mcp</code>` +
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
    `<label for="recipe-browser-search">Filter curated workflows</label>` +
    `<div class="recipe-browser__search-field">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m21 21-4.3-4.3M10.8 18a7.2 7.2 0 1 1 0-14.4 7.2 7.2 0 0 1 0 14.4Z"/></svg>` +
    `<input id="recipe-browser-search" type="search" maxlength="160" autocomplete="off" spellcheck="false" ` +
    `data-recipe-search placeholder="Finding, outcome, framework, ecosystem…" ` +
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
    `<p>Clear one or more filters, or use the dedicated database for vulnerability intelligence.</p>` +
    `<a class="recipe-library__utility" href="/cve-database/">Open CVE Database</a></div>` +
    `<div class="recipe-browser__more"><button type="button" class="recipe-browser__more-button" data-recipe-load-more hidden>Load more</button></div>` +
    `<p class="recipe-browser__status" data-recipe-status aria-live="polite"></p>` +
    `</div></section>` +
    `</section>`
  );
};
