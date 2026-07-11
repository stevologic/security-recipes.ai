// The /recipes/ browser. Renders the controls plus a small first page of cards
// server-side (for SEO, no-JS, and fast first paint); assets/js/recipe-browser.js
// then fetches /recipes-browser.json and renders/filters the full catalogue
// client-side with pagination, so the DOM stays bounded no matter how many
// thousands of recipes exist. Card data + markup are shared via lib/recipe-cards.js.

const { escapeHtml } = require("../util");
const {
  CATEGORIES,
  browserCardObjects,
  browserStats,
  renderCardHtml,
} = require("../recipe-cards");

// How many cards the server renders into the initial HTML. Enough to fill the
// viewport and give crawlers real content without shipping the whole library.
const SSR_PAGE_SIZE = 24;

module.exports = function recipeBrowser() {
  const cards = browserCardObjects();
  const stats = browserStats(cards);
  const plural = (n) => (n === 1 ? "" : "s");

  const firstPage = cards.slice(0, SSR_PAGE_SIZE).map(renderCardHtml).join("");

  const categoryButtons = CATEGORIES.filter((c) => (stats.categoryCounts[c.slug] || 0) > 0)
    .map((c) => {
      const count = stats.categoryCounts[c.slug];
      return (
        `<button type="button" class="recipe-browser__category recipe-browser__category--${c.slug}" data-recipe-filter="${c.slug}" data-recipe-filter-label="${escapeHtml(c.label)}">` +
        `<span class="recipe-browser__category-mark"></span><strong>${escapeHtml(c.label)}</strong>` +
        `<small>${count} recipe${plural(count)}</small></button>`
      );
    })
    .join("");

  return (
    `<section class="recipe-browser" data-recipe-browser data-recipe-api="/api/recipes.json" data-recipe-legacy-api="/recipes-index.json" data-recipe-feed="/recipes-browser.json" data-recipe-mcp="/mcp" data-recipe-total="${stats.total}" data-recipe-ssr-count="${Math.min(SSR_PAGE_SIZE, stats.total)}" data-recipe-page-size="36">` +
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
    `<article><strong>${stats.total}</strong><span>Total recipes</span></article>` +
    `<article><strong>${CATEGORIES.length + 1}</strong><span>Browse lanes</span></article>` +
    `<article><strong>${stats.cve}</strong><span>CVE recipes</span></article>` +
    `<article><strong>${stats.highImpact}</strong><span>High-impact advisories</span></article>` +
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
    `<span class="recipe-browser__category-mark"></span><strong>All</strong><small>${stats.total} recipes</small></button>` +
    `<button type="button" class="recipe-browser__category recipe-browser__category--zero-day" data-recipe-filter="zero-day" data-recipe-filter-label="0-Day">` +
    `<span class="recipe-browser__category-mark"></span><strong>0-Day</strong><small>${stats.zeroDay} CVE recipe${plural(stats.zeroDay)}</small></button>` +
    categoryButtons +
    `</div>` +
    `<p id="recipe-browser-summary" class="recipe-browser__summary" data-recipe-summary>Showing ${stats.total} recipe${plural(stats.total)}.</p>` +
    `<div class="recipe-browser__grid" data-recipe-grid>${firstPage}</div>` +
    `<p class="recipe-browser__empty" data-recipe-empty hidden>No recipes match those filters.</p>` +
    `<div class="recipe-browser__more"><button type="button" class="recipe-browser__more-button" data-recipe-load-more hidden>Load more recipes</button></div>` +
    `<p class="recipe-browser__status" data-recipe-status aria-live="polite"></p>` +
    `</section>`
  );
};
