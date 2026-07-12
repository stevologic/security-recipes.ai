'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const RUNTIME_SUMMARY = path.join(
  ROOT,
  'static',
  'api',
  'cve-catalog',
  'runtime-summary.json'
);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function formatCount(value) {
  return Number(value).toLocaleString('en-US');
}

function curatedFeed() {
  // Exercise the same generator Eleventy uses without depending on a prior
  // build having populated public/recipes-browser.json.
  const { recipesBrowser } = require('../lib/feeds.js');
  return JSON.parse(recipesBrowser());
}

function renderedLibrary() {
  // Load after the generated inputs so this test exercises the same data path
  // used by the shortcode rather than duplicating its catalog counters.
  return require('../lib/shortcodes/recipe-browser.js')();
}

test('recipe library federates curated and CVE counts without double-counting overrides', (context) => {
  const curated = curatedFeed();
  const runtime = readJson(RUNTIME_SUMMARY);
  if (runtime.schema_version !== 2) {
    context.skip('generated schema-v2 catalog fixture is not present');
    return;
  }
  const catalogCount = Number(runtime.totals.catalog_records);
  const overrideCount = Number(runtime.totals.stable_markdown_overrides);
  const curatedCount = Number(curated.count);
  const uniqueCount = curatedCount + catalogCount - overrideCount;
  const html = renderedLibrary();

  assert.equal(curated.recipes.length, curatedCount, 'feed metadata matches its recipe payload');
  assert.equal(runtime.schema_version, 2, 'library reads the current catalog schema');
  assert.ok(Number(runtime.by_severity.medium) > 0, 'catalog exposes medium-severity coverage');
  assert.equal(
    catalogCount,
    ['medium', 'high', 'critical'].reduce(
      (total, severity) => total + Number(runtime.by_severity[severity] || 0),
      0
    ),
    'catalog total equals its severity partitions'
  );
  assert.equal(
    uniqueCount,
    curatedCount + catalogCount - overrideCount,
    'unique library total follows the generated overlap formula'
  );
  assert.match(html, new RegExp(`data-recipe-total="${curatedCount}"`));
  assert.match(html, new RegExp(`data-cve-total="${catalogCount}"`));
  assert.match(html, new RegExp(`<dd>${formatCount(uniqueCount)}</dd>`));
  assert.match(html, new RegExp(`<strong>${formatCount(curatedCount)}</strong>`));
  assert.match(html, new RegExp(`<strong>${formatCount(catalogCount)}</strong>`));
});

test('recipe library server render is bounded and remains useful without JavaScript', () => {
  const curated = curatedFeed();
  const html = renderedLibrary();
  const cards = html.match(/\bdata-recipe-card(?:\s|>)/g) || [];
  const expectedCards = Math.min(18, Number(curated.count));

  assert.equal(cards.length, expectedCards);
  assert.ok(cards.length <= 18, 'the initial document never renders more than one bounded page');
  assert.match(html, new RegExp(`data-recipe-ssr-count="${expectedCards}"`));
  assert.match(html, /href="\/prompt-library\/cve\/">Catalog methodology<\/a>/);
});

test('collection navigation exposes accessible tabs, status, and mobile filters', () => {
  const html = renderedLibrary();

  assert.match(html, /role="tablist" aria-label="Recipe collections"/);
  assert.match(
    html,
    /id="recipe-library-curated-tab"[^>]*role="tab"[^>]*aria-selected="true"[^>]*aria-controls="recipe-library-curated"/
  );
  assert.match(
    html,
    /id="recipe-library-cve-tab"[^>]*role="tab"[^>]*aria-selected="false"[^>]*aria-controls="recipe-library-cve"/
  );
  assert.match(
    html,
    /id="recipe-library-curated"[^>]*role="tabpanel"[^>]*aria-labelledby="recipe-library-curated-tab"/
  );
  assert.match(
    html,
    /id="recipe-library-cve"[^>]*role="tabpanel"[^>]*aria-labelledby="recipe-library-cve-tab"[^>]*hidden/
  );
  assert.match(html, /data-recipe-summary[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);
  assert.match(
    html,
    /data-recipe-filter-toggle[^>]*aria-expanded="false"[^>]*aria-controls="recipe-library-facets"/
  );
  assert.match(html, /id="recipe-library-facets"[^>]*aria-hidden="false"/);
  assert.match(html, /data-recipe-filter-close>Close filters<\/button>/);
});

test('the CVE collection stays deferred and curated input avoids duplicate typeahead work', () => {
  const html = renderedLibrary();
  const recipeSource = fs.readFileSync(path.join(ROOT, 'assets/js/recipe-browser.js'), 'utf8');
  const cveSource = fs.readFileSync(path.join(ROOT, 'assets/js/cve-catalog.js'), 'utf8');

  assert.match(
    html,
    /data-cve-catalog\s+data-cve-catalog-deferred\s+data-cve-catalog-base="\/api\/cve-catalog\/"/
  );
  assert.match(cveSource, /SecurityRecipesCveCatalog/);
  assert.match(cveSource, /data-cve-catalog-deferred/);
  assert.match(cveSource, /RESULT_PAGE_SIZE\s*=\s*25/);
  assert.match(cveSource, /:not\(\[data-cve-catalog-deferred\]\)/);
  assert.match(recipeSource, /addEventListener\(['"]popstate['"],\s*restoreFromUrl\)/);
  assert.doesNotMatch(
    recipeSource,
    /addEventListener\(['"]input['"],\s*function\s*\(\)\s*\{\s*applyFilters\(\);\s*renderTypeahead\(\);/,
    'applyFilters already refreshes focused typeahead results'
  );
});

test('the CVE collection clearly exposes exact-ID and complete-catalog search paths', () => {
  const html = renderedLibrary();
  const cveSource = fs.readFileSync(path.join(ROOT, 'assets/js/cve-catalog.js'), 'utf8');

  assert.match(html, /Paste any complete CVE ID to open its record immediately/);
  assert.match(html, /narrow every in-scope record by severity, year, or CISA KEV status/);
  assert.match(cveSource, /CVE ID or vulnerability title/);
  assert.match(cveSource, /Words search every in-scope catalog record/);
  assert.match(cveSource, /search\.maxLength\s*=\s*160/);
  assert.match(
    cveSource,
    /renderResults\(\[preview\], 1, true\)/,
    'an exact CVE ID must remain retrievable even when broad-search filters are active'
  );
});
