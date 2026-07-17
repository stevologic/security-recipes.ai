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

function workflowFeed() {
  const { cveWorkflows } = require('../lib/feeds.js');
  return JSON.parse(cveWorkflows());
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
  assert.match(html, /href="\/recipes\/cve\/">Catalog methodology<\/a>/);
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

  assert.match(html, /Paste a complete CVE ID to open the exact record, source facts, and matched curated workflows/);
  assert.match(html, /narrow the full catalog by severity, year, or CISA KEV status/);
  assert.match(cveSource, /CVE ID or vulnerability title/);
  assert.match(cveSource, /Words search every in-scope catalog record/);
  assert.match(cveSource, /search\.maxLength\s*=\s*160/);
  assert.match(
    cveSource,
    /renderResults\(\[preview\], 1, true\)/,
    'an exact CVE ID must remain retrievable even when broad-search filters are active'
  );
});

test('one primary search connects exact CVEs to curated workflows and shareable routes', () => {
  const html = renderedLibrary();
  const recipeSource = fs.readFileSync(path.join(ROOT, 'assets/js/recipe-browser.js'), 'utf8');
  const cveSource = fs.readFileSync(path.join(ROOT, 'assets/js/cve-catalog.js'), 'utf8');

  assert.match(html, /data-library-search-form/);
  assert.match(html, /data-library-search[^>]*placeholder="CVE-2024-3400/);
  assert.match(html, /data-cve-workflow-index="\/api\/cve-workflows\.json"/);
  assert.match(html, /Find the vulnerability\. Run the right workflow\./);
  assert.match(recipeSource, /canonicalCve\(restoredQuery\)/);
  assert.match(recipeSource, /setCollection\('cve', \{ push: true, query: exact \}\)/);
  assert.match(cveSource, /exactDetails\.open = true/);
  assert.match(cveSource, /basePrefix\(\) \+ 'cve\/' \+ encodeURIComponent\(preview\.cve\) \+ '\/'/);
});

test('CVE workflow relationships are explicit, valid, searchable, and visible on cards', () => {
  const feed = workflowFeed();
  const curated = curatedFeed();
  const archetypes = new Set(
    Object.keys(readJson(path.join(ROOT, 'static', 'api', 'cve-catalog', 'archetypes.json')).archetypes)
  );
  const roles = new Set(['remediate', 'contain', 'audit', 'intake']);
  const bySlug = new Map(curated.recipes.map((recipe) => [recipe.slug, recipe]));

  assert.equal(feed.schema_version, 1);
  assert.equal(feed.count, feed.workflows.length);
  assert.ok(feed.count >= 10, 'the relationship index covers multiple reviewed workflow families');
  assert.equal(new Set(feed.workflows.map((workflow) => workflow.id)).size, feed.count);

  for (const workflow of feed.workflows) {
    assert.ok(roles.has(workflow.role), `${workflow.id} has a supported workflow role`);
    assert.match(workflow.url, /^\/recipes\/[^.]*\/$/);
    assert.ok(workflow.archetypes.length > 0, `${workflow.id} declares CVE archetypes`);
    for (const archetype of workflow.archetypes) {
      assert.ok(archetype === '*' || archetypes.has(archetype), `${workflow.id} maps to ${archetype}`);
    }
    const card = bySlug.get(workflow.id);
    assert.ok(card, `${workflow.id} remains discoverable in the curated feed`);
    assert.deepEqual(card.cveArchetypes, workflow.archetypes);
    assert.equal(card.cveWorkflowRole, workflow.role);
    assert.ok(
      workflow.archetypes.every((archetype) => card.search.includes(archetype)),
      `${workflow.id} relationship fields participate in curated search`
    );
  }

  const universal = feed.workflows.filter((workflow) => workflow.archetypes.includes('*'));
  assert.equal(universal.length, 1);
  assert.equal(universal[0].role, 'intake');
  const { browserCardObjects, renderCardHtml } = require('../lib/recipe-cards.js');
  const mappedCard = browserCardObjects().find((card) => card.cveArchetypes.length > 0);
  assert.ok(mappedCard);
  assert.match(renderCardHtml(mappedCard), /recipe-browser-card__cve-linkage/);
});

test('mobile CSS prevents iOS form zoom and keeps core controls touch friendly', () => {
  const libraryCss = fs.readFileSync(path.join(ROOT, 'assets/css/recipe-library.css'), 'utf8');
  const cveCss = fs.readFileSync(path.join(ROOT, 'assets/css/cve-catalog.css'), 'utf8');
  const docsLayout = fs.readFileSync(path.join(ROOT, '_includes/layouts/docs.njk'), 'utf8');

  assert.match(docsLayout, /viewport-fit=cover/);
  assert.match(libraryCss, /\.recipe-library__mission-field input\s*\{[\s\S]*?font-size:\s*16px/);
  assert.match(libraryCss, /\.recipe-library__sort select\s*\{[\s\S]*?min-height:\s*44px;[\s\S]*?font-size:\s*16px/);
  assert.match(cveCss, /@media \(max-width: 760px\)[\s\S]*?\.cve-catalog__input,[\s\S]*?font-size:\s*16px/);
  assert.match(cveCss, /\.cve-catalog__permalink,[\s\S]*?min-height:\s*44px/);
  assert.match(libraryCss, /env\(safe-area-inset-bottom\)/);
});
