'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { renderAiProvenance } = require('../lib/ai-provenance.js');
const contentIndex = require('../lib/content-index.js');
const { loadCveSearchIndexableRecords } = require('../lib/cve-indexability.js');
const { cveDisplayTitle, stripFirstH1 } = require('../lib/html-content.js');
const { renderCardHtml } = require('../lib/recipe-cards.js');

const ROOT = path.resolve(__dirname, '..');

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
  return require('../lib/shortcodes/recipe-browser.js')();
}

function cveHubSource() {
  const topLevel = path.join(ROOT, 'content', 'cve-database', '_index.md');
  const nested = path.join(ROOT, 'content', 'recipes', 'cve', '_index.md');
  const file = fs.existsSync(topLevel) ? topLevel : nested;
  return {
    file,
    source: fs.readFileSync(file, 'utf8'),
    isTopLevel: file === topLevel,
  };
}

test('recipe library is curated-only and reports the curated feed count', () => {
  const curated = curatedFeed();
  const html = renderedLibrary();
  const curatedCount = Number(curated.count);

  assert.equal(curated.recipes.length, curatedCount, 'feed metadata matches its recipe payload');
  assert.ok(curated.recipes.length > 0, 'fixture repository exposes curated recipes');
  assert.ok(
    curated.recipes.every(
      (recipe) => recipe.category !== 'cve' && !String(recipe.url || '').startsWith('/recipes/cve/')
    ),
    'the browser feed must not leak CVE overrides into Recipes'
  );
  assert.match(html, new RegExp(`data-recipe-total="${curatedCount}"`));
  assert.match(html, new RegExp(`<dd>${formatCount(curatedCount)}</dd>`));
  assert.match(html, /data-recipe-api="\/api\/curated-recipes\.json"/);
  assert.match(html, /href="\/cve-database\/">Open CVE Database<\/a>/);
  assert.doesNotMatch(html, /data-cve-total=/);
  assert.doesNotMatch(html, /data-library-tab=/);
  assert.doesNotMatch(html, /data-library-panel=/);
  assert.doesNotMatch(html, /data-cve-catalog/);
});

test('recipe library server render is bounded and remains useful without JavaScript', () => {
  const curated = curatedFeed();
  const html = renderedLibrary();
  const cards = html.match(/\bdata-recipe-card(?:\s|>)/g) || [];
  const expectedCards = Math.min(18, Number(curated.count));
  const seedMatch = html.match(
    /<script type="application\/json" data-recipe-seed>([\s\S]*?)<\/script>/
  );

  assert.equal(cards.length, expectedCards);
  assert.ok(cards.length <= 18, 'the initial document never renders more than one bounded page');
  assert.ok(seedMatch, 'the SSR cards have a matching inline hydration seed');
  const seed = JSON.parse(seedMatch[1]);
  assert.equal(seed.length, expectedCards, 'the inline seed contains only the SSR page');
  assert.ok(seed.length <= 18, 'the inline seed cannot grow into an eager catalogue payload');
  assert.deepEqual(
    seed.map((recipe) => recipe.url),
    [...html.matchAll(/\bdata-recipe-path="([^"]+)"/g)].map((match) => match[1]),
    'seed records and crawlable SSR cards describe the same recipe links'
  );
  assert.match(html, new RegExp(`data-recipe-ssr-count="${expectedCards}"`));
  assert.match(html, /data-recipe-feed-policy="interaction"/);
  assert.match(html, /full feed is available at <code>\/api\/curated-recipes\.json<\/code>/);
  assert.match(html, /data-recipe-summary[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);
  assert.match(
    html,
    /data-recipe-filter-toggle[^>]*aria-expanded="false"[^>]*aria-controls="recipe-library-facets"/
  );
  assert.match(html, /id="recipe-library-facets"[^>]*aria-hidden="false"/);
  assert.match(html, /data-recipe-filter-close>Close filters<\/button>/);
});

test('recipe browser defers the complete feed until meaningful interaction', () => {
  const source = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'recipe-browser.js'), 'utf8');
  const ensureStart = source.indexOf('function ensureCatalogueLoaded()');
  const refreshStart = source.indexOf('function refreshCatalogueAfterInteraction()');
  const deferredLoad = source.indexOf('cataloguePromise = loadFeed()', ensureStart);
  const readyMarker = source.lastIndexOf("root.dataset.recipeBrowserReady = 'true'");
  const initEnd = source.indexOf('\n  }\n\n  function init()', readyMarker);

  assert.ok(ensureStart > 0 && refreshStart > ensureStart);
  assert.ok(
    deferredLoad > ensureStart && deferredLoad < refreshStart,
    'the slim feed starts only inside the shared interaction loader'
  );
  assert.match(
    source.slice(ensureStart, refreshStart),
    /if \(cataloguePromise\) return cataloguePromise;/,
    'concurrent interactions reuse one in-flight catalogue request'
  );
  assert.equal(
    [...source.matchAll(/\bloadFeed\(\)/g)].length,
    2,
    'loadFeed appears only in its declaration and the deferred loader'
  );
  assert.doesNotMatch(
    source.slice(readyMarker, initEnd),
    /loadFeed\(\)/,
    'initialization must not fetch the catalogue after mounting the SSR page'
  );
  assert.match(source, /addEventListener\('input', refreshCatalogueAfterInteraction\)/);
  assert.match(source, /addEventListener\('search', refreshCatalogueAfterInteraction\)/);
  assert.match(
    source,
    /addEventListener\('focus', function \(\) \{[\s\S]*?ensureCatalogueLoaded\(\)/
  );
  assert.match(source, /severityFilter\.addEventListener\('change', refreshCatalogueAfterInteraction\)/);
  assert.match(source, /facetFilter\.addEventListener\('change', refreshCatalogueAfterInteraction\)/);
  assert.match(source, /qualityFilter\.addEventListener\('change', refreshCatalogueAfterInteraction\)/);
  assert.match(source, /sortSelect\.addEventListener\('change', refreshCatalogueAfterInteraction\)/);
  assert.match(
    source,
    /button\.addEventListener\('click', function \(\) \{ setActiveCategory\(filter\); \}\);/
  );
  assert.match(
    source,
    /function setActiveCategory\([^)]+\) \{[\s\S]*?refreshCatalogueAfterInteraction\(\);\s*\}/
  );
  assert.match(source, /loadMoreButton\.addEventListener\('click', requestNextPage\)/);
  assert.match(
    source,
    /if \(hasActiveSelection\(\)\) \{\s*ensureCatalogueLoaded\(\)/,
    'a shared or bookmarked filtered URL loads the complete result set'
  );
});

test('indexed agent remediation recipes use branded headings and concise navigation labels', () => {
  const expected = [
    {
      sourcePath: 'recipes/codex/vulnerable-dep-remediation.md',
      title: 'Codex Vulnerable Dependency Remediation',
      linkTitle: 'Vulnerable dep remediation',
      brand: 'Codex',
    },
    {
      sourcePath: 'recipes/codex/sensitive-data-remediation.md',
      title: 'Codex Sensitive Data Remediation',
      linkTitle: 'Sensitive data remediation',
      brand: 'Codex',
    },
    {
      sourcePath: 'recipes/claude/cve-triage-skill.md',
      title: 'Claude Code CVE and Dependency Remediation Skill',
      linkTitle: 'CVE triage skill',
      brand: 'Claude Code',
    },
    {
      sourcePath: 'recipes/claude/sensitive-data-remediation-skill.md',
      title: 'Claude Code Sensitive Data Remediation Skill',
      linkTitle: 'Sensitive data remediation skill',
      brand: 'Claude Code',
    },
    {
      sourcePath: 'recipes/cursor/vulnerable-dep-remediation.md',
      title: 'Cursor Vulnerable Dependency Remediation',
      linkTitle: 'Vulnerable dep remediation',
      brand: 'Cursor',
    },
    {
      sourcePath: 'recipes/cursor/sensitive-data-remediation.md',
      title: 'Cursor Sensitive Data Remediation',
      linkTitle: 'Sensitive data remediation',
      brand: 'Cursor',
    },
    {
      sourcePath: 'recipes/github_copilot/vulnerable-dep-remediation.md',
      title: 'GitHub Copilot Vulnerable Dependency Remediation',
      linkTitle: 'Vulnerable dep remediation',
      brand: 'GitHub Copilot',
    },
    {
      sourcePath: 'recipes/github_copilot/sensitive-data-remediation.md',
      title: 'GitHub Copilot Sensitive Data Remediation',
      linkTitle: 'Sensitive data remediation',
      brand: 'GitHub Copilot',
    },
    {
      sourcePath: 'recipes/devin/scheduled-vulnerability-remediation.md',
      title: 'Devin Scheduled Vulnerability Remediation',
      linkTitle: 'Scheduled vulnerability remediation',
      brand: 'Devin',
    },
    {
      sourcePath: 'recipes/devin/scheduled-sde-remediation.md',
      title: 'Devin Scheduled Sensitive Data Remediation',
      linkTitle: 'Scheduled SDE remediation',
      brand: 'Devin',
    },
  ];
  const pages = new Map(
    contentIndex.getIndex().pages.map((page) => [page.sourcePath, page])
  );
  const cards = new Map(curatedFeed().recipes.map((recipe) => [recipe.url, recipe]));

  assert.equal(expected.length, 10);
  for (const fixture of expected) {
    const page = pages.get(fixture.sourcePath);
    assert.ok(page, `${fixture.sourcePath} exists`);
    assert.equal(page.title, fixture.title);
    assert.equal(page.linkTitle, fixture.linkTitle);
    assert.match(page.title, new RegExp(`^${fixture.brand.replace(' ', '\\s')}\\b`));
    assert.ok(page.title.length <= 60, `${fixture.sourcePath} has a concise search title`);
    assert.notEqual(page.fm.noindex, true, `${fixture.sourcePath} remains indexable`);
    assert.equal(cards.get(page.url)?.title, fixture.title, `${page.url} exposes the branded title`);
  }
});

test('CVE Database is a standalone catalog route in the primary navigation', () => {
  const site = require('../lib/site-config.js');
  const hub = cveHubSource();
  const hubHtml = require('../lib/shortcodes/cve-database.js')();
  const head = fs.readFileSync(path.join(ROOT, '_includes', 'partials', 'head-common.njk'), 'utf8');
  const cveSource = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'cve-catalog.js'), 'utf8');
  const databaseCss = fs.readFileSync(path.join(ROOT, 'assets', 'css', 'cve-database.css'), 'utf8');

  assert.deepEqual(
    site.menu.filter((item) => item.url === '/cve-database/'),
    [{ name: 'CVE Database', url: '/cve-database/' }]
  );
  if (!hub.isTopLevel) {
    assert.match(
      hub.source,
      /^url:\s*\/cve-database\/?\s*$/m,
      'the historical nested source must publish its hub at the top-level route'
    );
  }
  assert.match(hub.source, /\{\{<\s*cve-database\s*>\}\}/);
  assert.match(hubHtml, /data-cve-catalog\s+data-cve-catalog-base="\/api\/cve-catalog\/"/);
  assert.doesNotMatch(hubHtml, /data-cve-catalog-deferred/);
  assert.match(hubHtml, /<h1 id="cve-database-heading">CVE Database<\/h1>/);
  assert.match(hubHtml, /<h2 id="cve-qualified-heading">Reviewed and evidence-qualified CVEs<\/h2>/);
  assert.match(hubHtml, /<h2 id="cve-historical-heading">Historical reviewed CVEs<\/h2>/);
  assert.match(hubHtml, /href="\/security-remediation\/">AI vulnerability remediation playbooks<\/a>/);
  assert.match(hubHtml, /href="\/security-remediation\/vulnerable-dependencies\/">vulnerable dependency workflow<\/a>/);
  assert.match(hubHtml, /href="\/recipes\/general\/cve-intelligence-intake-gate\/">CVE intelligence intake gate<\/a>/);
  assert.doesNotMatch(hubHtml, /From vulnerability signal to a bounded response plan/);
  assert.doesNotMatch(hubHtml, /data-cve-hero-search/);
  assert.ok(
    hubHtml.indexOf('id="cve-catalog"') < hubHtml.indexOf('id="cve-quick-heading"'),
    'the searchable records must appear before supporting content'
  );
  assert.ok(
    hubHtml.indexOf('id="cve-qualified-heading"') < hubHtml.indexOf('id="cve-quick-heading"'),
    'qualified canonical links must appear before supporting content'
  );

  const qualified = loadCveSearchIndexableRecords();
  const catalogManifest = readJson(
    path.join(ROOT, 'static', 'api', 'cve-catalog', 'manifest.json')
  );
  assert.ok(qualified.length > 0, 'the evidence-qualified CVE list is not empty');
  assert.equal(qualified.length, catalogManifest.search_index.records);
  assert.equal(qualified.length, catalogManifest.totals.search_indexable_records);
  const stableRoutes = new Map(
    contentIndex.getIndex().pages
      .filter((page) => String(page.fm?.maturity || '').toLowerCase() === 'stable' && page.fm?.cve)
      .map((page) => [String(page.fm.cve).toUpperCase(), contentIndex.canonicalUrlForPage(page)])
  );
  const expectedQualifiedLinks = new Map(
    qualified.map((record) => [
      record.cve,
      stableRoutes.get(record.cve) || `/cve/${record.cve}/`
    ])
  );
  const renderedQualifiedLinks = new Map(
    [...hubHtml.matchAll(/<a href="([^"]+)" data-qualified-cve-link="(CVE-\d{4}-\d{4,})">/g)]
      .map((match) => [match[2], match[1]])
  );
  assert.deepEqual(
    [...renderedQualifiedLinks].sort(([a], [b]) => a.localeCompare(b, 'en')),
    [...expectedQualifiedLinks].sort(([a], [b]) => a.localeCompare(b, 'en'))
  );
  assert.equal(renderedQualifiedLinks.get('CVE-2017-18342'), '/recipes/cve/cve-2017-18342-pyyaml/');
  const reviewedPyYamlAnchor = hubHtml.match(
    /<a href="([^"]+)" data-qualified-cve-link="CVE-2017-18342"><strong>CVE-2017-18342<\/strong><span>([^<]+)<\/span>/
  );
  assert.ok(reviewedPyYamlAnchor, 'the reviewed PyYAML record has a visible database anchor');
  assert.equal(reviewedPyYamlAnchor[1], '/recipes/cve/cve-2017-18342-pyyaml/');
  assert.equal(
    reviewedPyYamlAnchor[2],
    'CVE-2017-18342 — PyYAML default load resolves arbitrary tags'
  );
  assert.doesNotMatch(
    hubHtml,
    /In PyYAML before 5\.1, the yaml\.load\(\) API could execute arbitrary code if used with untrusted data/
  );
  const qualifiedIds = new Set(qualified.map((record) => record.cve));
  const expectedHistoricalLinks = new Map(
    [...stableRoutes].filter(([cve]) => !qualifiedIds.has(cve))
  );
  const renderedHistoricalLinks = new Map(
    [...hubHtml.matchAll(/<a href="([^"]+)" data-historical-cve-link="(CVE-\d{4}-\d{4,})">/g)]
      .map((match) => [match[2], match[1]])
  );
  assert.deepEqual(
    [...renderedHistoricalLinks].sort(([a], [b]) => a.localeCompare(b, 'en')),
    [...expectedHistoricalLinks].sort(([a], [b]) => a.localeCompare(b, 'en'))
  );
  assert.equal(
    renderedHistoricalLinks.get('CVE-2014-0160'),
    '/recipes/cve/cve-2014-0160-heartbleed/'
  );
  assert.equal(
    renderedHistoricalLinks.get('CVE-2014-6271'),
    '/recipes/cve/cve-2014-6271-shellshock/'
  );
  assert.equal(renderedHistoricalLinks.has('CVE-2017-18342'), false);
  assert.ok(
    head.includes('/cve-database/'),
    'the standalone route must opt into route-specific CVE assets'
  );
  assert.match(head, /\/css\/cve-catalog\.css/);
  assert.match(head, /\/js\/cve-catalog\.js/);
  assert.match(cveSource, /RESULT_PAGE_SIZE\s*=\s*25/);
  assert.match(cveSource, /CVE ID or vulnerability title/);
  assert.match(cveSource, /Words search every in-scope catalog record/);
  assert.match(cveSource, /search\.maxLength\s*=\s*160/);
  assert.match(databaseCss, /width:\s*min\(1400px,\s*calc\(100vw - 64px\)\)/);
  assert.match(databaseCss, /@media \(max-width:\s*860px\)/);
  assert.match(databaseCss, /width:\s*min\(100% - 32px,\s*1400px\)/);
  assert.match(databaseCss, /--cve-db-border:\s*var\(--arr-card-border/);
  assert.match(
    cveSource,
    /renderResults\(\[preview\], 1, true\)/,
    'an exact CVE ID must remain retrievable even when broad-search filters are active'
  );
});

test('legacy Recipes CVE URLs hand off to the standalone database', () => {
  const recipeSource = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'recipe-browser.js'), 'utf8');

  assert.doesNotMatch(recipeSource, /prefix \+ ['"]api\/recipes\.json['"]/);
  assert.doesNotMatch(recipeSource, /prefix \+ ['"]recipes-index\.json['"]/);
  assert.match(recipeSource, /sourceFile\.indexOf\(['"]recipes\/cve\/['"]\)\s*===\s*0/);
  assert.match(recipeSource, /params\.get\(['"]view['"]\)\s*===\s*['"]cve['"]/);
  assert.match(recipeSource, /new URL\(['"]\/cve-database\/['"]/);
  assert.match(recipeSource, /win\.location\.replace\(legacyTarget\.pathname \+ legacyTarget\.search\)/);
  assert.match(recipeSource, /['"]\/cve-database\/\?q=['"]\s*\+\s*encodeURIComponent/);
  assert.match(recipeSource, /addEventListener\(['"]popstate['"],\s*restoreFromUrl\)/);
  assert.doesNotMatch(
    recipeSource,
    /addEventListener\(['"]input['"],\s*function\s*\(\)\s*\{\s*applyFilters\(\);\s*renderTypeahead\(\);/,
    'applyFilters already refreshes focused typeahead results'
  );
});

test('standalone CVE records use a scoped theme and one canonical page heading', () => {
  const layout = fs.readFileSync(path.join(ROOT, '_includes', 'layouts', 'docs.njk'), 'utf8');
  const head = fs.readFileSync(path.join(ROOT, '_includes', 'partials', 'head-common.njk'), 'utf8');
  const css = fs.readFileSync(path.join(ROOT, 'assets', 'css', 'cve-detail.css'), 'utf8');
  const rendered = [
    '<blockquote><p>Development warning</p></blockquote>',
    '<h1 id="duplicate">CVE-2025-20337 duplicate title</h1>',
    '<h2 id="review-scope">Review scope</h2>',
  ].join('\n');

  assert.equal((stripFirstH1(rendered).match(/<h1\b/g) || []).length, 0);
  assert.match(stripFirstH1(rendered), /Development warning/);
  assert.match(stripFirstH1(rendered), /Review scope/);
  assert.equal(
    cveDisplayTitle('CVE-2014-0160 — Heartbleed', 'CVE-2014-0160'),
    'CVE-2014-0160: Heartbleed'
  );
  assert.equal(
    cveDisplayTitle('Heartbleed', 'CVE-2014-0160'),
    'CVE-2014-0160: Heartbleed'
  );
  assert.match(layout, /detailTitleSource \| cveDisplayTitle\(cve\)/);
  assert.match(layout, /data-cve-detail-page="true"/);
  assert.match(layout, /content \| stripFirstH1/);
  assert.match(layout, /class="sr-cve-detail-header"/);
  assert.match(layout, /Back to CVE Database/);
  assert.match(head, /\/css\/cve-detail\.css/);
  assert.match(css, /\.sr-cve-detail-page \.sr-main \.sr-cve-detail-content\s*\{[^}]*max-width:\s*78ch/s);
  assert.match(css, /\.sr-cve-detail-header \.sr-cve-detail-header__title\s*\{[^}]*overflow-wrap:\s*anywhere/s);
  assert.match(css, /\.sr-cve-detail-content h2\s*\{[^}]*margin:\s*2\.75rem 0 1rem/s);
  assert.match(css, /@media \(max-width:\s*860px\)/);
  assert.match(css, /@media \(max-width:\s*560px\)[\s\S]*padding-right:\s*16px/);
});

test('AI provenance badges are escaped and only render when a model is present', () => {
  const unsafeModel = 'gpt<5>&"';
  const provenance = renderAiProvenance(unsafeModel, { label: 'AI-enriched' });
  const baseCard = {
    slug: 'fixture',
    title: 'Fixture',
    url: '/recipes/general/fixture/',
    category: 'general',
    categoryLabel: 'General',
    severity: 'unspecified',
    maturity: 'stable',
    quality: 100,
    tier: 'world-class',
    facets: ['remediation'],
    identity: '',
    published: '',
    ecosystem: '',
    summary: '',
    zeroDay: false,
  };

  assert.equal(renderAiProvenance(''), '');
  assert.match(
    renderCardHtml(baseCard),
    /<h3 id="recipe-card-fixture"><a href="\/recipes\/general\/fixture\/">Fixture<\/a><\/h3>/
  );
  assert.match(provenance, /class="sr-ai-provenance"/);
  assert.match(provenance, /aria-label="AI-enriched with gpt&lt;5&gt;&amp;&quot;"/);
  assert.match(provenance, /<code>gpt&lt;5&gt;&amp;&quot;<\/code>/);
  assert.doesNotMatch(provenance, /(?:<script|gpt<5>)/i);
  assert.doesNotMatch(
    renderCardHtml({ ...baseCard, model: '', aiAssisted: false }),
    /sr-ai-provenance/
  );
  assert.match(
    renderCardHtml({ ...baseCard, model: unsafeModel, aiAssisted: true }),
    /AI-enriched with gpt&lt;5&gt;&amp;&quot;/
  );
  assert.match(
    renderCardHtml({ ...baseCard, cve: 'CVE-2024-3400' }),
    /class="recipe-browser-card__evidence" href="\/cve\/CVE-2024-3400\/" aria-describedby="recipe-card-fixture"/
  );
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
  assert.match(libraryCss, /\.recipe-library \.recipe-browser__search-field input\s*\{[\s\S]*?font-size:\s*16px/);
  assert.match(libraryCss, /\.recipe-library__sort select\s*\{[\s\S]*?min-height:\s*44px;[\s\S]*?font-size:\s*16px/);
  assert.match(cveCss, /@media \(max-width: 760px\)[\s\S]*?\.cve-catalog__input,[\s\S]*?font-size:\s*16px/);
  assert.match(cveCss, /\.cve-catalog__permalink,[\s\S]*?min-height:\s*44px/);
  assert.match(libraryCss, /env\(safe-area-inset-bottom\)/);
});
