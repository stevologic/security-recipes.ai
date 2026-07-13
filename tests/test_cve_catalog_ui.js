'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const test = require('node:test');
const zlib = require('node:zlib');

const controller = require('../assets/js/cve-catalog.js');
const worker = require('../assets/js/cve-catalog-worker.js');

const RECIPE_FIELDS = [
  'exposure_checks',
  'remediation_steps',
  'containment_steps',
  'verification_steps',
  'stop_conditions',
  'watch_for'
];

function recipe(title) {
  const value = { title };
  for (const field of RECIPE_FIELDS) value[field] = [`${title} ${field}`];
  return value;
}

function browserIndex(rows) {
  return worker.validateIndex({
    schema_version: 1,
    fields: [
      'cve',
      'title',
      'severity',
      'score',
      'published',
      'ecosystem_index',
      'kev',
      'archetype_indexes',
      'has_markdown'
    ],
    ecosystems: ['network-appliance', 'java/maven'],
    archetypes: ['generic', 'command_code_injection'],
    records: rows
  });
}

test('canonical CVE recognition is exact and shard paths use identifier buckets', () => {
  assert.deepEqual(controller.canonicalCve(' cve-2024-3400 '), {
    id: 'CVE-2024-3400',
    year: '2024',
    sequence: '3400'
  });
  assert.equal(controller.canonicalCve('CVE-2024-3400-extra'), null);
  assert.equal(controller.canonicalCve('prefix CVE-2024-3400'), null);
  assert.equal(controller.canonicalCve('CVE-2024-999'), null);
  assert.equal(controller.shardPathForCve('CVE-2024-0999'), 'shards/2024/0000.jsonl.gz');
  assert.equal(controller.shardPathForCve('CVE-2024-1000'), 'shards/2024/0001.jsonl.gz');
  assert.equal(controller.shardPathForCve('CVE-2026-123456'), 'shards/2026/0123.jsonl.gz');
  assert.throws(() => controller.shardPathForCve('CVE-2024-3400-extra'));
});

test('JSONL exact lookup never accepts a longer CVE prefix', () => {
  const text = [
    JSON.stringify({ cve: 'CVE-2024-34001', title: 'Prefix neighbor' }),
    JSON.stringify({ cve: 'CVE-2024-3400', title: 'Exact record' })
  ].join('\n');
  assert.equal(controller.parseJsonLineRecord(text, 'CVE-2024-3400').title, 'Exact record');
  assert.throws(
    () => controller.parseJsonLineRecord(JSON.stringify({ cve: 'CVE-2024-34001' }), 'CVE-2024-3400'),
    (error) => error.catalogCode === 'record-not-found'
  );
});

test('Markdown paths become safe internal rendered-page links', () => {
  assert.equal(
    controller.markdownPathToHref(
      'content/prompt-library/cve/cve-2024-3400-pan-os-globalprotect-command-injection.md',
      '/docs/'
    ),
    '/docs/prompt-library/cve/cve-2024-3400-pan-os-globalprotect-command-injection/'
  );
  assert.equal(
    controller.markdownPathToHref('content\\prompt-library\\cve\\recipe.md', '/'),
    '/prompt-library/cve/recipe/'
  );
  assert.equal(
    controller.markdownPathToHref('content/prompt-library/cve/_index.md', '/'),
    '/prompt-library/cve/'
  );
  assert.equal(controller.markdownPathToHref('content/../secrets.md', '/'), '');
  assert.equal(controller.markdownPathToHref('https://example.com/recipe.md', '/'), '');
  assert.equal(controller.markdownPathToHref('content/prompt-library/cve/recipe.txt', '/'), '');
  assert.equal(controller.markdownPathToHref('content//prompt-library/recipe.md', '/'), '');
});

test('only stable Markdown in an explicit override record wins precedence', () => {
  const stable = { path: 'content/prompt-library/cve/stable.md', maturity: 'stable' };
  const development = { path: 'content/prompt-library/cve/dev.md', maturity: 'development' };
  assert.deepEqual(
    controller.authoritativeMarkdownEntries({
      recipe_kind: 'markdown-override',
      markdown: [development, stable]
    }),
    [stable]
  );
  assert.deepEqual(
    controller.authoritativeMarkdownEntries({
      recipe_kind: 'markdown-override',
      markdown: [development]
    }),
    []
  );
  assert.deepEqual(
    controller.authoritativeMarkdownEntries({
      recipe_kind: 'markdown-override',
      markdown: [{ path: 'content/prompt-library/cve/legacy.md' }]
    }),
    []
  );
  assert.deepEqual(
    controller.authoritativeMarkdownEntries({
      recipe_kind: 'composed',
      markdown: [stable]
    }),
    []
  );
});

test('all archetype compositions are deduplicated and primary is first', () => {
  const catalog = controller.validateArchetypes({
    schema_version: 1,
    default_archetype: 'generic',
    archetypes: {
      generic: recipe('Generic remediation'),
      command_code_injection: recipe('Command injection remediation')
    }
  });
  const compositions = controller.resolveCompositions({
    archetype: 'command_code_injection',
    archetypes: ['generic', 'command_code_injection', 'generic']
  }, catalog);

  assert.equal(compositions.length, 2);
  assert.equal(compositions[0].id, 'command_code_injection');
  assert.equal(compositions[0].primary, true);
  assert.equal(compositions[1].id, 'generic');
});

test('runtime summary metadata produces coverage without loading the browser index', () => {
  const manifest = controller.validateManifest({
    schema_version: 1,
    totals: {
      catalog_records: 152335,
      in_scope_kev: 1278,
      coverage_percent: 100,
      stable_markdown_overrides: 6
    },
    by_severity: { critical: 40982, high: 111353 },
    scope: { published_start: '2016-07-12', published_end: '2026-07-12' },
    by_publication_year: { 2025: 100, 2026: 200 },
    browser_index: {
      path: 'browser-index.json.gz',
      sha256: 'a'.repeat(64),
      bytes: 3303059,
      uncompressed_bytes: 19313638,
      records: 152335
    },
    archetypes: {
      path: 'archetypes.json',
      sha256: 'b'.repeat(64),
      bytes: 50000
    },
    shard_set_sha256: 'c'.repeat(64)
  });
  const summary = controller.manifestCoverageText(manifest);
  assert.match(summary, /152,335 high\/critical CVEs/);
  assert.match(summary, /40,982 critical/);
  assert.match(summary, /1,278 CISA KEV/);
  assert.match(summary, /100% composed-recipe coverage/);
});

test('runtime summary requires content-derived shard and archetype versions', () => {
  const base = {
    schema_version: 1,
    totals: {},
    by_severity: {},
    scope: {},
    by_publication_year: {},
    browser_index: {
      path: 'browser-index.json.gz',
      sha256: 'a'.repeat(64),
      bytes: 1,
      uncompressed_bytes: 1,
      records: 0
    },
    archetypes: { path: 'archetypes.json', sha256: 'b'.repeat(64), bytes: 1 },
    shard_set_sha256: 'c'.repeat(64)
  };
  assert.equal(controller.validateManifest(base), base);
  assert.throws(
    () => controller.validateManifest({ ...base, shard_set_sha256: '' }),
    /asset version metadata/
  );
  assert.throws(
    () => controller.validateManifest({ ...base, archetypes: { ...base.archetypes, sha256: '' } }),
    /asset version metadata/
  );
});

test('catalog release values become bounded cache-version tokens', () => {
  assert.equal(
    controller.catalogVersionToken('2026-07-12T05:23:19.123Z'),
    '2026-07-12T052319.123Z'
  );
  assert.equal(controller.catalogVersionToken('?v=bad&other=value'), 'vbadothervalue');
  assert.equal(controller.catalogVersionToken('x'.repeat(100)).length, 64);
});

test('truncated product coverage is explicit and safe for affected-version decisions', () => {
  const coverage = controller.productCoverage({
    products: Array.from({ length: 12 }, (_, index) => ({ product: `product-${index}` })),
    product_match_count: 87,
    products_stored: 12,
    products_truncated: true
  });

  assert.deepEqual(coverage, { stored: 12, total: 87, truncated: true });
  assert.equal(
    controller.productCoverageText(coverage),
    '12 stored of 87 total product matches'
  );

  const warning = controller.productTruncationWarning(coverage);
  assert.match(warning, /representative and incomplete/);
  assert.match(warning, /Agents must consult the linked NVD and vendor evidence/);
  assert.match(warning, /before making affected-version decisions/);
  assert.doesNotMatch(warning, /[<>]/);

  const inferred = controller.productCoverage({
    products: [{ product: 'one stored row' }],
    product_match_count: 2,
    products_stored: 1,
    products_truncated: false
  });
  assert.equal(inferred.truncated, true, 'stored-of-total mismatch must remain conservative');
  assert.equal(controller.productTruncationWarning({ stored: 2, total: 2, truncated: false }), '');
});

test('full-record cache is bounded and refreshes recently used entries', () => {
  const cache = new Map();
  controller.lruSet(cache, 'a', { cve: 'CVE-2024-1000' }, 3);
  controller.lruSet(cache, 'b', { cve: 'CVE-2024-1001' }, 3);
  controller.lruSet(cache, 'c', { cve: 'CVE-2024-1002' }, 3);
  assert.equal(controller.lruGet(cache, 'a').cve, 'CVE-2024-1000');

  controller.lruSet(cache, 'd', { cve: 'CVE-2024-1003' }, 3);
  assert.equal(cache.size, 3);
  assert.equal(controller.lruGet(cache, 'b'), undefined, 'least recently used record is evicted');
  assert.ok(cache.has('a'), 'recently read record remains cached');

  for (let index = 0; index < 100; index += 1) {
    controller.lruSet(cache, `bulk-${index}`, { index }, controller.MAX_FULL_RECORD_CACHE);
  }
  assert.equal(cache.size, controller.MAX_FULL_RECORD_CACHE);
});

test('browser index dictionaries decode compact rows without losing zero-valued high severity', () => {
  const index = browserIndex([
    ['CVE-2024-3400', 'GlobalProtect command injection', 1, 10, '2024-04-12', 0, 1, [1, 0, 1], 1],
    ['CVE-2024-3401', 'Another GlobalProtect issue', 0, 8.1, '2023-04-12', 1, 0, [0], 0]
  ]);
  const critical = worker.decodeRecord(index, index.records[0]);
  const high = worker.decodeRecord(index, index.records[1]);

  assert.equal(critical.severity, 'critical');
  assert.equal(high.severity, 'high');
  assert.equal(critical.ecosystem, 'network-appliance');
  assert.deepEqual(critical.archetypes, ['command_code_injection', 'generic']);
  assert.equal(critical.hasMarkdown, true);
  assert.equal(critical.shard, 'shards/2024/0003.jsonl.gz');
});

test('blank catalog searches show at least ten newest published CVEs first', async () => {
  assert.ok(controller.RESULT_PAGE_SIZE >= 10, 'the initial catalog view exposes at least ten rows');

  const rows = Array.from({ length: 12 }, (_, indexNumber) => [
    `CVE-${2014 + indexNumber}-${String(2000 + indexNumber)}`,
    `Catalog record ${indexNumber}`,
    indexNumber === 0 ? 1 : 0,
    indexNumber === 0 ? 10 : 7.1,
    `${2014 + indexNumber}-07-01`,
    0,
    0,
    [0],
    0
  ]);
  let stats;
  const latest = await worker.searchIndex(browserIndex(rows), {
    query: '',
    filters: { severity: 'all', year: 'all', kev: 'all' }
  }, {
    yieldControl: async () => {},
    onStats: (value) => { stats = value; }
  });

  assert.equal(latest.results.length, 12);
  assert.deepEqual(
    latest.results.slice(0, 3).map((record) => record.published),
    ['2025-07-01', '2024-07-01', '2023-07-01']
  );
  assert.equal(
    latest.results.at(-1).cve,
    'CVE-2014-2000',
    'an older critical CVSS 10 record must not outrank newer publications'
  );
  assert.equal(stats.newNormalizedTitles, 0, 'blank latest searches do not normalize every title');
});

test('worker search ranks, filters, caps previews, and supports stale cancellation', async () => {
  const rows = [
    ['CVE-2024-3400', 'GlobalProtect command injection', 1, 10, '2024-04-12', 0, 1, [1], 1],
    ['CVE-2024-3401', 'Another GlobalProtect issue', 0, 8.1, '2023-04-12', 1, 0, [0], 0],
    ['CVE-2021-44228', 'Log4Shell', 1, 10, '2021-12-10', 1, 1, [1], 1]
  ];
  const index = browserIndex(rows);
  const all = await worker.searchIndex(index, {
    query: 'globalprotect',
    filters: { severity: 'all', year: 'all', kev: 'all' }
  }, { yieldControl: async () => {} });
  assert.equal(all.totalMatches, 2);
  assert.deepEqual(all.results.map((record) => record.cve), ['CVE-2024-3400', 'CVE-2024-3401']);

  const high = await worker.searchIndex(index, {
    query: '',
    filters: { severity: 'high', year: '2023', kev: 'no' }
  }, { yieldControl: async () => {} });
  assert.deepEqual(high.results.map((record) => record.cve), ['CVE-2024-3401']);

  const manyRows = Array.from({ length: 150 }, (_, indexNumber) => [
    `CVE-2025-${String(1000 + indexNumber)}`,
    `Matching title ${indexNumber}`,
    indexNumber % 2,
    7 + (indexNumber % 30) / 10,
    '2025-01-01',
    0,
    0,
    [0],
    0
  ]);
  const capped = await worker.searchIndex(browserIndex(manyRows), {
    query: 'matching',
    filters: { severity: 'all', year: 'all', kev: 'all' }
  }, { batchSize: 25, yieldControl: async () => {} });
  assert.equal(capped.totalMatches, 150);
  assert.equal(capped.results.length, 100);

  const stale = await worker.searchIndex(index, {
    query: '',
    filters: { severity: 'all', year: 'all', kev: 'all' }
  }, { isStale: () => true, yieldControl: async () => {} });
  assert.equal(stale.stale, true);
  assert.deepEqual(stale.results, []);
});

test('worker broad searches decode only retained rows and reuse normalized titles', async () => {
  const rows = Array.from({ length: 5_000 }, (_, indexNumber) => [
    `CVE-2024-${String(1000 + indexNumber)}`,
    `Shared performance title ${indexNumber}`,
    indexNumber % 2,
    7 + (indexNumber % 30) / 10,
    `2024-${String((indexNumber % 12) + 1).padStart(2, '0')}-01`,
    indexNumber % 2,
    indexNumber % 11 === 0 ? 1 : 0,
    [indexNumber % 2],
    0
  ]);
  rows.push(['not-a-cve', 'Shared performance title invalid', 1, 10, '2024-01-01', 0, 1, [0], 0]);
  const index = browserIndex(rows);
  let firstStats;
  const first = await worker.searchIndex(index, {
    query: 'shared performance',
    filters: { severity: 'all', year: 'all', kev: 'all' }
  }, {
    batchSize: 10_000,
    yieldControl: async () => {},
    onStats: (value) => { firstStats = value; }
  });

  assert.equal(first.totalMatches, 5_000, 'invalid compact rows do not count as matches');
  assert.equal(first.results.length, worker.MAX_RESULTS);
  assert.equal(firstStats.scannedRecords, 5_001);
  assert.equal(firstStats.decodedRecords, worker.MAX_RESULTS);
  assert.equal(firstStats.newNormalizedTitles, 5_000);

  let secondStats;
  await worker.searchIndex(index, {
    query: 'performance title 49',
    filters: { severity: 'all', year: 'all', kev: 'all' }
  }, {
    batchSize: 10_000,
    yieldControl: async () => {},
    onStats: (value) => { secondStats = value; }
  });
  assert.equal(secondStats.newNormalizedTitles, 0, 'later searches reuse worker-local title normalization');
  assert.ok(secondStats.decodedRecords <= worker.MAX_RESULTS);
});

test('cold CVE-prefix search does not normalize titles for identity matches', async () => {
  const rows = Array.from({ length: 5_000 }, (_, indexNumber) => [
    `CVE-2024-${String(1000 + indexNumber)}`,
    `Title that should stay cold ${indexNumber}`,
    indexNumber % 2,
    8,
    '2024-01-01',
    0,
    0,
    [0],
    0
  ]);
  rows.push(['CVE-2023-9999', 'Unrelated title', 0, 8, '2023-01-01', 0, 0, [0], 0]);
  const index = browserIndex(rows);
  let stats;
  const result = await worker.searchIndex(index, {
    query: 'CVE-2024',
    filters: { severity: 'all', year: 'all', kev: 'all' }
  }, {
    batchSize: 10_000,
    yieldControl: async () => {},
    onStats: (value) => { stats = value; }
  });

  assert.equal(result.totalMatches, 5_000);
  assert.equal(result.results.length, worker.MAX_RESULTS);
  assert.equal(stats.newNormalizedTitles, 1, 'only the nonmatching CVE needs a title check');
});

test('controller never parses the full index and feed Markdown is never injected as HTML', () => {
  const root = path.resolve(__dirname, '..');
  const controllerSource = fs.readFileSync(path.join(root, 'assets/js/cve-catalog.js'), 'utf8');
  const workerSource = fs.readFileSync(path.join(root, 'assets/js/cve-catalog-worker.js'), 'utf8');

  assert.doesNotMatch(controllerSource, /fetchJson\(\s*['"]index\.json['"]\s*\)/);
  assert.doesNotMatch(controllerSource, /\.innerHTML\s*=/);
  assert.doesNotMatch(workerSource, /\.innerHTML\s*=/);
  assert.match(controllerSource, /browser-index\.json\.gz/);
  assert.match(controllerSource, /fetchJson\('runtime-summary\.json'\)/);
  assert.doesNotMatch(controllerSource, /fetchJson\('manifest\.json'\)/);
  assert.match(controllerSource, /state\.runtimeSummary\.shard_set_sha256/);
  assert.match(controllerSource, /metadata && metadata\.sha256/);
  assert.match(workerSource, /browser-index\.json\.gz/);
  assert.match(
    controllerSource,
    /loadManifest\(false\)\.then\([\s\S]*?if \(state\.requestId === 0\) runSearch\(\);/,
    'the catalog runs its newest-first browse query after bootstrap'
  );
  assert.doesNotMatch(
    controllerSource,
    /if \(!query && filtersAreDefault\(\)\)\s*\{[\s\S]{0,200}?return;/,
    'a blank default query must not restore the old filter-required empty state'
  );
  assert.match(
    controllerSource,
    /clear\.addEventListener\([\s\S]*?kev\.value = 'all';\s*runSearch\(\);/,
    'clearing filters restores the newest-first browse view'
  );
});

test('worker accepts only a single bounded cache-version parameter', () => {
  const workerScope = {
    location: {
      href: 'https://security-recipes.test/js/cve-catalog-worker.js',
      origin: 'https://security-recipes.test'
    }
  };
  assert.equal(
    worker.safeBrowserIndexUrl(
      'https://security-recipes.test/api/cve-catalog/browser-index.json.gz?v=abcdef0123456789',
      workerScope
    ),
    'https://security-recipes.test/api/cve-catalog/browser-index.json.gz?v=abcdef0123456789'
  );
  assert.throws(() => worker.safeBrowserIndexUrl(
    'https://security-recipes.test/api/cve-catalog/browser-index.json.gz?v=abc&other=1',
    workerScope
  ));
  assert.throws(() => worker.safeBrowserIndexUrl(
    'https://security-recipes.test/api/cve-catalog/browser-index.json.gz?v=%2Fescape',
    workerScope
  ));
});

test('derived exact path resolves the generated CVE-2024-3400 shard when fixtures exist', (context) => {
  const root = path.resolve(__dirname, '..');
  const relative = controller.shardPathForCve('CVE-2024-3400');
  const shard = path.join(root, 'static', 'api', 'cve-catalog', ...relative.split('/'));
  if (!fs.existsSync(shard)) {
    context.skip('generated catalog fixture is not present');
    return;
  }
  const text = zlib.gunzipSync(fs.readFileSync(shard)).toString('utf8');
  const record = controller.parseJsonLineRecord(text, 'CVE-2024-3400');
  assert.equal(record.cve, 'CVE-2024-3400');
});

test('generated browser index supports full-catalog title search when present', async (context) => {
  const root = path.resolve(__dirname, '..');
  const runtimeSummaryPath = path.join(
    root,
    'static',
    'api',
    'cve-catalog',
    'runtime-summary.json'
  );
  const browserIndexPath = path.join(
    root,
    'static',
    'api',
    'cve-catalog',
    'browser-index.json.gz'
  );
  if (!fs.existsSync(browserIndexPath) || !fs.existsSync(runtimeSummaryPath)) {
    context.skip('generated browser catalog artifacts are not present');
    return;
  }

  const runtimeSummaryBytes = fs.readFileSync(runtimeSummaryPath);
  assert.ok(runtimeSummaryBytes.length < 4 * 1024, 'runtime bootstrap stays below 4 KiB');
  const runtimeSummary = controller.validateManifest(JSON.parse(runtimeSummaryBytes));
  const compressed = fs.readFileSync(browserIndexPath);
  const uncompressed = zlib.gunzipSync(compressed);
  assert.equal(runtimeSummary.browser_index.path, 'browser-index.json.gz');
  assert.equal(runtimeSummary.browser_index.bytes, compressed.length);
  assert.equal(runtimeSummary.browser_index.uncompressed_bytes, uncompressed.length);
  assert.equal(
    runtimeSummary.browser_index.sha256,
    crypto.createHash('sha256').update(compressed).digest('hex')
  );
  assert.ok(compressed.length < 4 * 1024 * 1024, 'compressed browser payload stays below 4 MiB');
  assert.ok(uncompressed.length < 24 * 1024 * 1024, 'parsed browser payload stays below 24 MiB');
  const payload = JSON.parse(uncompressed.toString('utf8'));
  const index = worker.validateIndex(payload);
  assert.ok(index.records.length >= 150_000);
  const latest = await worker.searchIndex(
    index,
    {
      query: '',
      filters: { severity: 'all', year: 'all', kev: 'all' }
    },
    { batchSize: 10_000, yieldControl: async () => {} }
  );
  const publishedIndex = index.indexes.published;
  const newestPublished = index.records.reduce(
    (newest, row) => String(row[publishedIndex] || '').localeCompare(newest) > 0
      ? String(row[publishedIndex] || '')
      : newest,
    ''
  );
  assert.ok(latest.results.length >= 10, 'the generated catalog can fill the initial browse view');
  assert.equal(latest.results[0].published, newestPublished);
  for (let position = 1; position < latest.results.length; position += 1) {
    assert.ok(
      latest.results[position - 1].published >= latest.results[position].published,
      'default catalog results stay newest-first'
    );
  }
  let stats;
  const result = await worker.searchIndex(
    index,
    {
      query: 'Apache Log4j2',
      filters: { severity: 'all', year: 'all', kev: 'all' }
    },
    {
      batchSize: 10_000,
      yieldControl: async () => {},
      onStats: (value) => { stats = value; }
    }
  );
  assert.equal(result.stale, false);
  assert.ok(result.results.some((record) => record.cve === 'CVE-2021-44228'));
  assert.equal(stats.scannedRecords, index.records.length);
  assert.ok(stats.decodedRecords <= worker.MAX_RESULTS);

  const broadStarted = performance.now();
  const broad = await worker.searchIndex(
    index,
    {
      query: 'CVE-2024',
      filters: { severity: 'all', year: 'all', kev: 'all' }
    },
    { batchSize: 10_000, yieldControl: async () => {} }
  );
  const broadElapsed = performance.now() - broadStarted;
  assert.ok(broad.totalMatches > 10_000);
  assert.ok(
    broadElapsed < 1_500,
    `warm full-catalog broad search took ${broadElapsed.toFixed(1)} ms (limit: 1500 ms)`
  );
});
