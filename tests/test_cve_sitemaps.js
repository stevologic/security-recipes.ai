const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const zlib = require("node:zlib");

const {
  CANONICAL_CVE_ID,
  CVE_SITEMAP_URL_LIMIT,
  isPagesSitemapEntry,
  loadCveSitemapManifest,
  planCveSitemaps,
  renderCveSitemap,
  renderSitemapIndex,
} = require("../eleventy.config").cveSitemaps;
const {
  buildRecentCatalogItems,
  cleanCveSourceText,
  cveArchiveOutputPath,
  planCveArchivePages,
  renderCveArchivePage,
} = require("../eleventy.config").cveArchives;
const {
  latestSitemapLastmod,
  planPagesSitemapEntries,
} = require("../eleventy.config").pageSitemap;

const CATALOG_ROOT = path.join(
  __dirname,
  "..",
  "static",
  "api",
  "cve-catalog"
);

function count(xml, token) {
  return xml.split(token).length - 1;
}

test("CVE archive display text removes upstream encoding artifacts", () => {
  assert.equal(
    cleanCveSourceText("SAP\uFFFDBusinessObjects Business\uFFFDIntelligence"),
    "SAP BusinessObjects Business Intelligence",
  );
  assert.equal(cleanCveSourceText("application\uFFFDs memory"), "application's memory");
  assert.equal(cleanCveSourceText("Composer\u00e2\u20ac\u2122s backup"), "Composer's backup");
});

test("production manifest plans one bounded sitemap per current yearly partition", () => {
  const manifest = loadCveSitemapManifest(CATALOG_ROOT);
  const entries = planCveSitemaps(manifest);

  assert.equal(entries.length, manifest.partitions.length);
  assert.equal(
    entries.reduce((total, entry) => total + entry.count, 0),
    manifest.total
  );
  assert.equal(new Set(entries.map((entry) => entry.outputPath)).size, entries.length);
  for (const entry of entries) {
    assert.ok(entry.count > 0);
    assert.ok(entry.count < 50_000);
    assert.ok(entry.count <= CVE_SITEMAP_URL_LIMIT);
    assert.match(entry.outputPath, /^\/sitemaps\/cves-\d{4}\.xml$/);
    assert.match(entry.sourcePath, /^indexes\/\d{4}\.json\.gz$/);
  }
});

test("future oversized yearly partitions are split below 50,000 URLs", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cve-sitemap-large-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(tempRoot, "indexes"), { recursive: true });
  const records = Array.from({ length: 100_001 }, (_, index) => ({
    cve: `CVE-2026-${index + 1000}`,
  }));
  fs.writeFileSync(
    path.join(tempRoot, "indexes", "2026.json.gz"),
    zlib.gzipSync(JSON.stringify({ records })),
  );
  const manifest = {
    catalog_updated_at: "2026-07-17T07:02:25Z",
    total: 100_001,
    partitions: [
      { year: "2026", path: "indexes/2026.json.gz", records: 100_001 },
    ],
  };
  const entries = planCveSitemaps(
    manifest,
    CVE_SITEMAP_URL_LIMIT,
    tempRoot,
  );

  assert.deepEqual(
    entries.map(({ outputPath, offset, count }) => ({ outputPath, offset, count })),
    [
      { outputPath: "/sitemaps/cves-2026-1.xml", offset: 0, count: 49_000 },
      { outputPath: "/sitemaps/cves-2026-2.xml", offset: 49_000, count: 49_000 },
      { outputPath: "/sitemaps/cves-2026-3.xml", offset: 98_000, count: 2_001 },
    ]
  );
  assert.ok(entries.every((entry) => entry.count < 50_000));
});

test("root sitemap is an index referencing pages and every CVE sitemap", () => {
  const entries = [
    {
      outputPath: "/sitemaps/cves-2025.xml",
      lastmod: "2026-07-17",
    },
    {
      outputPath: "/sitemaps/cves-2026.xml",
      lastmod: "2026-07-17",
    },
  ];
  const xml = renderSitemapIndex(entries, "2026-07-19T12:00:00Z");

  assert.match(xml, /^<\?xml version="1\.0" encoding="utf-8"\?>/);
  assert.match(xml, /<sitemapindex xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  assert.match(xml, /<loc>https:\/\/security-recipes\.ai\/sitemaps\/pages\.xml<\/loc>/);
  assert.match(
    xml,
    /<loc>https:\/\/security-recipes\.ai\/sitemaps\/pages\.xml<\/loc><lastmod>2026-07-19<\/lastmod>/,
  );
  assert.match(xml, /<loc>https:\/\/security-recipes\.ai\/sitemaps\/cves-2025\.xml<\/loc>/);
  assert.match(xml, /<loc>https:\/\/security-recipes\.ai\/sitemaps\/cves-2026\.xml<\/loc>/);
  assert.equal(count(xml, "<sitemap>"), 3);
  assert.doesNotMatch(xml, /<urlset/);
});

test("pages sitemap excludes noindex archives from URLs and child lastmod", () => {
  const archiveEntries = [
    { outputPath: "/cve/archive/2025/", lastmod: "2026-07-18" },
    { outputPath: "/cve/archive/2026/", lastmod: "2026-07-20" },
  ];
  const entries = planPagesSitemapEntries(
    [
      {
        sourcePath: "security-remediation/_index.md",
        url: "/security-remediation/",
        date: "2026-07-01",
        fm: {},
      },
      {
        sourcePath: "draft.md",
        url: "/draft/",
        date: "2026-07-30",
        fm: { noindex: true },
      },
    ],
    {
      cveArchiveEntries: archiveEntries,
      lastmodResolver: (_sourcePath, date) => `${date}T12:00:00Z`,
    },
  );

  assert.deepEqual(entries.map((entry) => entry.loc), ["/security-remediation/"]);
  assert.equal(latestSitemapLastmod(entries), "2026-07-01");
  assert.doesNotMatch(
    renderSitemapIndex([], latestSitemapLastmod(entries)),
    /2026-07-(?:20|30)/,
  );
});

test("pages sitemap honors an authored lastmod newer than publication", () => {
  const entries = planPagesSitemapEntries([
    {
      sourcePath: "docs/authored-freshness-example.md",
      url: "/docs/authored-freshness-example/",
      date: "2026-05-02",
      fm: { lastmod: "2026-07-19T18:30:00Z" },
    },
  ]);

  assert.deepEqual(entries, [
    {
      loc: "/docs/authored-freshness-example/",
      lastmod: "2026-07-19",
    },
  ]);
});

test("normal pages sitemap excludes aliases, redirects, and noindex pages", () => {
  assert.equal(
    isPagesSitemapEntry({
      sourcePath: "recipes/cve/cve-2026-0001-example.md",
      fm: { cve: "CVE-2026-0001", maturity: "stable" },
    }),
    false
  );
  assert.equal(
    isPagesSitemapEntry({
      sourcePath: "recipes/cve/cve-2014-0160-heartbleed.md",
      fm: {
        cve: "CVE-2014-0160",
        maturity: "stable",
        canonical_cve_route: false,
      },
    }),
    true
  );
  assert.equal(
    isPagesSitemapEntry({
      sourcePath: "recipes/general/intake.md",
      fm: {},
    }),
    true
  );
  assert.equal(
    isPagesSitemapEntry({ sourcePath: "draft.md", fm: { noindex: true } }),
    false
  );
  assert.equal(
    isPagesSitemapEntry({ sourcePath: "alias.md", fm: { redirectTo: "/target/" } }),
    false
  );
});

test("yearly sitemap renders only canonical dynamic CVE detail URLs", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cve-sitemap-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(tempRoot, "indexes"), { recursive: true });

  const payload = {
    year: "2026",
    records: [
      { cve: "CVE-2026-0001" },
      { cve: "CVE-2026-12345" },
      { cve: "CVE-2026-9999999" },
    ],
  };
  fs.writeFileSync(
    path.join(tempRoot, "indexes", "2026.json.gz"),
    zlib.gzipSync(JSON.stringify(payload))
  );
  const [entry] = planCveSitemaps(
    {
      catalog_updated_at: "2026-07-17T07:02:25Z",
      total: payload.records.length,
      partitions: [
        {
          year: "2026",
          path: "indexes/2026.json.gz",
          records: payload.records.length,
        },
      ],
    },
    CVE_SITEMAP_URL_LIMIT,
    tempRoot,
  );
  const xml = renderCveSitemap(entry, tempRoot);

  assert.equal(count(xml, "<url>"), payload.records.length);
  for (const { cve } of payload.records) {
    assert.match(cve, CANONICAL_CVE_ID);
    assert.match(
      xml,
      new RegExp(`<loc>https:\\/\\/security-recipes\\.ai\\/cve\\/${cve}\\/<\\/loc>`)
    );
  }
  assert.doesNotMatch(xml, /\/recipes\/\?view=cve/);
  assert.doesNotMatch(xml, /<lastmod>/);

  const excluded = renderCveSitemap(
    entry,
    tempRoot,
    new Set([payload.records[0].cve]),
  );
  assert.equal(count(excluded, "<url>"), payload.records.length - 1);
  assert.doesNotMatch(excluded, new RegExp(`/cve/${payload.records[0].cve}/`));

  const searchIndexable = new Set([payload.records[0].cve, payload.records[2].cve]);
  const [filteredEntry] = planCveSitemaps(
    {
      catalog_updated_at: "2026-07-17T07:02:25Z",
      total: payload.records.length,
      partitions: [
        {
          year: "2026",
          path: "indexes/2026.json.gz",
          records: payload.records.length,
        },
      ],
    },
    CVE_SITEMAP_URL_LIMIT,
    tempRoot,
    new Set(),
    searchIndexable,
  );
  const filtered = renderCveSitemap(
    filteredEntry,
    tempRoot,
    new Set(),
    searchIndexable,
  );
  assert.equal(count(filtered, "<url>"), searchIndexable.size);
  assert.doesNotMatch(filtered, new RegExp(`/cve/${payload.records[1].cve}/`));
  assert.deepEqual(
    planCveSitemaps(
      {
        catalog_updated_at: "2026-07-17T07:02:25Z",
        total: payload.records.length,
        partitions: [
          {
            year: "2026",
            path: "indexes/2026.json.gz",
            records: payload.records.length,
          },
        ],
      },
      CVE_SITEMAP_URL_LIMIT,
      tempRoot,
      new Set(),
      new Set(),
    ),
    [],
  );
});

test("yearly sitemap emits only record-specific significant-update dates", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cve-sitemap-lastmod-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(tempRoot, "indexes"), { recursive: true });
  const payload = {
    year: "2026",
    records: [
      { cve: "CVE-2026-1234", page_lastmod: "2026-07-21" },
      { cve: "CVE-2026-5678" },
    ],
  };
  fs.writeFileSync(
    path.join(tempRoot, "indexes", "2026.json.gz"),
    zlib.gzipSync(JSON.stringify(payload))
  );
  const [entry] = planCveSitemaps(
    {
      catalog_updated_at: "2026-07-22T00:00:00Z",
      total: payload.records.length,
      partitions: [
        {
          year: "2026",
          path: "indexes/2026.json.gz",
          records: payload.records.length,
        },
      ],
    },
    CVE_SITEMAP_URL_LIMIT,
    tempRoot,
  );

  const xml = renderCveSitemap(entry, tempRoot);

  assert.match(
    xml,
    /<url><loc>https:\/\/security-recipes\.ai\/cve\/CVE-2026-1234\/<\/loc><lastmod>2026-07-21<\/lastmod><\/url>/
  );
  assert.match(
    xml,
    /<url><loc>https:\/\/security-recipes\.ai\/cve\/CVE-2026-5678\/<\/loc><\/url>/
  );
  assert.equal(count(xml, "<lastmod>"), 1);
  assert.doesNotMatch(xml, /2026-07-22/);
});

test("sitemap index child lastmods come from each filtered chunk", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cve-sitemap-index-lastmod-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(tempRoot, "indexes"), { recursive: true });
  const records = [
    { cve: "CVE-2026-1001", page_lastmod: "2026-07-18" },
    { cve: "CVE-2026-1002", page_lastmod: "2026-07-20T10:00:00Z" },
    { cve: "CVE-2026-1003", page_lastmod: "2026-07-31" },
  ];
  fs.writeFileSync(
    path.join(tempRoot, "indexes", "2026.json.gz"),
    zlib.gzipSync(JSON.stringify({ year: "2026", records })),
  );
  const entries = planCveSitemaps(
    {
      catalog_updated_at: "2026-08-01T00:00:00Z",
      total: records.length,
      partitions: [
        {
          year: "2026",
          path: "indexes/2026.json.gz",
          records: records.length,
        },
      ],
    },
    1,
    tempRoot,
    new Set(),
    new Set([records[0].cve, records[1].cve]),
  );

  assert.deepEqual(
    entries.map(({ outputPath, count, lastmod }) => ({ outputPath, count, lastmod })),
    [
      { outputPath: "/sitemaps/cves-2026-1.xml", count: 1, lastmod: "2026-07-18" },
      { outputPath: "/sitemaps/cves-2026-2.xml", count: 1, lastmod: "2026-07-20" },
    ],
  );
  const indexXml = renderSitemapIndex(entries, "2026-07-19");
  assert.match(
    indexXml,
    /cves-2026-1\.xml<\/loc><lastmod>2026-07-18<\/lastmod>/,
  );
  assert.match(
    indexXml,
    /cves-2026-2\.xml<\/loc><lastmod>2026-07-20<\/lastmod>/,
  );
  assert.doesNotMatch(indexXml, /2026-07-31|2026-08-01/);
});

test("HTML archive pages provide bounded crawlable canonical CVE links", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cve-archive-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(tempRoot, "indexes"), { recursive: true });

  const records = Array.from({ length: 205 }, (_, index) => ({
    cve: `CVE-2026-${String(index + 1000).padStart(4, "0")}`,
    title: index === 150 ? "Unsafe <script>alert(1)</script> title" : `Record ${index}`,
    severity: index % 2 ? "high" : "medium",
    score: index % 2 ? 8.1 : 5.4,
    published: `2026-07-${String((index % 20) + 1).padStart(2, "0")}T12:00:00Z`,
    kev: index === 150,
    ecosystem: "Test ecosystem",
  }));
  fs.writeFileSync(
    path.join(tempRoot, "indexes", "2026.json.gz"),
    zlib.gzipSync(JSON.stringify({ year: "2026", records }))
  );
  const manifest = {
    catalog_updated_at: "2026-07-21T07:00:00Z",
    total: records.length,
    partitions: [{ year: "2026", path: "indexes/2026.json.gz", records: records.length }],
  };
  const entries = planCveArchivePages(manifest, 100, tempRoot);

  assert.deepEqual(
    entries.map(({ outputPath, offset, records: pageRecords }) => ({
      outputPath,
      offset,
      count: pageRecords.length,
    })),
    [
      { outputPath: "/cve/archive/2026/", offset: 0, count: 100 },
      { outputPath: "/cve/archive/2026/page/2/", offset: 100, count: 100 },
      { outputPath: "/cve/archive/2026/page/3/", offset: 200, count: 5 },
    ]
  );
  assert.equal(cveArchiveOutputPath("2026", 1), "/cve/archive/2026/");
  assert.equal(cveArchiveOutputPath("2026", 3), "/cve/archive/2026/page/3/");

  const html = renderCveArchivePage(entries[1]);
  assert.match(html, /Showing records 101–200 of 205/);
  assert.equal(count(html, 'class="cve-archive__record"'), 100);
  for (const record of entries[1].records) {
    assert.match(html, new RegExp(`href="/cve/${record.cve}/"`));
  }
  assert.match(html, /rel="prev" href="\/cve\/archive\/2026\/"/);
  assert.match(html, /rel="next" href="\/cve\/archive\/2026\/page\/3\/"/);

  const maliciousEntry = entries.find((entry) =>
    entry.records.some((record) => record.title.includes("Unsafe"))
  );
  const maliciousHtml = renderCveArchivePage(maliciousEntry);
  assert.doesNotMatch(maliciousHtml, /<script>/);
  assert.match(maliciousHtml, /Unsafe &lt;script&gt;alert\(1\)&lt;\/script&gt; title/);

  const excludedEntries = planCveArchivePages(
    manifest,
    100,
    tempRoot,
    new Set([records[0].cve]),
  );
  assert.equal(excludedEntries[0].total, records.length - 1);
  assert.ok(
    excludedEntries.every((entry) =>
      entry.records.every((record) => record.cve !== records[0].cve)
    )
  );

  const searchIndexable = new Set([records[0].cve, records[150].cve]);
  const indexableEntries = planCveArchivePages(
    manifest,
    100,
    tempRoot,
    new Set(),
    searchIndexable,
  );
  assert.equal(indexableEntries.length, 1);
  assert.equal(indexableEntries[0].total, searchIndexable.size);
  const indexableHtml = renderCveArchivePage(indexableEntries[0]);
  for (const cve of searchIndexable) {
    assert.match(indexableHtml, new RegExp(`href="/cve/${cve}/"`));
  }
  assert.doesNotMatch(indexableHtml, new RegExp(`href="/cve/${records[1].cve}/"`));
});

test("HTML archive retains reviewed static CVEs at their canonical recipe route", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cve-static-archive-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(tempRoot, "indexes"), { recursive: true });
  const staticCve = "CVE-2017-18342";
  const records = [
    {
      cve: staticCve,
      title: "PyYAML source record",
      page_title: "CVE-2017-18342 — PyYAML safe loading remediation",
      page_description: "Replace unsafe PyYAML loading with safe_load and verify callers.",
      page_lastmod: "2026-07-20",
      published: "2018-06-27T00:00:00Z",
      severity: "high",
    },
    {
      cve: "CVE-2017-9999",
      title: "Dynamic source record",
      page_lastmod: "2026-07-19",
      published: "2018-06-28T00:00:00Z",
      severity: "medium",
    },
  ];
  fs.writeFileSync(
    path.join(tempRoot, "indexes", "2017.json.gz"),
    zlib.gzipSync(JSON.stringify({ year: "2017", records })),
  );
  const manifest = {
    catalog_updated_at: "2026-07-21T07:00:00Z",
    total: records.length,
    partitions: [{ year: "2017", path: "indexes/2017.json.gz", records: records.length }],
  };
  const staticRoute = "/recipes/cve/cve-2017-18342-pyyaml/";
  const entries = planCveArchivePages(
    manifest,
    100,
    tempRoot,
    new Set([staticCve]),
    new Set(records.map((record) => record.cve)),
    new Map([[staticCve, staticRoute]]),
  );

  assert.equal(entries.length, 1);
  assert.equal(entries[0].total, records.length);
  assert.equal(entries[0].lastmod, "2026-07-20");
  const reviewed = entries[0].records.find((record) => record.cve === staticCve);
  assert.deepEqual(
    {
      title: reviewed.title,
      description: reviewed.description,
      pageLastmod: reviewed.pageLastmod,
      url: reviewed.url,
    },
    {
      title: "CVE-2017-18342 — PyYAML safe loading remediation",
      description: "Replace unsafe PyYAML loading with safe_load and verify callers.",
      pageLastmod: "2026-07-20",
      url: staticRoute,
    },
  );
  const html = renderCveArchivePage(entries[0]);
  assert.match(html, /href="\/recipes\/cve\/cve-2017-18342-pyyaml\/"/);
  assert.doesNotMatch(html, /href="\/cve\/CVE-2017-18342\/"/);

  assert.throws(
    () =>
      planCveArchivePages(
        manifest,
        100,
        tempRoot,
        new Set([staticCve]),
        new Set([staticCve]),
        new Map([[staticCve, "https://example.test/escape/"]]),
      ),
    /Unsafe canonical archive route/,
  );
});

test("CVE RSS items prefer reviewed metadata, canonical routes, and page freshness", () => {
  const reviewed = {
    cve: "CVE-2017-18342",
    title: "CVE-2017-18342 — PyYAML safe loading remediation",
    description: "Replace unsafe PyYAML loading with safe_load and verify callers.",
    severity: "high",
    published: "2018-06-27",
    pageLastmod: "2026-07-20",
    url: "/recipes/cve/cve-2017-18342-pyyaml/",
  };
  const generated = {
    cve: "CVE-2026-1234",
    title: "Example parser memory corruption...",
    description: "",
    severity: "critical",
    published: "2026-07-19",
    pageLastmod: "",
    url: "/cve/CVE-2026-1234/",
  };

  const items = buildRecentCatalogItems([{ records: [generated, reviewed] }]);

  assert.equal(items[0].title, reviewed.title);
  assert.equal(items[0].url, reviewed.url);
  assert.equal(items[0].description, reviewed.description);
  assert.equal(items[0].date.toISOString(), "2026-07-20T00:00:00.000Z");
  assert.equal(items[1].title, "CVE-2026-1234: Example parser memory corruption");
  assert.match(items[1].description, /CVE-2026-1234 is a CRITICAL vulnerability/);
  assert.match(items[1].description, /affected versions, source evidence/);
  assert.doesNotMatch(items[1].description, /\.\.\.|…/);
});

test("unsafe partitions and non-canonical CVE IDs fail closed", (t) => {
  assert.throws(
    () =>
      planCveSitemaps({
        total: 1,
        partitions: [{ year: "2026", path: "../2026.json.gz", records: 1 }],
      }),
    /Unsafe CVE catalog partition path/
  );

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cve-sitemap-invalid-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(tempRoot, "indexes"), { recursive: true });
  fs.writeFileSync(
    path.join(tempRoot, "indexes", "2026.json.gz"),
    zlib.gzipSync(JSON.stringify({ records: [{ cve: "cve-2026-0001" }] }))
  );
  const [entry] = planCveSitemaps(
    {
      total: 1,
      partitions: [{ year: "2026", path: "indexes/2026.json.gz", records: 1 }],
    },
    CVE_SITEMAP_URL_LIMIT,
    tempRoot,
  );

  assert.throws(
    () => renderCveSitemap(entry, tempRoot),
    /Invalid canonical CVE ID/
  );
});
