const assert = require("node:assert/strict");
const test = require("node:test");

const {
  CANONICAL_CVE_ID,
  CVE_SITEMAP_URL_LIMIT,
  isPagesSitemapEntry,
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
const {
  canonicalCvePresentationLastmod,
} = require("../lib/cve-editorial-metadata");
const {
  loadCveSearchIndexableRecords,
} = require("../lib/cve-indexability");

function count(xml, token) {
  return xml.split(token).length - 1;
}

test("CVE archive display text removes upstream encoding artifacts", () => {
  assert.equal(
    cleanCveSourceText("SAP\uFFFDBusinessObjects Business\uFFFDIntelligence"),
    "SAP BusinessObjects Business Intelligence",
  );
  assert.equal(cleanCveSourceText("application\uFFFDs memory"), "application's memory");
  assert.equal(cleanCveSourceText("Composer\u00e2\u20ac\u2122s backup"), "Composer’s backup");
  assert.equal(cleanCveSourceText("Intel\u00e2\u201e\u00a2 product"), "Intel™ product");
  assert.equal(cleanCveSourceText("Cisco IM &amp;P&nbsp;Service"), "Cisco IM &P Service");
  assert.equal(cleanCveSourceText("Ângela — München"), "Ângela — München");
});

test("verified compact records plan bounded publication-year sitemaps", () => {
  const records = loadCveSearchIndexableRecords();
  const entries = planCveSitemaps(records);
  const entriesByYear = Map.groupBy
    ? Map.groupBy(entries, (entry) => entry.year)
    : entries.reduce((grouped, entry) => {
        const current = grouped.get(entry.year) || [];
        current.push(entry);
        grouped.set(entry.year, current);
        return grouped;
      }, new Map());
  const recordCountsByYear = records.reduce((counts, record) => {
    const year = record.published.slice(0, 4);
    counts.set(year, (counts.get(year) || 0) + 1);
    return counts;
  }, new Map());

  assert.equal(
    entries.reduce((total, entry) => total + entry.count, 0),
    records.length,
  );
  assert.equal(new Set(entries.map((entry) => entry.outputPath)).size, entries.length);
  assert.deepEqual(
    [...entriesByYear.keys()].sort(),
    [...recordCountsByYear.keys()].sort(),
  );
  for (const [year, recordCount] of recordCountsByYear) {
    const yearEntries = entriesByYear.get(year);
    const expectedChunks = Math.ceil(recordCount / CVE_SITEMAP_URL_LIMIT);
    assert.ok(yearEntries);
    assert.equal(yearEntries.length, expectedChunks);
    assert.equal(
      yearEntries.reduce((total, entry) => total + entry.count, 0),
      recordCount,
    );
    yearEntries.forEach((entry, index) => {
      assert.ok(entry.count > 0);
      assert.ok(entry.count < 50_000);
      assert.ok(entry.count <= CVE_SITEMAP_URL_LIMIT);
      assert.equal(entry.offset, index * CVE_SITEMAP_URL_LIMIT);
      assert.equal(entry.records.length, entry.count);
      assert.ok(entry.records.every((record) => record.published.startsWith(year)));
      assert.equal(Object.hasOwn(entry, "sourcePath"), false);
      if (expectedChunks === 1) {
        assert.equal(entry.outputPath, `/sitemaps/cves-${year}.xml`);
      } else {
        assert.equal(entry.outputPath, `/sitemaps/cves-${year}-${index + 1}.xml`);
      }
    });
  }
});

test("a 500,001-record qualified projection is split into bounded sitemap chunks", () => {
  const records = Array.from({ length: 500_001 }, (_, index) => ({
    cve: `CVE-2026-${index + 1000}`,
    published: "2026-07-17",
  }));
  const entries = planCveSitemaps(records, CVE_SITEMAP_URL_LIMIT);

  assert.equal(entries.length, 11);
  assert.deepEqual(
    Object.fromEntries(Object.entries(entries[0]).filter(([key]) => key !== "records")),
    {
      year: "2026",
      outputPath: "/sitemaps/cves-2026-1.xml",
      offset: 0,
      count: 49_000,
      lastmod: "",
    },
  );
  assert.deepEqual(
    Object.fromEntries(Object.entries(entries.at(-1)).filter(([key]) => key !== "records")),
    {
      year: "2026",
      outputPath: "/sitemaps/cves-2026-11.xml",
      offset: 490_000,
      count: 10_001,
      lastmod: "",
    },
  );
  assert.equal(entries[0].records.length, 49_000);
  assert.equal(entries.at(-1).records.length, 10_001);
  assert.equal(entries.reduce((total, entry) => total + entry.count, 0), 500_001);
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
      sourcePath: "recipes/cve/historical/cve-2014-0160-heartbleed.md",
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

test("yearly sitemap renders only canonical dynamic CVE detail URLs", () => {
  const records = [
    { cve: "CVE-2026-0001", published: "2026-07-17" },
    { cve: "CVE-2026-12345", published: "2026-07-17" },
    { cve: "CVE-2026-9999999", published: "2026-07-17" },
  ];
  const [entry] = planCveSitemaps(records);
  const xml = renderCveSitemap(entry);

  assert.equal(count(xml, "<url>"), records.length);
  for (const { cve } of records) {
    assert.match(cve, CANONICAL_CVE_ID);
    assert.match(
      xml,
      new RegExp(`<loc>https:\\/\\/security-recipes\\.ai\\/cve\\/${cve}\\/<\\/loc>`)
    );
  }
  assert.doesNotMatch(xml, /\/recipes\/\?view=cve/);
  assert.doesNotMatch(xml, /<lastmod>/);

  const [filteredEntry] = planCveSitemaps(
    records,
    CVE_SITEMAP_URL_LIMIT,
    new Set([records[1].cve]),
  );
  const filtered = renderCveSitemap(filteredEntry);
  assert.equal(count(filtered, "<url>"), records.length - 1);
  assert.doesNotMatch(filtered, new RegExp(`/cve/${records[1].cve}/`));
  assert.deepEqual(planCveSitemaps([]), []);
});

test("yearly sitemap emits only record-specific significant-update dates", () => {
  const records = [
    { cve: "CVE-2026-1234", published: "2026-07-17", page_lastmod: "2026-07-21" },
    { cve: "CVE-2026-5678", published: "2026-07-17" },
  ];
  const [entry] = planCveSitemaps(records);

  const xml = renderCveSitemap(entry);

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

test("sitemap index child lastmods come from each compact-record chunk", () => {
  const records = [
    { cve: "CVE-2026-1001", published: "2026-07-17", page_lastmod: "2026-07-18" },
    { cve: "CVE-2026-1002", published: "2026-07-17", page_lastmod: "2026-07-20" },
    { cve: "CVE-2026-1003", published: "2026-07-17", page_lastmod: "2026-07-31" },
  ];
  const entries = planCveSitemaps(
    records,
    1,
    new Set([records[2].cve]),
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

test("HTML archive pages provide bounded crawlable canonical CVE links", () => {
  const records = Array.from({ length: 205 }, (_, index) => ({
    cve: `CVE-2026-${String(index + 1000).padStart(4, "0")}`,
    title: index === 150 ? "Unsafe <SCRIPT src=x>alert(1)</SCRIPT> title" : `Record ${index}`,
    severity: index % 2 ? "high" : "medium",
    score: index % 2 ? 8.1 : 5.4,
    published: `2026-07-${String((index % 20) + 1).padStart(2, "0")}`,
    kev: index === 150,
    ecosystem: "Test ecosystem",
  }));
  const entries = planCveArchivePages(records, 100);

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
  assert.doesNotMatch(maliciousHtml, /<script\b/i);
  assert.match(maliciousHtml, /Unsafe &lt;SCRIPT src=x&gt;alert\(1\)&lt;\/SCRIPT&gt; title/);

  const excludedEntries = planCveArchivePages(
    records,
    100,
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
    records.filter((record) => searchIndexable.has(record.cve)),
    100,
  );
  assert.equal(indexableEntries.length, 1);
  assert.equal(indexableEntries[0].total, searchIndexable.size);
  const indexableHtml = renderCveArchivePage(indexableEntries[0]);
  for (const cve of searchIndexable) {
    assert.match(indexableHtml, new RegExp(`href="/cve/${cve}/"`));
  }
  assert.doesNotMatch(indexableHtml, new RegExp(`href="/cve/${records[1].cve}/"`));
});

test("HTML archive retains reviewed static CVEs at their canonical recipe route", () => {
  const staticCve = "CVE-2017-18342";
  const records = [
    {
      cve: staticCve,
      title: "PyYAML source record",
      page_title: "CVE-2017-18342 — PyYAML safe loading remediation",
      page_description: "Replace unsafe PyYAML loading with safe_load and verify callers.",
      page_lastmod: "2026-07-20",
      published: "2018-06-27",
      severity: "high",
    },
    {
      cve: "CVE-2017-9999",
      title: "Dynamic source record",
      page_lastmod: "2026-07-19",
      published: "2018-06-28",
      severity: "medium",
    },
  ];
  const staticRoute = "/recipes/cve/cve-2017-18342-pyyaml/";
  const entries = planCveArchivePages(
    records,
    100,
    new Set([staticCve]),
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
        records,
        100,
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

test("CVE RSS disambiguates canonical records that share source titles", () => {
  const records = [
    ["CVE-2021-41773", "Apache HTTP Server Path Traversal Vulnerability"],
    ["CVE-2021-42013", "Apache HTTP Server Path Traversal Vulnerability"],
    ["CVE-2025-20281", "Cisco ISE API Remote Code Execution Vulnerability"],
    ["CVE-2025-20337", "Cisco ISE API Remote Code Execution Vulnerability"],
  ].map(([cve, title]) => ({
    cve,
    title,
    description: `${cve} source description`,
    severity: "critical",
    published: "2026-01-01",
    pageLastmod: "",
    url: `/cve/${cve}/`,
  }));

  const byUrl = new Map(
    buildRecentCatalogItems([{ records }]).map((item) => [item.url, item]),
  );
  assert.equal(
    byUrl.get("/cve/CVE-2021-41773/").title,
    "CVE-2021-41773: Apache HTTP Server 2.4.49 Path Traversal",
  );
  assert.equal(
    byUrl.get("/cve/CVE-2021-42013/").title,
    "CVE-2021-42013: Apache HTTP Server 2.4.50 Incomplete-Fix Bypass",
  );
  assert.equal(
    byUrl.get("/cve/CVE-2025-20281/").title,
    "CVE-2025-20281: Cisco ISE API Root RCE (CSCwo99449)",
  );
  assert.equal(
    byUrl.get("/cve/CVE-2025-20337/").title,
    "CVE-2025-20337: Cisco ISE API Root RCE (CSCwp02814)",
  );
  assert.match(
    byUrl.get("/cve/CVE-2025-20281/").description,
    /CSCwo99449/,
  );
  assert.match(
    byUrl.get("/cve/CVE-2025-20337/").description,
    /CSCwp02814/,
  );
});

test("CVE RSS preserves concise reviewed titles for canonical stable pages", () => {
  const reviewedTitles = new Map([
    ["CVE-2026-14956", "CVE-2026-14956 — Bricksforge Pro Forms privilege escalation"],
    ["CVE-2021-44228", "CVE-2021-44228 — Log4Shell"],
    ["CVE-2024-6387", "CVE-2024-6387: OpenSSH regreSSHion RCE Remediation"],
  ]);
  const records = [...reviewedTitles].map(([cve, pageTitle]) => ({
    cve,
    title: `${cve} verbose upstream source sentence that should not replace reviewed copy`,
    page_title: pageTitle,
    page_description: `${cve} reviewed remediation summary`,
    severity: "critical",
    published: "2026-01-01",
  }));
  const byUrl = new Map(
    buildRecentCatalogItems(planCveArchivePages(records, 100)).map((item) => [item.url, item]),
  );
  assert.equal(
    byUrl.get("/cve/CVE-2026-14956/").title,
    "CVE-2026-14956 — Bricksforge Pro Forms privilege escalation",
  );
  assert.equal(
    byUrl.get("/cve/CVE-2021-44228/").title,
    "CVE-2021-44228 — Log4Shell",
  );
  assert.equal(
    byUrl.get("/cve/CVE-2024-6387/").title,
    "CVE-2024-6387: OpenSSH regreSSHion RCE Remediation",
  );
});

test("editorial CVE updates advance canonical sitemap freshness", () => {
  assert.equal(
    canonicalCvePresentationLastmod("CVE-2021-41773", "2026-07-17"),
    "2026-07-23",
  );
  assert.equal(
    canonicalCvePresentationLastmod("CVE-2026-33116", "2026-07-15"),
    "2026-07-23",
  );
  assert.equal(
    canonicalCvePresentationLastmod("CVE-2024-3400", "2026-07-20"),
    "2026-07-20",
  );
  assert.equal(
    canonicalCvePresentationLastmod("CVE-2021-41773", "2026-08-01"),
    "2026-08-01",
  );
  assert.equal(
    canonicalCvePresentationLastmod(
      "CVE-2021-41773",
      "2026-08-02T10:15:30Z",
    ),
    "2026-08-02",
  );
});

test("malformed compact records fail closed and use publication year", () => {
  assert.throws(
    () => planCveSitemaps({ records: [] }),
    /must be an array/,
  );
  assert.throws(
    () => planCveSitemaps([{ cve: "cve-2026-0001", published: "2026-07-17" }]),
    /Invalid canonical CVE ID/,
  );
  assert.throws(
    () => planCveSitemaps([{ cve: "CVE-2026-0001", published: "" }]),
    /Invalid publication date/,
  );
  assert.throws(
    () => planCveSitemaps([
      { cve: "CVE-2026-0001", published: "2026-07-17" },
      { cve: "CVE-2026-0001", published: "2026-07-18" },
    ]),
    /Duplicate search-indexable CVE record/,
  );

  const [entry] = planCveSitemaps([
    { cve: "CVE-2025-9999", published: "2026-01-02" },
  ]);
  assert.equal(entry.year, "2026");
  assert.equal(entry.outputPath, "/sitemaps/cves-2026.xml");
  assert.match(renderCveSitemap(entry), /\/cve\/CVE-2025-9999\//);

  assert.throws(
    () => renderCveSitemap({ ...entry, year: "2025" }),
    /wrong publication-year sitemap/,
  );
});
