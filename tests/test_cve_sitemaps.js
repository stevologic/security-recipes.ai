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

test("future oversized yearly partitions are split below 50,000 URLs", () => {
  const manifest = {
    catalog_updated_at: "2026-07-17T07:02:25Z",
    total: 100_001,
    partitions: [
      { year: "2026", path: "indexes/2026.json.gz", records: 100_001 },
    ],
  };
  const entries = planCveSitemaps(manifest);

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
  const xml = renderSitemapIndex(entries);

  assert.match(xml, /^<\?xml version="1\.0" encoding="utf-8"\?>/);
  assert.match(xml, /<sitemapindex xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  assert.match(xml, /<loc>https:\/\/security-recipes\.ai\/sitemaps\/pages\.xml<\/loc>/);
  assert.match(xml, /<loc>https:\/\/security-recipes\.ai\/sitemaps\/cves-2025\.xml<\/loc>/);
  assert.match(xml, /<loc>https:\/\/security-recipes\.ai\/sitemaps\/cves-2026\.xml<\/loc>/);
  assert.equal(count(xml, "<sitemap>"), 3);
  assert.doesNotMatch(xml, /<urlset/);
});

test("normal pages sitemap excludes only CVE aliases owned by catalog routes", () => {
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
  const [entry] = planCveSitemaps({
    catalog_updated_at: "2026-07-17T07:02:25Z",
    total: payload.records.length,
    partitions: [
      {
        year: "2026",
        path: "indexes/2026.json.gz",
        records: payload.records.length,
      },
    ],
  });
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
  const [entry] = planCveSitemaps({
    total: 1,
    partitions: [{ year: "2026", path: "indexes/2026.json.gz", records: 1 }],
  });

  assert.throws(
    () => renderCveSitemap(entry, tempRoot),
    /Invalid canonical CVE ID/
  );
});
