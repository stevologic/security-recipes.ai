"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const MarkdownIt = require("markdown-it");

const { createPreprocessor } = require("../lib/hugo-preprocess");
const { getIndex } = require("../lib/content-index");
const { homepageMetrics } = require("../lib/homepage-metrics");
const {
  CANONICAL_CVE_ID,
  loadCveSearchIndexableRecords,
  searchIndexablePublicationStats,
} = require("../lib/cve-indexability");
const { planCveSitemaps } = require("../eleventy.config").cveSitemaps;

const ROOT = path.resolve(__dirname, "..");
const COUNT_PAGES = [
  path.join("content", "security-remediation", "_index.md"),
  path.join("content", "mcp-servers", "_index.md"),
];
const HARDCODED_COUNT = /\b(\d+)\s+search-indexable CVE pages\b/gu;

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function publishedCountSentence(source) {
  const match = source.match(
    /(\d+) search-indexable CVE pages(?:: (\d+) human-reviewed stable guides\nand (\d+) AI-qualified pages|\s+\((\d+) stable, (\d+)\nAI-qualified\))/,
  );
  assert.ok(match, "expected a generated search-indexable count sentence");
  return {
    total: Number(match[1]),
    stable: Number(match[2] || match[4]),
    aiQualified: Number(match[3] || match[5]),
  };
}

test("published search-indexable counts are generated from the catalog", () => {
  const stats = searchIndexablePublicationStats();
  const manifest = JSON.parse(read("static/api/cve-catalog/manifest.json"));
  const records = loadCveSearchIndexableRecords();
  const preprocess = createPreprocessor(new MarkdownIt());

  assert.equal(stats.total, records.length);
  assert.equal(stats.total, manifest.totals.search_indexable_records);
  assert.equal(stats.manifestTotal, manifest.totals.search_indexable_records);
  assert.equal(stats.catalogRecords, manifest.totals.catalog_records);
  assert.equal(stats.stableMarkdown + stats.recipeReadyAi, stats.total);
  assert.equal(homepageMetrics().cves.value, stats.catalogRecords);

  const renderedCounts = COUNT_PAGES.map((relativePath) => {
    const source = read(relativePath);
    assert.match(source, /\{\{<\s*search-indexable-count field="total"\s*>\}\}/u);
    assert.doesNotMatch(source, HARDCODED_COUNT);
    return publishedCountSentence(preprocess(source, relativePath));
  });

  assert.deepEqual(new Set(renderedCounts.map((count) => JSON.stringify(count))).size, 1);
  assert.deepEqual(renderedCounts[0], {
    total: stats.total,
    stable: stats.stableMarkdown,
    aiQualified: stats.recipeReadyAi,
  });
});

test("search-indexable pages, manifest, and sitemap owners stay aligned", () => {
  const stats = searchIndexablePublicationStats();
  const records = loadCveSearchIndexableRecords();
  const historicalIds = new Set(
    getIndex()
      .pages.filter(
        (page) =>
          page.fm?.canonical_cve_route === false &&
          String(page.fm?.maturity || "").toLowerCase() === "stable" &&
          CANONICAL_CVE_ID.test(String(page.fm?.cve || "")),
      )
      .map((page) => String(page.fm.cve)),
  );
  const sitemapCount = planCveSitemaps(records, undefined, historicalIds)
    .reduce((total, entry) => total + entry.count, 0);
  const historicalIndexable = records.filter((record) => historicalIds.has(record.cve)).length;

  assert.equal(sitemapCount + historicalIndexable, stats.total);
  assert.equal(historicalIndexable, 1);
});

test("authored copy does not hardcode a disagreeing search-indexable count", () => {
  const stats = searchIndexablePublicationStats();
  const mismatches = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === "public") continue;
        walk(fullPath);
        continue;
      }
      if (!entry.name.endsWith(".md") && !entry.name.endsWith(".njk") && !entry.name.endsWith(".html")) {
        continue;
      }
      const source = fs.readFileSync(fullPath, "utf8");
      for (const match of source.matchAll(HARDCODED_COUNT)) {
        if (Number(match[1]) !== stats.total) {
          mismatches.push(`${path.relative(ROOT, fullPath)}:${match[1]}`);
        }
      }
    }
  };

  walk(path.join(ROOT, "content"));
  walk(path.join(ROOT, "_includes"));
  assert.deepEqual(mismatches, []);
});
