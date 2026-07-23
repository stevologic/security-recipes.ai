const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  SEARCH_INDEX_POLICY,
  SEARCH_INDEX_SCHEMA_VERSION,
  hasCompleteAiEnrichment,
  hasStableMarkdown,
  isCveSearchIndexable,
  loadCveSearchIndexableIds,
  loadCveSearchIndexableRecords,
} = require("../lib/cve-indexability");

function qualifiedRecord(cve, overrides = {}) {
  return {
    cve,
    title: `${cve} qualified guidance`,
    severity: "critical",
    score: 9.8,
    published: "2026-07-20",
    ecosystem: "software/application",
    kev: true,
    archetypes: ["command-code-injection"],
    cwes: ["CWE-78"],
    products: [{ vendor: "Example", product: "Widget" }],
    qualification: "recipe_ready_ai",
    ...overrides,
  };
}

test("CVE search indexability requires stable Markdown or an explicit qualified decision", () => {
  assert.equal(hasStableMarkdown({ has_markdown: true }), true);
  assert.equal(hasStableMarkdown({ recipe_kind: "markdown-override" }), true);
  assert.equal(
    hasStableMarkdown({ markdown: [{ maturity: "development" }, { maturity: "stable" }] }),
    true,
  );
  assert.equal(hasStableMarkdown({ quality: "curated" }), false);

  assert.equal(hasCompleteAiEnrichment({ ai_enrichment: { status: "complete" } }), true);
  assert.equal(
    hasCompleteAiEnrichment({ ai_enrichment: { status: "insufficient_evidence" } }),
    false,
  );
  assert.equal(hasCompleteAiEnrichment({ ai_enrichment: ["complete"] }), false);
  assert.equal(isCveSearchIndexable({ recipe_kind: "composed" }), false);
  assert.equal(
    isCveSearchIndexable({
      recipe_kind: "composed",
      ai_enrichment: { status: "complete" },
    }),
    false,
  );
  assert.equal(isCveSearchIndexable({ search_indexable: true }), true);
});

test("indexable CVE IDs come from the integrity-checked evidence-qualified allowlist", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cve-indexability-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const catalogUpdatedAt = "2026-07-21T00:00:00Z";
  const searchIndex = Buffer.from(JSON.stringify({
    schema_version: SEARCH_INDEX_SCHEMA_VERSION,
    catalog_updated_at: catalogUpdatedAt,
    policy: SEARCH_INDEX_POLICY,
    records: [
      qualifiedRecord("CVE-2026-1000", { qualification: "stable_markdown" }),
      qualifiedRecord("CVE-2026-1001"),
    ],
  }));
  fs.writeFileSync(path.join(root, "search-indexable.json"), searchIndex);
  fs.writeFileSync(
    path.join(root, "manifest.json"),
    JSON.stringify({
      catalog_updated_at: catalogUpdatedAt,
      search_index: {
        path: "search-indexable.json",
        schema_version: SEARCH_INDEX_SCHEMA_VERSION,
        policy: SEARCH_INDEX_POLICY,
        records: 2,
        bytes: searchIndex.length,
        sha256: crypto.createHash("sha256").update(searchIndex).digest("hex"),
      },
    }),
  );

  assert.deepEqual(
    [...loadCveSearchIndexableIds(root)].sort(),
    ["CVE-2026-1000", "CVE-2026-1001"],
  );
  assert.deepEqual(
    loadCveSearchIndexableRecords(root).map((record) => record.qualification),
    ["stable_markdown", "recipe_ready_ai"],
  );
});

test("tampered search allowlists fail closed", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cve-indexability-tamper-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = Buffer.from("{}\n");
  fs.writeFileSync(path.join(root, "search-indexable.json"), source);
  fs.writeFileSync(path.join(root, "manifest.json"), JSON.stringify({
    catalog_updated_at: "2026-07-21T00:00:00Z",
    search_index: {
      path: "search-indexable.json",
      schema_version: SEARCH_INDEX_SCHEMA_VERSION,
      policy: SEARCH_INDEX_POLICY,
      records: 0,
      bytes: source.length,
      sha256: "0".repeat(64),
    },
  }));

  assert.throws(
    () => loadCveSearchIndexableIds(root),
    /search index integrity mismatch/,
  );
});
