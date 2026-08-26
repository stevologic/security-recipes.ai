"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const zlib = require("node:zlib");

const ROOT = path.resolve(__dirname, "..");
const {
  copyCatalog,
  validateCatalogRoot,
} = require("../scripts/copy_cve_catalog");
const { addStaticPassthroughCopies } =
  require("../eleventy.config").catalogBuildBoundary;

function digest(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function writeFile(root, relative, bytes) {
  const destination = path.join(root, ...relative.split("/"));
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, bytes);
  return {
    path: relative,
    bytes: bytes.length,
    sha256: digest(bytes),
  };
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function writeCatalog(root, catalogRecords = 777) {
  fs.mkdirSync(root, { recursive: true });
  const updated = "2026-08-26T00:00:00Z";
  const record = {
    cve: "CVE-2099-9999",
    title: "Temporary catalog root sentinel",
    severity: "high",
    score: 8.1,
    published: "2099-01-15",
    ecosystem: "software/application",
    kev: false,
    archetypes: ["command_code_injection"],
    cwes: ["CWE-78"],
    products: [{ vendor: "Boundary Labs", product: "Sentinel" }],
    qualification: "stable_markdown",
  };
  const browserPayload = zlib.gzipSync(jsonBytes({ schema_version: 2, records: [] }));
  const browser = writeFile(root, "browser-index.json.gz", browserPayload);
  const search = {
    ...writeFile(
      root,
      "search-indexable.json",
      jsonBytes({
        schema_version: 2,
        policy: "stable-markdown-or-recipe-ready-v1",
        catalog_updated_at: updated,
        records: [record],
      }),
    ),
    schema_version: 2,
    policy: "stable-markdown-or-recipe-ready-v1",
    records: 1,
  };
  const partitionPayload = zlib.gzipSync(
    jsonBytes({
      schema_version: 2,
      year: "2099",
      records: [record],
    }),
  );
  const partition = {
    ...writeFile(root, "indexes/2099.json.gz", partitionPayload),
    records: 1,
    uncompressed_bytes: zlib.gunzipSync(partitionPayload).length,
    year: "2099",
  };
  const shardPayload = zlib.gzipSync(jsonBytes({ ...record, summary: "Sentinel record" }));
  const shard = {
    ...writeFile(root, "shards/2099/0009.jsonl.gz", shardPayload),
    records: 1,
    uncompressed_bytes: zlib.gunzipSync(shardPayload).length,
  };
  const archetypesBytes = fs.readFileSync(
    path.join(ROOT, "static", "api", "cve-catalog", "archetypes.json"),
  );
  const archetypes = writeFile(root, "archetypes.json", archetypesBytes);
  const runtime = writeFile(
    root,
    "runtime-summary.json",
    jsonBytes({
      schema_version: 2,
      catalog_updated_at: updated,
      scope: { published_start: "2099-01-01", published_end: "2099-12-31" },
      totals: {
        catalog_records: catalogRecords,
        in_scope_kev: 0,
        agentic_recipe_coverage: catalogRecords,
      },
      by_severity: { medium: 0, high: catalogRecords, critical: 0 },
      browser_index: {
        ...browser,
        records: catalogRecords,
        uncompressed_bytes: zlib.gunzipSync(browserPayload).length,
      },
      search_api: {
        schema_version: 1,
        path: "search",
        max_query_length: 120,
        max_results: 100,
      },
      record_api: {
        schema_version: 1,
        path: "records/{cve}",
        max_response_bytes: 524288,
      },
      shard_set_sha256: "a".repeat(64),
    }),
  );
  const completeIndex = {
    format: "published-year-partitions",
    path: "index.json",
    records: 1,
    partitions: [partition],
  };
  writeFile(
    root,
    "index.json",
    jsonBytes({
      schema_version: 2,
      catalog_updated_at: updated,
      partition_key: "published_year",
      scope: { published_start: "2099-01-01", published_end: "2099-12-31" },
      total: 1,
      partitions: [partition],
    }),
  );
  fs.writeFileSync(
    path.join(root, "manifest.json"),
    jsonBytes({
      schema_version: 2,
      catalog_updated_at: updated,
      totals: { catalog_records: catalogRecords },
      archetypes_asset: archetypes,
      browser_index: browser,
      runtime_summary: runtime,
      search_index: search,
      complete_index: completeIndex,
      shard_manifest: [shard],
    }),
  );
  return { record };
}

test("Eleventy registers every non-catalog static entry, including dotfiles", () => {
  const copies = [];
  addStaticPassthroughCopies({
    addPassthroughCopy(value) {
      copies.push(value);
    },
  });
  const sources = copies.flatMap((copy) => Object.keys(copy));
  assert.ok(sources.includes("static/.nojekyll"));
  assert.ok(sources.includes("static/images"));
  assert.ok(sources.includes("static/site.webmanifest"));
  assert.equal(sources.some((source) => source.includes("cve-catalog")), false);
  assert.equal(sources.includes("static"), false);
});

test("validated catalog post-copy is exact, replaceable, and confined to the API subtree", (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "cve-catalog-copy-test-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const source = path.join(temporary, "source");
  const output = path.join(temporary, "site");
  fs.mkdirSync(output);
  fs.writeFileSync(path.join(output, ".nojekyll"), "");
  writeCatalog(source);

  const validated = validateCatalogRoot(source);
  const first = copyCatalog(source, output);
  const second = copyCatalog(source, output);
  assert.equal(first.files, validated.declared.size);
  assert.deepEqual(second, first);
  assert.equal(fs.readFileSync(path.join(output, ".nojekyll"), "utf8"), "");
  assert.deepEqual(
    fs.readFileSync(path.join(output, "api", "cve-catalog", "manifest.json")),
    fs.readFileSync(path.join(source, "manifest.json")),
  );

  fs.appendFileSync(path.join(source, "browser-index.json.gz"), "corruption");
  assert.throws(() => validateCatalogRoot(source), /byte count differs from the manifest/);
});

test("catalog validation rejects files outside the manifest inventory", (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "cve-catalog-orphan-test-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  writeCatalog(temporary);
  fs.writeFileSync(path.join(temporary, "orphan.json"), "{}\n");
  assert.throws(() => validateCatalogRoot(temporary), /orphaned=orphan\.json/);
});

test("Eleventy data readers honor the catalog-root override and preserve the default", (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "cve-catalog-env-test-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const fixture = writeCatalog(temporary);
  const environment = {
    ...process.env,
    SECURITY_RECIPES_CVE_CATALOG_ROOT: temporary,
  };
  const script = String.raw`
    const config = require('./eleventy.config');
    const records = require('./lib/cve-indexability').loadCveSearchIndexableRecords();
    const latest = require('./lib/cve-latest').latestCves(1);
    const metrics = require('./lib/homepage-metrics').homepageMetrics();
    const database = require('./lib/shortcodes/cve-database')();
    process.stdout.write(JSON.stringify({
      root: config.catalogBuildBoundary.catalogRoot,
      cves: records.map((record) => record.cve),
      latest: latest.map((record) => record.cve),
      total: metrics.cves.value,
      databaseHasSentinel: database.includes('Temporary catalog root sentinel'),
    }));
  `;
  const overridden = spawnSync("node", ["-e", script], {
    cwd: ROOT,
    env: environment,
    encoding: "utf8",
  });
  assert.equal(overridden.status, 0, overridden.stderr || overridden.stdout);
  const result = JSON.parse(overridden.stdout);
  assert.equal(path.resolve(result.root), path.resolve(temporary));
  assert.deepEqual(result.cves, [fixture.record.cve]);
  assert.deepEqual(result.latest, [fixture.record.cve]);
  assert.equal(result.total, 777);
  assert.equal(result.databaseHasSentinel, true);

  const defaultEnvironment = { ...process.env };
  delete defaultEnvironment.SECURITY_RECIPES_CVE_CATALOG_ROOT;
  const defaultRoot = spawnSync(
    "node",
    ["-e", "process.stdout.write(require('./eleventy.config').catalogBuildBoundary.catalogRoot)"],
    { cwd: ROOT, env: defaultEnvironment, encoding: "utf8" },
  );
  assert.equal(defaultRoot.status, 0, defaultRoot.stderr || defaultRoot.stdout);
  assert.equal(
    path.resolve(defaultRoot.stdout),
    path.resolve(ROOT, "static", "api", "cve-catalog"),
  );
});
