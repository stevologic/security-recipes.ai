"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { getIndex, isDiscoveryPage } = require("../lib/content-index");
const { homepageMetrics } = require("../lib/homepage-metrics");

const ROOT = path.resolve(__dirname, "..");

function json(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
}

test("homepage metrics are derived from the authoritative local sources", () => {
  const metrics = homepageMetrics();
  const runtime = json("static/api/cve-catalog/runtime-summary.json");
  const remediation = json("data/remediation_suite/playbooks.json");
  const compliance = json("data/compliance-frameworks/catalog.json");
  const hygiene = json("data/code-hygiene/catalog.json");
  const mcpSource = fs.readFileSync(path.join(ROOT, "mcp_server.py"), "utf8");
  const reviewed = getIndex().pages.filter(
    (page) =>
      page.sourcePath.startsWith("recipes/") &&
      !page.isSection &&
      isDiscoveryPage(page),
  );

  assert.equal(metrics.cves.value, runtime.totals.catalog_records);
  assert.equal(metrics.reviewedWorkflows.value, reviewed.length);
  assert.equal(metrics.playbooks.value, remediation.playbooks.length);
  assert.equal(
    metrics.mcpTools.value,
    (mcpSource.match(/^\s*@mcp\.tool\s*\(/gm) || []).length,
  );
  assert.equal(metrics.complianceFrameworks.value, compliance.framework_count);
  assert.equal(metrics.codeHygieneWorkflows.value, hygiene.expected_recipe_count);
  assert.equal(metrics.kevRecords.value, runtime.totals.in_scope_kev);
  assert.equal(metrics.updatedAt, runtime.catalog_updated_at);
  assert.equal(metrics.sourceStatus, "authoritative");
  assert.deepEqual(metrics.fallbackSources, []);
});

test("homepage metrics include stable display formats", () => {
  const metrics = homepageMetrics();

  assert.equal(metrics.cves.formatted, metrics.cves.value.toLocaleString("en-US"));
  assert.match(metrics.cves.compact, /^\d+K\+$/);
  assert.equal(
    metrics.reviewedWorkflows.formatted,
    metrics.reviewedWorkflows.value.toLocaleString("en-US"),
  );
  assert.equal(
    metrics.mcpTools.formatted,
    metrics.mcpTools.value.toLocaleString("en-US"),
  );
});
