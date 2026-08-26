"use strict";

const fs = require("node:fs");
const path = require("node:path");

const { getIndex, isDiscoveryPage } = require("./content-index");

const ROOT = path.resolve(__dirname, "..");
const CVE_CATALOG_ROOT = path.resolve(
  String(process.env.SECURITY_RECIPES_CVE_CATALOG_ROOT || "").trim() ||
    path.join(ROOT, "static", "api", "cve-catalog"),
);
const NUMBER_FORMAT = new Intl.NumberFormat("en-US");
const DATE_FORMAT = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  year: "numeric",
  timeZone: "UTC",
});

// These values are layout-safe snapshots, used only when a source file is
// temporarily unavailable. The normal build always derives the live values
// below from the repository's generated catalogs and server implementation.
const FALLBACKS = Object.freeze({
  cves: 266251,
  reviewedWorkflows: 167,
  playbooks: 75,
  mcpTools: 73,
  complianceFrameworks: 39,
  codeHygieneWorkflows: 72,
  kevRecords: 1421,
});

function readJson(relativePath) {
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
  } catch {
    return null;
  }
}

function readJsonFile(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function readText(relativePath) {
  try {
    return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
  } catch {
    return "";
  }
}

function positiveInteger(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : null;
}

function resolvedMetric(value, fallback, label, fallbackSources) {
  const resolved = positiveInteger(value);
  if (resolved !== null) return resolved;
  fallbackSources.push(label);
  return fallback;
}

function metric(value) {
  return {
    value,
    formatted: NUMBER_FORMAT.format(value),
  };
}

function compactThousands(value) {
  if (value < 1000) return NUMBER_FORMAT.format(value);
  return `${Math.floor(value / 1000)}K+`;
}

function reviewedWorkflowCount() {
  try {
    return getIndex().pages.filter(
      (page) =>
        page.sourcePath.startsWith("recipes/") &&
        !page.isSection &&
        isDiscoveryPage(page),
    ).length;
  } catch {
    return null;
  }
}

function mcpToolCount() {
  const source = readText("mcp_server.py");
  if (!source) return null;
  const registrations = source.match(/^\s*@mcp\.tool\s*\(/gm) || [];
  return positiveInteger(registrations.length);
}

function homepageMetrics() {
  const runtime = readJsonFile(path.join(CVE_CATALOG_ROOT, "runtime-summary.json")) || {};
  const remediation = readJson("data/remediation_suite/playbooks.json") || {};
  const compliance = readJson("data/compliance-frameworks/catalog.json") || {};
  const hygiene = readJson("data/code-hygiene/catalog.json") || {};
  const fallbackSources = [];

  const cves = resolvedMetric(
    runtime?.totals?.catalog_records,
    FALLBACKS.cves,
    "CVE catalog total",
    fallbackSources,
  );
  const reviewedWorkflows = resolvedMetric(
    reviewedWorkflowCount(),
    FALLBACKS.reviewedWorkflows,
    "reviewed workflow index",
    fallbackSources,
  );
  const playbooks = resolvedMetric(
    remediation?.playbooks?.length,
    FALLBACKS.playbooks,
    "remediation playbook catalog",
    fallbackSources,
  );
  const mcpTools = resolvedMetric(
    mcpToolCount(),
    FALLBACKS.mcpTools,
    "MCP tool registrations",
    fallbackSources,
  );
  const complianceFrameworks = resolvedMetric(
    compliance?.framework_count ?? compliance?.frameworks?.length,
    FALLBACKS.complianceFrameworks,
    "compliance framework catalog",
    fallbackSources,
  );
  const codeHygieneWorkflows = resolvedMetric(
    hygiene?.expected_recipe_count ?? hygiene?.records?.length,
    FALLBACKS.codeHygieneWorkflows,
    "code-hygiene catalog",
    fallbackSources,
  );
  const kevRecords = resolvedMetric(
    runtime?.totals?.in_scope_kev,
    FALLBACKS.kevRecords,
    "CISA KEV total",
    fallbackSources,
  );
  const updatedAt = String(runtime?.catalog_updated_at || "");
  let updatedDate = "";
  if (updatedAt) {
    const parsed = new Date(updatedAt);
    if (!Number.isNaN(parsed.valueOf())) updatedDate = DATE_FORMAT.format(parsed);
  }

  if (fallbackSources.length) {
    console.warn(
      `[homepage-metrics] Using last verified snapshots for: ${fallbackSources.join(", ")}`,
    );
  }

  return {
    cves: {
      ...metric(cves),
      compact: compactThousands(cves),
    },
    reviewedWorkflows: metric(reviewedWorkflows),
    playbooks: metric(playbooks),
    mcpTools: metric(mcpTools),
    complianceFrameworks: metric(complianceFrameworks),
    codeHygieneWorkflows: metric(codeHygieneWorkflows),
    kevRecords: metric(kevRecords),
    updatedAt,
    updatedDate,
    sourceStatus: fallbackSources.length ? "fallback" : "authoritative",
    fallbackSources,
  };
}

module.exports = {
  FALLBACKS,
  homepageMetrics,
};
