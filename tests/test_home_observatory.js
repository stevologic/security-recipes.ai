"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");

function source(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

test("homepage preserves the observatory narrative and authoritative bindings", () => {
  const template = source("_includes/layouts/home-static.html");

  assert.match(
    template,
    /OPEN SECURITY INTELLIGENCE &bull; HUMAN \+ AGENT READY/,
  );
  assert.match(
    template,
    /From vulnerability intelligence to verified action/,
  );
  assert.match(template, /homepageMetrics\.cves\.compact/);
  assert.match(template, /homepageMetrics\.reviewedWorkflows\.formatted/);
  assert.match(template, /homepageMetrics\.playbooks\.formatted/);
  assert.match(template, /homepageMetrics\.mcpTools\.formatted/);
  assert.match(template, /CVE-2021-44228/);
  assert.match(template, /Vulnerable Dependency Remediation/);
  assert.match(template, /Proof required/);
});

test("homepage action links point to local, reviewable product surfaces", () => {
  const template = source("_includes/layouts/home-static.html");
  const expectedLinks = [
    "/recipes/",
    "/mcp-servers/",
    "/security-remediation/",
    "/security-remediation/#exact-scope",
    "/mcp-servers/#read-only-context",
    "/security-remediation/reviewer-playbook/#proof-by-default",
    "/security-remediation/reviewer-playbook/#human-in-the-loop",
    "/docs/ai-adoption-blueprint/",
    "/quickstart/",
  ];

  for (const href of expectedLinks) {
    const escapedHref = href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    assert.match(template, new RegExp(`href="${escapedHref}"`));
  }

  assert.match(
    template,
    /href="https:\/\/github\.com\/stevologic\/security-recipes\.ai"/,
  );
});

test("homepage motion is bounded by user preference and page visibility", () => {
  const template = source("_includes/layouts/home-static.html");
  const css = source("assets/css/home-observatory.css");
  const background = source("assets/js/home-signal-background.js");

  assert.match(template, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(background, /matchMedia\("\(prefers-reduced-motion: reduce\)"\)/);
  assert.match(background, /document\.addEventListener\("visibilitychange", start\)/);
  assert.doesNotMatch(background, /https?:\/\//);
});
