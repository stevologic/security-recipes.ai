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
    /Search CVEs\. Remediate vulnerabilities with AI agents/,
  );
  assert.match(template, /homepageMetrics\.cves\.compact/);
  assert.match(template, /homepageMetrics\.reviewedWorkflows\.formatted/);
  assert.match(template, /homepageMetrics\.playbooks\.formatted/);
  assert.match(template, /homepageMetrics\.mcpTools\.formatted/);
  assert.match(template, /CVE-2021-44228/);
  assert.match(template, /Vulnerable Dependency Remediation/);
  assert.match(template, /Proof required/);
});

test("homepage research console keeps a complete heading outline", () => {
  const template = source("_includes/layouts/home-static.html");
  const consoleAt = template.indexOf('<section class="research-console">');
  const headingAt = template.indexOf(
    '<h2 class="sr-only">Security Research Console example</h2>',
    consoleAt,
  );
  const findingAt = template.indexOf(
    "<h3>Apache Log4j Remote Code Execution</h3>",
    consoleAt,
  );

  assert.notEqual(consoleAt, -1, "homepage must retain the research console");
  assert.ok(headingAt > consoleAt, "research console must introduce an accessible H2");
  assert.ok(findingAt > headingAt, "finding H3 must follow the console H2");
});

test("homepage features the hosted MCP connect endpoint before the metric rail", () => {
  const template = source("_includes/layouts/home-static.html");
  const css = source("assets/css/home-observatory.css");
  const heroAt = template.indexOf('<section class="observatory-hero"');
  const connectAt = template.indexOf('id="mcp-connect"');
  const metricsAt = template.indexOf('class="metric-rail"');
  const philosophyAt = template.indexOf("MCP is context, not authority.");
  const connectBlock = template.slice(connectAt, metricsAt);

  assert.notEqual(heroAt, -1, "homepage must keep the observatory hero");
  assert.notEqual(connectAt, -1, "homepage must feature an MCP connect block");
  assert.ok(connectAt > heroAt, "MCP connect must follow the hero");
  assert.ok(
    connectAt < metricsAt,
    "MCP connect must sit immediately after the hero, not below the metric rail",
  );
  assert.ok(
    philosophyAt > metricsAt,
    "the later philosophy line may remain, but it is not the featured MCP mention",
  );

  assert.match(template, /There is an MCP server\./);
  assert.match(
    template,
    /Read-only recipes, a CVE catalog, and playbook start plans for MCP-compatible agents\./,
  );
  assert.match(template, /data-home-mcp-source="url">https:\/\/security-recipes\.ai\/mcp</);
  assert.match(template, /"transport": "streamable-http"/);
  assert.match(template, /"security-recipes"/);
  assert.match(
    template,
    /<a class="mcp-connect__more" href="\/mcp-servers\/">Docker, stdio, and the rest/,
  );
  assert.match(template, /src="\/js\/home-mcp-connect\.js\?v=20260826"/);
  assert.match(css, /\.mcp-connect\s*\{/);
  assert.match(css, /\.mcp-connect__url code\s*\{[^}]*user-select:\s*all;/s);

  assert.doesNotMatch(
    connectBlock,
    /unlock agentic|auto-fix|hosted chat|ticket writer|command runner/i,
  );
});

test("homepage action links point to local, reviewable product surfaces", () => {
  const template = source("_includes/layouts/home-static.html");
  const expectedLinks = [
    "/recipes/",
    "/recipes/general/code-hygiene/",
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

test("observatory topic nodes stay readable around the console perimeter", () => {
  const css = source("assets/css/home-observatory.css");

  assert.match(css, /\.observatory\s*{[^}]*min-height:\s*570px;/s);
  assert.match(
    css,
    /\.observatory-node\s*{[^}]*z-index:\s*5;[^}]*max-width:\s*none;[^}]*pointer-events:\s*none;[^}]*white-space:\s*nowrap;/s,
  );
  assert.match(css, /\.observatory-node--cve\s*{\s*top:\s*0;\s*left:\s*0;/);
  assert.match(
    css,
    /\.observatory-node--playbooks\s*{\s*top:\s*0;\s*left:\s*50%;/,
  );
  assert.match(
    css,
    /\.observatory-node--hygiene\s*{\s*top:\s*0;\s*right:\s*0;/,
  );
  assert.match(
    css,
    /\.observatory-node--compliance\s*{\s*bottom:\s*0;\s*left:\s*0;/,
  );
  assert.match(
    css,
    /\.observatory-node--guides\s*{\s*bottom:\s*0;\s*left:\s*50%;[^}]*translateX\(-50%\);/,
  );
  assert.match(
    css,
    /\.observatory-node--delivery\s*{\s*right:\s*0;\s*bottom:\s*0;/,
  );
  assert.match(
    css,
    /@media \(min-width: 1101px\) and \(max-width: 1400px\)[\s\S]*?\.observatory\s*{\s*min-height:\s*555px;[\s\S]*?\.research-console\s*{\s*top:\s*11%;/,
  );
  assert.match(
    css,
    /@media \(max-width: 720px\)[\s\S]*?\.observatory-node,[\s\S]*?display:\s*none;/,
  );
});
