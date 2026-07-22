"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..");

function source(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function frontMatter(relativePath) {
  const input = source(relativePath);
  const match = input.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/u);
  assert.ok(match, `${relativePath} must have YAML front matter`);
  return yaml.load(match[1]);
}

test("homepage metadata targets CVE lookup and AI vulnerability remediation", () => {
  const homepage = source("_includes/layouts/home-static.html");

  assert.match(
    homepage,
    /<title>CVE Database &amp; AI Vulnerability Remediation \| Security Recipes<\/title>/u,
  );
  assert.match(homepage, /title: "CVE Database & AI Vulnerability Remediation"/u);
  assert.match(
    homepage,
    /description: "Search source-backed CVE intelligence and use reviewed AI vulnerability remediation playbooks[^"]+"/u,
  );
  assert.match(homepage, /image: "\/images\/og-card\.png"/u);
  assert.match(homepage, /imageWidth: 1731/u);
  assert.match(homepage, /imageHeight: 909/u);
});

test("high-intent landing pages remain concise, distinct, and query-specific", () => {
  const pages = [
    ["content/agents/_index.md", /AI Agents for Vulnerability Remediation/iu],
    ["content/how-to-use/_index.md", /Visual Guide to Security Recipes/iu],
    ["content/mcp-servers/_index.md", /MCP.+AI Vulnerability Remediation/iu],
    ["content/cve-database/_index.md", /^CVE Database$/iu],
    ["content/recipes/general/_index.md", /Tool-Agnostic Security Remediation Recipes/iu],
    ["content/security-remediation/_index.md", /AI Vulnerability Remediation Playbooks/iu],
  ];
  const titles = new Set();

  for (const [relativePath, expectedTitle] of pages) {
    const data = frontMatter(relativePath);
    const description = data.description.trim();
    assert.match(data.title, expectedTitle, `${relativePath} title misses its search intent`);
    assert.ok(data.title.length <= 60, `${relativePath} title is unnecessarily long`);
    assert.ok(description.length >= 100, `${relativePath} description is too thin`);
    assert.ok(description.length <= 165, `${relativePath} description is too long`);
    assert.match(description, /[.!?]$/u, `${relativePath} description is incomplete`);
    titles.add(data.title.toLocaleLowerCase("en-US"));
  }

  assert.equal(titles.size, pages.length, "high-intent pages must not reuse titles");
  assert.doesNotMatch(
    frontMatter("content/how-to-use/_index.md").title,
    /vulnerability remediation/iu,
    "the visual tour must not compete with the remediation pillar",
  );
});

test("the remediation pillar links to every agent with descriptive anchors", () => {
  const pillar = source("content/security-remediation/_index.md");
  const expected = [
    ["/codex/", "Remediate vulnerabilities with Codex"],
    ["/claude/", "Remediate CVEs with Claude Code"],
    ["/cursor/", "Remediate vulnerable dependencies with Cursor"],
    ["/github_copilot/", "Remediate vulnerabilities with GitHub Copilot"],
    ["/devin/", "Run scheduled vulnerability remediation with Devin"],
  ];

  for (const [href, label] of expected) {
    assert.ok(pillar.includes(`[${label}](${href})`), `missing descriptive link to ${href}`);
  }
});

test("the homepage, remediation pillar, and agent hub cross-link contextually", () => {
  const homepage = source("_includes/layouts/home-static.html");
  const pillar = source("content/security-remediation/_index.md");
  const agents = source("content/agents/_index.md");

  assert.match(homepage, /<a href="\/agents\/">AI agent setup guides<\/a>/u);
  assert.match(pillar, /\[AI agents for vulnerability remediation\]\(\/agents\/\)/u);
  assert.match(
    agents,
    /\[AI vulnerability remediation playbooks\]\(\{\{< relref "\/security-remediation" >\}\}\)/u,
  );
});

test("the remediation pillar labels guidance and hypothetical examples truthfully", () => {
  const pillar = source("content/security-remediation/_index.md");

  assert.match(pillar, /^## CVE-specific remediation guides$/mu);
  assert.match(
    pillar,
    /^## Hypothetical workflow: remediate a dependency CVE with an AI agent$/mu,
  );
  assert.doesNotMatch(pillar, /^## Worked CVE remediation examples$/mu);
  assert.doesNotMatch(pillar, /^## Worked example:/mu);

  assert.match(pillar, /^## Production guardrails for AI remediation agents$/mu);
  assert.match(pillar, /^### Agent identity, delegated authority, and trust$/mu);
  assert.match(pillar, /^### Secure-context provenance and enterprise assurance$/mu);
});
