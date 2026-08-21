"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const yaml = require("js-yaml");
const { descriptionFor, seoTitle } = require("../lib/seo");

const ROOT = path.resolve(__dirname, "..");

function source(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function frontMatter(relativePath) {
  const input = source(relativePath);
  const match = input.match(/^\uFEFF?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/u);
  assert.ok(match, `${relativePath} must have YAML front matter`);
  return yaml.load(match[1]);
}

test("homepage metadata targets CVE lookup and AI vulnerability remediation", () => {
  const homepage = source("_includes/layouts/home-static.html");
  const homepageData = frontMatter("content/_index.md");
  const lastmod = homepageData.lastmod instanceof Date
    ? homepageData.lastmod.toISOString().slice(0, 10)
    : String(homepageData.lastmod);

  assert.equal(lastmod, "2026-08-21");
  assert.match(
    homepage,
    /<link rel="alternate" type="application\/rss\+xml" href="\/index\.xml" title="Security Recipes">/u,
  );
  assert.match(
    homepage,
    /<title>CVE Database &amp; AI Vulnerability Remediation \| Security Recipes<\/title>/u,
  );
  assert.match(homepage, /title: "CVE Database & AI Vulnerability Remediation"/u);
  assert.match(
    homepage,
    /description: "Search NVD and CISA KEV-backed CVE intelligence and use reviewed AI vulnerability remediation playbooks[^"]+"/u,
  );
  assert.match(homepage, /image: "\/images\/og-card\.png"/u);
  assert.match(homepage, /imageWidth: 1731/u);
  assert.match(homepage, /imageHeight: 909/u);
});

test("high-intent landing pages remain concise, distinct, and query-specific", () => {
  const pages = [
    ["content/agents/_index.md", /AI Coding Agents for Vulnerability Remediation/iu],
    ["content/how-to-use/_index.md", /Visual Guide to Security Recipes/iu],
    ["content/mcp-servers/_index.md", /MCP.+AI Vulnerability Remediation/iu],
    ["content/cve-database/_index.md", /^CVE Database$/iu],
    ["content/recipes/general/_index.md", /Tool-Agnostic Security Remediation Recipes/iu],
    ["content/security-remediation/_index.md", /How to Remediate Vulnerabilities with AI Agents/iu],
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

test("every agent-security control links from its hub and declares that breadcrumb parent", () => {
  const hub = source("content/agentic-security/_index.md");
  const controls = [...new Set(
    [...hub.matchAll(/\]\(\/security-remediation\/([^/]+)\/\)/gu)]
      .map((match) => match[1]),
  )];

  assert.ok(controls.length >= 58, "the agent-security hub must retain its complete control map");
  for (const slug of controls) {
    const relativePath = `content/security-remediation/${slug}/_index.md`;
    assert.equal(
      frontMatter(relativePath).breadcrumb_parent,
      "/agentic-security/",
      `${relativePath} must use the agent-security breadcrumb hierarchy`,
    );
  }
});

test("reviewed historical CVE guides preserve explicit rollback and recovery boundaries", () => {
  const guides = [
    ["content/recipes/cve/cve-2014-0160-heartbleed.md", /Do not restore an affected OpenSSL release/iu],
    ["content/recipes/cve/cve-2014-6271-shellshock.md", /Never roll back to a Bash package/iu],
    ["content/recipes/cve/cve-2017-18342-pyyaml.md", /Do not restore an unsafe `yaml\.load` path/iu],
  ];

  for (const [relativePath, recoveryBoundary] of guides) {
    const page = source(relativePath);
    assert.match(page, /^## Rollback and recovery$/mu, `${relativePath} needs recovery guidance`);
    assert.match(page, recoveryBoundary, `${relativePath} must forbid insecure rollback`);
  }
});

test("regreSSHion targets OpenSSH RCE remediation with primary-source authority", () => {
  const relativePath = "content/recipes/cve/cve-2024-6387-regresshion.md";
  const page = source(relativePath);
  const data = frontMatter(relativePath);

  assert.equal(data.title, "CVE-2024-6387: OpenSSH regreSSHion RCE Remediation");
  assert.equal(data.linkTitle, "CVE-2024-6387 OpenSSH regreSSHion RCE Remediation");
  assert.match(data.description, /Remediate CVE-2024-6387.+OpenSSH.+root RCE/iu);
  assert.ok(data.title.length <= 60, "the regreSSHion title must remain concise");
  assert.ok(data.description.length <= 165, "the regreSSHion snippet must remain concise");
  assert.match(page, /https:\/\/www\.openssh\.com\/txt\/release-9\.8/u);
  assert.match(
    page,
    /https:\/\/www\.qualys\.com\/2024\/07\/01\/cve-2024-6387\/regresshion\.txt/u,
  );
  assert.match(page, /did not investigate every other libc or\s+operating system/iu);
  assert.equal(data.kev, false, "regreSSHion is not in the live CISA KEV catalog");
  assert.match(
    page,
    /does \*\*not\*\* list\s+CVE-2024-6387/u,
    "regreSSHion must say CISA has not listed it",
  );
});

test("the visual guide documents the evidence-gated search publication path", () => {
  const guide = source("content/how-to-use/_index.md");
  const readme = source("README.md");
  const imagePath = path.join(
    ROOT,
    "static/images/how-to-use/canonical-cve-search-discovery.webp",
  );

  assert.match(guide, /^## How a qualified CVE becomes discoverable$/mu);
  assert.match(
    guide,
    /src="\.\.\/images\/how-to-use\/canonical-cve-search-discovery\.webp"[^>]+width="1774" height="887"/u,
  );
  assert.match(guide, /no markup or sitemap can guarantee a particular search\s+position\./u);
  assert.match(
    readme,
    /static\/images\/how-to-use\/canonical-cve-search-discovery\.webp/u,
  );
  assert.match(readme, /same-origin links drift\./u);
  assert.match(readme, /security-recipes\.ai\/pull\/89/u);
  assert.match(guide, /unrelated Fail2Ban work in\s+that pull request/iu);
  assert.ok(fs.statSync(imagePath).size > 0, "the themed search-discovery image must exist");
});

test("the documentation hub stays navigational instead of competing with the remediation pillar", () => {
  const docs = frontMatter("content/docs/_index.md");

  assert.equal(docs.title, "Security Recipes Documentation: Playbooks, Agents, and MCP");
  assert.doesNotMatch(docs.title, /AI Vulnerability Remediation Documentation/iu);
  assert.match(
    docs.description.trim(),
    /remediation playbooks, AI agent setup, AI-agent system security, read-only MCP integrations, CVE intake, and review workflows\.$/iu,
  );
});

test("agentic remediation control pages emit useful page-specific snippets", () => {
  const slugs = [
    "agent-capability-risk-register",
    "agent-identity-ledger",
    "agent-memory-boundary",
    "agentic-catastrophic-risk-annex",
    "agentic-protocol-conformance",
    "agentic-red-team-drills",
    "agentic-run-receipts",
    "agentic-soc-detection-pack",
    "agentic-system-bom",
    "agentic-telemetry-contract",
    "classic-vulnerable-defaults",
    "context-egress-boundary",
    "context-poisoning-guard",
    "critical-infrastructure-secure-context",
    "evidence-bundles",
    "mcp-elicitation-boundary",
    "mcp-gateway-policy",
    "runtime-controls",
    "secure-context-evals",
    "secure-context-trust-pack",
  ];
  const descriptions = new Set();

  for (const slug of slugs) {
    const relativePath = `content/security-remediation/${slug}/_index.md`;
    const renderedDescription = descriptionFor(frontMatter(relativePath));

    assert.ok(
      renderedDescription.length >= 120,
      `${relativePath} rendered description is too thin: ${renderedDescription}`,
    );
    assert.ok(
      renderedDescription.length <= 165,
      `${relativePath} rendered description is too long: ${renderedDescription}`,
    );
    assert.match(
      renderedDescription,
      /[.!?]$/u,
      `${relativePath} rendered description is incomplete`,
    );
    assert.doesNotMatch(
      renderedDescription,
      /^(?:A )?generated\b/iu,
      `${relativePath} should explain the page instead of its build process`,
    );
    descriptions.add(renderedDescription.toLocaleLowerCase("en-US"));
  }

  assert.equal(descriptions.size, slugs.length, "remediation snippets must remain unique");
});

test("OWASP web application recipes consolidate on the current 2025 edition", () => {
  const audit = frontMatter("content/recipes/general/owasp-top-10-2025-audit.md");
  const remediate = frontMatter("content/recipes/general/owasp-top-10-2025-remediate.md");
  const retiredAudit = frontMatter("content/recipes/general/owasp-top-10-2026-audit.md");
  const retiredRemediate = frontMatter("content/recipes/general/owasp-top-10-2026-remediate.md");

  assert.match(audit.title, /Top 10:2025/u);
  assert.match(remediate.title, /Top 10:2025/u);
  assert.match(descriptionFor(audit), /current OWASP Top 10:2025/u);
  assert.match(descriptionFor(remediate), /current OWASP Top 10:2025/u);
  assert.deepEqual(
    [retiredAudit.redirectTo, retiredRemediate.redirectTo],
    [
      "/recipes/general/owasp-top-10-2025-audit/",
      "/recipes/general/owasp-top-10-2025-remediate/",
    ],
  );
  assert.equal(retiredAudit.noindex, true);
  assert.equal(retiredRemediate.noindex, true);
});

test("top-level discovery pages emit complete search snippets without title truncation", () => {
  const pages = [
    "content/quickstart/_index.md",
    "content/fundamentals/_index.md",
    "content/agents/_index.md",
    "content/mcp-servers/_index.md",
    "content/docs/agent-integration/_index.md",
    "content/docs/_index.md",
  ];

  for (const relativePath of pages) {
    const data = frontMatter(relativePath);
    const renderedTitle = seoTitle(data.title);
    const renderedDescription = descriptionFor(data);

    assert.ok(
      renderedTitle.length <= 65,
      `${relativePath} rendered title is too long: ${renderedTitle}`,
    );
    assert.ok(
      renderedDescription.length >= 120,
      `${relativePath} rendered description is too thin: ${renderedDescription}`,
    );
    assert.ok(
      renderedDescription.length <= 165,
      `${relativePath} rendered description is too long: ${renderedDescription}`,
    );
    assert.match(
      renderedDescription,
      /[.!?]$/u,
      `${relativePath} rendered description is incomplete`,
    );
  }
});

test("documentation hub links contextually to marketplace and release guidance", () => {
  const docs = source("content/docs/_index.md");

  assert.match(
    docs,
    /\[Control Plane Marketplace\]\(\/docs\/control-plane-marketplace\/\)/u,
  );
  assert.match(
    docs,
    /\[Secure Context Release Gate\]\(\/docs\/secure-context-release\/\)/u,
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
  assert.match(
    homepage,
    /<a class="button" href="\/security-remediation\/">How to remediate vulnerabilities with AI agents<\/a>/u,
  );
  assert.match(pillar, /\[AI agents for vulnerability remediation\]\(\/agents\/\)/u);
  assert.match(
    agents,
    /\[AI vulnerability remediation playbooks\]\(\{\{< relref "\/security-remediation" >\}\}\)/u,
  );
});

test("the contribution guide describes the immutable deployment pipeline", () => {
  const contributionGuide = source("content/contribute/_index.md");

  assert.doesNotMatch(contributionGuide, /push(?:es)? to `gh-pages`|publishes `gh-pages`/iu);
  assert.match(contributionGuide, /commit-tagged site and MCP (?:container )?images/iu);
  assert.match(contributionGuide, /`security-recipes-deploy\.timer`/u);
  assert.match(contributionGuide, /`deploy\.sh`/u);
  assert.match(contributionGuide, /immutable images through the\s+blue\/green slots/iu);
});

test("global navigation names the AI remediation destination descriptively", () => {
  const homepage = source("_includes/layouts/home-static.html");
  const siteConfig = source("lib/site-config.js");
  const pillar = frontMatter("content/security-remediation/_index.md");

  assert.equal(pillar.linkTitle, "AI Remediation");
  assert.match(
    siteConfig,
    /\{ name: "AI Remediation", url: "\/security-remediation\/" \}/u,
  );
  assert.deepEqual(
    [...homepage.matchAll(/<a href="\/security-remediation\/">([^<]+)<\/a>/gu)]
      .map((match) => match[1]),
    ["AI Remediation", "AI Remediation"],
  );
});

test("the remediation pillar labels hypothetical and repository evidence truthfully", () => {
  const pillar = source("content/security-remediation/_index.md");
  const agentic = source("content/agentic-security/_index.md");

  assert.match(pillar, /^## CVE-specific remediation guides$/mu);
  assert.match(
    pillar,
    /^## Hypothetical workflow: remediate a dependency CVE with an AI agent$/mu,
  );
  assert.match(
    pillar,
    /^## Real repository case study: CVE-2026-13149 in brace-expansion$/mu,
  );
  assert.match(pillar, /github\.com\/advisories\/GHSA-3jxr-9vmj-r5cp/u);
  assert.match(pillar, /github\.com\/stevologic\/security-recipes\.ai\/pull\/89/u);
  assert.match(pillar, /also fixed a\s+separate Fail2Ban deployment bootstrap problem/u);
  assert.match(
    pillar,
    /src="\/images\/how-to-use\/cve-to-agent-plan\.webp"/u,
  );
  assert.match(pillar, /A CVE is an evidence input, not permission to patch/u);

  assert.match(pillar, /^## Secure the remediation agent separately$/mu);
  assert.match(
    pillar,
    /\[AI Agent Security: How to Secure AI Agent Systems\]\(\/agentic-security\/\)/u,
  );
  assert.match(agentic, /^## Control directory for securing AI agent systems$/mu);
  assert.match(agentic, /^### Agent identity, delegated authority, and trust$/mu);
  assert.match(agentic, /^### Secure-context provenance and enterprise assurance$/mu);
  assert.match(
    pillar,
    /\[CVE-2021-35395: Realtek AP-Router SDK buffer overflow\]\(\/cve\/CVE-2021-35395\/\)/u,
  );
  assert.match(
    pillar,
    /\[CVE-2014-0160: Heartbleed in OpenSSL\]\(\/recipes\/cve\/cve-2014-0160-heartbleed\/\)/u,
  );
  assert.match(
    pillar,
    /\[CVE-2026-48172: LiteSpeed cPanel plugin root privilege escalation\]\(\/cve\/CVE-2026-48172\/\)/u,
  );
  assert.match(
    pillar,
    /\[CVE-2014-6271: Shellshock Bash environment-variable RCE\]\(\/recipes\/cve\/cve-2014-6271-shellshock\/\)/u,
  );
});

test("high-intent remediation pages expose current review provenance", () => {
  // Each page pins its own verified review date so a content change cannot
  // silently advertise a review that never happened.
  for (const [relativePath, reviewedIso, reviewedLabel] of [
    ["content/security-remediation/_index.md", "2026-07-23", "July 23, 2026"],
    ["content/agents/_index.md", "2026-08-21", "August 21, 2026"],
  ]) {
    const page = source(relativePath);
    const data = frontMatter(relativePath);
    const lastmod = data.lastmod instanceof Date
      ? data.lastmod.toISOString().slice(0, 10)
      : String(data.lastmod);
    assert.equal(lastmod, reviewedIso);
    assert.match(
      page,
      new RegExp(`\\*\\*Last updated ${reviewedLabel}\\.\\*\\*`, "u"),
    );
    assert.match(page, /\[source and revision history\]\(https:\/\/github\.com\/stevologic/u);
    assert.match(page, /\[review methodology\]\(\/about\/#editorial-principles\)/u);
    assert.match(page, /\[corrections policy\]\(\/about\/#corrections\)/u);
  }
});

test("the remediation workflow protects finding evidence from the patching agent", () => {
  const pillar = source("content/security-remediation/_index.md");
  const prerequisites = pillar.indexOf("Before granting write access");
  const firstMutation = pillar.indexOf("1. **Identify one finding.**");

  assert.ok(prerequisites > 0 && prerequisites < firstMutation);
  assert.match(pillar, /production-only\s+infrastructure[\s\S]*stop for\s+operator-led triage/u);
  assert.match(pillar, /Preserve the original alert, reproducer, or scan result and its checksum/u);
  assert.match(
    pillar,
    /Do not weaken, delete, skip, or reconfigure the scanner, CI gate, or original\s+regression/u,
  );
  assert.match(pillar, /protected reproducer or an independently owned verifier/u);
});
