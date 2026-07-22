"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");

const guides = [
  {
    file: "content/codex/_index.md",
    heading: "## Remediate a vulnerability with Codex",
    links: [
      "https://learn.chatgpt.com/docs/security/plugin",
      "https://learn.chatgpt.com/docs/security/plugin/triage-backlog",
      "https://learn.chatgpt.com/docs/security/plugin/fix-findings",
      "https://learn.chatgpt.com/docs/security/setup",
    ],
    stale: /gpt-5\.3-codex|gpt-5\.4|--max-tokens|--session-log|--max-iterations|Org-level API key/u,
  },
  {
    file: "content/claude/_index.md",
    heading: "## Remediate a vulnerability with Claude",
    links: [
      "https://claude.com/product/claude-security",
      "https://claude.com/resources/tutorials/getting-started-with-claude-security",
      "https://support.anthropic.com/en/articles/11932705-automated-security-reviews-in-claude-code/",
    ],
    stale: /Claude Code Security|Claude Team or Enterprise seat/u,
  },
  {
    file: "content/cursor/_index.md",
    heading: "## Remediate a vulnerability with Cursor",
    links: [
      "https://cursor.com/docs/security-agents",
      "https://cursor.com/changelog/04-30-26",
      "https://cursor.com/blog/cloud-agents",
    ],
    stale: /Cursor Business|Settings → Background Agents|CURSOR_AUTOMATION_WEBHOOK|# Settings → Automations/u,
  },
  {
    file: "content/github_copilot/_index.md",
    heading: "## Remediate a vulnerability with GitHub Copilot",
    links: [
      "https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning",
      "https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-code-scanning-alerts/resolve-alerts",
      "https://docs.github.com/en/code-security/getting-started/github-security-features",
      "https://docs.github.com/en/copilot/concepts/agents/cloud-agent/about-cloud-agent",
    ],
    stale: /Copilot Coding Agent|copilot-remediate|@copilot|Auto-assign labeled issues|Project findings into GitHub Issues|Code security and analysis/u,
  },
  {
    file: "content/devin/_index.md",
    heading: "## Remediate a vulnerability with Devin",
    links: [
      "https://docs.devin.ai/work-with-devin/security-swarm",
      "https://devin.ai/security-program",
      "https://devin.ai/pricing",
    ],
    stale: /offers Team and Enterprise|API access, Knowledge, and Playbooks are on all supported tiers|\bACU\b|API access enabled and a Devin API key/u,
  },
];

function source(file) {
  return fs.readFileSync(path.join(ROOT, file), "utf8");
}

test("agent guides answer remediation directly before onboarding", () => {
  for (const guide of guides) {
    const content = source(guide.file);
    const headingAt = content.indexOf(guide.heading);
    const prerequisitesAt = content.indexOf("## Prerequisites");
    const onboardingAt = content.indexOf("## General onboarding");

    assert.notEqual(headingAt, -1, `${guide.file} is missing its direct remediation H2`);
    assert.equal(
      content.split(guide.heading).length - 1,
      1,
      `${guide.file} must contain exactly one direct remediation H2`,
    );
    assert.ok(headingAt < prerequisitesAt, `${guide.file} must answer before prerequisites`);
    assert.ok(headingAt < onboardingAt, `${guide.file} must answer before onboarding`);
  }
});

test("agent remediation answers link to current official product guidance", () => {
  for (const guide of guides) {
    const content = source(guide.file);
    for (const link of guide.links) {
      assert.ok(content.includes(link), `${guide.file} is missing official source ${link}`);
    }
  }
});

test("agent guides do not restore superseded product and workflow advice", () => {
  for (const guide of guides) {
    assert.doesNotMatch(source(guide.file), guide.stale, `${guide.file} contains stale guidance`);
  }
});
