// Central site metadata for the Eleventy build.
// Values mirror the retired hugo.yaml so templates, feeds, and SEO output
// stay byte-compatible with the Hugo era wherever practical.

// CI and Docker override the canonical origin the same way they used to
// override Hugo's --baseURL. Keep SECURITY_RECIPES_BASE_URL as the primary
// knob because docker-compose already passes it.
const rawBase =
  process.env.SECURITY_RECIPES_BASE_URL ||
  process.env.BASE_URL ||
  "https://security-recipes.ai/";

const baseURL = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

// Root-relative prefix for subpath deploys (e.g. GitHub Pages project sites).
// "https://user.github.io/repo/" -> "/repo/".
const pathPrefix = new URL(baseURL).pathname;

module.exports = {
  baseURL,
  pathPrefix,
  title: "security-recipes.ai",
  languageCode: "en-us",
  description:
    "Security recipes for AI-assisted remediation: reviewed playbooks, " +
    "prompts, agent setup guides, and MCP context patterns that keep agents " +
    "scoped, evidence-driven, and human-reviewed.",
  repoURL:
    process.env.SECURITY_RECIPES_REPO_URL ||
    "https://github.com/stevologic/security-recipes.ai",
  seo: {
    siteName: "Security Recipes",
    author: "security-recipes.ai contributors",
    twitter: "",
    defaultImage: "images/og-card.svg",
    defaultImageWidth: 1200,
    defaultImageHeight: 630,
    sameAs: ["https://github.com/stevologic/security-recipes.ai"],
    defaultKeywords: [
      "security recipes",
      "agentic security remediation",
      "AI security remediation",
      "AI coding agents",
      "vulnerability remediation",
      "CVE remediation",
      "GitHub Copilot",
      "Claude Code",
      "Cursor",
      "Devin",
      "Codex",
      "MCP servers",
      "SAST",
      "secure software supply chain",
      "OWASP Top 10",
    ],
  },
  footer: {
    copyright:
      "Copyright 2026 security-recipes.ai - bounded recipes for agent-assisted security remediation",
  },
  // Primary nav: one label -> one destination section, in the order a
  // visitor moves: pick a recipe, follow a playbook, wire the agent,
  // connect context, read the docs.
  menu: [
    { name: "Recipes", url: "/recipes/" },
    { name: "Playbooks", url: "/security-remediation/" },
    { name: "Agents", url: "/agents/" },
    { name: "MCP", url: "/mcp-servers/" },
    { name: "Docs", url: "/docs/" },
  ],
};
