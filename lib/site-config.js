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

// Visible product host on the canonical origin. Mirror hosts (see
// brand-host.js) rewrite marked chrome to these values at request time.
// SEO canonical / og:url / JSON-LD stay on baseURL even when Host is a mirror.
const canonicalHost = "security-recipes.ai";
const mirrorHosts = ["security-recipes.si"];
const mcpPublicUrl = new URL("mcp", baseURL).toString();

module.exports = {
  baseURL,
  pathPrefix,
  canonicalHost,
  mirrorHosts,
  mcpPublicUrl,
  title: canonicalHost,
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
    author: "Security Recipes contributors",
    authorUrl: "/about/",
    knownAuthors: {
      "Stephen M Abbott": {
        name: "Stephen M Abbott",
        url: "/about/#stephen-m-abbott",
        sameAs: ["https://github.com/stevologic"],
      },
    },
    organizationUrl: "/",
    publishingPrinciples: "/about/#editorial-principles",
    correctionsPolicy: "/about/#corrections",
    twitter: "",
    defaultImage: "images/og-card.png",
    defaultImageWidth: 1731,
    defaultImageHeight: 909,
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
      "Copyright 2026 " +
      canonicalHost +
      " - bounded recipes for agent-assisted security remediation",
  },
  donations: [
    {
      currency: "BTC",
      name: "Bitcoin",
      slug: "btc",
      scheme: "bitcoin",
      address: "3M9PTxL15b6c8REcHMZCVPbfMomXNZ5AGR",
    },
    {
      currency: "DOGE",
      name: "Dogecoin",
      slug: "doge",
      scheme: "dogecoin",
      address: "DTW2M5oEW97WbmYJRM71qD7uE6xfJs1MUK",
    },
  ],
  // Primary nav: one label -> one destination section, in the order a
  // visitor moves: pick a workflow or investigate a CVE, follow a playbook,
  // wire the agent, connect context, read the docs.
  menu: [
    { name: "Recipes", url: "/recipes/" },
    { name: "CVE Database", url: "/cve-database/" },
    { name: "AI Remediation", url: "/security-remediation/" },
    { name: "Agents", url: "/agents/" },
    { name: "MCP", url: "/mcp-servers/" },
    { name: "Docs", url: "/docs/" },
  ],
};
