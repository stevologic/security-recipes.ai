// Shared derivations for recipe content. The recipe browser
// shortcode, /api/recipes.json, and /recipes-index.json all agree on
// category, facet, quality, and zero-day logic because they run through
// this module — mirroring the duplicated Go template logic it replaces.

const { plainifyMarkdown, truncate, isoDate } = require("./util");

// Category tables. The agent feed uses long labels ("Classic Vulnerable
// Defaults"); the on-page browser uses short ones ("Defaults").
const FEED_CATEGORIES = [
  ["recipes/cve/", "cve", "CVE"],
  ["recipes/general/classic-vulnerable-defaults/", "classic-defaults", "Classic Vulnerable Defaults"],
  ["recipes/general/compliance-standards/", "compliance-standards", "Compliance Standards"],
  ["recipes/general/code-hygiene/", "code-hygiene", "Code Hygiene"],
  ["recipes/general/crypto-defi/", "crypto-defi", "Crypto/DeFi"],
  ["recipes/claude/", "claude", "Claude"],
  ["recipes/github_copilot/", "github-copilot", "GitHub Copilot"],
  ["recipes/cursor/", "cursor", "Cursor"],
  ["recipes/codex/", "codex", "Codex"],
  ["recipes/devin/", "devin", "Devin"],
];

const BROWSER_CATEGORIES = [
  ["recipes/cve/", "cve", "CVE"],
  ["recipes/general/classic-vulnerable-defaults/", "classic-defaults", "Defaults"],
  ["recipes/general/compliance-standards/", "compliance-standards", "Compliance"],
  ["recipes/general/code-hygiene/", "code-hygiene", "Code Hygiene"],
  ["recipes/general/crypto-defi/", "crypto-defi", "Crypto/DeFi"],
];

function categorize(sourcePath, table) {
  for (const [prefix, slug, label] of table) {
    if (sourcePath.startsWith(prefix)) return { slug, label };
  }
  return { slug: "general", label: "General" };
}

function slugFor(page) {
  const base = page.sourcePath.split("/").pop().replace(/\.md$/i, "");
  if (base !== "_index") return base;
  return page.url.replace(/^\/|\/$/g, "").replace(/\//g, "-");
}

function facetsFor(facetText, isCve) {
  const t = facetText.toLowerCase();
  const has = (...needles) => needles.some((n) => t.includes(n));
  const facets = ["remediation"];
  if (has("audit", "evidence", "review", "attestation")) facets.push("audit");
  if (has("compliance", "nist", "ssdf", "slsa", "owasp", "pci", "soc2")) facets.push("compliance");
  if (isCve || has("risk", "threat", "vulnerab", "exploit", "critical", "high")) facets.push("risk");
  if (has("source-code", "code", "sast", "secret", "dependency", "supply-chain", "hygiene", "unsafe default")) facets.push("code-hygiene");
  return facets;
}

const SUPPORTED_FACETS = new Set(["remediation", "risk", "audit", "compliance", "code-hygiene"]);

function explicitFacets(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => String(item || "").trim().toLowerCase()))]
    .filter((item) => SUPPORTED_FACETS.has(item));
}

function qualityFor(plainLower, facetCount) {
  const signals = [];
  let score = 20;
  const has = (...needles) => needles.some((n) => plainLower.includes(n));
  if (has("## inputs", "## input")) { signals.push("inputs"); score += 10; }
  if (has("## when to use", "when to use it")) { signals.push("selection-guidance"); score += 10; }
  if (plainLower.includes("## output contract")) { signals.push("output-contract"); score += 15; }
  if (has("## verification", "verification", "tests")) { signals.push("verification"); score += 15; }
  if (has("## guardrails", "stop condition", "do not")) { signals.push("guardrails"); score += 15; }
  if (has("## related", "## see also")) { signals.push("related-context"); score += 10; }
  if (facetCount >= 3) { signals.push("multi-facet"); score += 5; }
  if (score > 100) score = 100;
  let tier = "starter";
  if (score >= 85) tier = "world-class";
  else if (score >= 70) tier = "strong";
  else if (score >= 50) tier = "usable";
  return { score, tier, signals };
}

// Full derived model for one content-index page from recipes.
function recipeModel(page) {
  const fm = page.fm;
  const source = page.sourcePath;
  const feedCategory = categorize(source, FEED_CATEGORIES);
  const browserCategory = categorize(source, BROWSER_CATEGORIES);
  const slug = slugFor(page);
  const summary =
    page.description || truncate(page.summary, 240) || "";
  const browserSummary =
    page.description || truncate(page.summary, 180) || "";
  const tags = page.tags;
  const tagText = tags.join(" ");
  const facetText = [
    source,
    page.title,
    summary,
    tagText,
    fm.tool || "",
    fm.agent || "",
  ].join(" ");
  const declaredFacets = explicitFacets(fm.facets);
  const facets = declaredFacets.length
    ? declaredFacets
    : [...new Set(facetsFor(facetText, feedCategory.slug === "cve"))];
  // Hugo checked lower(RawContent + "\n" + Plain); the raw markdown alone
  // contains every phrase the quality heuristics look for.
  const plainLower = `${page.body}\n${plainifyMarkdown(page.body)}`.toLowerCase();
  const quality = qualityFor(plainLower, facets.length);
  const date = isoDate(page.date);
  const disclosed = fm.disclosed ? isoDate(fm.disclosed) : "";
  const knownAs = fm.known_as || fm.aliases || [];

  return {
    page,
    slug,
    source,
    feedCategory,
    browserCategory,
    summary,
    browserSummary,
    tags,
    tagText,
    facets,
    quality,
    date,
    disclosed,
    knownAs: Array.isArray(knownAs) ? knownAs : [knownAs],
    severity: (fm.severity || "").toLowerCase(),
    maturity: (fm.maturity || "").toLowerCase(),
    ecosystem: fm.ecosystem || "",
    cve: fm.cve || "",
    ghsa: fm.ghsa || "",
    kev: !!fm.kev,
    author: fm.author || "",
    team: fm.team || "",
    model: fm.model || fm.model_used || "",
    tool: fm.tool || "",
    agent: fm.agent || "",
    recipeId: fm.recipe_id || "",
    recipeKind: fm.recipe_kind || "",
    framework: fm.framework || "",
    frameworkVersion: fm.framework_version || "",
    jurisdiction: fm.jurisdiction || "",
    industry: Array.isArray(fm.industry) ? fm.industry : fm.industry ? [fm.industry] : [],
  };
}

module.exports = { recipeModel, categorize, FEED_CATEGORIES, BROWSER_CATEGORIES, SUPPORTED_FACETS };
