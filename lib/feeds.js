// Builders for every machine-readable feed the Hugo build used to emit
// as custom output formats: the site search index, the agent recipe feed,
// and the marketplace control-plane feeds.

const site = require("./site-config");
const { getIndex, sortByWeightTitle, isDiscoveryPage } = require("./content-index");
const { recipeModel } = require("./recipe-model");
const { marketplace } = require("./site-data");
const { schemaFeedMap } = require("./marketplace-schema-index");
const { plainifyMarkdown, truncate, isoDate, localDate } = require("./util");
const { lastmodFor } = require("./git-lastmod");

const absURL = (p) => new URL(p.replace(/^\//, ""), site.baseURL).toString();

function slugFor(page) {
  const base = page.sourcePath.split("/").pop().replace(/\.md$/i, "");
  if (base !== "_index") return base;
  return page.url.replace(/^\/|\/$/g, "").replace(/\//g, "-") || "home";
}

// h2/h3-style keyword headings, mirroring Hugo's .Fragments.Headings walk
// (top level plus one nested level, so pages whose body starts at h1 get
// h1+h2, and heading-only-h2 docs get h2+h3).
function headingsFor(body) {
  const found = [];
  const re = /^(#{1,6})\s+(.+?)\s*#*\s*$/gm;
  let m;
  while ((m = re.exec(body))) {
    found.push({ level: m[1].length, title: m[2].trim() });
  }
  if (!found.length) return "";
  const minLevel = Math.min(...found.map((h) => h.level));
  return found
    .filter((h) => h.level <= minLevel + 1)
    .map((h) => h.title)
    .join(" · ");
}

// /recipes-index.json — slim site-wide search index used by docs-search.js.
function recipesIndex() {
  const { pages } = getIndex();
  const docs = pages
    .filter((p) => p.url !== "/" && isDiscoveryPage(p)) // home is kind "home" in Hugo, excluded
    .sort((a, b) => a.url.localeCompare(b.url, "en"))
    .map((p) => ({
      slug: slugFor(p),
      title: p.title,
      url: absURL(p.url),
      path: p.url,
      section: p.sourcePath.split("/")[0].replace(/\.md$/i, ""),
      agent: p.fm.agent || "general",
      tags: p.tags,
      severity: p.fm.severity || "unspecified",
      last_updated: lastmodFor(p.sourcePath, p.date),
      summary: truncate(p.description || p.summary, 200),
      headings: truncate(headingsFor(p.body), 400),
      source_file: p.sourcePath,
    }));
  return JSON.stringify(docs);
}

// /recipes-browser.json — slim per-recipe card feed that powers the client
// side /recipes/ catalogue. Bodies are intentionally excluded: only the fields
// the browser renders and filters on ship, so the payload stays small enough to
// fetch once and filter in-memory even at 10k+ recipes. browserCardObjects() is
// the shared source of truth with the server-rendered first page.
function recipesBrowser() {
  const { browserCardObjects } = require("./recipe-cards");
  const recipes = browserCardObjects();
  return JSON.stringify({ count: recipes.length, recipes });
}

// /api/recipes.json — the rich agent-facing recipe feed.
function agentRecipes() {
  const { pages } = getIndex();
  const recipePages = pages
    .filter((p) => p.sourcePath.startsWith("recipes/") && !p.isSection && isDiscoveryPage(p))
    .sort((a, b) => a.url.localeCompare(b.url, "en"));

  const zeroDayWindowDays = 4;
  let referenceDate = localDate();
  for (const p of recipePages) {
    const d = isoDate(p.date);
    if (d && d > referenceDate) referenceDate = d;
  }
  const since = new Date(new Date(`${referenceDate}T00:00:00Z`).getTime() - zeroDayWindowDays * 86400000)
    .toISOString()
    .slice(0, 10);

  const categoryCounts = new Map();
  let zeroDayCount = 0;
  const recipes = recipePages.map((p) => {
    const m = recipeModel(p);
    const cat = m.feedCategory;
    categoryCounts.set(cat.slug, (categoryCounts.get(cat.slug) || 0) + 1);
    const isZeroDay = cat.slug === "cve" && !!m.date && m.date >= since;
    if (isZeroDay) zeroDayCount += 1;
    return {
      slug: m.slug,
      title: p.title,
      link_title: p.linkTitle,
      url: absURL(p.url),
      path: p.url,
      source_file: p.sourcePath,
      recipe_id: m.recipeId,
      recipe_kind: m.recipeKind,
      category: { slug: cat.slug, label: cat.label },
      agent: p.fm.agent || p.fm.tool || cat.slug,
      severity: p.fm.severity || "unspecified",
      maturity: p.fm.maturity || "unspecified",
      ecosystem: m.ecosystem,
      cve: m.cve,
      ghsa: m.ghsa,
      kev: m.kev,
      aliases: m.knownAs,
      framework: m.framework,
      framework_version: m.frameworkVersion,
      jurisdiction: m.jurisdiction,
      industry: m.industry,
      tags: m.tags,
      facets: m.facets,
      quality: {
        score: m.quality.score,
        tier: m.quality.tier,
        signals: m.quality.signals,
        scorecard:
          "inputs + selection guidance + output contract + verification + guardrails + related context + multi-facet coverage",
      },
      recipe_contract: {
        primary_job:
          "Give an agent bounded remediation context for one source-code security finding, audit question, or hygiene improvement.",
        selection_guidance:
          "Prefer the narrowest recipe that matches the finding, affected technology, compliance objective, and permitted output.",
        output_expectation:
          "Reviewer-ready patch, triage note, evidence report, or stop-condition report as specified by the recipe.",
        safety_boundary:
          "Read only until the operator explicitly authorizes edits; never rotate secrets, deploy, change cloud state, or widen scope unless the recipe and task both allow it.",
      },
      author: m.author,
      team: m.team,
      model: m.model,
      date: m.date,
      zero_day: isZeroDay,
      last_updated: lastmodFor(p.sourcePath, p.date),
      summary: m.summary,
      content_text: plainifyMarkdown(p.body),
      agent_handoff: {
        mcp_lookup_keys: [m.slug, p.url, p.sourcePath],
        recommended_mcp_tools: ["recipes_search", "recipes_get", "recipes_match_finding"],
        selection_facets: m.facets,
        source_text_field: "content_text",
        portable_download: `security-recipe-${m.slug}.json`,
      },
      download: {
        content_type: "application/json",
        suggested_filename: `security-recipe-${m.slug}.json`,
      },
    };
  });

  const labels = new Map(
    require("./recipe-model").FEED_CATEGORIES.map(([, slug, label]) => [slug, label])
  );
  labels.set("general", "General");
  const categories = [...categoryCounts.entries()]
    .map(([slug, count]) => ({ slug, label: labels.get(slug) || slug, count }))
    .sort((a, b) => a.slug.localeCompare(b.slug, "en"));

  return JSON.stringify({
    api_version: "2026-06-10",
    kind: "security-recipes.recipe-library",
    site: site.title,
    endpoint: absURL("/api/recipes.json"),
    legacy_endpoint: absURL("/recipes-index.json"),
    mcp_endpoint: absURL("/mcp"),
    generated_at: new Date().toISOString(),
    recipe_count: recipes.length,
    agent_contract: {
      read_only: true,
      primary_lookup_fields: ["slug", "path", "source_file", "cve", "ghsa", "aliases"],
      search_fields: ["recipe_id", "title", "summary", "content_text", "tags", "facets", "ecosystem", "agent", "severity", "framework", "framework_version", "jurisdiction", "industry"],
      mcp_tools: ["recipes_search", "recipes_list", "recipes_get", "recipes_match_finding"],
      download_schema: "https://security-recipes.ai/schemas/recipe-download/v1",
      recipe_facets: ["remediation", "risk", "audit", "compliance", "code-hygiene"],
      app_store_model:
        "Recipes are installable context packs: browse by human intent, fetch by API, and select by MCP for one bounded remediation or evidence job.",
      quality_model: {
        world_class: "85-100",
        strong: "70-84",
        usable: "50-69",
        starter: "0-49",
        signals: ["inputs", "selection-guidance", "output-contract", "verification", "guardrails", "related-context", "multi-facet"],
      },
    },
    zero_day: {
      label: "0-Day",
      window_days: zeroDayWindowDays,
      since,
      reference_date: referenceDate,
      count: zeroDayCount,
      description: "CVE recipes whose site-created date falls within the current 0-Day window.",
    },
    categories,
    recipes,
  });
}

// /api/recipes-index.json — lean feed the MCP server loads as its recipe
// index. Same per-recipe search/get fields as /api/recipes.json but WITHOUT
// the static agent boilerplate that repeats identically on every recipe
// (recipe_contract, agent_handoff, download, quality scorecard prose) — that
// guidance is duplicated ~1 KB/recipe in the public feed and MCP never reads
// it. Keeping content_text (median ~4 KB) is unavoidable: search scores on it
// and recipes_get returns it. Development CVE Markdown is intentionally absent
// from both generic feeds because the dedicated catalog is authoritative.
function recipesMcpIndex() {
  const { pages } = getIndex();
  const recipePages = pages
    .filter((p) => p.sourcePath.startsWith("recipes/") && !p.isSection && isDiscoveryPage(p))
    .sort((a, b) => a.url.localeCompare(b.url, "en"));

  const zeroDayWindowDays = 4;
  let referenceDate = localDate();
  for (const p of recipePages) {
    const d = isoDate(p.date);
    if (d && d > referenceDate) referenceDate = d;
  }
  const since = new Date(new Date(`${referenceDate}T00:00:00Z`).getTime() - zeroDayWindowDays * 86400000)
    .toISOString()
    .slice(0, 10);

  const recipes = recipePages.map((p) => {
    const m = recipeModel(p);
    const cat = m.feedCategory;
    return {
      slug: m.slug,
      title: p.title,
      link_title: p.linkTitle,
      url: absURL(p.url),
      path: p.url,
      source_file: p.sourcePath,
      recipe_id: m.recipeId,
      recipe_kind: m.recipeKind,
      category: { slug: cat.slug, label: cat.label },
      agent: p.fm.agent || p.fm.tool || cat.slug,
      severity: p.fm.severity || "unspecified",
      maturity: p.fm.maturity || "unspecified",
      ecosystem: m.ecosystem,
      cve: m.cve,
      ghsa: m.ghsa,
      kev: m.kev,
      aliases: m.knownAs,
      framework: m.framework,
      framework_version: m.frameworkVersion,
      jurisdiction: m.jurisdiction,
      industry: m.industry,
      tags: m.tags,
      facets: m.facets,
      quality: { score: m.quality.score, tier: m.quality.tier, signals: m.quality.signals },
      author: m.author,
      team: m.team,
      model: m.model,
      date: m.date,
      zero_day: cat.slug === "cve" && !!m.date && m.date >= since,
      last_updated: lastmodFor(p.sourcePath, p.date),
      summary: m.summary,
      content_text: plainifyMarkdown(p.body),
    };
  });

  return JSON.stringify({
    api_version: "2026-06-10",
    kind: "security-recipes.recipe-index",
    endpoint: absURL("/api/recipes-index.json"),
    full_feed: absURL("/api/recipes.json"),
    generated_at: new Date().toISOString(),
    recipe_count: recipes.length,
    recipes,
  });
}

// Marketplace feeds. The straight ones re-serialize their data file;
// the manifest and readiness feeds derive structure exactly like the old
// index.marketplacemanifest.json / index.marketplacereadiness.json.
function marketplaceControlPlane() {
  const data = marketplace();
  return JSON.stringify({
    generated_at: new Date().toISOString(),
    feeds: {
      manifest: "/marketplace-control-plane.json",
      catalog: "/marketplace-catalog.json",
      input_channels: "/marketplace-input-channels.json",
      output_channels: "/marketplace-output-channels.json",
      report_profiles: "/marketplace-report-profiles.json",
      workflow_templates: "/marketplace-workflow-templates.json",
      readiness: "/marketplace-readiness.json",
    },
    schemas: schemaFeedMap(),
    catalog: data.catalog,
    input_channels: data.input_channels,
    output_channels: data.output_channels,
    report_profiles: data.report_profiles,
    workflow_templates: data.workflow_templates,
    readiness_profiles: data.readiness_profiles,
  });
}

function marketplaceReadiness() {
  const data = marketplace();
  const profiles = data.readiness_profiles;
  const entries = [];

  for (const channel of data.input_channels.channels || []) {
    const runtime = channel.runtime_support || "live";
    const authModes = channel.auth_modes || ["none"];
    const requirements = [];
    if (profiles.runtime_requirements?.[runtime]) requirements.push(profiles.runtime_requirements[runtime]);
    for (const mode of authModes) {
      if (profiles.auth_mode_details?.[mode]) requirements.push(profiles.auth_mode_details[mode]);
    }
    if (channel.config?.source) requirements.push(`Runtime source: ${channel.config.source}.`);
    if (channel.config?.accepted_formats) {
      requirements.push(`Accepted formats: ${channel.config.accepted_formats.join(", ")}.`);
    } else if (channel.config?.base_url) {
      requirements.push(`Provider endpoint: ${channel.config.base_url}.`);
    }
    entries.push({
      key: `input:${channel.id}`,
      kind: "input",
      label: channel.label,
      category: channel.category,
      status: channel.status,
      runtime_support: runtime,
      runtime_label: profiles.runtime_labels?.[runtime],
      auth_modes: authModes,
      description: channel.description,
      config_type: channel.config?.type,
      requirements,
      blockers: profiles.runtime_blockers?.[runtime] || [],
    });
  }

  for (const channel of data.output_channels.channels || []) {
    const runtime = channel.runtime_support || "copy_only";
    const authModes = profiles.output_driver_auth_modes?.[channel.driver] || ["none"];
    const requirements = [channel.requirement];
    if (profiles.runtime_requirements?.[runtime]) requirements.push(profiles.runtime_requirements[runtime]);
    for (const mode of authModes) {
      if (profiles.auth_mode_details?.[mode]) requirements.push(profiles.auth_mode_details[mode]);
    }
    if (channel.browser_delivery) {
      requirements.push("Browser delivery is always operator-triggered; no server-side secret storage is introduced by this route.");
    }
    entries.push({
      key: `output:${channel.id}`,
      kind: "output",
      label: channel.label,
      category: channel.category,
      status: channel.status,
      runtime_support: runtime,
      runtime_label: profiles.runtime_labels?.[runtime],
      auth_modes: authModes,
      description: channel.description,
      config_type: channel.config?.type,
      browser_delivery: channel.browser_delivery,
      requirements,
      blockers: profiles.runtime_blockers?.[runtime] || [],
    });
  }

  const countBy = (rt) => entries.filter((e) => e.runtime_support === rt).length;
  return JSON.stringify({
    generated_at: new Date().toISOString(),
    profiles,
    counts: {
      total_entries: entries.length,
      live: countBy("live"),
      live_or_copy: countBy("live_or_copy"),
      copy_only: countBy("copy_only"),
      planned: countBy("planned"),
      config_only: countBy("config_only"),
    },
    entries,
  });
}

// RSS 2.0 feed for one section: its descendant regular pages, newest
// first. Hugo emitted every page; 100 is plenty for feed readers while
// keeping recipes's feed sane.
function sectionRss(section, items) {
  const esc = (s) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  const rows = items
    .slice(0, 100)
    .map(
      (p) =>
        `<item><title>${esc(p.title)}</title><link>${esc(absURL(p.url))}</link>` +
        `<guid>${esc(absURL(p.url))}</guid>` +
        (p.date ? `<pubDate>${new Date(p.date).toUTCString()}</pubDate>` : "") +
        `<description>${esc(p.description || truncate(p.summary, 200))}</description></item>`
    )
    .join("");
  return (
    `<?xml version="1.0" encoding="utf-8"?>` +
    `<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>` +
    `<title>${esc(`${section.title} on ${site.title}`)}</title>` +
    `<link>${esc(absURL(section.url))}</link>` +
    `<description>Recent content in ${esc(section.title)} on ${esc(site.title)}</description>` +
    `<language>${site.languageCode}</language>` +
    `<atom:link href="${esc(absURL(`${section.url}index.xml`))}" rel="self" type="application/rss+xml"/>` +
    rows +
    `</channel></rss>`
  );
}

module.exports = {
  recipesIndex,
  recipesBrowser,
  agentRecipes,
  recipesMcpIndex,
  marketplaceControlPlane,
  marketplaceReadiness,
  sectionRss,
  absURL,
};
