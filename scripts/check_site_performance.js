#!/usr/bin/env node

// Deployment-shape guardrails for the large CVE catalog. These budgets have
// deliberate headroom over the measured production build: they catch an
// accidental one-page-per-catalog-record build, an uncompressed search index,
// or development drafts leaking back into generic agent/browser feeds.

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const ROOT = path.resolve(process.env.SITE_OUTPUT_DIR || "public");
const CONTENT = path.resolve("content/recipes/cve");
const PLAYBOOK_CONTENT = path.resolve("content/security-remediation");
const MiB = 1024 * 1024;
const KiB = 1024;
const failures = [];

function fail(message) {
  failures.push(message);
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

function size(file) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full)) {
    fail(`missing required output: ${file}`);
    return 0;
  }
  return fs.statSync(full).size;
}

function budget(label, actual, maximum) {
  if (actual > maximum) {
    fail(`${label} is ${actual.toLocaleString()} bytes; budget is ${maximum.toLocaleString()}`);
  }
}

function readJson(file) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full)) {
    fail(`missing required output: ${file}`);
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(full, "utf8"));
  } catch (error) {
    fail(`invalid JSON in ${file}: ${error.message}`);
    return null;
  }
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function checkOpaquePng(file, expectedSize) {
  const output = path.join(ROOT, file);
  const source = path.resolve("static", file);
  if (!fs.existsSync(output) || !fs.existsSync(source)) {
    fail(`missing installed-app icon: ${file}`);
    return;
  }
  const png = fs.readFileSync(output);
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (png.length < 33 || !png.subarray(0, 8).equals(signature) || png.toString("ascii", 12, 16) !== "IHDR") {
    fail(`${file} is not a valid PNG with an IHDR header`);
    return;
  }
  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  const colorType = png[25];
  if (width !== expectedSize || height !== expectedSize) {
    fail(`${file} is ${width}x${height}; expected ${expectedSize}x${expectedSize}`);
  }
  if (colorType !== 2) fail(`${file} must be an opaque RGB PNG (color type 2); found ${colorType}`);
  if (sha256(source) !== sha256(output)) fail(`${file} differs between static source and site output`);
  budget(file, png.length, 256 * KiB);
}

function routeForSource(file) {
  return `/recipes/cve/${path.basename(file, ".md")}/`;
}

if (!fs.existsSync(ROOT)) throw new Error(`site output does not exist: ${ROOT}`);
if (!fs.existsSync(CONTENT)) throw new Error(`CVE content does not exist: ${CONTENT}`);

const files = walk(ROOT);
const retiredNamespace = new RegExp(["prompt", "library"].join("[-_ ]?"), "i");
const generatedTextExtensions = new Set([
  ".css", ".html", ".js", ".json", ".map", ".md", ".svg", ".txt", ".webmanifest", ".xml",
]);
for (const file of files) {
  const relative = path.relative(ROOT, file).replace(/\\/g, "/");
  if (retiredNamespace.test(relative)) {
    fail(`retired recipe namespace remains in output path: ${relative}`);
  }
  if (generatedTextExtensions.has(path.extname(file).toLowerCase())) {
    const content = fs.readFileSync(file, "utf8");
    if (retiredNamespace.test(content)) {
      fail(`retired recipe namespace remains in generated text: ${relative}`);
    }
  }
}
// This is deployed disk/image size and intentionally includes precompressed
// sidecars. Logical feed checks below parse only canonical, uncompressed URLs.
const totalBytes = files.reduce((sum, file) => sum + fs.statSync(file).size, 0);
const cveHtml = files.filter((file) =>
  file.startsWith(path.join(ROOT, "recipes", "cve") + path.sep) && file.endsWith("index.html"),
);
const cveHtmlBytes = cveHtml.reduce((sum, file) => sum + fs.statSync(file).size, 0);

budget("site output", totalBytes, 320 * MiB);
if (files.length > 5500) fail(`site output has ${files.length.toLocaleString()} files; budget is 5,500`);
if (cveHtml.length > 4000) fail(`CVE HTML has ${cveHtml.length.toLocaleString()} files; budget is 4,000`);
budget("CVE HTML", cveHtmlBytes, 110 * MiB);
budget("CVE browser index", size("api/cve-catalog/browser-index.json.gz"), 8 * MiB);
budget("CVE complete index manifest", size("api/cve-catalog/index.json"), 1 * MiB);
budget("CVE runtime summary", size("api/cve-catalog/runtime-summary.json"), 8 * KiB);
budget("CVE manifest", size("api/cve-catalog/manifest.json"), 256 * KiB);
budget("CVE remediation archetypes", size("api/cve-catalog/archetypes.json"), 1 * MiB);
budget("CVE hub HTML", size("recipes/cve/index.html"), 512 * KiB);
budget("recipe library HTML", size("recipes/index.html"), 768 * KiB);
budget("recipe library JavaScript", size("js/recipe-browser.js"), 160 * KiB);
budget("recipe library styles", size("css/recipe-library.css"), 160 * KiB);
budget("playbook workflow styles", size("css/playbook-workflows.css"), 32 * KiB);
budget("generic docs search index", size("recipes-index.json"), 2 * MiB);
budget("generic recipe browser feed", size("recipes-browser.json"), 2 * MiB);
budget("generic rich agent feed", size("api/recipes.json"), 8 * MiB);
budget("generic MCP recipe feed", size("api/recipes-index.json"), 6 * MiB);

const manifest = readJson("site.webmanifest");
if (manifest) {
  if (manifest.id !== "/" || manifest.start_url !== "/" || manifest.scope !== "/") {
    fail("site.webmanifest must keep installed navigation within the site root");
  }
  if (manifest.display !== "standalone") fail("site.webmanifest display must be standalone");
  if (manifest.background_color !== "#000000" || manifest.theme_color !== "#000000") {
    fail("site.webmanifest launch and theme surfaces must be black");
  }
  const manifestIcons = new Map((manifest.icons || []).map((icon) => [icon.src, icon]));
  for (const [src, sizes, purpose] of [
    ["/icon-192x192.png", "192x192", "any"],
    ["/icon-512x512.png", "512x512", "any"],
    ["/icon-maskable-512x512.png", "512x512", "maskable"],
  ]) {
    const icon = manifestIcons.get(src);
    if (!icon || icon.sizes !== sizes || icon.type !== "image/png" || icon.purpose !== purpose) {
      fail(`site.webmanifest is missing the ${sizes} ${purpose} icon contract`);
    }
  }
}

for (const [file, expectedSize] of [
  ["apple-touch-icon.png", 180],
  ["apple-touch-icon-180x180.png", 180],
  ["icon-192x192.png", 192],
  ["icon-512x512.png", 512],
  ["icon-maskable-512x512.png", 512],
]) {
  checkOpaquePng(file, expectedSize);
}

for (const file of ["index.html", "recipes/index.html", "recipes/cve/index.html"]) {
  const htmlPath = path.join(ROOT, file);
  if (!fs.existsSync(htmlPath)) {
    fail(`missing installable page output: ${file}`);
    continue;
  }
  const html = fs.readFileSync(htmlPath, "utf8");
  if (!html.includes('name="apple-mobile-web-app-capable" content="yes"')) {
    fail(`${file} does not enable Apple installed-app mode`);
  }
  const statusBarTags = html.match(/<meta name="apple-mobile-web-app-status-bar-style" content="black">/g) || [];
  if (statusBarTags.length !== 1) {
    fail(`${file} must request exactly one opaque black Apple status bar`);
  }
  const themeTags = html.match(/<meta name="theme-color"[^>]*>/g) || [];
  if (themeTags.length !== 1 || themeTags[0] !== '<meta name="theme-color" content="#000000">') {
    fail(`${file} must expose exactly one black HTML theme color`);
  }
  if (html.includes("black-translucent") || /name="theme-color"[^>]+content="#fff(?:fff)?"/i.test(html)) {
    fail(`${file} contains a white or translucent installed-app status surface`);
  }
  if (!html.includes('rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon-180x180.png"')) {
    fail(`${file} does not advertise the versioned 180x180 Apple touch icon`);
  }
  if (!html.includes('rel="manifest" href="/site.webmanifest"')) {
    fail(`${file} does not advertise site.webmanifest`);
  }
  if (!html.includes("manifest-src 'self'")) fail(`${file} CSP does not permit its own manifest`);
  if (html.includes("manifest-src 'none'")) fail(`${file} CSP still blocks installed-app manifests`);
}

const playbookSources = fs.readdirSync(PLAYBOOK_CONTENT, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .filter((slug) => fs.existsSync(path.join(PLAYBOOK_CONTENT, slug, "_index.md")))
  .sort();
if (playbookSources.length !== 75) {
  fail(`playbook source count is ${playbookSources.length}; expected 75`);
}

let playbookHtmlBytes = 0;
let largestPlaybookHtml = 0;
for (const slug of playbookSources) {
  const output = path.join(ROOT, "security-remediation", slug, "index.html");
  if (!fs.existsSync(output)) {
    fail(`missing playbook output: security-remediation/${slug}/index.html`);
    continue;
  }
  const bytes = fs.statSync(output).size;
  playbookHtmlBytes += bytes;
  largestPlaybookHtml = Math.max(largestPlaybookHtml, bytes);
  const html = fs.readFileSync(output, "utf8");
  const workflowCount = (html.match(/\bdata-playbook-workflow(?:\s|>)/g) || []).length;
  if (workflowCount !== 1) {
    fail(`${slug} renders ${workflowCount} playbook workflow components; expected exactly one`);
  }
  const mainStart = html.indexOf('<main id="content"');
  const mainEnd = html.indexOf("</main>", mainStart);
  const workflowAt = html.indexOf("data-playbook-workflow", mainStart);
  if (mainStart < 0 || mainEnd < 0 || workflowAt < mainStart || workflowAt > mainEnd) {
    fail(`${slug} does not render its workflow inside the main document`);
  } else if ((workflowAt - mainStart) / Math.max(1, mainEnd - mainStart) > 0.6) {
    fail(`${slug} places its workflow below the first 60% of the main document`);
  }
  if (!html.includes("sr-playbook-python")) {
    fail(`${slug} is missing the Python companion inside its workflow`);
  }
}
budget("playbook HTML", playbookHtmlBytes, 10 * MiB);
budget("largest playbook HTML", largestPlaybookHtml, 160 * KiB);

const shards = files.filter((file) => file.includes(`${path.sep}api${path.sep}cve-catalog${path.sep}shards${path.sep}`));
const largestShard = shards.reduce((largest, file) => Math.max(largest, fs.statSync(file).size), 0);
budget("largest compressed CVE shard", largestShard, 1 * MiB);

const cveIndexPartitions = files.filter((file) =>
  file.includes(`${path.sep}api${path.sep}cve-catalog${path.sep}indexes${path.sep}`) && file.endsWith(".json.gz"),
);
const cveIndexPartitionBytes = cveIndexPartitions.reduce((sum, file) => sum + fs.statSync(file).size, 0);
const largestCveIndexPartition = cveIndexPartitions.reduce(
  (largest, file) => Math.max(largest, fs.statSync(file).size),
  0,
);
if (cveIndexPartitions.length > 12) {
  fail(`CVE complete index has ${cveIndexPartitions.length} partitions; budget is 12 rolling-window years`);
}
budget("CVE complete index partitions", cveIndexPartitionBytes, 24 * MiB);
budget("largest CVE complete index partition", largestCveIndexPartition, 4 * MiB);

for (const feed of [
  "recipes-index.json",
  "recipes-browser.json",
  "api/recipes.json",
  "api/recipes-index.json",
  "api/cve-catalog/index.json",
  "sitemap.xml",
]) {
  const raw = size(feed);
  if (raw >= 64 * KiB) {
    const zipped = size(`${feed}.gz`);
    if (zipped && zipped >= raw * 0.5) fail(`${feed}.gz does not reduce its source by at least 50%`);
  }
}

const cveSources = fs.readdirSync(CONTENT)
  .filter((name) => name.endsWith(".md") && name !== "_index.md")
  .map((name) => path.join(CONTENT, name));
const stableRoutes = new Set();
const stableOverrides = [];
const developmentRoutes = new Set();
for (const file of cveSources) {
  const source = fs.readFileSync(file, "utf8");
  const frontmatter = source.startsWith("---") ? source.slice(3, source.indexOf("---", 3)) : "";
  const match = frontmatter.match(/^maturity:\s*["']?([^"'\r\n]+)["']?\s*$/im);
  const route = routeForSource(file);
  if (String(match?.[1] || "").trim().toLowerCase() === "stable") {
    const cve = String(
      frontmatter.match(/^cve:\s*["']?(CVE-\d{4}-\d{4,7})["']?\s*$/im)?.[1] || ""
    ).toUpperCase();
    const canonicalCveRoute =
      !/^canonical_cve_route:\s*false\s*$/im.test(frontmatter);
    stableRoutes.add(route);
    stableOverrides.push({ route, cve, canonicalCveRoute });
  } else {
    developmentRoutes.add(route);
  }
}
if (!stableRoutes.size) fail("no stable CVE Markdown overrides were found");
if (!developmentRoutes.size) fail("no development CVE Markdown compatibility pages were found");

const docs = readJson("recipes-index.json") || [];
const browser = readJson("recipes-browser.json")?.recipes || [];
const rich = readJson("api/recipes.json")?.recipes || [];
const mcp = readJson("api/recipes-index.json")?.recipes || [];
const runtimeSummary = readJson("api/cve-catalog/runtime-summary.json") || {};
if (browser.length > 5000) {
  fail(`recipe browser feed has ${browser.length.toLocaleString()} records; keep the CVE catalog on its worker index`);
}

const recipeLibraryPath = path.join(ROOT, "recipes", "index.html");
if (fs.existsSync(recipeLibraryPath)) {
  const recipeLibrary = fs.readFileSync(recipeLibraryPath, "utf8");
  const ssrCards = (recipeLibrary.match(/\bdata-recipe-card(?:\s|>)/g) || []).length;
  if (ssrCards > 18) fail(`recipe library server-renders ${ssrCards} cards; budget is 18`);
  if (!recipeLibrary.includes('data-library-tab="curated"') || !recipeLibrary.includes('data-library-tab="cve"')) {
    fail("recipe library is missing its curated and CVE collection tabs");
  }
  if (!recipeLibrary.includes("data-cve-catalog-deferred")) {
    fail("recipe library eagerly mounts the CVE catalog");
  }
  const catalogRecords = Number(runtimeSummary?.totals?.catalog_records || 0);
  const overlap = Number(runtimeSummary?.totals?.stable_markdown_overrides || 0);
  const uniqueTotal = browser.length + catalogRecords - overlap;
  if (!recipeLibrary.includes(uniqueTotal.toLocaleString("en-US"))) {
    fail(`recipe library does not display its ${uniqueTotal.toLocaleString("en-US")} unique-entry total`);
  }
}
const surfaces = [
  ["docs search", new Set(docs.map((item) => item.path))],
  ["recipe browser", new Set(browser.map((item) => item.url))],
  ["rich agent feed", new Set(rich.map((item) => item.path))],
  ["MCP recipe feed", new Set(mcp.map((item) => item.path))],
];
for (const [label, routes] of surfaces) {
  for (const route of stableRoutes) {
    if (!routes.has(route)) fail(`${label} is missing stable override ${route}`);
  }
  for (const route of developmentRoutes) {
    if (routes.has(route)) fail(`${label} exposes development CVE draft ${route}`);
  }
}

const sitemap = fs.readFileSync(path.join(ROOT, "sitemap.xml"), "utf8");
const pagesSitemapPath = path.join(ROOT, "sitemaps", "pages.xml");
const pagesSitemap = fs.existsSync(pagesSitemapPath)
  ? fs.readFileSync(pagesSitemapPath, "utf8")
  : "";
if (!pagesSitemap) fail("missing required output: sitemaps/pages.xml");
if (!sitemap.includes("/sitemaps/pages.xml")) {
  fail("root sitemap index does not reference /sitemaps/pages.xml");
}

const indexedSitemapRoutes = Array.from(
  sitemap.matchAll(/<loc>https?:\/\/[^/]+(\/[^<]+)<\/loc>/g),
  (match) => match[1]
);
const sitemapCache = new Map();
function readIndexedSitemap(route) {
  if (sitemapCache.has(route)) return sitemapCache.get(route);
  const output = path.join(ROOT, route.replace(/^\//, ""));
  const content = fs.existsSync(output) ? fs.readFileSync(output, "utf8") : "";
  if (!content) fail(`root sitemap references missing output ${route}`);
  sitemapCache.set(route, content);
  return content;
}

for (const override of stableOverrides) {
  if (!override.canonicalCveRoute) {
    if (!pagesSitemap.includes(override.route)) {
      fail(`pages sitemap is missing historical stable override ${override.route}`);
    }
    continue;
  }
  if (!/^CVE-\d{4}-\d{4,7}$/.test(override.cve)) {
    fail(`stable override ${override.route} is missing a canonical CVE ID`);
    continue;
  }
  if (pagesSitemap.includes(override.route)) {
    fail(`pages sitemap exposes superseded CVE alias ${override.route}`);
  }
  const year = override.cve.slice(4, 8);
  const yearSitemaps = indexedSitemapRoutes.filter((route) =>
    new RegExp(`^/sitemaps/cves-${year}(?:-\\d+)?\\.xml$`).test(route)
  );
  if (!yearSitemaps.length) {
    fail(`root sitemap index has no CVE partition for ${override.cve}`);
    continue;
  }
  const canonicalRoute = `/cve/${override.cve}/`;
  if (!yearSitemaps.some((route) => readIndexedSitemap(route).includes(canonicalRoute))) {
    fail(`CVE sitemaps are missing canonical route ${canonicalRoute}`);
  }
}
for (const route of developmentRoutes) {
  if (pagesSitemap.includes(route)) fail(`pages sitemap exposes development CVE draft ${route}`);
}

for (const route of developmentRoutes) {
  const html = path.join(ROOT, route.replace(/^\//, "").replace(/\/$/, ""), "index.html");
  if (!fs.existsSync(html)) {
    fail(`development compatibility URL was not rendered: ${route}`);
    continue;
  }
  if (!fs.readFileSync(html, "utf8").includes('name="robots" content="noindex,nofollow"')) {
    fail(`development compatibility URL is not marked noindex: ${route}`);
  }
}

if (failures.length) {
  console.error("Site performance/discovery budgets failed:");
  for (const message of failures) console.error(`- ${message}`);
  process.exit(1);
}

console.log(
  `Performance budgets passed: ${files.length.toLocaleString()} files, ` +
  `${(totalBytes / MiB).toFixed(1)} MiB, ${cveHtml.length.toLocaleString()} CVE HTML pages, ` +
  `${stableRoutes.size} stable overrides, ${developmentRoutes.size.toLocaleString()} noindex compatibility drafts.`,
);
