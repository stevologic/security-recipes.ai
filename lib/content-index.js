// One-pass index of rendered content front matter and raw bodies, shared by the
// shortcode preprocessor (relref resolution, prompt/CVE TOCs, recipe browser)
// and the JSON feeds. Bulk CVE Markdown is editorial/catalog input and is
// deliberately excluded because it does not render through Eleventy.

const fs = require("node:fs");
const path = require("node:path");
const matter = require("gray-matter");

const CONTENT_DIR = path.join(__dirname, "..", "content");
const CVE_EDITORIAL_DIR = path.join(CONTENT_DIR, "recipes", "cve");

let cache = null;

// content/recipes/cve/foo.md -> /recipes/cve/foo/
// content/docs/_index.md            -> /docs/
// Honors a front-matter `url:` override the way Hugo did
// (recipes/_index.md lives at /recipes/).
function urlForFile(relPath, fmUrl) {
  if (fmUrl) {
    return fmUrl.endsWith("/") ? fmUrl : `${fmUrl}/`;
  }
  let stem = relPath.replace(/\\/g, "/").replace(/\.md$/i, "");
  if (stem.endsWith("_index")) {
    stem = stem.slice(0, -"_index".length).replace(/\/$/, "");
  }
  return stem ? `/${stem}/` : "/";
}

// Approximation of Hugo's .Summary | plainify: first non-heading paragraph
// of the raw markdown with inline markup stripped. Only used as a fallback
// when a page has no `description`, which is rare in this content set.
function summaryFromBody(body) {
  const blocks = body.split(/\n\s*\n/);
  for (const block of blocks) {
    const t = block.trim();
    if (!t || t.startsWith("#") || t.startsWith("{{") || t.startsWith("```")) continue;
    return t
      .replace(/`([^`]*)`/g, "$1")
      .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
      .replace(/[*_>#]/g, "")
      .replace(/\s+/g, " ")
      .trim();
  }
  return "";
}

function isRenderedContentFile(full) {
  if (!full.toLowerCase().endsWith(".md")) return false;
  const cveRelative = path.relative(CVE_EDITORIAL_DIR, full).replace(/\\/g, "/");
  if (
    cveRelative &&
    !cveRelative.startsWith("../") &&
    cveRelative !== ".." &&
    !path.isAbsolute(cveRelative)
  ) {
    return cveRelative === "_index.md" || cveRelative.startsWith("historical/");
  }
  return true;
}

function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (entry.isFile() && isRenderedContentFile(full)) {
      out.push(full);
    }
  }
  return out;
}

function build() {
  const files = walk(CONTENT_DIR, []);
  const pages = [];
  const byUrl = new Map();

  for (const full of files) {
    const rel = path.relative(CONTENT_DIR, full).replace(/\\/g, "/");
    let parsed;
    try {
      parsed = matter(fs.readFileSync(full, "utf8"));
    } catch (err) {
      throw new Error(`content-index: bad front matter in ${rel}: ${err.message}`);
    }
    const data = parsed.data || {};
    const url = urlForFile(rel, data.url);
    const page = {
      sourcePath: rel,
      url,
      fm: data,
      body: parsed.content,
      title: data.title || "",
      linkTitle: data.linkTitle || data.title || "",
      description: data.description || "",
      weight: typeof data.weight === "number" ? data.weight : Number.MAX_SAFE_INTEGER,
      date: data.date ? new Date(data.date) : null,
      tags: Array.isArray(data.tags) ? data.tags : [],
      isSection: rel.endsWith("_index.md"),
      get summary() {
        if (this._summary === undefined) this._summary = summaryFromBody(this.body);
        return this._summary;
      },
    };
    pages.push(page);
    if (byUrl.has(url) && byUrl.get(url) !== page) {
      throw new Error(
        `content-index: duplicate URL ${url} from ${byUrl.get(url).sourcePath} and ${rel}`,
      );
    }
    byUrl.set(url, page);
    // Natural (pre-`url:` override) location still resolves, mirroring
    // Hugo which kept relref working against the source path.
    const naturalUrl = urlForFile(rel, null);
    if (byUrl.has(naturalUrl) && byUrl.get(naturalUrl) !== page) {
      throw new Error(
        `content-index: ambiguous natural URL ${naturalUrl} from ${byUrl.get(naturalUrl).sourcePath} and ${rel}`,
      );
    }
    byUrl.set(naturalUrl, page);
  }

  return { pages, byUrl };
}

function getIndex() {
  if (!cache) cache = build();
  return cache;
}

// Development CVE Markdown remains directly addressable for backwards
// compatibility, but it is not an authoritative recipe surface. The complete
// generated CVE catalog owns discovery for those records; only reviewed
// maturity=stable Markdown overrides belong in generic search, feeds, tags,
// sitemaps, and RSS. CVE navigation is curated separately from generic sibling
// pagination so chronology and remediation relevance are never inferred from
// filename or weight order.
function isDiscoveryPage(page) {
  const source = String(page?.sourcePath || "");
  if (page?.fm?.redirectTo || page?.fm?.layout === "layouts/redirect.njk") return false;
  if (!source.startsWith("recipes/cve/") || page?.isSection) return true;
  return String(page?.fm?.maturity || "").toLowerCase() === "stable";
}

function canonicalUrlForPage(page) {
  const cve = String(page?.fm?.cve || "").trim().toUpperCase();
  if (/^CVE-\d{4}-\d{4,}$/.test(cve) && page?.fm?.canonical_cve_route !== false) {
    return `/cve/${cve}/`;
  }
  return page?.url || "/";
}

// Resolve a Hugo relref target ("/docs/agent-integration#anchor") to a
// site-relative URL. All relrefs in this repo are root-absolute.
function resolveRelref(target, fromFile) {
  const [rawPath, fragment] = target.split("#");
  let p = rawPath.trim().replace(/\.md$/i, "");
  if (!p.startsWith("/")) {
    // Defensive: resolve relative to the referencing file's directory.
    const baseDir = path.posix.dirname(`/${fromFile}`);
    p = path.posix.normalize(`${baseDir}/${p}`);
  }
  const url = p.endsWith("/") ? p : `${p}/`;
  const { byUrl } = getIndex();
  if (!byUrl.has(url)) {
    throw new Error(`content-index: unresolved relref "${target}" in ${fromFile} -> ${url}`);
  }
  return fragment ? `${url}#${fragment}` : url;
}

// Direct children of a section directory (Hugo's .Page.Pages for a branch
// bundle): regular pages in the same directory plus immediate child
// sections. Sorted by weight, then linkTitle — Hugo's default ordering.
function childrenOf(sectionSourcePath) {
  const dir = path.posix.dirname(sectionSourcePath); // e.g. "claude"
  const prefix = dir === "." ? "" : `${dir}/`;
  const { pages } = getIndex();
  return pages
    .filter((p) => {
      if (!isDiscoveryPage(p)) return false;
      if (p.sourcePath === sectionSourcePath) return false;
      if (!p.sourcePath.startsWith(prefix)) return false;
      const rest = p.sourcePath.slice(prefix.length);
      const parts = rest.split("/");
      if (parts.length === 1) return !p.isSection; // sibling page
      if (parts.length === 2 && parts[1] === "_index.md") return true; // child section
      return false;
    })
    .sort(sortByWeightTitle);
}

// Every regular (non-section) page under a content directory prefix —
// Hugo's .RegularPagesRecursive for that section.
function regularPagesUnder(prefix) {
  const { pages } = getIndex();
  return pages
    .filter((p) => p.sourcePath.startsWith(prefix) && !p.isSection)
    .sort(sortByWeightTitle);
}

function sortByWeightTitle(a, b) {
  return (
    a.weight - b.weight || a.linkTitle.localeCompare(b.linkTitle, "en")
  );
}

// Regular pages grouped by their source directory, sorted, built once —
// keeps per-page prev/next lookups O(siblings) instead of O(site).
let siblingsCache = null;
function siblingsByDir() {
  if (!siblingsCache) {
    siblingsCache = new Map();
    for (const p of getIndex().pages) {
      if (p.isSection || !isDiscoveryPage(p)) continue;
      const dir = p.sourcePath.split("/").slice(0, -1).join("/");
      if (!siblingsCache.has(dir)) siblingsCache.set(dir, []);
      siblingsCache.get(dir).push(p);
    }
    for (const list of siblingsCache.values()) list.sort(sortByWeightTitle);
  }
  return siblingsCache;
}

function pagerForSourcePath(inputPath) {
  const sourcePath = String(inputPath || "")
    .replace(/\\/g, "/")
    .replace(/^\.\/?content\//, "");
  if (!sourcePath || sourcePath.endsWith("_index.md")) return {};

  const dir = sourcePath.split("/").slice(0, -1).join("/");
  const siblings = siblingsByDir().get(dir) || [];
  const index = siblings.findIndex((page) => page.sourcePath === sourcePath);
  if (index === -1) return {};
  const currentPage = siblings[index];
  if (Object.prototype.hasOwnProperty.call(currentPage.fm || {}, "cve")) return {};

  const navigationItem = (page) => ({
    title: page.linkTitle,
    url: canonicalUrlForPage(page),
  });
  return {
    prev: index > 0 ? navigationItem(siblings[index - 1]) : null,
    next: index < siblings.length - 1 ? navigationItem(siblings[index + 1]) : null,
  };
}

module.exports = {
  getIndex,
  resolveRelref,
  childrenOf,
  regularPagesUnder,
  urlForFile,
  sortByWeightTitle,
  siblingsByDir,
  pagerForSourcePath,
  isDiscoveryPage,
  canonicalUrlForPage,
  isRenderedContentFile,
};
