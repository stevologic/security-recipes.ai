// One-pass index of content/*.md front matter and raw bodies, shared by the
// shortcode preprocessor (relref resolution, prompt/cve TOCs, recipe browser)
// and the JSON feeds so nothing re-reads 2,500 files per page. Built lazily
// on first access and cached for the whole build process.

const fs = require("node:fs");
const path = require("node:path");
const matter = require("gray-matter");

const CONTENT_DIR = path.join(__dirname, "..", "content");

let cache = null;

// content/prompt-library/cve/foo.md -> /prompt-library/cve/foo/
// content/docs/_index.md            -> /docs/
// Honors a front-matter `url:` override the way Hugo did
// (prompt-library/_index.md lives at /recipes/).
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

function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) {
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
    byUrl.set(url, page);
    // Natural (pre-`url:` override) location still resolves, mirroring
    // Hugo which kept relref working against the source path.
    const naturalUrl = urlForFile(rel, null);
    if (!byUrl.has(naturalUrl)) byUrl.set(naturalUrl, page);
  }

  return { pages, byUrl };
}

function getIndex() {
  if (!cache) cache = build();
  return cache;
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
    console.warn(`[relref] unresolved "${target}" in ${fromFile} -> ${url}`);
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
      if (p.isSection) continue;
      const dir = p.sourcePath.split("/").slice(0, -1).join("/");
      if (!siblingsCache.has(dir)) siblingsCache.set(dir, []);
      siblingsCache.get(dir).push(p);
    }
    for (const list of siblingsCache.values()) list.sort(sortByWeightTitle);
  }
  return siblingsCache;
}

module.exports = {
  getIndex,
  resolveRelref,
  childrenOf,
  regularPagesUnder,
  urlForFile,
  sortByWeightTitle,
  siblingsByDir,
};
