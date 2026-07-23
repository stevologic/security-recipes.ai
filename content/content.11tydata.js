// Directory data for everything under content/: Hugo-compatible
// permalinks (_index.md maps to its directory, `url:` front matter wins)
// and the default docs layout. The home page (content/_index.md) uses the
// standalone landing layout instead. Virtual templates (feeds, tag pages)
// also resolve under this directory, so every rule is gated on .md input.

const contentIndex = require("../lib/content-index");

const isMarkdown = (data) => data.page.inputPath.replace(/\\/g, "/").endsWith(".md");
const stemOf = (data) => data.page.filePathStem.replace(/\\/g, "/");
const PAGE_KINDS = new Set(["article", "collection", "webpage"]);

function sourcePathOf(inputPath) {
  return String(inputPath || "")
    .replace(/\\/g, "/")
    .replace(/^\.\/?content\//, "");
}

function explicitPageKind(data) {
  const kind = String(data.page_kind || "").trim().toLowerCase();
  if (!kind) return "";
  if (!PAGE_KINDS.has(kind)) {
    throw new Error(
      `Unsupported page_kind "${data.page_kind}" in ${sourcePathOf(data.page?.inputPath)}. ` +
      `Expected article, collection, or webpage.`,
    );
  }
  return kind;
}

function hasSectionChildren(inputPath) {
  const sourcePath = sourcePathOf(inputPath);
  if (!sourcePath.endsWith("_index.md")) return false;
  return contentIndex
    .childrenOf(sourcePath)
    .some((page) => page.isSection || contentIndex.isDiscoveryPage(page));
}

function pageKindFor(data) {
  const explicit = explicitPageKind(data);
  if (explicit) return explicit;
  if (!isMarkdown(data)) {
    if (data.isHome === true) return "home";
    if (data.isSection === true) return "collection";
    return data.isError === true ? "webpage" : "article";
  }

  const sourcePath = sourcePathOf(data.page.inputPath);
  if (sourcePath === "_index.md") return "home";
  if (sourcePath.endsWith("_index.md") && hasSectionChildren(data.page.inputPath)) {
    return "collection";
  }
  return "article";
}

function hasSectionFeed(inputPath) {
  const sourcePath = sourcePathOf(inputPath);
  if (!sourcePath.endsWith("_index.md")) return false;
  if (sourcePath === "cve-database/_index.md") return true;
  const directory = sourcePath.replace(/_index\.md$/, "");
  return contentIndex
    .regularPagesUnder(directory)
    .some((page) => page.date && contentIndex.isDiscoveryPage(page));
}

module.exports = {
  eleventyComputed: {
    permalink(data) {
      if (!isMarkdown(data)) return data.permalink;
      if (data.url) {
        const u = data.url.endsWith("/") ? data.url : `${data.url}/`;
        return `${u}index.html`;
      }
      // Derived from inputPath, not filePathStem: Eleventy strips
      // YYYY-MM-DD patterns out of stems, which mangles CVE filenames
      // that embed disclosure dates.
      let stem = data.page.inputPath
        .replace(/\\/g, "/")
        .replace(/^\.\/?content\//, "")
        .replace(/\.md$/i, "");
      if (stem.endsWith("/_index")) stem = stem.slice(0, -"/_index".length);
      else if (stem === "_index") stem = "";
      return `/${stem}${stem ? "/" : ""}index.html`;
    },
    layout(data) {
      if (data.layout) return data.layout;
      if (!isMarkdown(data)) return undefined;
      return stemOf(data) === "/_index" ? "layouts/home.njk" : "layouts/docs.njk";
    },
    sourcePath(data) {
      if (!isMarkdown(data)) return "";
      return sourcePathOf(data.page.inputPath);
    },
    pageKind(data) {
      return pageKindFor(data);
    },
    sectionFeed(data) {
      return (
        isMarkdown(data) &&
        pageKindFor(data) === "collection" &&
        hasSectionFeed(data.page.inputPath)
      );
    },
    isSection(data) {
      if (!isMarkdown(data)) return data.isSection === true;
      return pageKindFor(data) === "collection";
    },
    isArticle(data) {
      return pageKindFor(data) === "article";
    },
    isHome(data) {
      if (!isMarkdown(data)) return data.isHome === true;
      return stemOf(data) === "/_index";
    },
  },
};
