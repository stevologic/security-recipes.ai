// Directory data for everything under content/: Hugo-compatible
// permalinks (_index.md maps to its directory, `url:` front matter wins)
// and the default docs layout. The home page (content/_index.md) uses the
// standalone landing layout instead. Virtual templates (feeds, tag pages)
// also resolve under this directory, so every rule is gated on .md input.

const isMarkdown = (data) => data.page.inputPath.replace(/\\/g, "/").endsWith(".md");
const stemOf = (data) => data.page.filePathStem.replace(/\\/g, "/");

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
      return data.page.inputPath.replace(/\\/g, "/").replace(/^\.\/?content\//, "");
    },
    isSection(data) {
      return isMarkdown(data) && data.page.inputPath.replace(/\\/g, "/").endsWith("_index.md");
    },
    isHome(data) {
      return isMarkdown(data) && stemOf(data) === "/_index";
    },
  },
};
