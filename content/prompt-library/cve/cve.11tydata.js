// Draft CVE Markdown is retained at its historical URL, but the generated
// catalog is authoritative until a recipe is reviewed and marked stable.
// Keep drafts out of search-engine indexes as well as the site's own generic
// discovery surfaces.

module.exports = {
  eleventyComputed: {
    noindex(data) {
      const input = String(data.page?.inputPath || "").replace(/\\/g, "/");
      if (input.endsWith("/_index.md")) return false;
      return String(data.maturity || "").toLowerCase() !== "stable";
    },
  },
};
