// The generated catalog owns canonical URLs for CVEs inside its rolling
// window. A small set of reviewed historical recipes explicitly opts out of
// that runtime route and must remain static because the catalog does not carry
// their older records. Development drafts and superseded aliases emit no HTML.

const inputPath = (data) => String(data.page?.inputPath || "").replace(/\\/g, "/");

const keepsHistoricalRoute = (data) =>
  data.canonical_cve_route === false &&
  String(data.maturity || "").toLowerCase() === "stable";

module.exports = {
  eleventyComputed: {
    layout(data) {
      const input = inputPath(data);
      if (input.endsWith("/_index.md")) return "layouts/redirect.njk";
      return keepsHistoricalRoute(data) ? "layouts/docs.njk" : false;
    },
    permalink(data) {
      const input = inputPath(data);
      // Catalog CVEs are rendered at /cve/CVE-ID/. Their Markdown slugs are
      // redirected by nginx and should not consume thousands of static files;
      // explicit pre-catalog historical pages keep their reviewed route.
      if (input.endsWith("/_index.md")) return "/recipes/cve/index.html";
      if (!keepsHistoricalRoute(data)) return false;
      const slug = input.split("/").pop().replace(/\.md$/i, "");
      return `/recipes/cve/${slug}/index.html`;
    },
    noindex(data) {
      const input = inputPath(data);
      if (input.endsWith("/_index.md")) return false;
      if (keepsHistoricalRoute(data)) return false;
      return String(data.maturity || "").toLowerCase() !== "stable";
    },
  },
};
