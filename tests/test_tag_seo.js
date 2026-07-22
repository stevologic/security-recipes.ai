const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { seoHead } = require("../lib/seo");
const {
  authoredTagUrl,
  GENERATED_TAG_PAGE_SEO,
  planPagesSitemapEntries,
  renderPagesSitemap,
} = require("../eleventy.config").pageSitemap;

function robots(output, name = "robots") {
  const match = output.match(new RegExp(`<meta name="${name}" content="([^"]+)">`));
  assert.ok(match, `expected ${name} metadata`);
  return match[1];
}

test("generated tag listings are noindex,follow", () => {
  assert.deepEqual(GENERATED_TAG_PAGE_SEO, {
    noindex: true,
    noindex_follow: true,
  });

  const output = seoHead({
    url: "/tags/example/",
    title: "Example",
    description: "Generated resources tagged Example.",
    isSection: true,
    noindex: GENERATED_TAG_PAGE_SEO.noindex,
    noindexFollow: GENERATED_TAG_PAGE_SEO.noindex_follow,
  });

  assert.equal(robots(output), "noindex,follow");
  assert.equal(robots(output, "googlebot"), "noindex,follow");
});

test("error pages remain noindex,nofollow even when follow is requested", () => {
  const output = seoHead({
    url: "/404.html",
    title: "Page not found",
    isError: true,
    noindex: true,
    noindexFollow: true,
  });

  assert.equal(robots(output), "noindex,nofollow");
  assert.equal(robots(output, "googlebot"), "noindex,nofollow");
});

test("generated tag routes stay out of the pages sitemap while authored tag pages remain", () => {
  const pages = [
    {
      sourcePath: "recipes/general/example.md",
      url: "/recipes/general/example/",
      fm: {},
      tags: ["generated-topic"],
      date: null,
    },
    {
      sourcePath: "tags/reviewed-topic/_index.md",
      url: "/tags/reviewed-topic/",
      fm: {},
      tags: [],
      isSection: true,
      date: null,
    },
  ];
  const entries = planPagesSitemapEntries(pages, {
    cveCatalogUpdatedAt: "2026-07-21T07:00:00Z",
    lastmodResolver: () => "2026-07-20",
  });
  const xml = renderPagesSitemap(entries);

  assert.match(xml, /\/recipes\/general\/example\//);
  assert.match(xml, /\/tags\/reviewed-topic\//);
  assert.doesNotMatch(xml, /<loc>[^<]*\/tags\/<\/loc>/);
  assert.doesNotMatch(xml, /\/tags\/generated-topic\//);
});

test("only an authored, indexable taxonomy page receives a navigable tag URL", () => {
  const generatedOnly = {
    sourcePath: "recipes/general/example.md",
    url: "/recipes/general/example/",
    fm: {},
    tags: ["generated-topic"],
    date: null,
  };
  const authored = {
    sourcePath: "tags/reviewed-topic/_index.md",
    url: "/tags/reviewed-topic/",
    fm: {},
    tags: [],
    isSection: true,
    date: null,
  };
  const authoredNoindex = {
    ...authored,
    sourcePath: "tags/private-topic/_index.md",
    url: "/tags/private-topic/",
    fm: { noindex: true },
  };
  const pages = [generatedOnly, authored, authoredNoindex];

  assert.equal(authoredTagUrl("generated topic", pages), "");
  assert.equal(authoredTagUrl("reviewed topic", pages), "/tags/reviewed-topic/");
  assert.equal(authoredTagUrl("private topic", pages), "");
});

test("article tag labels do not link to generated noindex taxonomy pages", () => {
  const template = fs.readFileSync(
    path.join(__dirname, "..", "_includes", "layouts", "docs.njk"),
    "utf8",
  );

  assert.match(template, /set tagUrl = tag \| authoredTagUrl/u);
  assert.match(template, /\{% if tagUrl %\}<a[^>]+href="\{\{ tagUrl \}\}"/u);
  assert.match(template, /\{% else %\}<span class="sr-tag-chip sr-tag-chip--small">/u);
  assert.doesNotMatch(template, /href="\/tags\/\{\{ tag \| tagSlug \}\}\//u);
});
