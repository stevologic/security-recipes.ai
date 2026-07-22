"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const contentIndex = require("../lib/content-index");
const feeds = require("../lib/feeds");

test("CVE overrides stay in compatible feeds and out of curated recipe feeds", () => {
  const cvePages = contentIndex.getIndex().pages.filter(
    (page) => page.sourcePath.startsWith("recipes/cve/") && !page.isSection,
  );
  const stable = cvePages.filter((page) => page.fm.maturity === "stable");
  const development = cvePages.filter((page) => page.fm.maturity !== "stable");

  assert.ok(stable.length > 0, "fixture repository must contain stable CVE overrides");
  assert.ok(development.length > 0, "fixture repository must contain development CVE pages");
  assert.ok(stable.every(contentIndex.isDiscoveryPage));
  assert.ok(development.every((page) => !contentIndex.isDiscoveryPage(page)));

  const stablePaths = new Set(stable.map(contentIndex.canonicalUrlForPage));
  const developmentPaths = new Set(development.map((page) => page.url));
  const compatibleSurfaces = [
    ["docs search", JSON.parse(feeds.recipesIndex()).map((item) => item.path)],
    ["rich agent feed", JSON.parse(feeds.agentRecipes()).recipes.map((item) => item.path)],
    ["MCP recipe feed", JSON.parse(feeds.recipesMcpIndex()).recipes.map((item) => item.path)],
  ];
  for (const [label, paths] of compatibleSurfaces) {
    const actual = new Set(paths);
    for (const stablePath of stablePaths) {
      assert.ok(actual.has(stablePath), `${label} is missing ${stablePath}`);
    }
    for (const developmentPath of developmentPaths) {
      assert.ok(!actual.has(developmentPath), `${label} exposes ${developmentPath}`);
    }
  }

  const browser = JSON.parse(feeds.recipesBrowser());
  const curated = JSON.parse(feeds.curatedAgentRecipes());
  const curatedSurfaces = [
    ["recipe browser", browser.recipes.map((item) => item.url)],
    ["curated agent feed", curated.recipes.map((item) => item.path)],
  ];
  for (const [label, paths] of curatedSurfaces) {
    const actual = new Set(paths);
    for (const cvePath of [...stablePaths, ...developmentPaths]) {
      assert.ok(!actual.has(cvePath), `${label} exposes ${cvePath}`);
    }
  }

  assert.equal(browser.count, browser.recipes.length);
  assert.equal(curated.recipe_count, curated.recipes.length);
  assert.deepEqual(
    browser.recipes.map((item) => item.url).sort(),
    curated.recipes.map((item) => item.path).sort(),
    "human and agentic curated feeds must describe the same collection",
  );
  assert.ok(browser.recipes.every((item) => item.category !== "cve"));
  assert.ok(curated.recipes.every((item) => item.category?.slug !== "cve"));
});

test("reviewed CVE feeds and TOC use each page's canonical destination", () => {
  const stable = contentIndex.getIndex().pages.filter(
    (page) =>
      page.sourcePath.startsWith("recipes/cve/") &&
      !page.isSection &&
      contentIndex.isDiscoveryPage(page),
  );
  const migrated = stable.filter(
    (page) => contentIndex.canonicalUrlForPage(page) !== page.url,
  );
  assert.ok(migrated.length > 0, "fixture repository must contain canonicalized CVE overrides");

  const expectedPaths = new Set(stable.map(contentIndex.canonicalUrlForPage));
  const stableSources = new Set(stable.map((page) => page.sourcePath));
  for (const result of [
    JSON.parse(feeds.recipesIndex()),
    JSON.parse(feeds.agentRecipes()).recipes,
    JSON.parse(feeds.recipesMcpIndex()).recipes,
  ]) {
    const cveItems = result.filter((item) => stableSources.has(item.source_file));
    assert.deepEqual(new Set(cveItems.map((item) => item.path)), expectedPaths);
    for (const item of cveItems) {
      assert.equal(new URL(item.url).pathname, item.path);
    }
  }

  const section = { title: "Reviewed CVEs", url: "/recipes/cve/" };
  const rss = feeds.sectionRss(section, stable);
  for (const page of stable) {
    const canonical = contentIndex.canonicalUrlForPage(page);
    assert.match(rss, new RegExp(`<link>https://security-recipes\\.ai${canonical}</link>`));
    assert.match(rss, new RegExp(`<guid>https://security-recipes\\.ai${canonical}</guid>`));
  }
  for (const page of migrated) {
    assert.doesNotMatch(rss, new RegExp(`https://security-recipes\\.ai${page.url}`));
  }

  const cveToc = require("../lib/shortcodes/cve-toc");
  const html = cveToc("recipes/cve/_index.md");
  for (const page of stable) {
    assert.match(html, new RegExp(`href="${contentIndex.canonicalUrlForPage(page)}"`));
  }
  for (const page of migrated) {
    assert.doesNotMatch(html, new RegExp(`href="${page.url}"`));
  }
});

test("reviewed CVE sibling pagers use canonical destinations", () => {
  const siblings = contentIndex.siblingsByDir().get("recipes/cve") || [];
  assert.ok(siblings.length > 1, "fixture repository must contain sibling CVE overrides");

  let sawCanonicalizedNeighbor = false;
  for (const [index, page] of siblings.entries()) {
    const expectedItem = (neighbor) => {
      if (!neighbor) return null;
      const canonical = contentIndex.canonicalUrlForPage(neighbor);
      if (canonical !== neighbor.url) sawCanonicalizedNeighbor = true;
      return { title: neighbor.linkTitle, url: canonical };
    };
    assert.deepEqual(
      contentIndex.pagerForSourcePath(`./content/${page.sourcePath}`),
      {
        prev: expectedItem(siblings[index - 1]),
        next: expectedItem(siblings[index + 1]),
      },
    );
  }

  assert.ok(sawCanonicalizedNeighbor, "fixture must exercise a migrated CVE neighbor");
  assert.deepEqual(contentIndex.pagerForSourcePath("./content/recipes/cve/_index.md"), {});
});
