"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const contentIndex = require("../lib/content-index");
const feeds = require("../lib/feeds");
const { isSectionFeedEntry } = require("../eleventy.config").sectionFeeds;
const { buildSidebarTree } = require("../eleventy.config").sidebarNavigation;

test("redirect sections do not publish competing RSS feeds", () => {
  assert.equal(
    isSectionFeedEntry({
      isSection: true,
      fm: { layout: "layouts/redirect.njk", redirectTo: "/cve-database/" },
    }),
    false,
  );
  assert.equal(isSectionFeedEntry({ isSection: true, fm: {} }), true);
  assert.equal(isSectionFeedEntry({ isSection: false, fm: {} }), false);
  assert.equal(
    contentIndex.isDiscoveryPage({
      sourcePath: "recipes/general/retired.md",
      fm: { redirectTo: "/recipes/general/current/" },
    }),
    false,
  );
});

test("root RSS uses the public site name without a duplicated suffix", () => {
  const rss = feeds.sectionRss(
    { title: "security-recipes.ai", url: "/" },
    [],
  );
  assert.match(rss, /<title>Security Recipes<\/title>/);
  assert.match(rss, /<description>Security recipes for AI-assisted remediation:/);
  assert.doesNotMatch(rss, /security-recipes\.ai on security-recipes\.ai/);
});

test("retired redirects do not receive collection or sidebar links", () => {
  const retired = new Set([
    "/recipes/general/owasp-top-10-2026-audit/",
    "/recipes/general/owasp-top-10-2026-remediate/",
  ]);
  const current = new Set([
    "/recipes/general/owasp-top-10-2025-audit/",
    "/recipes/general/owasp-top-10-2025-remediate/",
  ]);
  const generalChildren = contentIndex
    .childrenOf("recipes/general/_index.md")
    .map((page) => page.url);
  for (const url of retired) assert.ok(!generalChildren.includes(url));
  for (const url of current) assert.ok(generalChildren.includes(url));

  const sidebarUrls = [];
  const collectUrls = (items) => {
    for (const item of items) {
      sidebarUrls.push(item.url);
      collectUrls(item.children || []);
    }
  };
  collectUrls(buildSidebarTree());
  for (const url of retired) assert.ok(!sidebarUrls.includes(url));
  for (const url of current) assert.ok(sidebarUrls.includes(url));
});

test("only rendered historical CVEs enter the content index and compatible feeds", () => {
  const cvePages = contentIndex.getIndex().pages.filter(
    (page) => page.sourcePath.startsWith("recipes/cve/") && !page.isSection,
  );
  const stable = cvePages.filter((page) => page.fm.maturity === "stable");
  const development = cvePages.filter((page) => page.fm.maturity !== "stable");

  assert.equal(stable.length, 3, "only the three historical static CVEs belong in Eleventy");
  assert.equal(development.length, 0, "catalog/editorial CVE drafts must bypass the content index");
  assert.ok(stable.every(contentIndex.isDiscoveryPage));

  assert.equal(
    contentIndex.isRenderedContentFile(
      path.resolve("content/recipes/cve/cve-2021-44228-log4shell.md"),
    ),
    false,
  );
  assert.equal(
    contentIndex.isRenderedContentFile(
      path.resolve("content/recipes/cve/historical/cve-2014-0160-heartbleed.md"),
    ),
    true,
  );

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

test("historical CVE feeds and TOC preserve their authored public routes", () => {
  const stable = contentIndex.getIndex().pages.filter(
    (page) =>
      page.sourcePath.startsWith("recipes/cve/") &&
      !page.isSection &&
      contentIndex.isDiscoveryPage(page),
  );
  assert.equal(stable.length, 3);
  assert.ok(stable.every((page) => contentIndex.canonicalUrlForPage(page) === page.url));

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
  const cveToc = require("../lib/shortcodes/cve-toc");
  const html = cveToc("recipes/cve/_index.md");
  for (const page of stable) {
    assert.match(html, new RegExp(`href="${contentIndex.canonicalUrlForPage(page)}"`));
  }
});

test("CVE pages do not receive generic sibling pagers", () => {
  const siblings = contentIndex.siblingsByDir().get("recipes/cve/historical") || [];
  assert.ok(siblings.length > 1, "fixture repository must contain sibling CVE overrides");

  const requiredLegacyCves = new Set([
    "CVE-2014-0160",
    "CVE-2014-6271",
    "CVE-2017-18342",
  ]);
  for (const page of siblings) {
    requiredLegacyCves.delete(page.fm.cve);
    assert.deepEqual(
      contentIndex.pagerForSourcePath(`./content/${page.sourcePath}`),
      {},
      `${page.fm.cve} must not link to an arbitrary CVE sibling`,
    );
  }

  assert.deepEqual([...requiredLegacyCves], [], "legacy CVE pager fixtures are missing");
  assert.deepEqual(contentIndex.pagerForSourcePath("./content/recipes/cve/_index.md"), {});
});

test("non-CVE articles retain sibling pagers", () => {
  const siblings = contentIndex.siblingsByDir().get("recipes/general") || [];
  assert.ok(siblings.length > 2, "fixture repository must contain general recipe siblings");
  const index = Math.floor(siblings.length / 2);
  const page = siblings[index];
  assert.equal(Object.hasOwn(page.fm, "cve"), false);

  const navigationItem = (neighbor) => ({
    title: neighbor.linkTitle,
    url: contentIndex.canonicalUrlForPage(neighbor),
  });
  assert.deepEqual(
    contentIndex.pagerForSourcePath(`./content/${page.sourcePath}`),
    {
      prev: navigationItem(siblings[index - 1]),
      next: navigationItem(siblings[index + 1]),
    },
  );
});
