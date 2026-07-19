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

  const stablePaths = new Set(stable.map((page) => page.url));
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
