"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const contentIndex = require("../lib/content-index");
const feeds = require("../lib/feeds");

test("development CVE Markdown is excluded from generic discovery feeds", () => {
  const cvePages = contentIndex.getIndex().pages.filter(
    (page) => page.sourcePath.startsWith("prompt-library/cve/") && !page.isSection,
  );
  const stable = cvePages.filter((page) => page.fm.maturity === "stable");
  const development = cvePages.filter((page) => page.fm.maturity !== "stable");

  assert.ok(stable.length > 0, "fixture repository must contain stable CVE overrides");
  assert.ok(development.length > 0, "fixture repository must contain development CVE pages");
  assert.ok(stable.every(contentIndex.isDiscoveryPage));
  assert.ok(development.every((page) => !contentIndex.isDiscoveryPage(page)));

  const stablePaths = new Set(stable.map((page) => page.url));
  const developmentPaths = new Set(development.map((page) => page.url));
  const surfaces = [
    JSON.parse(feeds.recipesIndex()).map((item) => item.path),
    JSON.parse(feeds.recipesBrowser()).recipes.map((item) => item.url),
    JSON.parse(feeds.recipesMcpIndex()).recipes.map((item) => item.path),
  ];

  for (const paths of surfaces) {
    const actual = new Set(paths);
    for (const stablePath of stablePaths) assert.ok(actual.has(stablePath), stablePath);
    for (const developmentPath of developmentPaths) assert.ok(!actual.has(developmentPath), developmentPath);
  }
});
