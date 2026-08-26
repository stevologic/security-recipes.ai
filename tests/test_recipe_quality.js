"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { qualityFor } = require("../lib/recipe-model");

const ROOT = path.resolve(__dirname, "..");

test("quality scoring recognizes required output contract headings", () => {
  const aliased = qualityFor(
    "## when to use it\n## inputs\n## required output contract\n## verification\n## related recipes\ndo not invent exploits\n",
    2,
  );
  assert.ok(aliased.signals.includes("output-contract"));
  assert.ok(aliased.signals.includes("selection-guidance"));
  assert.equal(aliased.tier, "world-class");

  const canonical = qualityFor(
    "## when to use it\n## inputs\n## output contract\n## verification\n## related recipes\ndo not invent exploits\n",
    2,
  );
  assert.ok(canonical.signals.includes("output-contract"));
  assert.equal(canonical.tier, "world-class");
});

test("discovery recipes in the agent feed stay world-class", () => {
  const { agentRecipes } = require("../lib/feeds.js");
  const feed = JSON.parse(agentRecipes());
  const gaps = feed.recipes
    .filter((recipe) => recipe.quality.tier !== "world-class")
    .map((recipe) => `${recipe.slug}:${recipe.quality.score}`);

  assert.equal(feed.recipe_count, feed.recipes.length);
  assert.ok(feed.recipe_count >= 150, "the authored MCP discovery surface must remain complete");
  assert.equal(
    feed.categories.find((category) => category.slug === "cve")?.count,
    3,
    "only rendered historical CVEs belong in the generic recipe feed",
  );
  assert.deepEqual(gaps, [], "recipes_quality_report gaps must be empty on the local feed");
});

test("the MCP page publishes the live recipes_* tool count", () => {
  const server = fs.readFileSync(path.join(ROOT, "mcp_server.py"), "utf8");
  const page = fs.readFileSync(path.join(ROOT, "content", "mcp-servers", "_index.md"), "utf8");
  const tools = [...server.matchAll(/@mcp\.tool\(\)\s*\n(?:async )?def (recipes_[a-z0-9_]+)/gu)]
    .map((match) => match[1]);

  assert.equal(new Set(tools).size, tools.length, "MCP tool names must stay unique");
  assert.match(page, new RegExp(`defines ${tools.length} \`recipes_\\*\` tools`, "u"));
  assert.match(page, /recipes_cve_search/u);
  assert.match(page, /recipes_quality_report/u);
  assert.match(page, /recipes_playbooks_list/u);
});
