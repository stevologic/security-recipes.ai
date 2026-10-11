"use strict";

const { searchIndexablePublicationStats } = require("../cve-indexability");

const FIELDS = Object.freeze({
  total: (stats) => stats.total,
  stable: (stats) => stats.stableMarkdown,
  stable_markdown: (stats) => stats.stableMarkdown,
  recipe_ready_ai: (stats) => stats.recipeReadyAi,
  ai_qualified: (stats) => stats.recipeReadyAi,
});

module.exports = function searchIndexableCount(field = "total") {
  const key = String(field || "total").trim() || "total";
  const resolve = FIELDS[key];
  if (!resolve) {
    throw new Error(`Unknown search-indexable-count field: ${key}`);
  }
  return String(resolve(searchIndexablePublicationStats()));
};
