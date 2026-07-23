"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const LEGACY_GLOBAL = /window\.__SECURITY_RECIPES_MARKETPLACE\b/u;

function sourceFiles(root) {
  if (!fs.existsSync(root)) return [];
  const files = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const target = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...sourceFiles(target));
    } else if (/\.(?:c?js|mjs|njk|html)$/u.test(entry.name)) {
      files.push(target);
    }
  }
  return files;
}

test("the unused marketplace payload is neither emitted nor loaded sitewide", () => {
  const headPath = path.join(ROOT, "_includes", "partials", "head-common.njk");
  const configPath = path.join(ROOT, "eleventy.config.js");
  const head = fs.readFileSync(headPath, "utf8");
  const config = fs.readFileSync(configPath, "utf8");

  assert.doesNotMatch(head, /<script[^>]+src="\/js\/marketplace-globals\.js"/u);
  assert.doesNotMatch(config, /marketplace-globals\.11ty\.js/u);
  assert.doesNotMatch(config, LEGACY_GLOBAL);

  const runtimeFiles = [
    ...sourceFiles(path.join(ROOT, "_includes")),
    ...sourceFiles(path.join(ROOT, "assets", "js")),
    ...sourceFiles(path.join(ROOT, "static", "js")),
    ...sourceFiles(path.join(ROOT, "lib")),
  ];
  const consumers = runtimeFiles
    .filter((file) => LEGACY_GLOBAL.test(fs.readFileSync(file, "utf8")))
    .map((file) => path.relative(ROOT, file));

  assert.deepEqual(consumers, [], "legacy marketplace global regained a runtime consumer");

  // The marketplace remains available through small endpoint maps and public
  // JSON feeds; only the unconsumed aggregate payload has been removed.
  assert.match(head, /window\.__SECURITY_RECIPES_MARKETPLACE_FEEDS\b/u);
  assert.match(head, /window\.__SECURITY_RECIPES_MARKETPLACE_SCHEMAS\b/u);
  assert.match(config, /marketplace-control-plane\.json/u);
});
