// Loader for the data/ directory (Hugo's site.Data), cached per process.

const fs = require("node:fs");
const path = require("node:path");

const DATA_DIR = path.join(__dirname, "..", "data");
const cache = new Map();

function loadJson(...segments) {
  const key = segments.join("/");
  if (!cache.has(key)) {
    const file = path.join(DATA_DIR, ...segments);
    cache.set(key, JSON.parse(fs.readFileSync(file, "utf8")));
  }
  return cache.get(key);
}

function marketplace() {
  return {
    catalog: loadJson("marketplace", "catalog.json"),
    input_channels: loadJson("marketplace", "input_channels.json"),
    output_channels: loadJson("marketplace", "output_channels.json"),
    report_profiles: loadJson("marketplace", "report_profiles.json"),
    workflow_templates: loadJson("marketplace", "workflow_templates.json"),
    readiness_profiles: loadJson("marketplace", "readiness_profiles.json"),
  };
}

module.exports = { loadJson, marketplace };
