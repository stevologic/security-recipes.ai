// The checked-in schema index owns marketplace schema discovery. Consumers
// derive their inventories from it so adding, renaming, or removing a schema
// cannot silently leave the public control-plane feeds out of sync.

const fs = require("node:fs");
const path = require("node:path");

const INDEX_HREF = "/marketplace-schemas/index.json";
const INDEX_PATH = path.join(__dirname, "..", "static", "marketplace-schemas", "index.json");
const schemaIndex = JSON.parse(fs.readFileSync(INDEX_PATH, "utf8"));

const snakeCase = (value) =>
  String(value)
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();

function schemaFeedMap() {
  return Object.fromEntries([
    ["index", INDEX_HREF],
    ...(schemaIndex.schemas || []).map((schema) => [snakeCase(schema.key), schema.href]),
  ]);
}

function schemaFeedRows() {
  return [
    [
      INDEX_HREF,
      "Schema manifest",
      "Discovery list for every marketplace, browser-local, case, asset, portfolio, and routing schema URL.",
    ],
    ...(schemaIndex.schemas || []).map((schema) => [schema.href, schema.label, schema.description]),
  ];
}

module.exports = { schemaFeedMap, schemaFeedRows };
