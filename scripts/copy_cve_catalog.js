#!/usr/bin/env node

// Hydrate the generated CVE catalog after Eleventy finishes. Keeping this
// tree out of Eleventy's passthrough graph prevents hundreds of megabytes of
// immutable catalog data from being watched, inventoried, and copied by the
// template build. This copier accepts only a manifest-owned, integrity-checked
// regular-file tree and installs it as one bounded output subtree.

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const REPOSITORY_ROOT = path.resolve(__dirname, "..");
const DEFAULT_CATALOG_ROOT = path.join(REPOSITORY_ROOT, "static", "api", "cve-catalog");
const DEFAULT_OUTPUT_ROOT = path.join(REPOSITORY_ROOT, "public");
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_CATALOG_FILES = 4_096;
const MAX_CATALOG_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_CATALOG_FILE_BYTES = 128 * 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES = 512;

function fail(message) {
  throw new Error(`CVE catalog hydration failed: ${message}`);
}

function parseArguments(argv = process.argv.slice(2), environment = process.env) {
  let catalogRoot = String(environment.SECURITY_RECIPES_CVE_CATALOG_ROOT || "").trim();
  let outputRoot = String(environment.SITE_OUTPUT_DIR || "").trim();
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const [name, inlineValue] = argument.split("=", 2);
    if (name !== "--catalog-root" && name !== "--output") {
      fail(`unknown argument: ${argument}`);
    }
    const value = inlineValue === undefined ? argv[++index] : inlineValue;
    if (!value || !String(value).trim()) fail(`${name} requires a path`);
    if (name === "--catalog-root") catalogRoot = String(value).trim();
    else outputRoot = String(value).trim();
  }
  return {
    catalogRoot: path.resolve(catalogRoot || DEFAULT_CATALOG_ROOT),
    outputRoot: path.resolve(outputRoot || DEFAULT_OUTPUT_ROOT),
  };
}

function safeRelativePath(value, label) {
  if (
    typeof value !== "string" ||
    !value ||
    value.includes("\\") ||
    value.includes(":") ||
    value.includes("\0") ||
    Buffer.byteLength(value, "utf8") > MAX_RELATIVE_PATH_BYTES
  ) {
    fail(`${label} has an unsafe path`);
  }
  const segments = value.split("/");
  if (
    path.posix.isAbsolute(value) ||
    segments.some((segment) => !segment || segment === "." || segment === "..") ||
    path.posix.normalize(value) !== value
  ) {
    fail(`${label} has an unsafe path`);
  }
  return value;
}

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function integrityEntry(value, label, expectedPath = "") {
  const entry = requireObject(value, label);
  const relative = safeRelativePath(entry.path, label);
  if (expectedPath && relative !== expectedPath) {
    fail(`${label} must use ${expectedPath}`);
  }
  if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 1) {
    fail(`${label} has an invalid byte count`);
  }
  if (typeof entry.sha256 !== "string" || !SHA256.test(entry.sha256)) {
    fail(`${label} has an invalid SHA-256 digest`);
  }
  return { path: relative, bytes: entry.bytes, sha256: entry.sha256 };
}

function declaredCatalogFiles(manifest) {
  requireObject(manifest, "manifest");
  if (manifest.schema_version !== 2) fail("manifest schema version must be 2");

  const declared = new Map([["manifest.json", null]]);
  const add = (entry, label) => {
    if (declared.has(entry.path)) fail(`${label} duplicates ${entry.path}`);
    declared.set(entry.path, entry);
  };
  add(integrityEntry(manifest.archetypes_asset, "archetypes asset", "archetypes.json"), "archetypes asset");
  add(integrityEntry(manifest.browser_index, "browser index", "browser-index.json.gz"), "browser index");
  add(integrityEntry(manifest.runtime_summary, "runtime summary", "runtime-summary.json"), "runtime summary");
  add(integrityEntry(manifest.search_index, "search index", "search-indexable.json"), "search index");

  const completeIndex = requireObject(manifest.complete_index, "complete index");
  const indexPath = safeRelativePath(completeIndex.path, "complete index");
  if (indexPath !== "index.json") fail("complete index must use index.json");
  add({ path: indexPath }, "complete index");
  if (!Array.isArray(completeIndex.partitions) || !completeIndex.partitions.length) {
    fail("complete index must declare at least one partition");
  }
  for (const [index, value] of completeIndex.partitions.entries()) {
    add(integrityEntry(value, `complete index partition ${index + 1}`), `complete index partition ${index + 1}`);
  }

  if (!Array.isArray(manifest.shard_manifest) || !manifest.shard_manifest.length) {
    fail("manifest must declare at least one shard");
  }
  for (const [index, value] of manifest.shard_manifest.entries()) {
    add(integrityEntry(value, `shard ${index + 1}`), `shard ${index + 1}`);
  }
  if (declared.size > MAX_CATALOG_FILES) {
    fail(`manifest declares ${declared.size} files; ceiling is ${MAX_CATALOG_FILES}`);
  }
  return declared;
}

function assertRegularDirectory(root, label) {
  let stat;
  try {
    stat = fs.lstatSync(root);
  } catch (error) {
    fail(`${label} is unavailable: ${error.message}`);
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    fail(`${label} must be a real directory, not a link or special node`);
  }
}

function walkPhysicalTree(root) {
  const files = new Set();
  const directories = new Set();
  const visit = (directory) => {
    for (const name of fs.readdirSync(directory).sort((left, right) => left.localeCompare(right, "en"))) {
      const full = path.join(directory, name);
      const relative = path.relative(root, full).replace(/\\/g, "/");
      const stat = fs.lstatSync(full);
      if (stat.isSymbolicLink()) fail(`catalog contains a link: ${relative}`);
      if (stat.isDirectory()) {
        directories.add(relative);
        visit(full);
      } else if (stat.isFile()) {
        files.add(relative);
      } else {
        fail(`catalog contains a special filesystem node: ${relative}`);
      }
    }
  };
  visit(root);
  return { files, directories };
}

function validateCatalogRoot(catalogRoot) {
  const root = path.resolve(catalogRoot);
  assertRegularDirectory(root, "catalog root");
  const manifestPath = path.join(root, "manifest.json");
  const manifestStat = fs.lstatSync(manifestPath);
  if (manifestStat.isSymbolicLink() || !manifestStat.isFile()) {
    fail("manifest.json must be a regular file");
  }
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (error) {
    fail(`manifest.json is invalid JSON: ${error.message}`);
  }
  const declared = declaredCatalogFiles(manifest);
  const physical = walkPhysicalTree(root);
  const missing = [...declared.keys()].filter((relative) => !physical.files.has(relative));
  const orphaned = [...physical.files].filter((relative) => !declared.has(relative));
  if (missing.length || orphaned.length) {
    fail(
      `physical file set differs from the manifest (missing=${missing.slice(0, 10).join(",") || "none"}; ` +
        `orphaned=${orphaned.slice(0, 10).join(",") || "none"})`,
    );
  }
  const expectedDirectories = new Set();
  for (const relative of declared.keys()) {
    let parent = path.posix.dirname(relative);
    while (parent !== ".") {
      expectedDirectories.add(parent);
      parent = path.posix.dirname(parent);
    }
  }
  const orphanedDirectories = [...physical.directories].filter(
    (relative) => !expectedDirectories.has(relative),
  );
  if (orphanedDirectories.length) {
    fail(`catalog contains undeclared directories: ${orphanedDirectories.slice(0, 10).join(",")}`);
  }

  let totalBytes = 0;
  for (const [relative, metadata] of declared) {
    const file = path.join(root, ...relative.split("/"));
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink() || !stat.isFile()) fail(`${relative} is not a regular file`);
    if (stat.size > MAX_CATALOG_FILE_BYTES) {
      fail(`${relative} exceeds the ${MAX_CATALOG_FILE_BYTES.toLocaleString("en-US")}-byte file ceiling`);
    }
    totalBytes += stat.size;
    if (totalBytes > MAX_CATALOG_BYTES) {
      fail(`catalog exceeds the ${MAX_CATALOG_BYTES.toLocaleString("en-US")}-byte ceiling`);
    }
    if (!metadata?.sha256) continue;
    if (stat.size !== metadata.bytes) fail(`${relative} byte count differs from the manifest`);
    const actual = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    if (actual !== metadata.sha256) fail(`${relative} SHA-256 differs from the manifest`);
  }

  let index;
  try {
    index = JSON.parse(fs.readFileSync(path.join(root, "index.json"), "utf8"));
  } catch (error) {
    fail(`index.json is invalid JSON: ${error.message}`);
  }
  if (
    index?.schema_version !== 2 ||
    index?.catalog_updated_at !== manifest.catalog_updated_at ||
    index?.total !== manifest.complete_index.records ||
    JSON.stringify(index?.partitions) !== JSON.stringify(manifest.complete_index.partitions)
  ) {
    fail("index.json disagrees with the manifest complete-index contract");
  }
  return { root, manifest, declared, totalBytes };
}

function assertOutputRoot(outputRoot) {
  const root = path.resolve(outputRoot);
  if (root === path.parse(root).root) fail("site output root cannot be a filesystem root");
  assertRegularDirectory(root, "site output root");
  const marker = path.join(root, ".nojekyll");
  const markerStat = fs.existsSync(marker) ? fs.lstatSync(marker) : null;
  if (!markerStat || markerStat.isSymbolicLink() || !markerStat.isFile()) {
    fail("site output root is missing Eleventy's regular-file .nojekyll marker");
  }
  return root;
}

function pathContains(parent, child) {
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..");
}

function copyCatalog(catalogRoot, outputRoot) {
  const source = validateCatalogRoot(catalogRoot);
  const output = assertOutputRoot(outputRoot);
  const sourceReal = fs.realpathSync(source.root);
  const outputReal = fs.realpathSync(output);
  if (pathContains(sourceReal, outputReal) || pathContains(outputReal, sourceReal)) {
    fail("catalog source and site output roots must not overlap");
  }
  const apiRoot = path.join(output, "api");
  if (fs.existsSync(apiRoot)) assertRegularDirectory(apiRoot, "site API output root");
  else fs.mkdirSync(apiRoot);
  const destination = path.join(apiRoot, "cve-catalog");
  if (fs.existsSync(destination) && fs.realpathSync(destination) === sourceReal) {
    fail("source and destination catalog roots must differ");
  }

  const nonce = `${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const stage = path.join(apiRoot, `.cve-catalog-stage-${nonce}`);
  const backup = path.join(apiRoot, `.cve-catalog-backup-${nonce}`);
  fs.mkdirSync(stage);
  try {
    for (const relative of source.declared.keys()) {
      const from = path.join(source.root, ...relative.split("/"));
      const to = path.join(stage, ...relative.split("/"));
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.copyFileSync(from, to, fs.constants.COPYFILE_EXCL);
    }
    validateCatalogRoot(stage);

    const hadDestination = fs.existsSync(destination);
    if (hadDestination) {
      const stat = fs.lstatSync(destination);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        fail("existing catalog output must be a real directory");
      }
      fs.renameSync(destination, backup);
    }
    try {
      fs.renameSync(stage, destination);
    } catch (error) {
      if (hadDestination && fs.existsSync(backup)) fs.renameSync(backup, destination);
      throw error;
    }
    if (hadDestination) fs.rmSync(backup, { recursive: true, force: false });
  } finally {
    if (fs.existsSync(stage)) fs.rmSync(stage, { recursive: true, force: true });
    if (fs.existsSync(backup) && !fs.existsSync(destination)) fs.renameSync(backup, destination);
  }
  return {
    destination,
    files: source.declared.size,
    bytes: source.totalBytes,
    records: source.manifest?.totals?.catalog_records,
  };
}

function main() {
  const options = parseArguments();
  const result = copyCatalog(options.catalogRoot, options.outputRoot);
  console.log(
    `Hydrated ${result.files.toLocaleString("en-US")} validated CVE catalog files ` +
      `(${result.bytes.toLocaleString("en-US")} bytes, ` +
      `${Number(result.records || 0).toLocaleString("en-US")} records) into ${result.destination}.`,
  );
}

if (require.main === module) main();

module.exports = {
  MAX_CATALOG_BYTES,
  MAX_CATALOG_FILE_BYTES,
  MAX_CATALOG_FILES,
  copyCatalog,
  declaredCatalogFiles,
  parseArguments,
  safeRelativePath,
  validateCatalogRoot,
};
