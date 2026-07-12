#!/usr/bin/env node

// Precompress large generated machine feeds once at build time. nginx serves
// these sidecars with gzip_static, avoiding repeated compression of the 51 MB
// complete CVE index and other JSON feeds under concurrent traffic.

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const ROOT = path.resolve(process.env.SITE_OUTPUT_DIR || "public");
const MIN_BYTES = 64 * 1024;

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

if (!fs.existsSync(ROOT)) {
  throw new Error(`site output does not exist: ${ROOT}`);
}

let sourceBytes = 0;
let compressedBytes = 0;
let count = 0;

for (const file of walk(ROOT)) {
  if (file.toLowerCase().endsWith(".gz")) continue;
  if (!/\.(?:json|xml)$/i.test(file)) continue;
  const stat = fs.statSync(file);
  if (stat.size < MIN_BYTES) continue;

  const source = fs.readFileSync(file);
  const compressed = zlib.gzipSync(source, { level: zlib.constants.Z_BEST_COMPRESSION });
  fs.writeFileSync(`${file}.gz`, compressed);
  sourceBytes += source.length;
  compressedBytes += compressed.length;
  count += 1;
}

const ratio = sourceBytes ? ((compressedBytes / sourceBytes) * 100).toFixed(1) : "0.0";
console.log(
  `Precompressed ${count} machine feeds: ${sourceBytes.toLocaleString()} -> ` +
  `${compressedBytes.toLocaleString()} bytes (${ratio}%).`,
);
