"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  generatedOutputForPathname,
  missingGeneratedInternalLinks,
} = require("../lib/site-output-path");

test("generatedOutputForPathname resolves HTML routes and direct static outputs", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "site-output-path-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const guide = path.join(root, "guide", "index.html");
  const download = path.join(root, "downloads", "remediation-checklist.pdf");
  const image = path.join(root, "images", "site-theme.webp");
  fs.mkdirSync(path.dirname(guide), { recursive: true });
  fs.mkdirSync(path.dirname(download), { recursive: true });
  fs.mkdirSync(path.dirname(image), { recursive: true });
  fs.writeFileSync(guide, "<!doctype html>");
  fs.writeFileSync(download, "PDF fixture");
  fs.writeFileSync(image, "WEBP fixture");

  assert.equal(generatedOutputForPathname(root, "/guide/"), guide);
  assert.equal(generatedOutputForPathname(root, "/guide"), guide);
  assert.equal(
    generatedOutputForPathname(root, "/downloads/remediation-checklist.pdf"),
    download,
  );
  assert.equal(generatedOutputForPathname(root, "/images/site-theme.webp"), image);
});

test("generatedOutputForPathname rejects missing, malformed, and escaping paths", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "site-output-path-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  assert.equal(generatedOutputForPathname(root, "/missing/"), "");
  assert.equal(generatedOutputForPathname(root, "/%E0%A4%A"), "");
  assert.equal(generatedOutputForPathname(root, "/%2e%2e/outside.html"), "");
});

test("missingGeneratedInternalLinks reports only missing same-origin targets", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "site-output-path-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  for (const relative of [
    path.join("guide", "index.html"),
    path.join("downloads", "remediation-checklist.pdf"),
    path.join("images", "site-theme.webp"),
  ]) {
    const output = path.join(root, relative);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, "fixture");
  }

  const html = `
    <a href="/guide/">Guide</a>
    <a href="/downloads/remediation-checklist.pdf?format=print">Download</a>
    <a href="/images/site-theme.webp">Theme image</a>
    <a href="/missing/path/#section">Missing internal page</a>
    <a href="https://example.com/missing/path/">External page</a>
  `;
  assert.deepEqual(
    missingGeneratedInternalLinks(root, "/", html),
    ["/missing/path/"],
  );
});
