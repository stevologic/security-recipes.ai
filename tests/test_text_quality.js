"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  cleanCatalogText,
  decodeTextEntitiesOnce,
  hasHtmlEncodingArtifact,
  hasTextEncodingArtifact,
} = require("../lib/text-quality");

test("catalog cleanup repairs upstream encoding and HTML entity artifacts", () => {
  const samples = [
    ["vendor\u00e2\u0080\u0099s advisory", "vendor’s advisory"],
    ["versions 1\u00e2\u20ac\u201c3", "versions 1–3"],
    ["Intel\u00e2\u201e\u00a2 product", "Intel™ product"],
    ["men\u00c3\u00ba", "menú"],
    ["product\u00c3\u201a\u00c2 name", "product name"],
    ["application\u00ef\u00bf\u00bds cache", "application's cache"],
    ["Cisco IM &amp;P&nbsp;Service", "Cisco IM &P Service"],
  ];
  for (const [source, expected] of samples) assert.equal(cleanCatalogText(source), expected);
  const clean = "München — “already quoted” ™ 😀 Ângela";
  assert.equal(cleanCatalogText(clean), clean);
});

test("text-quality checks detect contextual UTF-8 decoding artifacts", () => {
  const artifacts = [
    "replacement \ufffd character",
    "apostrophe \u00e2\u20ac\u2122",
    "opening quote \u00e2\u20ac\u0153",
    "en dash \u00e2\u20ac\u201c",
    "em dash \u00e2\u20ac\u201d",
    "accent \u00c3\u00a9",
    "nonbreaking space \u00c2\u00a0",
    "emoji \u00f0\u0178\u02dc\u20ac",
    "replacement bytes \u00ef\u00bf\u00bd",
    "C1 control \u009d",
  ];
  for (const value of artifacts) assert.equal(hasTextEncodingArtifact(value), true, value);
});

test("text-quality checks preserve valid Unicode", () => {
  const clean = [
    "“quoted”",
    "don’t",
    "en–dash",
    "em—dash",
    "José",
    "São",
    "Ângela",
    "lone Ã and Â characters",
    "emoji 😀",
  ];
  for (const value of clean) assert.equal(hasTextEncodingArtifact(value), false, value);
});

test("HTML checks detect named, numeric, and nested encoded artifacts", () => {
  const artifacts = [
    "&acirc;&euro;&trade;",
    "&#226;&#8364;&#8482;",
    "&#xE2;&#x20AC;&#x2122;",
    "&amp;#226;&amp;#8364;&amp;#8482;",
  ];
  for (const value of artifacts) assert.equal(hasHtmlEncodingArtifact(value), true, value);
  assert.equal(hasHtmlEncodingArtifact("&ldquo;quoted&rdquo; &mdash; Jos&eacute;"), false);
  assert.equal(decodeTextEntitiesOnce("&amp;#226;"), "&#226;");
});
