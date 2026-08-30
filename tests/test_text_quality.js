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

test("catalog cleanup removes Han-bearing mixed CJK runs and empty wrappers", () => {
  const samples = [
    ["Acme\u4e2d\u6587Gateway", "Acme Gateway"],
    ["alpha\u3400\u3401beta", "alpha beta"],
    ["vendor\uf900product", "vendor product"],
    ["before\ud840\udc00after", "before after"],
    ["before\ud87e\ude1fafter", "before after"],
    ["left\ud880\udc00right", "left right"],
    ["left\ud88d\udc7fright", "left right"],
    ["Acme\u3010\u4e2d\u6587\u3001\u6e2c\u8a66\u3011Gateway", "Acme Gateway"],
    ["Acme ({[ \u4e2d\u6587 ]}) Gateway", "Acme Gateway"],
    ["Web\u306e\u76f8\u8ac7\u6240 plugin", "Web plugin"],
    ["\uff08\u4e2d\u6587\uff09", ""],
    ["\u4e2d\u6587", ""],
    ["encoded &#x4e2d;&#x6587; value", "encoded value"],
  ];
  for (const [source, expected] of samples) assert.equal(cleanCatalogText(source), expected);
});

test("catalog cleanup leaves kana and empty ASCII pairs alone without Han", () => {
  const samples = [
    "\u300c\u30ab\u30bf\u30ab\u30ca\u300d",
    "\u3072\u3089\u304c\u306a",
    "\uff76\uff80\uff76\uff85",
    "Acme () [] {}",
    `left${String.fromCodePoint(0x33480)}right`,
  ];
  for (const source of samples) assert.equal(cleanCatalogText(source), source);
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
