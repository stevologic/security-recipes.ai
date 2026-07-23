"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  decodeHtmlAttributeOnce,
  hasTechArticleSchemaType,
} = require("../lib/html-content");

test("HTML attributes are decoded exactly once", () => {
  assert.equal(
    decodeHtmlAttributeOnce("&quot;safe&#39;&#x2f;&amp;"),
    '"safe\'/&',
  );
  assert.equal(decodeHtmlAttributeOnce("&amp;quot;"), "&quot;");
  assert.equal(decodeHtmlAttributeOnce("&amp;#39;"), "&#39;");
  assert.equal(decodeHtmlAttributeOnce("&amp;#x26;"), "&#x26;");
  assert.equal(decodeHtmlAttributeOnce("&#38;quot;"), "&quot;");
  assert.equal(decodeHtmlAttributeOnce("&#38;amp;"), "&amp;");
});

test("TechArticle classification accepts only the canonical schema URL", () => {
  assert.equal(hasTechArticleSchemaType("https://schema.org/TechArticle"), true);
  assert.equal(hasTechArticleSchemaType(["Article", "https://schema.org/TechArticle"]), true);
  assert.equal(
    hasTechArticleSchemaType("https://attacker.example/https://schema.org/TechArticle"),
    false,
  );
  assert.equal(hasTechArticleSchemaType("https://schema.org/TechArticle.evil.example"), false);
  assert.equal(
    hasTechArticleSchemaType(["https://schema.org/TechArticle.evil.example"]),
    false,
  );
});
