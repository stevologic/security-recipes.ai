"use strict";

const TECH_ARTICLE_SCHEMA_URL = "https://schema.org/TechArticle";
const HTML_ATTRIBUTE_ENTITY = /&(?:amp|quot|#\d+|#x[0-9a-f]+);/giu;

function decodeHtmlAttributeOnce(value) {
  return String(value || "").replace(HTML_ATTRIBUTE_ENTITY, (entity) => {
    const normalized = entity.toLowerCase();
    if (normalized === "&amp;") return "&";
    if (normalized === "&quot;") return '"';

    const isHex = normalized.startsWith("&#x");
    const digits = normalized.slice(isHex ? 3 : 2, -1);
    const codePoint = Number.parseInt(digits, isHex ? 16 : 10);
    return String.fromCodePoint(codePoint);
  });
}

function hasTechArticleSchemaType(value) {
  const candidates = Array.isArray(value) ? value : [value];
  return candidates.some(
    (candidate) => typeof candidate === "string" && candidate === TECH_ARTICLE_SCHEMA_URL,
  );
}

function stripFirstH1(html) {
  return String(html || "").replace(/<h1\b[^>]*>[\s\S]*?<\/h1>\s*/i, "");
}

function cveDisplayTitle(title, cveId) {
  const value = String(title || "").trim();
  const identifier = String(cveId || "").trim();
  if (!identifier) return value;

  const escapedIdentifier = identifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const withoutIdentifier = value
    .replace(new RegExp(`^${escapedIdentifier}\\s*(?:[+\\-:—–]\\s*)?`, "i"), "")
    .trim();

  if (!withoutIdentifier) return identifier;
  return `${identifier}: ${withoutIdentifier}`;
}

module.exports = {
  cveDisplayTitle,
  decodeHtmlAttributeOnce,
  hasTechArticleSchemaType,
  stripFirstH1,
};
