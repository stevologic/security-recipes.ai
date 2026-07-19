"use strict";

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

  return withoutIdentifier || value;
}

module.exports = {
  cveDisplayTitle,
  stripFirstH1,
};
