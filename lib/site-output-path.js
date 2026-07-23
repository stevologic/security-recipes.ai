"use strict";

const fs = require("node:fs");
const path = require("node:path");

const { decodeHtmlAttributeOnce } = require("./html-content");

function generatedOutputForPathname(root, pathname) {
  if (typeof pathname !== "string" || !pathname.startsWith("/")) return "";

  let decodedPathname;
  try {
    decodedPathname = decodeURIComponent(pathname);
  } catch {
    return "";
  }
  if (decodedPathname.includes("\0")) return "";

  const resolvedRoot = path.resolve(root);
  const requested = path.resolve(resolvedRoot, decodedPathname.replace(/^\/+/, ""));
  if (requested !== resolvedRoot && !requested.startsWith(`${resolvedRoot}${path.sep}`)) {
    return "";
  }

  const candidates = decodedPathname.endsWith("/")
    ? [path.join(requested, "index.html")]
    : [requested, path.join(requested, "index.html")];
  for (const candidate of candidates) {
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // Missing and unreadable candidates are not generated site outputs.
    }
  }
  return "";
}

function missingGeneratedInternalLinks(
  root,
  sourceRoute,
  html,
  siteOrigin = "https://security-recipes.ai",
) {
  const missing = new Set();
  for (const match of String(html || "").matchAll(/<a\b[^>]*\bhref=(["'])([^"']+)\1/gi)) {
    let destination;
    try {
      destination = new URL(
        decodeHtmlAttributeOnce(match[2]),
        `${siteOrigin}${sourceRoute}`,
      );
    } catch {
      continue;
    }
    if (destination.origin !== siteOrigin) continue;
    if (!generatedOutputForPathname(root, destination.pathname)) {
      missing.add(destination.pathname);
    }
  }
  return [...missing];
}

function insecurePlainHttpLinks(html) {
  const insecure = new Set();
  const allowedLoopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);
  for (const match of String(html || "").matchAll(/<a\b[^>]*\bhref=(["'])([^"']+)\1/gi)) {
    let destination;
    try {
      destination = new URL(decodeHtmlAttributeOnce(match[2]));
    } catch {
      continue;
    }
    if (destination.protocol !== "http:") continue;
    if (allowedLoopbackHosts.has(destination.hostname)) continue;
    insecure.add(destination.href);
  }
  return [...insecure];
}

module.exports = {
  generatedOutputForPathname,
  insecurePlainHttpLinks,
  missingGeneratedInternalLinks,
};
