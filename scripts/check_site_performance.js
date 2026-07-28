#!/usr/bin/env node

// Deployment-shape guardrails for the large CVE catalog. These budgets have
// deliberate headroom over the measured production build: they catch an
// accidental one-page-per-catalog-record build, an uncompressed search index,
// or development drafts leaking back into generic agent/browser feeds.

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const zlib = require("node:zlib");

const { decodeHtmlAttributeOnce, hasTechArticleSchemaType } = require("../lib/html-content");
const {
  generatedOutputForPathname,
  insecurePlainHttpLinks,
  missingGeneratedInternalLinks,
} = require("../lib/site-output-path");
const { hasHtmlEncodingArtifact } = require("../lib/text-quality");

const ROOT = path.resolve(process.env.SITE_OUTPUT_DIR || "public");
const CONTENT = path.resolve("content/recipes/cve");
const PLAYBOOK_CONTENT = path.resolve("content/security-remediation");
const MiB = 1024 * 1024;
const KiB = 1024;
const failures = [];
const indexableTitles = new Map();
const indexableDescriptions = new Map();
const indexableCanonicals = new Map();
const htmlOutputs = new Map();
const indexableHtmlRoutes = new Set();
const noindexHtmlRoutes = new Set();
const GENERATED_SIMILARITY_COLLECTIONS = Object.freeze([
  {
    label: "code-hygiene recipes",
    routePattern: /^\/recipes\/general\/code-hygiene\/[^/]+\/[^/]+\/$/,
  },
  {
    label: "compliance-standard recipes",
    routePattern: /^\/recipes\/general\/compliance-standards\/[^/]+\/$/,
  },
]);
const GENERATED_SIMILARITY_SHINGLE_WORDS = 5;
const GENERATED_SIMILARITY_MIN_SHINGLES = 32;
const GENERATED_SIMILARITY_MAX_PAGES = 128;
const GENERATED_SIMILARITY_MAX_PAIRS = 8_192;
const GENERATED_SIMILARITY_MAX_REPORTS = 12;
const GENERATED_SIMILARITY_JACCARD_LIMIT = 0.5;
let maxIndexableTitleLength = 0;
let maxIndexableDescriptionLength = 0;
let maxIndexableDepth = 0;
const forbiddenSearchSpam = [
  /\b(?:NADIMTOGEL|BUGISTOTO)\b/i,
  /\bslot\s+gacor\b/i,
  /\btogel\b/i,
  /\bgampang\s+scatter\s+maxwin\b/i,
];

function fail(message) {
  failures.push(message);
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

function size(file) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full)) {
    fail(`missing required output: ${file}`);
    return 0;
  }
  return fs.statSync(full).size;
}

function budget(label, actual, maximum) {
  if (actual > maximum) {
    fail(`${label} is ${actual.toLocaleString()} bytes; budget is ${maximum.toLocaleString()}`);
  }
}

function readJson(file) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full)) {
    fail(`missing required output: ${file}`);
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(full, "utf8"));
  } catch (error) {
    fail(`invalid JSON in ${file}: ${error.message}`);
    return null;
  }
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function checkOpaquePng(file, expectedSize) {
  const output = path.join(ROOT, file);
  const source = path.resolve("static", file);
  if (!fs.existsSync(output) || !fs.existsSync(source)) {
    fail(`missing installed-app icon: ${file}`);
    return;
  }
  const png = fs.readFileSync(output);
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (png.length < 33 || !png.subarray(0, 8).equals(signature) || png.toString("ascii", 12, 16) !== "IHDR") {
    fail(`${file} is not a valid PNG with an IHDR header`);
    return;
  }
  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  const colorType = png[25];
  if (width !== expectedSize || height !== expectedSize) {
    fail(`${file} is ${width}x${height}; expected ${expectedSize}x${expectedSize}`);
  }
  if (colorType !== 2) fail(`${file} must be an opaque RGB PNG (color type 2); found ${colorType}`);
  if (sha256(source) !== sha256(output)) fail(`${file} differs between static source and site output`);
  budget(file, png.length, 256 * KiB);
}

function routeForSource(file) {
  return `/recipes/cve/${path.basename(file, ".md")}/`;
}

function canonicalRouteForCve(cve) {
  return `/cve/${cve}/`;
}

function outputForRoute(route) {
  return path.join(ROOT, route.replace(/^\//, "").replace(/\/$/, ""), "index.html");
}

function routeForOutput(file) {
  const relative = path.relative(ROOT, file).replace(/\\/g, "/");
  return `/${relative.replace(/index\.html$/, "")}`;
}

function outputRouteForPathname(pathname) {
  if (htmlOutputs.has(pathname)) return pathname;
  if (!pathname.endsWith("/") && htmlOutputs.has(`${pathname}/`)) return `${pathname}/`;
  return "";
}

const CVE_ROUTE_RE = /^\/cve\/(CVE-\d{4}-\d{4,})\/$/;
let catalogCveIds = null;

function catalogServedCveRoute(pathname) {
  const match = CVE_ROUTE_RE.exec(pathname);
  if (!match) return false;
  if (catalogCveIds === null) {
    catalogCveIds = new Set();
    try {
      const payload = JSON.parse(
        zlib
          .gunzipSync(fs.readFileSync(path.join(ROOT, "api/cve-catalog/browser-index.json.gz")))
          .toString("utf8"),
      );
      const cveField = Array.isArray(payload.fields) ? payload.fields.indexOf("cve") : -1;
      if (cveField >= 0 && Array.isArray(payload.records)) {
        for (const record of payload.records) {
          if (Array.isArray(record) && typeof record[cveField] === "string") {
            catalogCveIds.add(record[cveField]);
          }
        }
      }
    } catch (error) {
      fail(`unreadable catalog browser index for CVE link validation: ${error.message}`);
    }
  }
  return catalogCveIds.has(match[1]);
}

function checkInternalLinksAndFragments() {
  const targets = new Map();
  for (const [route, html] of htmlOutputs) {
    const ids = new Set(
      Array.from(
        html.matchAll(/\b(?:id|name)=(['"])([^'"]+)\1/gi),
        (match) => decodeHtmlAttributeOnce(match[2]),
      ),
    );
    targets.set(route, ids);
  }

  for (const [sourceRoute, html] of htmlOutputs) {
    for (const destination of insecurePlainHttpLinks(html)) {
      fail(`plain HTTP external link from ${sourceRoute} to ${destination}`);
    }
    for (const pathname of missingGeneratedInternalLinks(ROOT, sourceRoute, html)) {
      // Only a bounded subset of catalog CVEs is materialized as static
      // pages; every other catalog record still serves at /cve/<id>/ through
      // the runtime fallback, so catalog membership makes the link valid.
      if (catalogServedCveRoute(pathname)) continue;
      fail(`broken internal link from ${sourceRoute} to ${pathname}`);
    }
    for (const match of html.matchAll(/<a\b[^>]*\bhref=(['"])([^'"]+)\1/gi)) {
      let destination;
      try {
        destination = new URL(
          decodeHtmlAttributeOnce(match[2]),
          `https://security-recipes.ai${sourceRoute}`,
        );
      } catch {
        continue;
      }
      if (destination.origin !== "https://security-recipes.ai") continue;
      if (!generatedOutputForPathname(ROOT, destination.pathname)) continue;
      if (destination.hash.length <= 1) continue;
      const targetRoute = outputRouteForPathname(destination.pathname);
      if (!targetRoute) continue;
      let fragment;
      try {
        fragment = decodeURIComponent(destination.hash.slice(1));
      } catch {
        fragment = destination.hash.slice(1);
      }
      if (!targets.get(targetRoute).has(fragment)) {
        fail(`broken internal fragment from ${sourceRoute} to ${targetRoute}#${fragment}`);
      }
    }
  }
}

// Eleventy accepts functions for computed data. If one is accidentally placed
// in ordinary template data, JavaScript's source text can leak into titles,
// descriptions, canonical tags, or JSON-LD while the build still succeeds.
function hasStringifiedMetadataFunction(html) {
  const head = html.match(/<head\b[^>]*>([\s\S]*?)<\/head>/i)?.[1] || "";
  const values = [
    ...Array.from(head.matchAll(/<title\b[^>]*>([\s\S]*?)<\/title>/gi), (match) => match[1]),
    ...Array.from(
      head.matchAll(/<meta\b[^>]*\bcontent=(["'])([\s\S]*?)\1[^>]*>/gi),
      (match) => match[2],
    ),
    ...Array.from(
      head.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi),
      (match) => match[1],
    ),
  ];
  return values.some((value) => {
    const normalized = value.replace(/&gt;|&#(?:62|x3e);/gi, ">");
    return /\[object Function\]|\b(?:async\s+)?function\s*[^<(]*\([^)]*\)\s*\{|(?:\([^()<>]{0,80}\)|\b(?:data|ctx|page|item)\b)\s*=>/i.test(normalized);
  });
}

function hasBalancedSnippetDelimiters(value) {
  const stack = [];
  const closingToOpening = new Map([[')', '('], [']', '['], ['}', '{']]);
  for (const character of String(value || "")) {
    if (character === "(" || character === "[" || character === "{") {
      stack.push(character);
      continue;
    }
    const opening = closingToOpening.get(character);
    if (!opening) continue;
    if (stack.pop() !== opening) return false;
  }
  return stack.length === 0;
}

function checkIndexableHtml(relative, html) {
  if (!/<(?:!doctype\s+html|html\b)/i.test(html)) return;
  const isNoindex = /<meta\b[^>]*name=["'](?:robots|googlebot)["'][^>]*content=["'][^"']*noindex/i.test(html);
  const isRedirect = /<meta\b[^>]*http-equiv=["']refresh["']/i.test(html);
  const route = routeForOutput(path.join(ROOT, relative));
  if (isNoindex) noindexHtmlRoutes.add(route);
  if (isNoindex || isRedirect) return;
  indexableHtmlRoutes.add(route);

  const titleCount = (html.match(/<title\b/gi) || []).length;
  if (titleCount !== 1) {
    fail(`indexable HTML has ${titleCount} title elements; expected one: ${relative}`);
  }
  const title = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1].trim() || "";
  if (!title) fail(`indexable HTML has no non-empty title: ${relative}`);
  const descriptionCount = (
    html.match(/<meta\b[^>]*name=["']description["'][^>]*>/gi) || []
  ).length;
  if (descriptionCount !== 1) {
    fail(`indexable HTML has ${descriptionCount} meta descriptions; expected one: ${relative}`);
  }
  const description = html.match(
    /<meta\b[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i,
  )?.[1] || "";
  if (!description) {
    fail(`indexable HTML has no non-empty meta description: ${relative}`);
  }
  const canonicalCount = (
    html.match(/<link\b[^>]*rel=["']canonical["'][^>]*>/gi) || []
  ).length;
  if (canonicalCount !== 1) {
    fail(`indexable HTML has ${canonicalCount} canonical links; expected one: ${relative}`);
  }
  const canonical = html.match(
    /<link\b[^>]*rel=["']canonical["'][^>]*href=["'](https?:\/\/[^"']+)["']/i,
  )?.[1] || "";
  if (!canonical) {
    fail(`indexable HTML has no absolute canonical link: ${relative}`);
  }
  const ogImage = decodeHtmlAttributeOnce(
    html.match(/<meta\b[^>]*property=["']og:image["'][^>]*content=["']([^"']+)["']/i)?.[1] || "",
  );
  const twitterImage = decodeHtmlAttributeOnce(
    html.match(/<meta\b[^>]*name=["']twitter:image["'][^>]*content=["']([^"']+)["']/i)?.[1] || "",
  );
  const ogImageType = html.match(
    /<meta\b[^>]*property=["']og:image:type["'][^>]*content=["']([^"']+)["']/i,
  )?.[1] || "";
  const ogImageWidth = Number.parseInt(html.match(
    /<meta\b[^>]*property=["']og:image:width["'][^>]*content=["'](\d+)["']/i,
  )?.[1] || "", 10);
  const ogImageHeight = Number.parseInt(html.match(
    /<meta\b[^>]*property=["']og:image:height["'][^>]*content=["'](\d+)["']/i,
  )?.[1] || "", 10);
  if (!ogImage || !/\.(?:png|jpe?g|webp)(?:[?#]|$)/iu.test(ogImage)) {
    fail(`indexable HTML has no raster Open Graph image: ${relative}`);
  }
  if (!twitterImage || twitterImage !== ogImage) {
    fail(`indexable HTML does not keep Twitter and Open Graph images aligned: ${relative}`);
  }
  if (!/^image\/(?:png|jpeg|webp)$/iu.test(ogImageType)) {
    fail(`indexable HTML has an unsupported social image type: ${relative}`);
  }
  if (!Number.isSafeInteger(ogImageWidth) || !Number.isSafeInteger(ogImageHeight)) {
    fail(`indexable HTML has no numeric social image dimensions: ${relative}`);
  }
  if (ogImage) {
    try {
      const imageUrl = new URL(ogImage);
      if (imageUrl.origin === "https://security-recipes.ai") {
        const imagePath = path.resolve(
          ROOT,
          decodeURIComponent(imageUrl.pathname).replace(/^\/+/, ""),
        );
        if (!imagePath.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(imagePath)) {
          fail(`indexable HTML references a missing local social image: ${relative}`);
        } else if (imageUrl.pathname.toLowerCase().endsWith(".png")) {
          const png = fs.readFileSync(imagePath);
          const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
          if (
            png.length < 24 ||
            !png.subarray(0, 8).equals(signature) ||
            png.toString("ascii", 12, 16) !== "IHDR"
          ) {
            fail(`indexable HTML references an invalid PNG social image: ${relative}`);
          } else if (
            png.readUInt32BE(16) !== ogImageWidth ||
            png.readUInt32BE(20) !== ogImageHeight
          ) {
            fail(`indexable HTML social image dimensions do not match the PNG: ${relative}`);
          }
        }
      }
    } catch {
      fail(`indexable HTML has an invalid Open Graph image URL: ${relative}`);
    }
  }
  const decodedTitle = decodeHtmlAttributeOnce(title);
  const decodedDescription = decodeHtmlAttributeOnce(description);
  maxIndexableTitleLength = Math.max(maxIndexableTitleLength, decodedTitle.length);
  maxIndexableDescriptionLength = Math.max(
    maxIndexableDescriptionLength,
    decodedDescription.length,
  );
  if (decodedTitle.length > 70) {
    fail(`indexable title exceeds the 70-character search-result budget: ${relative}`);
  }
  if (/ \| Security Recipes$/u.test(decodedTitle) && decodedTitle.length > 65) {
    fail(`branded indexable title exceeds the 65-character search-result budget: ${relative}`);
  }
  if (decodedDescription.length > 165) {
    fail(`indexable meta description exceeds the 165-character search-result budget: ${relative}`);
  }
  for (const [label, value] of [
    ["title", decodedTitle],
    ["meta description", decodedDescription],
  ]) {
    if (/\u2026|&(?:hellip|#8230|#x2026);/iu.test(value)) {
      fail(`indexable ${label} contains an artificial ellipsis: ${relative}`);
    }
    if (/`|\[[^\]]+\]\(/u.test(value)) {
      fail(`indexable ${label} exposes Markdown presentation syntax: ${relative}`);
    }
  }
  if (decodedDescription.length >= 170 && !/[.!?]$/u.test(decodedDescription)) {
    fail(`long indexable meta description ends mid-thought: ${relative}`);
  }
  if (/(?:[,;:]\s*$|(?:[,;:]|\(|\[|\{)\s*[.!?]$)/u.test(decodedDescription)) {
    fail(`indexable meta description has dangling punctuation: ${relative}`);
  }
  if (!hasBalancedSnippetDelimiters(decodedDescription)) {
    fail(`indexable meta description has unbalanced delimiters: ${relative}`);
  }
  if (/\breviewers,\s+and\s+reviewers\b/iu.test(decodedDescription)) {
    fail(`indexable meta description repeats its reviewer audience: ${relative}`);
  }
  if (/\[[^\]\n]{1,240}\]\(<a\b/iu.test(html)) {
    fail(`indexable HTML exposes a malformed Markdown destination: ${relative}`);
  }
  if (/\bhref=["']http:\/\/(?:www\.)?security-recipes\.ai(?:[\/"'])/iu.test(html)) {
    fail(`indexable HTML links to the canonical site over plain HTTP: ${relative}`);
  }
  for (const [value, index] of [
    [title, indexableTitles],
    [description, indexableDescriptions],
    [canonical, indexableCanonicals],
  ]) {
    if (!value) continue;
    if (!index.has(value)) index.set(value, []);
    index.get(value).push(relative);
  }

  const h1Count = (html.match(/<h1\b/gi) || []).length;
  if (h1Count !== 1) {
    fail(`indexable HTML has ${h1Count} H1 elements; expected one: ${relative}`);
  }
  for (const image of html.matchAll(/<img\b[^>]*>/gi)) {
    if (!/\bwidth=["']\d+["']/i.test(image[0]) || !/\bheight=["']\d+["']/i.test(image[0])) {
      fail(`indexable HTML image has no intrinsic width and height: ${relative}`);
    }
  }

  const structured = Array.from(
    html.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi),
    (match) => match[1],
  );
  if (!structured.length) {
    fail(`indexable HTML has no JSON-LD: ${relative}`);
  }
  const structuredEntities = [];
  for (const document of structured) {
    try {
      const parsed = JSON.parse(document);
      if (Array.isArray(parsed?.["@graph"])) structuredEntities.push(...parsed["@graph"]);
      else if (parsed && typeof parsed === "object") structuredEntities.push(parsed);
    } catch (error) {
      fail(`indexable HTML has invalid JSON-LD (${error.message}): ${relative}`);
    }
  }

  const hasType = (entity, type) => {
    const values = Array.isArray(entity?.["@type"]) ? entity["@type"] : [entity?.["@type"]];
    return values.includes(type);
  };
  const articleEntities = structuredEntities.filter((entity) => hasType(entity, "Article"));
  const webPageEntities = structuredEntities.filter((entity) => hasType(entity, "WebPage"));
  const hasCollectionPage = structuredEntities.some((entity) => hasType(entity, "CollectionPage"));
  const hasWebPage = structuredEntities.some((entity) => hasType(entity, "WebPage"));
  const ogType = html.match(
    /<meta\b[^>]*property=["']og:type["'][^>]*content=["']([^"']+)["']/i,
  )?.[1] || "";
  const hasVisibleProvenance = /<aside\b[^>]*aria-label=["']Authorship and review["']/i.test(html);

  if (ogType === "article") {
    if (articleEntities.length !== 1) {
      fail(`indexable article has ${articleEntities.length} Article entities; expected one: ${relative}`);
    }
    if (
      !articleEntities.some((entity) => {
        return hasTechArticleSchemaType(entity.additionalType);
      })
    ) {
      fail(`indexable article has no TechArticle classification: ${relative}`);
    }
    if (!hasVisibleProvenance) {
      fail(`indexable article has no visible authorship and review provenance: ${relative}`);
    }
    const article = articleEntities[0] || {};
    const webPage = webPageEntities[0] || {};
    const publishedMeta = html.match(
      /<meta\b[^>]*property=["']article:published_time["'][^>]*content=["']([^"']+)["']/i,
    )?.[1] || "";
    const modifiedMeta = html.match(
      /<meta\b[^>]*property=["']article:modified_time["'][^>]*content=["']([^"']+)["']/i,
    )?.[1] || "";
    const visiblePublished = html.match(
      /Published\s*<time\b[^>]*datetime=["']([^"']+)["']/i,
    )?.[1] || "";
    const visibleModified = html.match(
      /Last updated\s*<time\b[^>]*datetime=["']([^"']+)["']/i,
    )?.[1] || "";
    if (!article.datePublished || !article.dateModified) {
      fail(`indexable article has incomplete structured publication dates: ${relative}`);
    }
    if (
      webPage.datePublished !== article.datePublished ||
      webPage.dateModified !== article.dateModified
    ) {
      fail(`indexable article WebPage dates do not match its Article dates: ${relative}`);
    }
    if (
      publishedMeta !== article.datePublished ||
      modifiedMeta !== article.dateModified
    ) {
      fail(`indexable article Open Graph dates do not match structured data: ${relative}`);
    }
    if (
      visiblePublished !== article.datePublished ||
      visibleModified !== article.dateModified
    ) {
      fail(`indexable article visible dates do not match structured data: ${relative}`);
    }
    if (hasCollectionPage) {
      fail(`indexable article also declares CollectionPage semantics: ${relative}`);
    }
  } else if (ogType === "website") {
    if (articleEntities.length) {
      fail(`indexable non-article declares Article structured data: ${relative}`);
    }
    if (!hasCollectionPage && !hasWebPage) {
      fail(`indexable non-article has no WebPage or CollectionPage entity: ${relative}`);
    }
    if (hasVisibleProvenance) {
      fail(`indexable non-article exposes article-only authorship provenance: ${relative}`);
    }
  } else {
    fail(`indexable HTML has unsupported or missing Open Graph type: ${relative}`);
  }
}

function checkIndexableLinksToNoindexTags() {
  for (const sourceRoute of indexableHtmlRoutes) {
    const html = htmlOutputs.get(sourceRoute) || "";
    for (const match of html.matchAll(/<a\b[^>]*\bhref=(["'])([^"']+)\1/gi)) {
      let destination;
      try {
        destination = new URL(
          decodeHtmlAttributeOnce(match[2]),
          `https://security-recipes.ai${sourceRoute}`,
        );
      } catch {
        continue;
      }
      if (destination.origin !== "https://security-recipes.ai") continue;
      const targetRoute = outputRouteForPathname(destination.pathname);
      if (
        targetRoute.startsWith("/tags/") &&
        noindexHtmlRoutes.has(targetRoute)
      ) {
        fail(`indexable page ${sourceRoute} links to noindex taxonomy ${targetRoute}`);
      }
    }
  }
}

function checkIndexableLinkGraph() {
  const inbound = new Map([...indexableHtmlRoutes].map((route) => [route, new Set()]));
  const outbound = new Map([...indexableHtmlRoutes].map((route) => [route, new Set()]));
  for (const sourceRoute of indexableHtmlRoutes) {
    const html = htmlOutputs.get(sourceRoute) || "";
    for (const match of html.matchAll(/<a\b[^>]*\bhref=(["'])([^"']+)\1/gi)) {
      let destination;
      try {
        destination = new URL(
          decodeHtmlAttributeOnce(match[2]),
          `https://security-recipes.ai${sourceRoute}`,
        );
      } catch {
        continue;
      }
      if (destination.origin !== "https://security-recipes.ai") continue;
      const targetRoute = outputRouteForPathname(destination.pathname);
      if (
        targetRoute &&
        targetRoute !== sourceRoute &&
        indexableHtmlRoutes.has(targetRoute)
      ) {
        inbound.get(targetRoute).add(sourceRoute);
        outbound.get(sourceRoute).add(targetRoute);
      }
    }
  }
  for (const [route, sources] of inbound) {
    if (route !== "/" && sources.size === 0) {
      fail(`indexable HTML is orphaned from every other indexable page: ${route}`);
    }
  }

  if (!indexableHtmlRoutes.has("/")) {
    fail("the homepage is not an indexable root for the internal-link graph");
    return;
  }
  const depths = new Map([["/", 0]]);
  const queue = ["/"];
  for (let index = 0; index < queue.length; index += 1) {
    const sourceRoute = queue[index];
    const nextDepth = depths.get(sourceRoute) + 1;
    for (const targetRoute of outbound.get(sourceRoute) || []) {
      if (depths.has(targetRoute)) continue;
      depths.set(targetRoute, nextDepth);
      queue.push(targetRoute);
    }
  }
  for (const route of indexableHtmlRoutes) {
    const depth = depths.get(route);
    if (!Number.isSafeInteger(depth)) {
      fail(`indexable HTML is unreachable from the homepage: ${route}`);
    } else if (depth > 3) {
      fail(`indexable HTML exceeds the three-click crawl-depth budget (${depth}): ${route}`);
    } else {
      maxIndexableDepth = Math.max(maxIndexableDepth, depth);
    }
  }
}

function renderedBodyText(html) {
  const main = html.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i)?.[1] || html;
  const content =
    main.match(
      /<div\b[^>]*class=["'][^"']*\bcontent\b[^"']*["'][^>]*>([\s\S]*?)<\/div>\s*(?=<aside\b[^>]*aria-label=["']Authorship and review["'])/i,
    )?.[1] || main;
  return decodeHtmlAttributeOnce(
    content
      .replace(/<script\b[\s\S]*?<\/script(?:\s[^>]*)?>/gi, " ")
      .replace(/<style\b[\s\S]*?<\/style(?:\s[^>]*)?>/gi, " ")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/&(?:apos|lt|gt|nbsp);/gi, " ")
    .replace(/\s+/gu, " ")
    .trim()
    .toLowerCase();
}

function wordShingles(text, size = GENERATED_SIMILARITY_SHINGLE_WORDS) {
  const words = text.match(/[\p{L}\p{N}][\p{L}\p{N}'’-]*/gu) || [];
  const shingles = new Set();
  for (let index = 0; index + size <= words.length; index += 1) {
    shingles.add(words.slice(index, index + size).join(" "));
  }
  return shingles;
}

function jaccardSimilarity(left, right) {
  if (left.size === 0 && right.size === 0) return 0;
  const smaller = left.size <= right.size ? left : right;
  const larger = smaller === left ? right : left;
  let intersection = 0;
  for (const value of smaller) {
    if (larger.has(value)) intersection += 1;
  }
  return intersection / (left.size + right.size - intersection);
}

function checkGeneratedSimilarityIndexability() {
  for (const collection of GENERATED_SIMILARITY_COLLECTIONS) {
    const pages = [...htmlOutputs.entries()]
      .filter(([route]) => collection.routePattern.test(route))
      .sort(([left], [right]) => left.localeCompare(right, "en"))
      .map(([route, html]) => ({
        route,
        shingles: wordShingles(renderedBodyText(html)),
      }));
    if (pages.length > GENERATED_SIMILARITY_MAX_PAGES) {
      fail(
        `${collection.label} similarity gate exceeds its bounded page budget ` +
          `(${pages.length} > ${GENERATED_SIMILARITY_MAX_PAGES})`,
      );
      continue;
    }
    const pairCount = (pages.length * (pages.length - 1)) / 2;
    if (pairCount > GENERATED_SIMILARITY_MAX_PAIRS) {
      fail(
        `${collection.label} similarity gate exceeds its bounded pair budget ` +
          `(${pairCount} > ${GENERATED_SIMILARITY_MAX_PAIRS})`,
      );
      continue;
    }

    for (const page of pages) {
      if (
        indexableHtmlRoutes.has(page.route) &&
        page.shingles.size < GENERATED_SIMILARITY_MIN_SHINGLES
      ) {
        fail(
          `${collection.label} leaves an indexable page with too little rendered body text ` +
            `for the similarity gate (${page.shingles.size} shingles): ${page.route}`,
        );
      }
    }

    let similarIndexablePairs = 0;
    for (let leftIndex = 0; leftIndex < pages.length; leftIndex += 1) {
      const left = pages[leftIndex];
      for (let rightIndex = leftIndex + 1; rightIndex < pages.length; rightIndex += 1) {
        const right = pages[rightIndex];
        if (
          !indexableHtmlRoutes.has(left.route) &&
          !indexableHtmlRoutes.has(right.route)
        ) {
          continue;
        }
        const similarity = jaccardSimilarity(left.shingles, right.shingles);
        if (similarity < GENERATED_SIMILARITY_JACCARD_LIMIT) continue;
        similarIndexablePairs += 1;
        if (similarIndexablePairs <= GENERATED_SIMILARITY_MAX_REPORTS) {
          fail(
            `${collection.label} leaves a materially duplicated generated page indexable ` +
              `(${similarity.toFixed(3)} five-word-shingle Jaccard): ` +
              `${left.route}, ${right.route}`,
          );
        }
      }
    }
    if (similarIndexablePairs > GENERATED_SIMILARITY_MAX_REPORTS) {
      fail(
        `${collection.label} has ${similarIndexablePairs - GENERATED_SIMILARITY_MAX_REPORTS} ` +
          "additional materially duplicated pairs involving an indexable page",
      );
    }
  }
}

if (!fs.existsSync(ROOT)) throw new Error(`site output does not exist: ${ROOT}`);
if (!fs.existsSync(CONTENT)) throw new Error(`CVE content does not exist: ${CONTENT}`);

const files = walk(ROOT);
const retiredNamespace = new RegExp(["prompt", "library"].join("[-_ ]?"), "i");
const generatedTextExtensions = new Set([
  ".css", ".html", ".js", ".json", ".map", ".md", ".svg", ".txt", ".webmanifest", ".xml",
]);
for (const file of files) {
  const relative = path.relative(ROOT, file).replace(/\\/g, "/");
  if (retiredNamespace.test(relative)) {
    fail(`retired recipe namespace remains in output path: ${relative}`);
  }
  if (generatedTextExtensions.has(path.extname(file).toLowerCase())) {
    const content = fs.readFileSync(file, "utf8");
    for (const pattern of forbiddenSearchSpam) {
      const match = content.match(pattern);
      if (match) {
        fail(`known search-spam signature ${JSON.stringify(match[0])} in ${relative}`);
      }
    }
    if (retiredNamespace.test(content)) {
      fail(`retired recipe namespace remains in generated text: ${relative}`);
    }
    if (path.extname(file).toLowerCase() === ".html" && hasStringifiedMetadataFunction(content)) {
      fail(`generated metadata stringifies a JavaScript function: ${relative}`);
    }
    if (path.extname(file).toLowerCase() === ".html") {
      htmlOutputs.set(routeForOutput(file), content);
      if (/SRFENCE\d+/u.test(content)) {
        fail(`generated HTML leaks a masked shortcode sentinel: ${relative}`);
      }
      if (hasHtmlEncodingArtifact(content)) {
        fail(`generated HTML contains a source-encoding replacement artifact: ${relative}`);
      }
      checkIndexableHtml(relative, content);
    }
  }
}
checkInternalLinksAndFragments();
checkIndexableLinksToNoindexTags();
checkIndexableLinkGraph();
checkGeneratedSimilarityIndexability();
for (const file of files.filter((candidate) => candidate.endsWith("index.xml"))) {
  const relative = path.relative(ROOT, file).replace(/\\/g, "/");
  const xml = fs.readFileSync(file, "utf8");
  if (/<rss\b/i.test(xml) && !/<item>/i.test(xml)) {
    fail(`generated RSS feed has no items: ${relative}`);
  }
}
for (const [sourceRoute, html] of htmlOutputs) {
  for (const match of html.matchAll(
    /<link\b[^>]*rel=["']alternate["'][^>]*type=["']application\/rss\+xml["'][^>]*href=["']([^"']+)["']/gi,
  )) {
    let destination;
    try {
      destination = new URL(
        decodeHtmlAttributeOnce(match[1]),
        `https://security-recipes.ai${sourceRoute}`,
      );
    } catch {
      fail(`invalid RSS alternate on ${sourceRoute}: ${match[1]}`);
      continue;
    }
    if (destination.origin !== "https://security-recipes.ai") continue;
    const output = path.join(ROOT, destination.pathname.replace(/^\//, ""));
    if (!fs.existsSync(output)) {
      fail(`RSS alternate on ${sourceRoute} has no generated feed: ${destination.pathname}`);
      continue;
    }
    if (!/<item>/i.test(fs.readFileSync(output, "utf8"))) {
      fail(`RSS alternate on ${sourceRoute} points to an empty feed: ${destination.pathname}`);
    }
  }
}
for (const [label, index] of [
  ["title", indexableTitles],
  ["meta description", indexableDescriptions],
  ["canonical URL", indexableCanonicals],
]) {
  for (const [value, routes] of index) {
    if (routes.length > 1) {
      fail(`duplicate indexable ${label} across ${routes.join(", ")}: ${value}`);
    }
  }
}
// This is deployed disk/image size and intentionally includes precompressed
// sidecars. Logical feed checks below parse only canonical, uncompressed URLs.
const totalBytes = files.reduce((sum, file) => sum + fs.statSync(file).size, 0);
const cveHtml = files.filter((file) =>
  file.startsWith(path.join(ROOT, "recipes", "cve") + path.sep) && file.endsWith("index.html"),
);
const cveHtmlBytes = cveHtml.reduce((sum, file) => sum + fs.statSync(file).size, 0);
const cveArchiveHtml = files.filter((file) =>
  file.startsWith(path.join(ROOT, "cve", "archive") + path.sep) && file.endsWith("index.html"),
);
const cveArchiveHtmlBytes = cveArchiveHtml.reduce(
  (sum, file) => sum + fs.statSync(file).size,
  0,
);
const generatedTagHtml = files.filter((file) => {
  if (!file.startsWith(path.join(ROOT, "tags") + path.sep) || !file.endsWith("index.html")) {
    return false;
  }
  return path.relative(path.join(ROOT, "tags"), file) !== "index.html";
});
const largestCveArchiveHtml = cveArchiveHtml.reduce(
  (largest, file) => Math.max(largest, fs.statSync(file).size),
  0,
);

budget("site output", totalBytes, 320 * MiB);
if (files.length > 3000) fail(`site output has ${files.length.toLocaleString()} files; budget is 3,000`);
if (cveHtml.length > 25) {
  fail(`legacy CVE Markdown HTML has ${cveHtml.length.toLocaleString()} files; budget is 25`);
}
budget("legacy CVE Markdown HTML", cveHtmlBytes, 5 * MiB);
if (cveArchiveHtml.length > 750) {
  fail(`CVE archive has ${cveArchiveHtml.length.toLocaleString()} HTML pages; budget is 750`);
}
budget("CVE archive HTML", cveArchiveHtmlBytes, 120 * MiB);
budget("largest CVE archive page", largestCveArchiveHtml, 512 * KiB);
budget("CVE browser index", size("api/cve-catalog/browser-index.json.gz"), 8 * MiB);
budget("CVE complete index manifest", size("api/cve-catalog/index.json"), 1 * MiB);
budget("CVE runtime summary", size("api/cve-catalog/runtime-summary.json"), 8 * KiB);
budget("CVE manifest", size("api/cve-catalog/manifest.json"), 256 * KiB);
budget("CVE remediation archetypes", size("api/cve-catalog/archetypes.json"), 1 * MiB);
budget("CVE Database HTML", size("cve-database/index.html"), 512 * KiB);
budget("recipe library HTML", size("recipes/index.html"), 128 * KiB);
budget("marketplace gallery HTML", size("docs/marketplace-gallery/index.html"), 160 * KiB);
budget("recipe library JavaScript", size("js/recipe-browser.js"), 160 * KiB);
budget("recipe library styles", size("css/recipe-library.css"), 160 * KiB);
budget("CVE detail styles", size("css/cve-detail.css"), 32 * KiB);
budget("playbook workflow styles", size("css/playbook-workflows.css"), 32 * KiB);
budget("generic docs search index", size("recipes-index.json"), 2 * MiB);
budget("curated recipe browser feed", size("recipes-browser.json"), 2 * MiB);
budget("curated rich agent feed", size("api/curated-recipes.json"), 8 * MiB);
budget("generic rich agent feed", size("api/recipes.json"), 8 * MiB);
budget("generic MCP recipe feed", size("api/recipes-index.json"), 6 * MiB);
if (generatedTagHtml.length) {
  fail(
    `site emits ${generatedTagHtml.length.toLocaleString()} generated noindex tag detail pages; expected none`,
  );
}

const marketplaceGalleryPath = path.join(ROOT, "docs", "marketplace-gallery", "index.html");
if (fs.existsSync(marketplaceGalleryPath)) {
  const marketplaceGallery = fs.readFileSync(marketplaceGalleryPath, "utf8");
  const marketplaceElements = (marketplaceGallery.match(/<[a-z][^>]*>/gi) || []).length;
  if (marketplaceElements > 4000) {
    fail(
      `marketplace gallery renders ${marketplaceElements.toLocaleString()} elements; budget is 4,000`,
    );
  }
}

const manifest = readJson("site.webmanifest");
if (manifest) {
  if (manifest.id !== "/" || manifest.start_url !== "/" || manifest.scope !== "/") {
    fail("site.webmanifest must keep installed navigation within the site root");
  }
  if (manifest.display !== "standalone") fail("site.webmanifest display must be standalone");
  if (manifest.background_color !== "#000000" || manifest.theme_color !== "#000000") {
    fail("site.webmanifest launch and theme surfaces must be black");
  }
  const manifestIcons = new Map((manifest.icons || []).map((icon) => [icon.src, icon]));
  for (const [src, sizes, purpose] of [
    ["/icon-192x192.png", "192x192", "any"],
    ["/icon-512x512.png", "512x512", "any"],
    ["/icon-maskable-512x512.png", "512x512", "maskable"],
  ]) {
    const icon = manifestIcons.get(src);
    if (!icon || icon.sizes !== sizes || icon.type !== "image/png" || icon.purpose !== purpose) {
      fail(`site.webmanifest is missing the ${sizes} ${purpose} icon contract`);
    }
  }
}

for (const [file, expectedSize] of [
  ["apple-touch-icon.png", 180],
  ["apple-touch-icon-180x180.png", 180],
  ["icon-192x192.png", 192],
  ["icon-512x512.png", 512],
  ["icon-maskable-512x512.png", 512],
]) {
  checkOpaquePng(file, expectedSize);
}

for (const file of ["index.html", "recipes/index.html", "cve-database/index.html"]) {
  const htmlPath = path.join(ROOT, file);
  if (!fs.existsSync(htmlPath)) {
    fail(`missing installable page output: ${file}`);
    continue;
  }
  const html = fs.readFileSync(htmlPath, "utf8");
  if (!html.includes('name="apple-mobile-web-app-capable" content="yes"')) {
    fail(`${file} does not enable Apple installed-app mode`);
  }
  const statusBarTags = html.match(/<meta name="apple-mobile-web-app-status-bar-style" content="black">/g) || [];
  if (statusBarTags.length !== 1) {
    fail(`${file} must request exactly one opaque black Apple status bar`);
  }
  const themeTags = html.match(/<meta name="theme-color"[^>]*>/g) || [];
  if (themeTags.length !== 1 || themeTags[0] !== '<meta name="theme-color" content="#000000">') {
    fail(`${file} must expose exactly one black HTML theme color`);
  }
  if (html.includes("black-translucent") || /name="theme-color"[^>]+content="#fff(?:fff)?"/i.test(html)) {
    fail(`${file} contains a white or translucent installed-app status surface`);
  }
  if (!html.includes('rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon-180x180.png"')) {
    fail(`${file} does not advertise the versioned 180x180 Apple touch icon`);
  }
  if (!html.includes('rel="manifest" href="/site.webmanifest"')) {
    fail(`${file} does not advertise site.webmanifest`);
  }
  if (!html.includes("manifest-src 'self'")) fail(`${file} CSP does not permit its own manifest`);
  if (html.includes("manifest-src 'none'")) fail(`${file} CSP still blocks installed-app manifests`);
}

const playbookSources = fs.readdirSync(PLAYBOOK_CONTENT, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .filter((slug) => fs.existsSync(path.join(PLAYBOOK_CONTENT, slug, "_index.md")))
  .sort();
if (playbookSources.length !== 75) {
  fail(`playbook source count is ${playbookSources.length}; expected 75`);
}

let playbookHtmlBytes = 0;
let largestPlaybookHtml = 0;
for (const slug of playbookSources) {
  const output = path.join(ROOT, "security-remediation", slug, "index.html");
  if (!fs.existsSync(output)) {
    fail(`missing playbook output: security-remediation/${slug}/index.html`);
    continue;
  }
  const bytes = fs.statSync(output).size;
  playbookHtmlBytes += bytes;
  largestPlaybookHtml = Math.max(largestPlaybookHtml, bytes);
  const html = fs.readFileSync(output, "utf8");
  const workflowCount = (html.match(/\bdata-playbook-workflow(?:\s|>)/g) || []).length;
  if (workflowCount !== 1) {
    fail(`${slug} renders ${workflowCount} playbook workflow components; expected exactly one`);
  }
  const mainStart = html.indexOf('<main id="content"');
  const mainEnd = html.indexOf("</main>", mainStart);
  const workflowAt = html.indexOf("data-playbook-workflow", mainStart);
  if (mainStart < 0 || mainEnd < 0 || workflowAt < mainStart || workflowAt > mainEnd) {
    fail(`${slug} does not render its workflow inside the main document`);
  } else if ((workflowAt - mainStart) / Math.max(1, mainEnd - mainStart) > 0.6) {
    fail(`${slug} places its workflow below the first 60% of the main document`);
  }
  if (!html.includes("sr-playbook-python")) {
    fail(`${slug} is missing the Python companion inside its workflow`);
  }
}
budget("playbook HTML", playbookHtmlBytes, 10 * MiB);
budget("largest playbook HTML", largestPlaybookHtml, 160 * KiB);

const shards = files.filter((file) => file.includes(`${path.sep}api${path.sep}cve-catalog${path.sep}shards${path.sep}`));
const largestShard = shards.reduce((largest, file) => Math.max(largest, fs.statSync(file).size), 0);
budget("largest compressed CVE shard", largestShard, 1 * MiB);

const cveIndexPartitions = files.filter((file) =>
  file.includes(`${path.sep}api${path.sep}cve-catalog${path.sep}indexes${path.sep}`) && file.endsWith(".json.gz"),
);
const cveIndexPartitionBytes = cveIndexPartitions.reduce((sum, file) => sum + fs.statSync(file).size, 0);
const largestCveIndexPartition = cveIndexPartitions.reduce(
  (largest, file) => Math.max(largest, fs.statSync(file).size),
  0,
);
if (cveIndexPartitions.length > 12) {
  fail(`CVE complete index has ${cveIndexPartitions.length} partitions; budget is 12 rolling-window years`);
}
budget("CVE complete index partitions", cveIndexPartitionBytes, 24 * MiB);
budget("largest CVE complete index partition", largestCveIndexPartition, 4 * MiB);

for (const feed of [
  "recipes-index.json",
  "recipes-browser.json",
  "api/curated-recipes.json",
  "api/recipes.json",
  "api/recipes-index.json",
  "api/cve-catalog/index.json",
  "sitemap.xml",
]) {
  const raw = size(feed);
  if (raw >= 64 * KiB) {
    const zipped = size(`${feed}.gz`);
    if (zipped && zipped >= raw * 0.5) fail(`${feed}.gz does not reduce its source by at least 50%`);
  }
}

const cveSources = fs.readdirSync(CONTENT)
  .filter((name) => name.endsWith(".md") && name !== "_index.md")
  .map((name) => path.join(CONTENT, name));
const stableOverrides = [];
const draftOverrides = [];
for (const file of cveSources) {
  const source = fs.readFileSync(file, "utf8");
  const frontmatter = source.startsWith("---") ? source.slice(3, source.indexOf("---", 3)) : "";
  const match = frontmatter.match(/^maturity:\s*["']?([^"'\r\n]+)["']?\s*$/im);
  const legacyRoute = routeForSource(file);
  const cve = String(
    frontmatter.match(/^cve:\s*["']?(CVE-\d{4}-\d{4,7})["']?\s*$/im)?.[1] || ""
  ).toUpperCase();
  const canonicalCveRoute = !/^canonical_cve_route:\s*false\s*$/im.test(frontmatter);
  const override = {
    sourceFile: path.relative(path.resolve("content"), file).replace(/\\/g, "/"),
    legacyRoute,
    cve,
    canonicalCveRoute,
    expectedRoute: canonicalCveRoute && cve ? canonicalRouteForCve(cve) : legacyRoute,
  };
  if (String(match?.[1] || "").trim().toLowerCase() === "stable") {
    stableOverrides.push(override);
  } else {
    draftOverrides.push(override);
  }
}
if (!stableOverrides.length) fail("no stable CVE Markdown overrides were found");
if (!draftOverrides.length) fail("no development CVE Markdown drafts were found");

const canonicalStableOverrides = stableOverrides.filter((override) => override.canonicalCveRoute);
const historicalStableOverrides = stableOverrides.filter((override) => !override.canonicalCveRoute);
const stableRoutes = new Set(stableOverrides.map((override) => override.expectedRoute));
const developmentRoutes = new Set(draftOverrides.map((override) => override.legacyRoute));

// Canonicalized reviewed records and drafts are runtime/catalog concerns; their
// old Markdown slugs must not consume static files or become crawl targets.
for (const override of [...canonicalStableOverrides, ...draftOverrides]) {
  const output = outputForRoute(override.legacyRoute);
  if (fs.existsSync(output)) {
    fail(`superseded CVE Markdown URL was rendered: ${override.legacyRoute}`);
  }
}

// A small set of historical reviewed recipes explicitly opts out of the
// runtime catalog route. Those remain complete, indexable static documents.
for (const override of historicalStableOverrides) {
  const { legacyRoute: route } = override;
  const output = outputForRoute(route);
  if (!fs.existsSync(output)) {
    fail(`missing historical stable CVE detail page: ${route}`);
    continue;
  }
  const html = fs.readFileSync(output, "utf8");
  const h1Count = (html.match(/<h1\b/g) || []).length;
  if (h1Count !== 1) fail(`historical CVE detail ${route} renders ${h1Count} H1 elements; expected one`);
  if (!html.includes('data-cve-detail-page="true"') || !html.includes("/css/cve-detail.css")) {
    fail(`historical CVE detail ${route} is missing its server-rendered detail theme`);
  }
  if (html.includes("/css/cve-catalog.css") || html.includes("/js/cve-catalog.js")) {
    fail(`historical CVE detail ${route} loads standalone database catalog assets`);
  }
  if (!html.includes('<a href="/cve-database/">CVE Database</a>')) {
    fail(`historical CVE detail ${route} is missing its CVE Database breadcrumb`);
  }
  if (!html.includes('href="/cve-database/" aria-current="page">CVE Database</a>')) {
    fail(`historical CVE detail ${route} is missing its current CVE Database navigation item`);
  }
  if (!html.includes(`<link rel="canonical" href="`) || !html.includes(route)) {
    fail(`historical CVE detail ${route} is missing its canonical deep URL`);
  }
  if (!/"item":"https?:[^"]*\/cve-database\/"/.test(html)) {
    fail(`historical CVE detail ${route} does not identify CVE Database in structured breadcrumbs`);
  }
  if (/"item":"https?:[^"]*\/recipes\/"/.test(html)) {
    fail(`historical CVE detail ${route} retains Recipes in structured breadcrumbs`);
  }
  if (html.includes('name="robots" content="noindex')) {
    fail(`historical CVE detail ${route} is unexpectedly noindex`);
  }
}

const docs = readJson("recipes-index.json") || [];
const browser = readJson("recipes-browser.json")?.recipes || [];
const curated = readJson("api/curated-recipes.json")?.recipes || [];
const rich = readJson("api/recipes.json")?.recipes || [];
const mcp = readJson("api/recipes-index.json")?.recipes || [];
if (browser.length > 5000) {
  fail(`recipe browser feed has ${browser.length.toLocaleString()} records; keep the CVE catalog on its worker index`);
}
const browserRoutes = new Set(browser.map((item) => item.url));
const curatedRoutes = new Set(curated.map((item) => item.path));
if (
  browserRoutes.size !== curatedRoutes.size ||
  [...browserRoutes].some((route) => !curatedRoutes.has(route))
) {
  fail("curated browser and rich agent feeds do not describe the same recipe collection");
}

const recipeLibraryPath = path.join(ROOT, "recipes", "index.html");
if (fs.existsSync(recipeLibraryPath)) {
  const recipeLibrary = fs.readFileSync(recipeLibraryPath, "utf8");
  const ssrCards = (recipeLibrary.match(/\bdata-recipe-card(?:\s|>)/g) || []).length;
  if (ssrCards > 18) fail(`recipe library server-renders ${ssrCards} cards; budget is 18`);
  const seedMatch = recipeLibrary.match(
    /<script type="application\/json" data-recipe-seed>([\s\S]*?)<\/script>/,
  );
  if (!seedMatch) {
    fail("recipe library is missing its bounded SSR hydration seed");
  } else {
    try {
      const seed = JSON.parse(seedMatch[1]);
      if (!Array.isArray(seed) || seed.length !== ssrCards || seed.length > 18) {
        fail(
          `recipe library hydration seed has ${Array.isArray(seed) ? seed.length : "non-array"} records; expected the ${ssrCards} SSR cards only`,
        );
      }
      if (Buffer.byteLength(seedMatch[1], "utf8") > 48 * KiB) {
        fail("recipe library hydration seed exceeds its 48 KiB payload budget");
      }
    } catch (error) {
      fail(`recipe library hydration seed is invalid JSON: ${error.message}`);
    }
  }
  if (!recipeLibrary.includes('data-recipe-feed-policy="interaction"')) {
    fail("recipe library does not declare its interaction-triggered feed policy");
  }
  if (recipeLibrary.includes("data-library-tab") || recipeLibrary.includes("data-library-panel")) {
    fail("recipe library still renders the retired federated collection tabs");
  }
  if (recipeLibrary.includes("data-cve-catalog")) {
    fail("recipe library still embeds the CVE catalog");
  }
  if (!recipeLibrary.includes('data-recipe-api="/api/curated-recipes.json"')) {
    fail("recipe library does not use the curated rich agent feed");
  }
  if (!recipeLibrary.includes(browser.length.toLocaleString("en-US"))) {
    fail(`recipe library does not display its ${browser.length.toLocaleString("en-US")} curated-recipe total`);
  }
}

const cveDatabasePath = path.join(ROOT, "cve-database", "index.html");
const cveDatabase = fs.existsSync(cveDatabasePath)
  ? fs.readFileSync(cveDatabasePath, "utf8")
  : "";
if (cveDatabase) {
  if (!cveDatabase.includes("data-cve-catalog")) {
    fail("CVE Database does not mount the catalog");
  }
  if (cveDatabase.includes("data-cve-catalog-deferred")) {
    fail("CVE Database defers its standalone catalog mount");
  }
  if (!cveDatabase.includes('href="/cve-database/" aria-current="page">CVE Database</a>')) {
    fail("CVE Database is missing its current primary-navigation item");
  }
}

const compatibleSurfaces = [
  ["docs search", docs],
  ["rich agent feed", rich],
  ["MCP recipe feed", mcp],
];
for (const [label, items] of compatibleSurfaces) {
  const bySource = new Map();
  for (const item of items) {
    if (!bySource.has(item.source_file)) bySource.set(item.source_file, []);
    bySource.get(item.source_file).push(item);
  }
  for (const override of stableOverrides) {
    const matches = bySource.get(override.sourceFile) || [];
    if (matches.length !== 1) {
      fail(
        `${label} has ${matches.length} records for stable override ${override.sourceFile}; expected one`,
      );
      continue;
    }
    if (matches[0].path !== override.expectedRoute) {
      fail(
        `${label} publishes ${override.sourceFile} at ${matches[0].path}; expected ${override.expectedRoute}`,
      );
    }
    let absolutePath = "";
    try {
      absolutePath = new URL(matches[0].url).pathname;
    } catch {
      // The policy failure below covers missing and malformed absolute URLs.
    }
    if (absolutePath !== override.expectedRoute) {
      fail(`${label} has a non-canonical absolute URL for ${override.sourceFile}`);
    }
  }
  for (const override of draftOverrides) {
    if (bySource.has(override.sourceFile)) {
      fail(`${label} exposes development CVE draft ${override.sourceFile}`);
    }
  }
}

const curatedSurfaces = [
  ["recipe browser", browserRoutes],
  ["curated rich agent feed", curatedRoutes],
];
for (const [label, routes] of curatedSurfaces) {
  for (const route of stableRoutes) {
    if (routes.has(route)) fail(`${label} exposes stable CVE override ${route}`);
  }
  for (const route of developmentRoutes) {
    if (routes.has(route)) fail(`${label} exposes development CVE draft ${route}`);
  }
}

const sitemap = fs.readFileSync(path.join(ROOT, "sitemap.xml"), "utf8");
const pagesSitemapPath = path.join(ROOT, "sitemaps", "pages.xml");
const pagesSitemap = fs.existsSync(pagesSitemapPath)
  ? fs.readFileSync(pagesSitemapPath, "utf8")
  : "";
if (!pagesSitemap) fail("missing required output: sitemaps/pages.xml");
if (!sitemap.includes("/sitemaps/pages.xml")) {
  fail("root sitemap index does not reference /sitemaps/pages.xml");
}
const pagesSitemapHas = (route) =>
  pagesSitemap.includes(`<loc>https://security-recipes.ai${route}</loc>`);

const remediationRoute = "/security-remediation/";
const remediationHtml = htmlOutputs.get(remediationRoute);
const remediationTitle = "How to Remediate Vulnerabilities with AI Agents";
if (!remediationHtml) {
  fail(`missing rendered remediation pillar: ${remediationRoute}`);
} else {
  const title = remediationHtml.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() || "";
  if (decodeHtmlAttributeOnce(title) !== remediationTitle) {
    fail(`remediation pillar title is not the exact query-specific title: ${title || "(missing)"}`);
  }

  const h1Contents = Array.from(
    remediationHtml.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1>/gi),
    (match) => match[1].trim(),
  );
  if (
    h1Contents.length !== 1 ||
    decodeHtmlAttributeOnce(h1Contents[0] || "") !== remediationTitle
  ) {
    fail(
      `remediation pillar renders ${h1Contents.length} H1 elements with ` +
      "the wrong search-intent title",
    );
  }

  if (
    !remediationHtml.includes(
      '<link rel="canonical" href="https://security-recipes.ai/security-remediation/">',
    )
  ) {
    fail("remediation pillar is not self-canonical");
  }
  for (const crawler of ["robots", "googlebot"]) {
    const indexablePattern = new RegExp(
      `<meta\\b(?=[^>]*\\bname=["']${crawler}["'])` +
      `(?=[^>]*\\bcontent=["']index,follow(?:,|["']))[^>]*>`,
      "i",
    );
    if (!indexablePattern.test(remediationHtml)) {
      fail(`remediation pillar ${crawler} directive does not begin with index,follow`);
    }
  }

  const remediationEntities = [];
  for (const document of remediationHtml.matchAll(
    /<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi,
  )) {
    try {
      const parsed = JSON.parse(document[1]);
      if (Array.isArray(parsed?.["@graph"])) remediationEntities.push(...parsed["@graph"]);
      else if (parsed && typeof parsed === "object") remediationEntities.push(parsed);
    } catch (error) {
      fail(`remediation pillar has invalid JSON-LD (${error.message})`);
    }
  }
  const hasSchemaType = (entity, type) => {
    const values = Array.isArray(entity?.["@type"]) ? entity["@type"] : [entity?.["@type"]];
    return values.includes(type);
  };
  const howTo = remediationEntities.find((entity) => hasSchemaType(entity, "HowTo"));
  const collectionPage = remediationEntities.find((entity) => hasSchemaType(entity, "CollectionPage"));
  const howToSteps = Array.isArray(howTo?.step) ? howTo.step : [];
  if (
    howToSteps.length !== 7 ||
    !howToSteps.every((step) => hasSchemaType(step, "HowToStep"))
  ) {
    fail(`remediation pillar HowTo has ${howToSteps.length} valid steps; expected seven`);
  }
  if (!howTo?.["@id"] || collectionPage?.mainEntity?.["@id"] !== howTo["@id"]) {
    fail("remediation pillar CollectionPage does not identify the HowTo as its main entity");
  }
}
if (!pagesSitemapHas(remediationRoute)) {
  fail(`pages sitemap is missing the remediation pillar ${remediationRoute}`);
}

const indexedSitemapRoutes = Array.from(
  sitemap.matchAll(/<loc>https?:\/\/[^/]+(\/[^<]+)<\/loc>/g),
  (match) => match[1]
);
const sitemapCache = new Map();
function readIndexedSitemap(route) {
  if (sitemapCache.has(route)) return sitemapCache.get(route);
  const output = path.join(ROOT, route.replace(/^\//, ""));
  const content = fs.existsSync(output) ? fs.readFileSync(output, "utf8") : "";
  if (!content) fail(`root sitemap references missing output ${route}`);
  sitemapCache.set(route, content);
  return content;
}

for (const override of stableOverrides) {
  if (!override.canonicalCveRoute) {
    if (!pagesSitemapHas(override.legacyRoute)) {
      fail(`pages sitemap is missing historical stable override ${override.legacyRoute}`);
    }
    if (/^CVE-\d{4}-\d{4,7}$/.test(override.cve)) {
      const dynamicRoute = canonicalRouteForCve(override.cve);
      const year = override.cve.slice(4, 8);
      for (const route of indexedSitemapRoutes.filter((candidate) =>
        new RegExp(`^/sitemaps/cves-${year}(?:-\\d+)?\\.xml$`).test(candidate)
      )) {
        if (readIndexedSitemap(route).includes(dynamicRoute)) {
          fail(`CVE sitemaps expose competing dynamic route ${dynamicRoute}`);
        }
      }
    }
    continue;
  }
  if (!/^CVE-\d{4}-\d{4,7}$/.test(override.cve)) {
    fail(`stable override ${override.legacyRoute} is missing a canonical CVE ID`);
    continue;
  }
  if (pagesSitemapHas(override.legacyRoute)) {
    fail(`pages sitemap exposes superseded CVE alias ${override.legacyRoute}`);
  }
  const year = override.cve.slice(4, 8);
  const yearSitemaps = indexedSitemapRoutes.filter((route) =>
    new RegExp(`^/sitemaps/cves-${year}(?:-\\d+)?\\.xml$`).test(route)
  );
  if (!yearSitemaps.length) {
    fail(`root sitemap index has no CVE partition for ${override.cve}`);
    continue;
  }
  const canonicalRoute = `/cve/${override.cve}/`;
  if (!yearSitemaps.some((route) => readIndexedSitemap(route).includes(canonicalRoute))) {
    fail(`CVE sitemaps are missing canonical route ${canonicalRoute}`);
  }
}
for (const override of draftOverrides) {
  if (pagesSitemapHas(override.legacyRoute)) {
    fail(`pages sitemap exposes development CVE draft ${override.legacyRoute}`);
  }
}

if (!cveArchiveHtml.length) fail("no crawlable CVE archive HTML pages were generated");
if (pagesSitemap.includes("/cve/archive/")) {
  fail("pages sitemap exposes the noindex CVE archive");
}

const searchIndexableRecords = readJson("api/cve-catalog/search-indexable.json")?.records || [];
const historicalCanonicalRoutes = new Map(
  historicalStableOverrides
    .filter((override) => /^CVE-\d{4}-\d{4,7}$/.test(override.cve))
    .map((override) => [override.cve, override.legacyRoute]),
);
const qualifiedCanonicalRoutes = new Map(
  searchIndexableRecords
    .filter((record) => /^CVE-\d{4}-\d{4,7}$/.test(String(record?.cve || "")))
    .map((record) => {
      const cve = String(record.cve);
      return [cve, historicalCanonicalRoutes.get(cve) || canonicalRouteForCve(cve)];
    }),
);
const remediationContextLink =
  '<a href="/security-remediation/">Explore AI vulnerability remediation playbooks</a>';
for (const [cve, route] of qualifiedCanonicalRoutes) {
  if (!route.startsWith("/cve/")) continue;
  const html = htmlOutputs.get(route);
  if (!html) {
    fail(`missing materialized canonical CVE page for ${cve}: ${route}`);
  } else if (!html.includes(remediationContextLink)) {
    fail(`canonical CVE page ${route} is missing its contextual remediation-pillar link`);
  }
}
const databaseQualifiedLinks = Array.from(
  cveDatabase.matchAll(
    /<a href=["']([^"']+)["'] data-qualified-cve-link=["'](CVE-\d{4}-\d{4,7})["']>/g,
  ),
  (match) => ({ route: match[1], cve: match[2] }),
);
if (databaseQualifiedLinks.length !== qualifiedCanonicalRoutes.size) {
  fail(
    `CVE Database renders ${databaseQualifiedLinks.length} qualified canonical links; ` +
    `expected ${qualifiedCanonicalRoutes.size}`,
  );
}
for (const [cve, route] of qualifiedCanonicalRoutes) {
  const matching = databaseQualifiedLinks.filter(
    (entry) => entry.cve === cve && entry.route === route,
  );
  if (matching.length !== 1) {
    fail(`CVE Database does not expose exactly one canonical qualified link for ${cve}`);
  }
}
const expectedHistoricalDatabaseRoutes = new Map(
  [...historicalCanonicalRoutes].filter(([cve]) => !qualifiedCanonicalRoutes.has(cve)),
);
const databaseHistoricalLinks = Array.from(
  cveDatabase.matchAll(
    /<a href=["']([^"']+)["'] data-historical-cve-link=["'](CVE-\d{4}-\d{4,7})["']>/g,
  ),
  (match) => ({ route: match[1], cve: match[2] }),
);
if (databaseHistoricalLinks.length !== expectedHistoricalDatabaseRoutes.size) {
  fail(
    `CVE Database renders ${databaseHistoricalLinks.length} historical reviewed links; ` +
    `expected ${expectedHistoricalDatabaseRoutes.size}`,
  );
}
for (const [cve, route] of expectedHistoricalDatabaseRoutes) {
  const matching = databaseHistoricalLinks.filter(
    (entry) => entry.cve === cve && entry.route === route,
  );
  if (matching.length !== 1) {
    fail(`CVE Database does not expose exactly one historical reviewed link for ${cve}`);
  }
}
for (const route of [
  "/security-remediation/",
  "/security-remediation/vulnerable-dependencies/",
  "/recipes/general/cve-intelligence-intake-gate/",
]) {
  if (!cveDatabase.includes(`href="${route}"`)) {
    fail(`CVE Database is missing its remediation-cluster link to ${route}`);
  }
}
const archiveTargets = new Set(qualifiedCanonicalRoutes.values());
const allowedArchiveTargets = new Set(archiveTargets);
const allowedHistoricalArchiveTargets = new Set(historicalCanonicalRoutes.values());
const forbiddenArchiveTargets = new Set(
  historicalStableOverrides
    .filter((override) => /^CVE-\d{4}-\d{4,7}$/.test(override.cve))
    .map((override) => canonicalRouteForCve(override.cve)),
);
let archiveCanonicalLinks = 0;
for (const file of cveArchiveHtml) {
  const route = routeForOutput(file);
  if (pagesSitemapHas(route)) {
    fail(`pages sitemap exposes generated noindex CVE archive page ${route}`);
  }
  const html = fs.readFileSync(file, "utf8");
  if (
    !html.includes('<meta name="robots" content="noindex,follow">') ||
    !html.includes('<meta name="googlebot" content="noindex,follow">')
  ) {
    fail(`CVE archive page is not noindex,follow: ${route}`);
  }
  if (!html.includes(`<link rel="canonical" href="https://security-recipes.ai${route}">`)) {
    fail(`CVE archive page is not self-canonical: ${route}`);
  }
  if (
    !html.includes('"@type":"CollectionPage"') ||
    html.includes('"additionalType":"https://schema.org/TechArticle"')
  ) {
    fail(`CVE archive page does not expose collection semantics: ${route}`);
  }
  if (!html.includes('<meta property="og:type" content="website">')) {
    fail(`CVE archive page has non-collection Open Graph semantics: ${route}`);
  }
  const historicalLinks = Array.from(
    html.matchAll(/href=["'](\/recipes\/cve\/[^"']+\/)["']/gi),
    (match) => match[1],
  );
  for (const target of historicalLinks) {
    if (!allowedHistoricalArchiveTargets.has(target)) {
      fail(`CVE archive page contains an unexpected Markdown CVE link ${target}: ${route}`);
    }
  }
  const dynamicLinks = Array.from(
    html.matchAll(/href=["'](\/cve\/CVE-\d{4}-\d{4,7}\/)["']/g),
    (match) => match[1],
  );
  for (const target of dynamicLinks) {
    if (!allowedArchiveTargets.has(target)) {
      fail(`CVE archive page links an unqualified dynamic record ${target}: ${route}`);
    }
  }
  const canonicalLinks = [...dynamicLinks, ...historicalLinks];
  archiveCanonicalLinks += canonicalLinks.length;
  if (route !== "/cve/archive/" && canonicalLinks.length === 0) {
    fail(`CVE archive page has no crawlable canonical CVE links: ${route}`);
  }
  for (const target of [...archiveTargets]) {
    if (html.includes(`href="${target}"`) || html.includes(`href='${target}'`)) {
      archiveTargets.delete(target);
    }
  }
  for (const target of forbiddenArchiveTargets) {
    if (html.includes(`href="${target}"`) || html.includes(`href='${target}'`)) {
      fail(`CVE archive exposes competing dynamic route ${target}`);
    }
  }
}
if (!archiveCanonicalLinks) fail("CVE archive contains no canonical CVE links");
for (const target of archiveTargets) {
  fail(`CVE archive is missing reviewed canonical record ${target}`);
}

const cveRssPath = path.join(ROOT, "cve-database", "index.xml");
if (!fs.existsSync(cveRssPath)) {
  fail("missing required output: cve-database/index.xml");
} else {
  const rss = fs.readFileSync(cveRssPath, "utf8");
  const items = Array.from(rss.matchAll(/<item>([\s\S]*?)<\/item>/g), (match) => match[1]);
  if (!items.length) fail("CVE Database RSS has no items");
  if (items.length > 100) fail(`CVE Database RSS has ${items.length} items; budget is 100`);
  for (const [index, item] of items.entries()) {
    const link = item.match(/<link>(https?:\/\/[^<]+)<\/link>/)?.[1] || "";
    const guid = item.match(/<guid>(https?:\/\/[^<]+)<\/guid>/)?.[1] || "";
    let linkUrl;
    try {
      linkUrl = new URL(link);
    } catch {
      // The canonical-link failure below also covers malformed URLs.
    }
    if (
      linkUrl?.origin !== "https://security-recipes.ai" ||
      !allowedArchiveTargets.has(linkUrl?.pathname)
    ) {
      fail(`CVE Database RSS item ${index + 1} has a non-canonical link: ${link || "(missing)"}`);
    }
    if (guid !== link) fail(`CVE Database RSS item ${index + 1} GUID does not match its link`);
  }
}

if (failures.length) {
  console.error("Site performance/discovery budgets failed:");
  for (const message of failures) console.error(`- ${message}`);
  process.exit(1);
}

console.log(
  `Performance budgets passed: ${files.length.toLocaleString()} files, ` +
  `${(totalBytes / MiB).toFixed(1)} MiB, ${cveArchiveHtml.length.toLocaleString()} CVE archive pages, ` +
  `${stableOverrides.length} stable overrides, ${draftOverrides.length.toLocaleString()} unrendered drafts, ` +
  `${indexableHtmlRoutes.size.toLocaleString()} indexable pages, max title/description ` +
  `${maxIndexableTitleLength}/${maxIndexableDescriptionLength} characters, max crawl depth ${maxIndexableDepth}.`,
);
