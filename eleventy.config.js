// Eleventy build for security-recipes.ai — replaces the Hugo + Hextra
// toolchain. content/*.md is consumed unchanged (Hugo shortcodes are
// translated by lib/hugo-preprocess.js); all JSON feeds, robots, sitemap,
// RSS, and tag pages are emitted as virtual templates so no build
// scaffolding lives inside content/.

const markdownIt = require("markdown-it");
const markdownItAnchor = require("markdown-it-anchor");
const markdownItContainer = require("markdown-it-container");
const syntaxHighlight = require("@11ty/eleventy-plugin-syntaxhighlight");
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const site = require("./lib/site-config");
const contentIndex = require("./lib/content-index");
const { createPreprocessor } = require("./lib/hugo-preprocess");
const feeds = require("./lib/feeds");
const { escapeHtml, stripTags, isoDate } = require("./lib/util");
const { articleDatesFor, presentationText, seoHead, seoTitle } = require("./lib/seo");
const { cveDisplayTitle, stripFirstH1 } = require("./lib/html-content");
const { cleanCatalogText } = require("./lib/text-quality");
const { loadCveSearchIndexableIds } = require("./lib/cve-indexability");
const {
  canonicalCvePresentationDescription,
  canonicalCvePresentationLastmod,
  canonicalCvePresentationTitle,
} = require("./lib/cve-editorial-metadata");
const { isDiscoveryPage, canonicalUrlForPage } = contentIndex;

// Search engines accept at most 50,000 locations in one sitemap. Keep a
// little headroom and derive output chunks from the small catalog manifest;
// an individual gzip partition is only opened while its sitemap is rendered.
const CVE_SITEMAP_URL_LIMIT = 49_000;
const CVE_ARCHIVE_PAGE_SIZE = 500;
const CANONICAL_CVE_ID = /^CVE-\d{4}-\d{4,}$/;
const CVE_PARTITION_PATH = /^indexes\/(\d{4})\.json\.gz$/;
const CVE_CATALOG_ROOT = path.join(__dirname, "static", "api", "cve-catalog");
const GENERATED_TAG_PAGE_SEO = Object.freeze({
  noindex: true,
  noindex_follow: true,
});
const ROBOTS_DISALLOW_RULES = Object.freeze([
  `Disallow: /search/`,
  `Disallow: /tags/null/`,
  `Disallow: /tags/Null/`,
]);
const AI_CRAWLER_USER_AGENTS = Object.freeze([
  "GPTBot",
  "ClaudeBot",
  "Claude-Web",
  "Google-Extended",
  "PerplexityBot",
  "anthropic-ai",
  "cohere-ai",
  "CCBot",
]);

function robotsGroup(userAgent) {
  return [
    `User-agent: ${userAgent}`,
    `Allow: /`,
    ...ROBOTS_DISALLOW_RULES,
    ``,
  ];
}

function renderRobotsTxt() {
  return [
    `# robots.txt for ${site.title}`,
    `# Generated at build time.`,
    ``,
    ...robotsGroup("*"),
    `# AI / LLM crawlers — explicitly allowed outside the shared exclusions.`,
    ...AI_CRAWLER_USER_AGENTS.flatMap((userAgent) => robotsGroup(userAgent)),
    `Sitemap: ${feeds.absURL("/sitemap.xml")}`,
    ``,
    `Host: ${site.baseURL.replace(/^https?:\/\//, "").replace(/\/$/, "")}`,
    ``,
  ].join("\n");
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function sitemapLastmod(value) {
  const match = String(value || "").match(/^(\d{4}-\d{2}-\d{2})(?:T.*)?$/);
  return match ? match[1] : "";
}

function latestSitemapLastmod(entries) {
  return entries.reduce((latest, entry) => {
    const candidate = sitemapLastmod(
      entry && typeof entry === "object" ? entry.lastmod : entry,
    );
    return candidate > latest ? candidate : latest;
  }, "");
}

function isPagesSitemapEntry(page) {
  const frontMatter = page && page.fm ? page.fm : {};
  const catalogOwnsCanonical =
    frontMatter.canonical_cve_route !== false &&
    CANONICAL_CVE_ID.test(String(frontMatter.cve || ""));
  return (
    isDiscoveryPage(page) &&
    frontMatter.noindex !== true &&
    !frontMatter.redirectTo &&
    frontMatter.layout !== "layouts/redirect.njk" &&
    !catalogOwnsCanonical
  );
}

function loadCveSitemapManifest(catalogRoot = CVE_CATALOG_ROOT) {
  const manifestPath = path.join(catalogRoot, "index.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (!Array.isArray(manifest.partitions)) {
    throw new Error("CVE catalog sitemap manifest is missing partitions");
  }
  return manifest;
}

function cveBelongsInSearchSurface(
  record,
  excludedCveIds = new Set(),
  searchIndexableCveIds = null,
) {
  const cve = String(record?.cve || "");
  if (!CANONICAL_CVE_ID.test(cve)) {
    throw new Error(`Invalid canonical CVE ID: ${cve || "(missing)"}`);
  }
  return (
    !excludedCveIds.has(cve) &&
    (!(searchIndexableCveIds instanceof Set) || searchIndexableCveIds.has(cve))
  );
}

function isSectionFeedEntry(page) {
  const frontMatter = page && page.fm ? page.fm : {};
  return (
    page?.isSection === true &&
    !frontMatter.redirectTo &&
    frontMatter.layout !== "layouts/redirect.njk"
  );
}

function readCvePartition(partition, catalogRoot = CVE_CATALOG_ROOT) {
  const partitionPath = path.resolve(catalogRoot, partition.path);
  const expectedRoot = `${path.resolve(catalogRoot)}${path.sep}`;
  if (!partitionPath.startsWith(expectedRoot)) {
    throw new Error("CVE catalog partition escaped the catalog root");
  }
  const payload = JSON.parse(zlib.gunzipSync(fs.readFileSync(partitionPath)).toString("utf8"));
  if (!Array.isArray(payload.records) || payload.records.length !== partition.records) {
    throw new Error(`CVE catalog partition count mismatch for ${partition.year}`);
  }
  return payload.records;
}

function planCveSitemaps(
  manifest,
  urlLimit = CVE_SITEMAP_URL_LIMIT,
  catalogRoot = CVE_CATALOG_ROOT,
  excludedCveIds = new Set(),
  searchIndexableCveIds = null,
) {
  if (!Number.isSafeInteger(urlLimit) || urlLimit < 1 || urlLimit >= 50_000) {
    throw new Error("CVE sitemap URL limit must be between 1 and 49,999");
  }

  const seenYears = new Set();
  const entries = [];
  let plannedRecords = 0;
  for (const partition of manifest.partitions) {
    const year = String(partition.year || "");
    const pathMatch = String(partition.path || "").match(CVE_PARTITION_PATH);
    if (!/^\d{4}$/.test(year) || !pathMatch || pathMatch[1] !== year) {
      throw new Error(`Unsafe CVE catalog partition path: ${partition.path || "(missing)"}`);
    }
    if (seenYears.has(year)) {
      throw new Error(`Duplicate CVE catalog sitemap year: ${year}`);
    }
    if (!Number.isSafeInteger(partition.records) || partition.records < 1) {
      throw new Error(`Invalid CVE catalog record count for ${year}`);
    }
    seenYears.add(year);
    plannedRecords += partition.records;

    const appliesSearchGate = searchIndexableCveIds instanceof Set || excludedCveIds.size > 0;
    const partitionRecords = readCvePartition(partition, catalogRoot);
    const eligibleRecordList = appliesSearchGate
      ? partitionRecords.filter((record) =>
          cveBelongsInSearchSurface(record, excludedCveIds, searchIndexableCveIds)
        )
      : partitionRecords;
    const eligibleRecords = eligibleRecordList.length;
    const chunkCount = Math.ceil(eligibleRecords / urlLimit);
    for (let chunk = 0; chunk < chunkCount; chunk += 1) {
      const offset = chunk * urlLimit;
      const count = Math.min(urlLimit, Math.max(0, eligibleRecords - offset));
      const chunkRecords = eligibleRecordList.slice(offset, offset + count);
      const suffix = chunkCount === 1 ? "" : `-${chunk + 1}`;
      entries.push({
        year,
        sourcePath: partition.path,
        outputPath: `/sitemaps/cves-${year}${suffix}.xml`,
        offset,
        count,
        partitionRecords: partition.records,
        ...(appliesSearchGate ? { eligibleRecords } : {}),
        lastmod: latestSitemapLastmod(
          chunkRecords.map((record) =>
            canonicalCvePresentationLastmod(
              record?.cve,
              record?.page_lastmod,
            ),
          ),
        ),
      });
    }
  }
  if (Number.isSafeInteger(manifest.total) && manifest.total !== plannedRecords) {
    throw new Error(
      `CVE catalog manifest total mismatch: expected ${manifest.total}, planned ${plannedRecords}`
    );
  }
  return entries;
}

function renderCveSitemap(
  entry,
  catalogRoot = CVE_CATALOG_ROOT,
  excludedCveIds = new Set(),
  searchIndexableCveIds = null,
) {
  if (!entry || !String(entry.sourcePath || "").match(CVE_PARTITION_PATH)) {
    throw new Error("Unsafe CVE sitemap partition");
  }
  const partitionPath = path.resolve(catalogRoot, entry.sourcePath);
  const expectedRoot = `${path.resolve(catalogRoot)}${path.sep}`;
  if (!partitionPath.startsWith(expectedRoot)) {
    throw new Error("CVE sitemap partition escaped the catalog root");
  }

  // Each call owns only one inflated yearly partition. Nothing is retained
  // between renders, keeping the build bounded on small production hosts.
  const payload = JSON.parse(zlib.gunzipSync(fs.readFileSync(partitionPath)).toString("utf8"));
  if (!Array.isArray(payload.records) || payload.records.length !== entry.partitionRecords) {
    throw new Error(`CVE sitemap partition count mismatch for ${entry.year}`);
  }
  const eligibleRecords = payload.records.filter((record) =>
    cveBelongsInSearchSurface(record, excludedCveIds, searchIndexableCveIds)
  );
  if (
    Number.isSafeInteger(entry.eligibleRecords) &&
    eligibleRecords.length !== entry.eligibleRecords
  ) {
    throw new Error(`CVE sitemap eligibility mismatch for ${entry.year}`);
  }
  const records = eligibleRecords.slice(entry.offset, entry.offset + entry.count);
  if (Number.isSafeInteger(entry.eligibleRecords) && records.length !== entry.count) {
    throw new Error(`CVE sitemap chunk bounds mismatch for ${entry.year}`);
  }

  const urls = records
    .map((record) => {
      const cve = String(record && record.cve ? record.cve : "");
      if (!CANONICAL_CVE_ID.test(cve)) {
        throw new Error(`Invalid canonical CVE ID in ${entry.sourcePath}: ${cve || "(missing)"}`);
      }
      const lastmod = sitemapLastmod(
        canonicalCvePresentationLastmod(cve, record?.page_lastmod),
      );
      return (
        `<url><loc>${escapeXml(feeds.absURL(`/cve/${cve}/`))}</loc>` +
        (lastmod ? `<lastmod>${escapeXml(lastmod)}</lastmod>` : "") +
        `</url>`
      );
    });
  return (
    `<?xml version="1.0" encoding="utf-8"?>` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
    urls.join("") +
    `</urlset>`
  );
}

function renderSitemapIndex(cveEntries, pagesLastmod = "") {
  const rows = [
    {
      outputPath: "/sitemaps/pages.xml",
      lastmod: sitemapLastmod(pagesLastmod),
    },
    ...cveEntries,
  ].map(
    (entry) =>
      `<sitemap><loc>${escapeXml(feeds.absURL(entry.outputPath))}</loc>` +
      (entry.lastmod ? `<lastmod>${escapeXml(entry.lastmod)}</lastmod>` : "") +
      `</sitemap>`
  );
  return (
    `<?xml version="1.0" encoding="utf-8"?>` +
    `<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
    rows.join("") +
    `</sitemapindex>`
  );
}

function cleanCveSourceText(value) {
  return cleanCatalogText(value);
}

function pageSitemapLastmod(sourcePath, date, lastmod, frontMatter = {}) {
  return articleDatesFor({
    ...frontMatter,
    sourcePath,
    date,
    lastmod,
  }).dateModified;
}

function planPagesSitemapEntries(
  pages,
  {
    lastmodResolver = pageSitemapLastmod,
  } = {},
) {
  return pages
    .filter(isPagesSitemapEntry)
    .map((page) => ({
      loc: page.url,
      lastmod: sitemapLastmod(
        lastmodResolver(page.sourcePath, page.date, page.fm?.lastmod, page.fm),
      ),
    }));
}

function renderPagesSitemap(entries) {
  const urls = entries.map(
    ({ loc, lastmod }) =>
      `<url><loc>${escapeXml(feeds.absURL(loc))}</loc>` +
      (lastmod ? `<lastmod>${escapeXml(lastmod)}</lastmod>` : "") +
      `</url>`,
  );
  return (
    `<?xml version="1.0" encoding="utf-8"?>` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
    urls.join("") +
    `</urlset>`
  );
}

function cveArchiveOutputPath(year, pageNumber) {
  return pageNumber === 1
    ? `/cve/archive/${year}/`
    : `/cve/archive/${year}/page/${pageNumber}/`;
}

function safeCanonicalCveRoute(value, cve) {
  const route = String(value || "");
  const segments = route.split("/");
  if (
    !/^\/[A-Za-z0-9][A-Za-z0-9._~/-]*\/$/.test(route) ||
    route.includes("//") ||
    segments.includes(".") ||
    segments.includes("..")
  ) {
    throw new Error(`Unsafe canonical archive route for ${cve}: ${route || "(missing)"}`);
  }
  return route;
}

function cveArchiveRecordRoute(
  record,
  excludedCveIds,
  searchIndexableCveIds,
  canonicalCveRoutes,
) {
  const cve = String(record?.cve || "");
  if (!CANONICAL_CVE_ID.test(cve)) {
    throw new Error(`Invalid canonical CVE ID: ${cve || "(missing)"}`);
  }
  if (searchIndexableCveIds instanceof Set && !searchIndexableCveIds.has(cve)) {
    return "";
  }
  if (!excludedCveIds.has(cve)) {
    return `/cve/${cve}/`;
  }
  if (!(canonicalCveRoutes instanceof Map) || !canonicalCveRoutes.has(cve)) {
    return "";
  }
  return safeCanonicalCveRoute(canonicalCveRoutes.get(cve), cve);
}

let stableCvePresentationCache = null;
function stableCvePresentation(cve) {
  if (!stableCvePresentationCache) {
    stableCvePresentationCache = new Map();
    for (const page of contentIndex.getIndex().pages) {
      const pageCve = String(page?.fm?.cve || "").trim().toUpperCase();
      if (
        !CANONICAL_CVE_ID.test(pageCve) ||
        String(page?.fm?.maturity || "").trim().toLowerCase() !== "stable"
      ) {
        continue;
      }
      if (stableCvePresentationCache.has(pageCve)) {
        throw new Error(`Duplicate stable canonical page for ${pageCve}`);
      }
      stableCvePresentationCache.set(pageCve, {
        title: presentationText(page?.fm?.title || pageCve),
        description: presentationText(page?.fm?.description || ""),
      });
    }
  }
  return stableCvePresentationCache.get(cve) || null;
}

function cveFeedTitle(record) {
  const cve = String(record?.cve || "");
  const isDynamicCanonical = record?.url === `/cve/${cve}/`;
  const fallbackTitle =
    (isDynamicCanonical ? stableCvePresentation(cve)?.title : "") ||
    record?.title ||
    "Vulnerability record";
  const title = cveFeedSubject(
    isDynamicCanonical
      ? canonicalCvePresentationTitle(cve, fallbackTitle)
      : fallbackTitle,
  );
  const normalizedTitle = title.toUpperCase();
  const nextCharacter = title.charAt(cve.length);
  const alreadyPrefixed =
    normalizedTitle === cve ||
    (normalizedTitle.startsWith(cve) && /[\s:—–-]/.test(nextCharacter));
  return alreadyPrefixed ? title : `${cve}: ${title}`;
}

function cveFeedSubject(value, limit = 160) {
  const text = cleanCveSourceText(value)
    .replace(/(?:\.{3,}|…)/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (text.length <= limit) return text.replace(/[.!?;:]+$/g, "");

  const prefix = text.slice(0, limit + 1);
  const boundary = prefix.lastIndexOf(" ");
  const clipped = prefix.slice(0, boundary >= limit / 2 ? boundary : limit);
  return clipped.trim().replace(/[.,!?;:]+$/g, "");
}

function cveFeedDescription(record) {
  const cve = String(record?.cve || "");
  const isDynamicCanonical = record?.url === `/cve/${cve}/`;
  const fallbackDescription =
    (isDynamicCanonical ? stableCvePresentation(cve)?.description : "") ||
    record?.description ||
    "";
  const reviewed = cleanCveSourceText(
    isDynamicCanonical
      ? canonicalCvePresentationDescription(cve, fallbackDescription)
      : fallbackDescription,
  );
  if (reviewed) return reviewed;

  const title = cveFeedSubject(record?.title || "Vulnerability record");
  const severity = String(record?.severity || "unscored").toUpperCase();
  return (
    `${record.cve} is a ${severity} vulnerability: ${title}. ` +
    `Review affected versions, source evidence, and bounded AI remediation guidance.`
  );
}

function buildRecentCatalogItems(cveArchiveEntries, limit = 100) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
    throw new Error("CVE RSS item limit must be between 1 and 1,000");
  }
  return cveArchiveEntries
    .flatMap((entry) => entry.records)
    .sort((a, b) => {
      const aDate = a.pageLastmod || a.published;
      const bDate = b.pageLastmod || b.published;
      return bDate.localeCompare(aDate, "en") || b.cve.localeCompare(a.cve, "en");
    })
    .slice(0, limit)
    .map((record) => {
      const feedDate = record.pageLastmod || record.published;
      return {
        title: cveFeedTitle(record),
        url: record.url,
        date: feedDate ? new Date(`${feedDate}T00:00:00Z`) : null,
        description: cveFeedDescription(record),
        fm: {},
      };
    });
}

// Build a crawlable HTML hierarchy from the same compact yearly partitions
// used by the XML sitemaps. Retain only archive/feed fields so the build stays
// bounded while every qualified CVE resolves to its actual canonical href.
function planCveArchivePages(
  manifest,
  pageSize = CVE_ARCHIVE_PAGE_SIZE,
  catalogRoot = CVE_CATALOG_ROOT,
  excludedCveIds = new Set(),
  searchIndexableCveIds = null,
  canonicalCveRoutes = new Map(),
) {
  if (!Number.isSafeInteger(pageSize) || pageSize < 100 || pageSize > 5_000) {
    throw new Error("CVE archive page size must be between 100 and 5,000");
  }
  const entries = [];
  for (const partition of manifest.partitions) {
    const year = String(partition.year || "");
    if (!/^\d{4}$/.test(year) || !String(partition.path || "").match(CVE_PARTITION_PATH)) {
      throw new Error(`Unsafe CVE archive partition: ${partition.path || "(missing)"}`);
    }
    const partitionPath = path.resolve(catalogRoot, partition.path);
    const payload = JSON.parse(zlib.gunzipSync(fs.readFileSync(partitionPath)).toString("utf8"));
    if (!Array.isArray(payload.records) || payload.records.length !== partition.records) {
      throw new Error(`CVE archive partition count mismatch for ${year}`);
    }
    const records = payload.records
      .map((record) => ({
        record,
        url: cveArchiveRecordRoute(
          record,
          excludedCveIds,
          searchIndexableCveIds,
          canonicalCveRoutes,
        ),
      }))
      .filter(({ url }) => Boolean(url))
      .map(({ record, url }) => ({
        cve: String(record?.cve || ""),
        title: cleanCveSourceText(
          record?.page_title || record?.title || "Vulnerability record",
        ),
        description: cleanCveSourceText(record?.page_description || ""),
        severity: String(record?.severity || "unscored").toLowerCase(),
        score: Number.isFinite(record?.score) ? record.score : null,
        published: sitemapLastmod(record?.published),
        pageLastmod: sitemapLastmod(
          url === `/cve/${record.cve}/`
            ? canonicalCvePresentationLastmod(
                record.cve,
                record?.page_lastmod,
              )
            : record?.page_lastmod,
        ),
        kev: record?.kev === true,
        ecosystem: String(record?.ecosystem || ""),
        url,
      }))
      .sort(
        (a, b) =>
          b.published.localeCompare(a.published, "en") ||
          b.cve.localeCompare(a.cve, "en"),
      );
    if (records.some((record) => !CANONICAL_CVE_ID.test(record.cve))) {
      throw new Error(`Invalid canonical CVE ID in archive partition ${year}`);
    }
    const pageCount = Math.ceil(records.length / pageSize);
    for (let pageNumber = 1; pageNumber <= pageCount; pageNumber += 1) {
      const pageRecords = records.slice(
        (pageNumber - 1) * pageSize,
        pageNumber * pageSize,
      );
      entries.push({
        year,
        pageNumber,
        pageCount,
        total: records.length,
        offset: (pageNumber - 1) * pageSize,
        lastmod: pageRecords.reduce(
          (latest, record) =>
            record.pageLastmod && record.pageLastmod > latest ? record.pageLastmod : latest,
          "",
        ),
        outputPath: cveArchiveOutputPath(year, pageNumber),
        records: pageRecords,
      });
    }
  }
  return entries;
}

function renderCveArchivePage(entry) {
  const first = entry.offset + 1;
  const last = first + entry.records.length - 1;
  const rows = entry.records
    .map((record) => {
      const score = record.score === null ? "" : ` · CVSS ${escapeHtml(record.score)}`;
      const kev = record.kev ? " · CISA KEV" : "";
      const ecosystem = record.ecosystem ? ` · ${escapeHtml(record.ecosystem)}` : "";
      return (
        `<li class="cve-archive__record">` +
        `<a href="${escapeHtml(record.url)}"><strong>${escapeHtml(record.cve)}</strong>` +
        `<span>${escapeHtml(record.title)}</span></a>` +
        `<small>${escapeHtml(record.severity.toUpperCase())}${score}${kev}${ecosystem}` +
        (record.published ? ` · Published <time datetime="${record.published}">${record.published}</time>` : "") +
        `</small></li>`
      );
    })
    .join("\n");
  const pageLinks = Array.from({ length: entry.pageCount }, (_, index) => {
    const pageNumber = index + 1;
    return pageNumber === entry.pageNumber
      ? `<strong aria-current="page">${pageNumber}</strong>`
      : `<a href="${cveArchiveOutputPath(entry.year, pageNumber)}">${pageNumber}</a>`;
  }).join(" ");
  const previous = entry.pageNumber > 1
    ? `<a rel="prev" href="${cveArchiveOutputPath(entry.year, entry.pageNumber - 1)}">← Previous</a>`
    : "<span></span>";
  const next = entry.pageNumber < entry.pageCount
    ? `<a rel="next" href="${cveArchiveOutputPath(entry.year, entry.pageNumber + 1)}">Next →</a>`
    : "<span></span>";
  return (
    `<p>This archive lists CVEs published in ${entry.year} that have stable human-reviewed ` +
    `guidance or complete source-linked AI enrichment. Open a record for sourced facts, ` +
    `affected-product evidence, and a bounded remediation workflow.</p>` +
    `<p>Showing records ${first.toLocaleString("en-US")}–${last.toLocaleString("en-US")} ` +
    `of ${entry.total.toLocaleString("en-US")}.</p>` +
    `<nav class="cve-archive__pages" aria-label="${entry.year} CVE archive pages">${pageLinks}</nav>` +
    `<ol class="cve-archive__records" start="${first}">${rows}</ol>` +
    `<nav class="hextra-pagination sr-pager" aria-label="CVE archive pagination">${previous}${next}</nav>` +
    `<p><a href="/cve/archive/">Browse every publication year</a> · ` +
    `<a href="/cve-database/">Search the CVE Database</a></p>`
  );
}

// Hugo-goldmark-compatible heading ids: lowercase, spaces to hyphens,
// punctuation dropped, underscores kept.
function slugifyHeading(s) {
  return stripTags(String(s).trim().toLowerCase())
    .replace(/[^\p{L}\p{N}\s_-]+/gu, "")
    .replace(/\s+/g, "-");
}

function slugifyTag(s) {
  return String(s)
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9_-]+/g, "");
}

function authoredTagUrl(tag, pages = contentIndex.getIndex().pages) {
  const slug = slugifyTag(tag);
  if (!slug) return "";
  const route = `/tags/${slug}/`;
  const page = pages.find((entry) => entry?.url === route);
  return page && isPagesSitemapEntry(page) ? route : "";
}

// Sidebar tree, computed once from the content index. Levels with more
// than 100 entries are pruned (the 2,300+ CVE leaves would bloat every
// page); the docs layout only expands the branch containing the current
// page, so big-but-reasonable levels stay cheap.
let sidebarTreeCache = null;
function buildSidebarTree() {
  if (sidebarTreeCache) return sidebarTreeCache;
  const { pages } = contentIndex.getIndex();
  const bySection = (dirPrefix, depth) => {
    const children = [];
    for (const p of pages) {
      if (!p.sourcePath.startsWith(dirPrefix)) continue;
      if (!isDiscoveryPage(p)) continue;
      if (p.fm?.sidebar?.exclude === true) continue;
      const rest = p.sourcePath.slice(dirPrefix.length);
      const parts = rest.split("/");
      if (parts.length === 1 && !p.isSection) {
        children.push({ title: p.linkTitle, url: p.url, children: [], weight: p.weight });
      } else if (parts.length === 2 && parts[1] === "_index.md") {
        const childDir = `${dirPrefix}${parts[0]}/`;
        children.push({
          title: p.linkTitle,
          url: p.url,
          children: depth < 3 ? bySection(childDir, depth + 1) : [],
          weight: p.weight,
        });
      }
    }
    children.sort(
      (a, b) => a.weight - b.weight || a.title.localeCompare(b.title, "en")
    );
    return children.length > 100 ? [] : children;
  };

  // Top-level order follows the primary nav (visitor journey), then the
  // remaining sections alphabetically — the raw front-matter weights were
  // tuned for Hextra menus and produce a scrambled order on their own.
  const topOrder = [
    "recipes", "cve-database", "security-remediation", "agents", "mcp-servers",
    "docs", "quickstart", "how-to-use", "fundamentals", "claude",
    "github_copilot", "cursor", "codex", "devin", "automation", "contribute",
  ];
  const rank = (p) => {
    const dir = p.sourcePath.split("/")[0];
    const i = topOrder.indexOf(dir);
    return i === -1 ? topOrder.length : i;
  };
  sidebarTreeCache = pages
    .filter(
      (p) =>
        /^[^/]+\/_index\.md$/.test(p.sourcePath) &&
        isDiscoveryPage(p) &&
        p.fm?.sidebar?.exclude !== true,
    )
    .sort((a, b) => rank(a) - rank(b) || a.linkTitle.localeCompare(b.linkTitle, "en"))
    .map((sec) => ({
      title: sec.linkTitle,
      url: sec.url,
      children: bySection(sec.sourcePath.replace(/_index\.md$/, ""), 1),
    }));
  return sidebarTreeCache;
}

// Unique tag list with page references, mirroring Hugo's tags taxonomy.
function buildTagList() {
  const { pages } = contentIndex.getIndex();
  const map = new Map();
  for (const p of pages) {
    if (!isDiscoveryPage(p)) continue;
    for (const tag of p.tags) {
      const slug = slugifyTag(tag);
      if (!slug) continue;
      if (!map.has(slug)) map.set(slug, { tag, slug, pages: [] });
      map.get(slug).pages.push({
        title: p.title,
        url: canonicalUrlForPage(p),
        date: p.date,
        description: p.description,
      });
    }
  }
  const list = [...map.values()].sort((a, b) => a.slug.localeCompare(b.slug, "en"));
  for (const entry of list) {
    entry.authoredUrl = authoredTagUrl(entry.tag, pages);
    entry.pages.sort(
      (a, b) => (b.date?.getTime() || 0) - (a.date?.getTime() || 0) || a.title.localeCompare(b.title, "en")
    );
  }
  return list;
}

function renderTagCloud(tags) {
  const items = tags
    .map((entry) => {
      const label = `${escapeHtml(entry.tag)} <span>${entry.pages.length}</span>`;
      return entry.authoredUrl
        ? `<a class="sr-tag-chip" href="${entry.authoredUrl}">${label}</a>`
        : `<span class="sr-tag-chip">${label}</span>`;
    })
    .join("\n");
  return `<div class="sr-tag-cloud">${items}</div>`;
}

// Heading HTML has already passed through Markdown rendering, so decode its
// character references before Nunjucks performs the single output escape.
// Keeping this as plain text (rather than marking rendered HTML as safe)
// prevents encoded heading markup from becoming executable in the TOC.
const decodeRenderedHeadingText = markdownIt().utils.unescapeAll;

function extractTocEntries(content) {
  const entries = [];
  const re = /<h([23])[^>]*\sid="([^"]+)"[^>]*>([\s\S]*?)<\/h\1>/g;
  let match;
  while ((match = re.exec(content || ""))) {
    entries.push({
      level: Number(match[1]),
      id: match[2],
      text: decodeRenderedHeadingText(stripTags(match[3])).trim(),
    });
  }
  return entries;
}

module.exports = function (eleventyConfig) {
  // ---------- markdown pipeline ----------
  const md = markdownIt({ html: true, linkify: true, typographer: true })
    .use(markdownItAnchor, {
      slugify: slugifyHeading,
      tabIndex: false,
    })
    .use(markdownItContainer, "callout", {
      marker: ":",
      validate: (params) => params.trim().startsWith("callout"),
      render: (tokens, idx) => {
        if (tokens[idx].nesting === 1) {
          const type = tokens[idx].info.trim().split(/\s+/)[1] || "default";
          return `<div class="hextra-callout" data-type="${escapeHtml(type)}"><div class="hextra-callout-content">\n`;
        }
        return `</div></div>\n`;
      },
    })
    .use(markdownItContainer, "tabs", {
      marker: ":",
      validate: (params) => params.trim() === "tabs",
      render: (tokens, idx) =>
        tokens[idx].nesting === 1
          ? `<div class="sr-tabs" data-sr-tabs>\n`
          : `</div>\n`,
    })
    .use(markdownItContainer, "tab", {
      marker: ":",
      validate: (params) => params.trim().startsWith("tab "),
      render: (tokens, idx) => {
        if (tokens[idx].nesting === 1) {
          const name = tokens[idx].info.trim().replace(/^tab\s+/, "");
          return `<section class="sr-tab" data-sr-tab-title="${escapeHtml(name)}">\n`;
        }
        return `</section>\n`;
      },
    });
  eleventyConfig.setLibrary("md", md);
  eleventyConfig.addPlugin(syntaxHighlight);

  // Hugo shortcode translation runs before markdown rendering.
  const preprocess = createPreprocessor(md);
  eleventyConfig.addWatchTarget("./data/remediation_suite/playbooks.json");
  eleventyConfig.addPreprocessor("hugo-shortcodes", "md", (data, content) => {
    const sourcePath = (data.page.inputPath || "")
      .replace(/\\/g, "/")
      .replace(/^\.\/?content\//, "");
    return preprocess(content, sourcePath);
  });

  // Markdown files are pre-rendered by the preprocessor; no Liquid pass.
  eleventyConfig.setTemplateFormats(["md", "njk", "11ty.js"]);
  eleventyConfig.markdownTemplateEngine = false;

  // ---------- static assets ----------
  eleventyConfig.addPassthroughCopy({ static: "/" });
  eleventyConfig.addPassthroughCopy({ "assets/js": "js" });
  eleventyConfig.addPassthroughCopy({ "assets/css": "css" });

  // ---------- global data ----------
  eleventyConfig.addGlobalData("site", site);
  eleventyConfig.addGlobalData("sidebarTree", () => buildSidebarTree());
  eleventyConfig.addGlobalData("marketplaceData", () => require("./lib/site-data").marketplace());

  // ---------- filters ----------
  // Sidebar HTML, cached per expanded branch: only ~40 distinct sidebars
  // exist across 2,500+ pages, so rendering them through the Nunjucks loop
  // on every page was pure waste. The active link is marked client-side.
  const sidebarCache = new Map();
  eleventyConfig.addFilter("sidebarHtml", (pageUrl) => {
    const tree = buildSidebarTree();
    const currentUrl = typeof pageUrl === "string" ? pageUrl : "";
    const navigationUrl =
      currentUrl.startsWith("/cve/") ||
      (currentUrl.startsWith("/recipes/cve/") && currentUrl !== "/recipes/cve/")
        ? "/cve-database/"
        : currentUrl;
    const active = (nodeUrl) => navigationUrl === nodeUrl || navigationUrl.startsWith(nodeUrl);
    const expandedTop = tree.find((s) => active(s.url));
    const expandedChild = expandedTop?.children.find((c) => active(c.url));
    const key = `${expandedTop?.url || ""}|${expandedChild?.url || ""}`;
    if (sidebarCache.has(key)) return sidebarCache.get(key);

    const link = (n) => `<a href="${n.url}">${escapeHtml(n.title)}</a>`;
    const items = tree.map((section) => {
      const isOpen = section === expandedTop && section.children.length;
      if (!isOpen) {
        return `<li class="sr-sidebar__section">${link(section)}</li>`;
      }
      const children = section.children.map((child) => {
        const grand =
          child === expandedChild && child.children.length
            ? `<ul>${child.children.map((g) => `<li>${link(g)}</li>`).join("")}</ul>`
            : "";
        return `<li>${link(child)}${grand}</li>`;
      });
      return (
        `<li class="sr-sidebar__section is-active"><details open>` +
        `<summary>${link(section)}</summary>` +
        `<ul>${children.join("")}</ul></details></li>`
      );
    });
    const html = `<ul class="sr-sidebar__list">${items.join("")}</ul>`;
    sidebarCache.set(key, html);
    return html;
  });

  eleventyConfig.addFilter("seoHead", seoHead);
  eleventyConfig.addFilter("seoTitle", seoTitle);
  eleventyConfig.addFilter("articleDates", articleDatesFor);
  eleventyConfig.addFilter("presentationText", presentationText);
  eleventyConfig.addFilter("isoDate", isoDate);
  eleventyConfig.addFilter("absURL", feeds.absURL);
  eleventyConfig.addFilter("tagSlug", slugifyTag);
  eleventyConfig.addFilter("authoredTagUrl", authoredTagUrl);
  eleventyConfig.addFilter("cveDisplayTitle", cveDisplayTitle);
  eleventyConfig.addFilter("stripFirstH1", stripFirstH1);

  // Right-rail table of contents from the rendered page HTML (h2/h3).
  eleventyConfig.addFilter("tocEntries", extractTocEntries);

  // Breadcrumb trail resolved against the content index.
  eleventyConfig.addFilter("breadcrumbs", (url) => {
    const { byUrl } = contentIndex.getIndex();
    const crumbs = [];
    const currentUrl = typeof url === "string" ? url : "";
    const segments = currentUrl.replace(/^\/|\/$/g, "").split("/");
    const isCveDetail = currentUrl.startsWith("/recipes/cve/") && currentUrl !== "/recipes/cve/";
    if (currentUrl.startsWith("/cve/archive/")) {
      crumbs.push({ title: "CVE Database", url: "/cve-database/" });
      if (currentUrl !== "/cve/archive/") {
        crumbs.push({ title: "CVE Archive", url: "/cve/archive/" });
        const year = segments[2];
        if (/^\d{4}$/.test(year) && currentUrl !== `/cve/archive/${year}/`) {
          crumbs.push({ title: `${year} CVEs`, url: `/cve/archive/${year}/` });
        }
      }
      return crumbs;
    }
    let acc = "";
    for (let i = 0; i < segments.length - 1; i += 1) {
      acc += `/${segments[i]}`;
      if (isCveDetail && acc === "/recipes") continue;
      if (isCveDetail && acc === "/recipes/cve") {
        crumbs.push({ title: "CVE Database", url: "/cve-database/" });
        continue;
      }
      const page = byUrl.get(`${acc}/`);
      if (page) crumbs.push({ title: page.linkTitle, url: page.url });
    }
    return crumbs;
  });

  // Previous/next among sibling pages in the same source directory.
  eleventyConfig.addFilter("pagerFor", contentIndex.pagerForSourcePath);

  // ---------- virtual templates: feeds ----------
  const virtualFeeds = {
    "recipes-index.11ty.js": { permalink: "/recipes-index.json", build: feeds.recipesIndex },
    "recipes-browser.11ty.js": { permalink: "/recipes-browser.json", build: feeds.recipesBrowser },
    "api-recipes.11ty.js": { permalink: "/api/recipes.json", build: feeds.agentRecipes },
    "api-curated-recipes.11ty.js": {
      permalink: "/api/curated-recipes.json",
      build: feeds.curatedAgentRecipes,
    },
    "api-recipes-index.11ty.js": { permalink: "/api/recipes-index.json", build: feeds.recipesMcpIndex },
    "api-cve-workflows.11ty.js": {
      permalink: "/api/cve-workflows.json",
      build: feeds.cveWorkflows,
    },
    "marketplace-catalog.11ty.js": {
      permalink: "/marketplace-catalog.json",
      build: () => JSON.stringify(require("./lib/site-data").marketplace().catalog),
    },
    "marketplace-inputs.11ty.js": {
      permalink: "/marketplace-input-channels.json",
      build: () => JSON.stringify(require("./lib/site-data").marketplace().input_channels),
    },
    "marketplace-outputs.11ty.js": {
      permalink: "/marketplace-output-channels.json",
      build: () => JSON.stringify(require("./lib/site-data").marketplace().output_channels),
    },
    "marketplace-reports.11ty.js": {
      permalink: "/marketplace-report-profiles.json",
      build: () => JSON.stringify(require("./lib/site-data").marketplace().report_profiles),
    },
    "marketplace-workflows.11ty.js": {
      permalink: "/marketplace-workflow-templates.json",
      build: () => JSON.stringify(require("./lib/site-data").marketplace().workflow_templates),
    },
    "marketplace-manifest.11ty.js": {
      permalink: "/marketplace-control-plane.json",
      build: feeds.marketplaceControlPlane,
    },
    "marketplace-readiness.11ty.js": {
      permalink: "/marketplace-readiness.json",
      build: feeds.marketplaceReadiness,
    },
  };
  for (const [name, def] of Object.entries(virtualFeeds)) {
    eleventyConfig.addTemplate(name, {
      data: () => ({ permalink: def.permalink, eleventyExcludeFromCollections: true }),
      render: () => def.build(),
    });
  }

  // robots.txt (port of layouts/robots.txt)
  eleventyConfig.addTemplate("robots.11ty.js", {
    data: () => ({ permalink: "/robots.txt", eleventyExcludeFromCollections: true }),
    render: renderRobotsTxt,
  });

  // The root sitemap is an index: normal content/tag coverage lives in one
  // child, and each bounded catalog partition gets its own CVE child sitemap.
  const cveSitemapManifest = loadCveSitemapManifest();
  const staticCanonicalCvePages = contentIndex
    .getIndex()
    .pages.filter(
      (page) =>
        page.fm?.canonical_cve_route === false &&
        String(page.fm?.maturity || "").toLowerCase() === "stable" &&
        CANONICAL_CVE_ID.test(String(page.fm?.cve || "")),
    );
  const staticCanonicalCveRoutes = new Map(
    staticCanonicalCvePages.map((page) => [
      String(page.fm.cve),
      canonicalUrlForPage(page),
    ]),
  );
  const staticCanonicalCveIds = new Set(staticCanonicalCveRoutes.keys());
  const cveSearchIndexableIds = loadCveSearchIndexableIds(CVE_CATALOG_ROOT);
  const cveSitemapEntries = planCveSitemaps(
    cveSitemapManifest,
    CVE_SITEMAP_URL_LIMIT,
    CVE_CATALOG_ROOT,
    staticCanonicalCveIds,
    cveSearchIndexableIds,
  );
  const cveArchiveEntries = planCveArchivePages(
    cveSitemapManifest,
    CVE_ARCHIVE_PAGE_SIZE,
    CVE_CATALOG_ROOT,
    staticCanonicalCveIds,
    cveSearchIndexableIds,
    staticCanonicalCveRoutes,
  );
  const recentCatalogItems = buildRecentCatalogItems(cveArchiveEntries);

  eleventyConfig.addTemplate("sitemap-index.11ty.js", {
    data: () => ({ permalink: "/sitemap.xml", eleventyExcludeFromCollections: true }),
    render: () => {
      const pageEntries = planPagesSitemapEntries(contentIndex.getIndex().pages);
      return renderSitemapIndex(
        cveSitemapEntries,
        latestSitemapLastmod(pageEntries),
      );
    },
  });

  eleventyConfig.addTemplate("pages-sitemap.11ty.js", {
    data: () => ({ permalink: "/sitemaps/pages.xml", eleventyExcludeFromCollections: true }),
    render: () => {
      const { pages } = contentIndex.getIndex();
      // Reviewed Markdown CVE overrides canonicalize to /cve/CVE-ID/ and are
      // already present in the partition sitemap. Do not advertise their old
      // content slug as a second crawl target. Generated tag listings are
      // intentionally absent too; manually authored tag pages remain ordinary
      // content entries and retain their own front-matter indexing policy. The
      // noindex CVE archive remains an HTML fallback and is omitted here too.
      return renderPagesSitemap(planPagesSitemapEntries(pages));
    },
  });

  eleventyConfig.addTemplate("cve-sitemaps.11ty.js", {
    data: () => ({
      pagination: { data: "cveSitemapEntries", size: 1, alias: "cveSitemapEntry" },
      cveSitemapEntries,
      eleventyExcludeFromCollections: true,
      permalink: (data) => data.cveSitemapEntry.outputPath,
    }),
    render: (data) =>
      renderCveSitemap(
        data.cveSitemapEntry,
        CVE_CATALOG_ROOT,
        staticCanonicalCveIds,
        cveSearchIndexableIds,
      ),
  });

  eleventyConfig.addTemplate("cve-archive-index.11ty.js", {
    data: () => ({
      permalink: "/cve/archive/index.html",
      eleventyExcludeFromCollections: true,
      layout: "layouts/docs.njk",
      noindex: true,
      noindex_follow: true,
      title: "CVE Archive by Publication Year",
      description:
        "Browse CVEs with stable reviewed guidance or complete source-linked AI enrichment through crawlable publication-year indexes.",
      image: "/images/cve-database-social.png",
      image_width: 1727,
      image_height: 911,
      isSection: true,
    }),
    render: () => {
      const years = [...new Set(cveArchiveEntries.map((entry) => entry.year))]
        .sort((a, b) => b.localeCompare(a, "en"));
      const rows = years.map((year) => {
        const yearEntries = cveArchiveEntries.filter((entry) => entry.year === year);
        const total = yearEntries[0]?.total || 0;
        return (
          `<li><a href="${cveArchiveOutputPath(year, 1)}"><strong>${year}</strong>` +
          `<span>${total.toLocaleString("en-US")} published records</span></a></li>`
        );
      }).join("\n");
      return (
        `<p>Use these server-rendered indexes to browse records with stable reviewed guidance ` +
        `or complete source-linked AI enrichment without JavaScript. Publication year follows ` +
        `the source publication date, which may differ from the year embedded in a CVE ` +
        `identifier. Search the CVE Database for all other catalog records.</p>` +
        `<ul class="cve-archive__years">${rows}</ul>` +
        `<p><a href="/cve-database/">Search and filter the complete CVE Database</a>.</p>`
      );
    },
  });

  eleventyConfig.addTemplate("cve-archive-pages.11ty.js", {
    data: () => ({
      pagination: { data: "cveArchiveEntries", size: 1, alias: "cveArchiveEntry" },
      cveArchiveEntries,
      eleventyExcludeFromCollections: true,
      layout: "layouts/docs.njk",
      noindex: true,
      noindex_follow: true,
      isSection: true,
      image: "/images/cve-database-social.png",
      image_width: 1727,
      image_height: 911,
      permalink: (data) => `${data.cveArchiveEntry.outputPath}index.html`,
      eleventyComputed: {
        title: (data) =>
          `${data.cveArchiveEntry.year} CVE Archive` +
          (data.cveArchiveEntry.pageNumber > 1 ? ` — Page ${data.cveArchiveEntry.pageNumber}` : ""),
        description: (data) =>
          `Browse evidence-qualified ${data.cveArchiveEntry.year} CVEs with severity, CVSS, ` +
          `publication dates, affected ecosystems, and canonical remediation records ` +
          `(page ${data.cveArchiveEntry.pageNumber} of ${data.cveArchiveEntry.pageCount}).`,
      },
    }),
    render: (data) => renderCveArchivePage(data.cveArchiveEntry),
  });

  // Alias redirect stubs (Hugo `aliases:` parity) for URL-safe alias
  // tokens like GHSA ids. Human-phrase aliases with spaces produced
  // unusable URLs under Hugo and are intentionally dropped.
  eleventyConfig.addTemplate("alias-redirects.11ty.js", {
    data: () => {
      const { pages } = contentIndex.getIndex();
      const aliases = [];
      for (const p of pages) {
        const list = p.fm.aliases;
        if (!Array.isArray(list)) continue;
        for (const alias of list) {
          if (typeof alias !== "string" || !/^[A-Za-z0-9._-]+$/.test(alias)) continue;
          const dir = p.url.split("/").slice(0, -2).join("/");
          aliases.push({ path: `${dir}/${alias}/index.html`, target: p.url });
        }
      }
      return {
        pagination: { data: "aliasList", size: 1, alias: "aliasEntry" },
        aliasList: aliases,
        eleventyExcludeFromCollections: true,
        permalink: (data) => data.aliasEntry.path,
      };
    },
    render: (data) => {
      const target = feeds.absURL(data.aliasEntry.target);
      return (
        `<!DOCTYPE html><html lang="en-us"><head>` +
        `<title>${target}</title><link rel="canonical" href="${target}">` +
        `<meta charset="utf-8"><meta http-equiv="refresh" content="0; url=${target}">` +
        `</head></html>`
      );
    },
  });

  // 404 page.
  eleventyConfig.addTemplate("404.11ty.js", {
    data: () => ({
      permalink: "/404.html",
      eleventyExcludeFromCollections: true,
      layout: "layouts/docs.njk",
      title: "Page not found",
      noindex: true,
      isError: true,
    }),
    render: () =>
      `<p>The page you were looking for doesn't exist. ` +
      `Try the <a href="/">home page</a> or browse the <a href="/recipes/">recipe library</a>.</p>`,
  });

  // Tag pages (/tags/ + /tags/<tag>/), replacing Hugo's tags taxonomy.
  eleventyConfig.addTemplate("tags.11ty.js", {
    data: () => ({
      permalink: "/tags/index.html",
      eleventyExcludeFromCollections: true,
      layout: "layouts/docs.njk",
      title: "Tags",
      description: "Browse security remediation recipes by technology, finding class, workflow, and review topic.",
      isSection: true,
      ...GENERATED_TAG_PAGE_SEO,
    }),
    render: () => renderTagCloud(buildTagList()),
  });

  // Section RSS feeds (index.xml under every section URL).
  eleventyConfig.addTemplate("section-rss.11ty.js", {
    data: () => {
      const { pages } = contentIndex.getIndex();
      const sections = pages
        .filter(isSectionFeedEntry)
        .map((sec) => {
          const dir = sec.sourcePath.replace(/_index\.md$/, "");
          const items = sec.url === "/cve-database/"
            ? recentCatalogItems
            : contentIndex
                .regularPagesUnder(dir)
                .filter((p) => p.date && isDiscoveryPage(p))
                .sort((a, b) => b.date - a.date);
          return { title: sec.title, url: sec.url, items };
        })
        .filter((section) => section.items.length > 0);
      return {
        pagination: { data: "rssSections", size: 1, alias: "rssSection" },
        rssSections: sections,
        eleventyExcludeFromCollections: true,
        permalink: (data) => `${data.rssSection.url}index.xml`,
      };
    },
    render: (data) => feeds.sectionRss(data.rssSection, data.rssSection.items),
  });

  // Subpath deploys (GitHub Pages forks) get every root-relative URL
  // rewritten; root deploys skip the extra HTML pass entirely.
  if (site.pathPrefix !== "/") {
    eleventyConfig.addPlugin(require("@11ty/eleventy").EleventyHtmlBasePlugin);
  }

  return {
    dir: {
      input: "content",
      includes: "../_includes",
      data: "../_data",
      output: "public",
    },
    markdownTemplateEngine: false,
    htmlTemplateEngine: "njk",
    pathPrefix: site.pathPrefix,
  };
};

module.exports.cveSitemaps = {
  CANONICAL_CVE_ID,
  CVE_SITEMAP_URL_LIMIT,
  escapeXml,
  isPagesSitemapEntry,
  loadCveSitemapManifest,
  planCveSitemaps,
  renderCveSitemap,
  renderSitemapIndex,
};

module.exports.cveArchives = {
  CVE_ARCHIVE_PAGE_SIZE,
  buildRecentCatalogItems,
  cleanCveSourceText,
  cveArchiveOutputPath,
  cveFeedDescription,
  cveFeedTitle,
  planCveArchivePages,
  renderCveArchivePage,
  safeCanonicalCveRoute,
};

module.exports.pageSitemap = {
  authoredTagUrl,
  GENERATED_TAG_PAGE_SEO,
  latestSitemapLastmod,
  pageSitemapLastmod,
  planPagesSitemapEntries,
  renderTagCloud,
  renderPagesSitemap,
};

module.exports.sectionFeeds = {
  isSectionFeedEntry,
};

module.exports.sidebarNavigation = {
  buildSidebarTree,
};

module.exports.robotsPolicy = {
  AI_CRAWLER_USER_AGENTS,
  ROBOTS_DISALLOW_RULES,
  renderRobotsTxt,
};

module.exports.toc = {
  extractTocEntries,
};
