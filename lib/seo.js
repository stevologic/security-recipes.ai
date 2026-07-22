// Shared metadata and structured-data renderer for every Eleventy page.
// Keep the visible page, canonical URL, social metadata, and JSON-LD aligned:
// search engines should never need to guess which entity a page represents.

const site = require("./site-config");
const { getIndex } = require("./content-index");
const { escapeHtml } = require("./util");
const { gitLastmod } = require("./git-lastmod");

const absURL = (p) => new URL(String(p || "").replace(/^\//, ""), site.baseURL).toString();
const ORGANIZATION_ID = `${site.baseURL}#organization`;
const WEBSITE_ID = `${site.baseURL}#website`;
const MAX_DESCRIPTION_LENGTH = 180;
const MAX_TITLE_LENGTH = 90;
let summariesBySourcePath;

function cleanText(value) {
  // Front matter is plain text, but older records sometimes use Markdown to
  // communicate inline code or emphasis. Search metadata and visible page
  // titles must carry the presented text rather than those source markers.
  let text = String(value || "")
    .replace(/<((?:https?:\/\/|mailto:)[^>]+)>/giu, "$1")
    .replace(/!\[([^\]]*)\]\([^)]*\)/gu, "$1")
    .replace(/\[([^\]]+)\]\([^)]*\)/gu, "$1")
    .replace(/(`+)([^`]*?)\1/gu, "$2");

  // Run the paired-marker rules twice so nested forms such as ***text*** are
  // completely unwrapped without deleting underscores inside identifiers.
  for (let pass = 0; pass < 2; pass += 1) {
    text = text
      .replace(/\*\*([^*\n]+)\*\*/gu, "$1")
      .replace(/__([^_\n]+)__/gu, "$1")
      .replace(/(^|[\s([{"'])\*([^*\n]+)\*(?=$|[\s)\]},.!?:;'"])/gu, "$1$2")
      .replace(/(^|[\s([{"'])_([^_\n]+)_(?=$|[\s)\]},.!?:;'"])/gu, "$1$2");
  }

  return text
    .replace(/\\([\\`*_[\]{}()#+\-.!>])/gu, "$1")
    .replace(/\s+/g, " ")
    .trim();
}

const TRAILING_PHRASE_WORDS = new Set([
  "a", "an", "and", "as", "at", "because", "before", "but", "by", "for",
  "from", "if", "in", "including", "into", "nor", "of", "on", "or", "so",
  "such", "than", "that", "the", "then", "through", "to", "unless", "until",
  "via", "when", "where", "whether", "which", "while", "with", "without", "yet",
]);

const PHRASE_BREAK_WORDS = new Set([
  "and", "as", "before", "but", "by", "for", "from", "including", "into", "or",
  "that", "then", "through", "to", "until", "via", "when", "where", "which",
  "while", "with", "without",
]);

function wordMatches(value) {
  return [...String(value || "").matchAll(/[\p{L}\p{N}][\p{L}\p{N}'’\-]*/gu)];
}

function trimTrailingPhraseWords(value, minimumLength) {
  let candidate = String(value || "").trim();
  while (candidate.length >= minimumLength) {
    const words = wordMatches(candidate);
    const last = words.at(-1);
    if (!last || !TRAILING_PHRASE_WORDS.has(last[0].toLowerCase())) break;
    candidate = candidate
      .slice(0, last.index)
      .replace(/[\s,;:–—-]+$/gu, "")
      .trim();
  }
  return candidate;
}

function minimumCompleteSnippetLength(limit) {
  return Math.max(32, Math.min(68, Math.floor(limit / 2)));
}

function trimTrailingDependentClause(value, minimumLength) {
  const candidate = String(value || "");
  const match = candidate.match(
    /(?:,\s*)?\b(?:and|or|but)\s+(?:(?:how|why|when|where|what|which|who|whether)\b|(?:turns?|translates?|converts?|maps?)\b)[^.!?]*$/iu,
  );
  if (!match || match.index < minimumLength) return candidate;
  return trimTrailingPhraseWords(candidate.slice(0, match.index), minimumLength);
}

function completePhraseCut(value, limit) {
  const minimumLength = minimumCompleteSnippetLength(limit);
  let candidate = trimTrailingPhraseWords(value, minimumLength);
  candidate = trimTrailingDependentClause(candidate, minimumLength);
  const words = wordMatches(candidate);

  // When truncation lands inside a trailing dependent phrase, retain the
  // preceding complete thought. This avoids snippets ending in shapes such as
  // "and an independently reviewed" or "with evidence from".
  for (let index = words.length - 1; index >= 0; index -= 1) {
    const word = words[index];
    if (word.index < Math.floor(limit * 0.48)) break;
    if (!PHRASE_BREAK_WORDS.has(word[0].toLowerCase())) continue;
    const prefix = trimTrailingPhraseWords(
      candidate.slice(0, word.index).replace(/[\s,;:–—-]+$/gu, ""),
      minimumLength,
    );
    if (prefix.length >= minimumLength) return prefix;
  }

  return candidate;
}

function trimSnippetEnding(value) {
  return String(value || "").replace(/[\s,;:–—\-([{]+$/gu, "").trim();
}

function trimUnclosedTrailingGroup(value, minimumLength) {
  const candidate = String(value || "");
  const stack = [];
  const closingToOpening = new Map([[")", "("], ["]", "["], ["}", "{"]]);
  for (let index = 0; index < candidate.length; index += 1) {
    const character = candidate[index];
    if (character === "(" || character === "[" || character === "{") {
      stack.push({ character, index });
      continue;
    }
    const opening = closingToOpening.get(character);
    if (opening && stack.at(-1)?.character === opening) stack.pop();
  }
  const unclosed = stack.at(-1);
  if (unclosed && unclosed.index >= minimumLength) {
    return trimSnippetEnding(candidate.slice(0, unclosed.index));
  }
  return candidate;
}

function punctuateSnippet(value, limit) {
  const minimumLength = minimumCompleteSnippetLength(limit);
  let candidate = trimUnclosedTrailingGroup(trimSnippetEnding(value), minimumLength);
  if (!candidate || /[.!?]$/u.test(candidate)) return candidate;
  if (candidate.length >= limit) {
    const slice = candidate.slice(0, Math.max(1, limit - 1));
    const boundary = slice.lastIndexOf(" ");
    candidate = (boundary > Math.floor(limit / 2) ? slice.slice(0, boundary) : slice).trim();
    candidate = trimUnclosedTrailingGroup(trimSnippetEnding(candidate), minimumLength);
  }
  return candidate ? `${candidate}.` : "";
}

function truncateWords(value, limit) {
  const text = cleanText(value);
  if (text.length <= limit) return text;
  const slice = text.slice(0, Math.max(1, limit + 1));
  const boundary = slice.lastIndexOf(" ");
  return (boundary > Math.floor(limit / 2) ? slice.slice(0, boundary) : text.slice(0, limit)).trim();
}

function shortenDescription(value, limit) {
  const text = cleanText(value);
  if (text.length <= limit) return text;

  let sentenceBoundary = 0;
  for (const match of text.matchAll(/[.!?](?=\s|$)/gu)) {
    const boundary = match.index + match[0].length;
    if (boundary > limit) break;
    sentenceBoundary = boundary;
  }
  const minimumLength = minimumCompleteSnippetLength(limit);
  if (sentenceBoundary >= minimumLength) {
    return text.slice(0, sentenceBoundary);
  }

  const slice = text.slice(0, limit + 1);
  const wordBoundary = slice.lastIndexOf(" ");
  const wordBound = (wordBoundary > 0 ? slice.slice(0, wordBoundary) : text.slice(0, limit)).trim();
  const minimumClauseLength = Math.min(minimumLength, 54);
  const clauseBoundaries = [...wordBound.matchAll(/[;:–—](?=\s|$)/gu)]
    .map((match) => match.index)
    .filter((boundary) => boundary >= minimumClauseLength);
  if (clauseBoundaries.length) {
    return punctuateSnippet(wordBound.slice(0, clauseBoundaries.at(-1)), limit);
  }
  return punctuateSnippet(completePhraseCut(wordBound, limit), limit);
}

function seoTitle(pageTitle) {
  const title = cleanText(pageTitle);
  const brand = site.seo.siteName || site.title;
  if (!title || title.toLowerCase() === site.title.toLowerCase() || title === brand) {
    return site.title;
  }
  const suffix = ` | ${brand}`;
  return `${truncateWords(title, Math.max(24, MAX_TITLE_LENGTH - suffix.length))}${suffix}`;
}

function sourceSummary(sourcePath) {
  if (!sourcePath) return "";
  if (!summariesBySourcePath) {
    summariesBySourcePath = new Map(
      getIndex().pages.map((entry) => [entry.sourcePath, entry.description || entry.summary || ""]),
    );
  }
  return summariesBySourcePath.get(sourcePath) || "";
}

function descriptionFor(ctx) {
  return shortenDescription(
    ctx.description || ctx.summary || sourceSummary(ctx.sourcePath) || site.description,
    MAX_DESCRIPTION_LENGTH,
  );
}

function validIso(value) {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? "" : value.toISOString();
  }
  if (typeof value !== "string") return "";

  const candidate = value.trim();
  if (!candidate) return "";
  const calendarDate = candidate.match(/^(\d{4}-\d{2}-\d{2})(?:T|$)/u)?.[1] || "";
  if (!calendarDate) return "";
  const calendarProbe = new Date(`${calendarDate}T00:00:00.000Z`);
  if (
    Number.isNaN(calendarProbe.getTime()) ||
    calendarProbe.toISOString().slice(0, 10) !== calendarDate
  ) {
    return "";
  }

  // Date-only front matter is unambiguous UTC. Full timestamps must include
  // an explicit timezone so a build machine's locale cannot change metadata.
  if (/^\d{4}-\d{2}-\d{2}$/u.test(candidate)) {
    return calendarProbe.toISOString();
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/iu.test(candidate)) {
    return "";
  }
  const parsed = new Date(candidate);
  return Number.isNaN(parsed.getTime()) ? "" : parsed.toISOString();
}

function articleDatesFor(ctx, gitLastmodResolver = gitLastmod) {
  const suppliedDate = validIso(ctx?.date);
  const hasCveIdentity = /^CVE-\d{4}-\d{4,}$/iu.test(cleanText(ctx?.cve));
  const disclosureDate = hasCveIdentity ? validIso(ctx.disclosed) : "";
  const datePublished = disclosureDate && suppliedDate.slice(0, 10) === disclosureDate.slice(0, 10)
    ? ""
    : suppliedDate;
  const explicitLastmod = validIso(ctx?.lastmod);

  let gitDate = "";
  const sourcePath = String(ctx?.sourcePath || "")
    .replace(/\\/gu, "/")
    .replace(/^(?:\.\/)?content\//u, "");
  if (sourcePath) {
    try {
      gitDate = validIso(gitLastmodResolver().get(`content/${sourcePath}`));
    } catch {
      // Git metadata is an optional freshness signal; authored dates remain
      // authoritative when the repository history is unavailable.
    }
  }

  const dateModified = [explicitLastmod, gitDate, datePublished]
    .filter(Boolean)
    .sort((left, right) => Date.parse(right) - Date.parse(left))[0] || "";

  return { datePublished, dateModified };
}

function imageType(url) {
  const pathname = new URL(url).pathname.toLowerCase();
  if (pathname.endsWith(".png")) return "image/png";
  if (pathname.endsWith(".jpg") || pathname.endsWith(".jpeg")) return "image/jpeg";
  if (pathname.endsWith(".webp")) return "image/webp";
  if (pathname.endsWith(".svg")) return "image/svg+xml";
  return "";
}

function jsonLd(payload) {
  const json = JSON.stringify(payload)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
  return `<script type="application/ld+json">${json}</script>`;
}

function organizationEntity() {
  return {
    "@type": "Organization",
    "@id": ORGANIZATION_ID,
    name: site.seo.siteName || site.title,
    url: absURL(site.seo.organizationUrl || "/"),
    logo: { "@type": "ImageObject", url: absURL("/images/logo.svg") },
    sameAs: site.seo.sameAs,
    publishingPrinciples: absURL(site.seo.publishingPrinciples || "/about/"),
    ethicsPolicy: absURL(site.seo.publishingPrinciples || "/about/"),
    correctionsPolicy: absURL(site.seo.correctionsPolicy || "/about/"),
  };
}

function isAiAttribution(name) {
  const normalized = cleanText(name).toLowerCase();
  return (
    /^(?:codex|chatgpt|claude|gemini|copilot)$/u.test(normalized) ||
    /\b(?:ai[- ]assisted|artificial intelligence|language model|llm|openai|anthropic)\b/u.test(normalized) ||
    /\bgpt(?:[- ]?\d|\b)/u.test(normalized)
  );
}

function isCollectiveAttribution(name, explicitAuthor) {
  const normalized = cleanText(name).toLowerCase();
  const knownOrganizations = [
    site.seo.author,
    site.seo.siteName,
    site.title,
    "security-recipes.ai",
  ].map((value) => cleanText(value).toLowerCase());
  return (
    !explicitAuthor ||
    knownOrganizations.includes(normalized) ||
    /\b(?:contributors?|maintainers?|editorial (?:board|team)|community)\b/u.test(normalized)
  );
}

function knownAuthorProfile(name) {
  const normalizedName = cleanText(name).toLowerCase();
  if (!normalizedName) return null;
  return Object.entries(site.seo.knownAuthors || {})
    .map(([configuredName, profile]) => ({
      ...profile,
      name: cleanText(profile?.name || configuredName),
    }))
    .find((profile) => profile.name.toLowerCase() === normalizedName) || null;
}

function articleAttribution(author) {
  const suppliedName = cleanText(author);
  const fallbackName = cleanText(site.seo.author || site.seo.siteName || site.title);
  const name = suppliedName || fallbackName;
  const aiAssisted = isAiAttribution(name);
  const collective = isCollectiveAttribution(name, suppliedName);

  if (aiAssisted || collective) {
    return {
      author: {
        "@type": "Organization",
        name: aiAssisted ? fallbackName : name,
        url: absURL(site.seo.authorUrl || "/about/"),
      },
      creditText: aiAssisted ? `AI assistance: ${name}` : "",
      metaAuthor: aiAssisted ? fallbackName : name,
    };
  }

  const profile = knownAuthorProfile(name);
  if (profile) {
    const profileUrl = absURL(profile.url);
    return {
      author: {
        "@type": "Person",
        "@id": profileUrl,
        name: profile.name,
        url: profileUrl,
        sameAs: profile.sameAs || [],
      },
      creditText: "",
      metaAuthor: profile.name,
    };
  }

  return {
    author: { "@type": "Person", name },
    creditText: "",
    metaAuthor: name,
  };
}

function breadcrumbEntity(ctx, canonical, pageTitle) {
  const { byUrl } = getIndex();
  const segments = String(ctx.url || "/").replace(/^\/|\/$/g, "").split("/").filter(Boolean);
  const crumbs = [{ name: site.seo.siteName || site.title, item: site.baseURL }];
  const isCveDetail =
    String(ctx.url || "").startsWith("/recipes/cve/") && ctx.url !== "/recipes/cve/";
  const isCveArchive = String(ctx.url || "").startsWith("/cve/archive/");

  if (isCveDetail) {
    const database = byUrl.get("/cve-database/");
    crumbs.push({
      name: database?.title || "CVE Database",
      item: absURL(database?.url || "/cve-database/"),
    });
    crumbs.push({ name: ctx.cve || pageTitle, item: canonical });
  } else if (isCveArchive) {
    crumbs.push({ name: "CVE Database", item: absURL("/cve-database/") });
    crumbs.push({ name: "CVE Archive", item: absURL("/cve/archive/") });
    const year = segments[2];
    if (/^\d{4}$/.test(year)) {
      crumbs.push({ name: `${year} CVEs`, item: absURL(`/cve/archive/${year}/`) });
    }
    if (segments[3] === "page" && /^\d+$/.test(segments[4] || "")) {
      crumbs.push({ name: `Page ${segments[4]}`, item: canonical });
    }
  } else {
    let acc = "";
    for (const segment of segments) {
      acc += `/${segment}`;
      const page = byUrl.get(`${acc}/`);
      if (page) crumbs.push({ name: page.title || pageTitle, item: absURL(page.url) });
    }
  }

  if (crumbs.length < 2) return null;
  return {
    "@type": "BreadcrumbList",
    "@id": `${canonical}#breadcrumb`,
    itemListElement: crumbs.map((crumb, index) => ({
      "@type": "ListItem",
      position: index + 1,
      name: crumb.name,
      item: crumb.item,
    })),
  };
}

function howToEntity(ctx, canonical, description) {
  const source = ctx.howTo;
  if (!source || typeof source !== "object" || !Array.isArray(source.steps)) return null;
  const steps = source.steps
    .map((step, index) => {
      const name = cleanText(step && step.name);
      const text = cleanText(step && step.text);
      if (!name || !text) return null;
      return {
        "@type": "HowToStep",
        position: index + 1,
        name,
        text,
      };
    })
    .filter(Boolean);
  if (steps.length < 2) return null;
  return {
    "@type": "HowTo",
    "@id": `${canonical}#how-to`,
    name: cleanText(source.name) || cleanText(ctx.title),
    description,
    url: canonical,
    inLanguage: "en-US",
    publisher: { "@id": ORGANIZATION_ID },
    step: steps,
  };
}

// ctx: { url, title, description, summary, tags, author, image, noindex,
//        noindexFollow,
//        cve, canonicalCveRoute, date, lastmod, disclosed, howTo, sourcePath,
//        isHome, isSection, isArticle }
function seoHead(ctx) {
  const isHome = !!ctx.isHome;
  const isSection = !!ctx.isSection;
  const isPage = !isHome && !isSection;
  const isArticle = isPage && !ctx.isError && ctx.isArticle !== false;
  const pageTitle = cleanText(ctx.title || site.title);
  const description = descriptionFor(ctx);
  const canonicalCve = /^CVE-\d{4}-\d{4,}$/i.test(cleanText(ctx.cve))
    ? cleanText(ctx.cve).toUpperCase()
    : "";
  const canonical = absURL(
    canonicalCve && ctx.canonicalCveRoute !== false ? `/cve/${canonicalCve}/` : ctx.url,
  );
  const imageAbs = absURL(ctx.image || site.seo.defaultImage);
  const imageW = ctx.imageWidth || site.seo.defaultImageWidth;
  const imageH = ctx.imageHeight || site.seo.defaultImageHeight;
  const imageMime = imageType(imageAbs);
  const attribution = articleAttribution(ctx.author);
  const author = attribution.metaAuthor;
  const robots = ctx.noindex || ctx.isError
    ? (!ctx.isError && ctx.noindexFollow ? "noindex,follow" : "noindex,nofollow")
    : "index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1";
  const { datePublished, dateModified } = articleDatesFor({
    ...ctx,
    cve: canonicalCve,
  });
  const siteName = site.seo.siteName || site.title;
  const ogType = isArticle ? "article" : "website";

  const lines = [
    `<meta name="description" content="${escapeHtml(description)}">`,
    `<meta name="author" content="${escapeHtml(author)}">`,
    `<meta name="robots" content="${robots}">`,
    `<meta name="googlebot" content="${robots}">`,
    `<meta name="referrer" content="strict-origin-when-cross-origin">`,
    ctx.isError ? "" : `<link rel="canonical" href="${canonical}">`,
    `<meta property="og:type" content="${ogType}">`,
    `<meta property="og:site_name" content="${escapeHtml(siteName)}">`,
    `<meta property="og:title" content="${escapeHtml(pageTitle)}">`,
    `<meta property="og:description" content="${escapeHtml(description)}">`,
    `<meta property="og:url" content="${canonical}">`,
    `<meta property="og:locale" content="en_US">`,
    `<meta property="og:image" content="${imageAbs}">`,
    imageMime ? `<meta property="og:image:type" content="${imageMime}">` : "",
    imageW ? `<meta property="og:image:width" content="${imageW}">` : "",
    imageH ? `<meta property="og:image:height" content="${imageH}">` : "",
    `<meta property="og:image:alt" content="${escapeHtml(`${pageTitle} — ${siteName}`)}">`,
  ];

  if (isArticle) {
    if (datePublished) lines.push(`<meta property="article:published_time" content="${datePublished}">`);
    if (dateModified) lines.push(`<meta property="article:modified_time" content="${dateModified}">`);
    lines.push(`<meta property="article:author" content="${escapeHtml(author)}">`);
    for (const tag of ctx.tags || []) {
      lines.push(`<meta property="article:tag" content="${escapeHtml(tag)}">`);
    }
  }

  lines.push(
    `<meta name="twitter:card" content="summary_large_image">`,
    `<meta name="twitter:title" content="${escapeHtml(pageTitle)}">`,
    `<meta name="twitter:description" content="${escapeHtml(description)}">`,
    `<meta name="twitter:image" content="${imageAbs}">`,
    `<meta name="twitter:image:alt" content="${escapeHtml(`${pageTitle} — ${siteName}`)}">`,
  );

  const webPageId = `${canonical}#webpage`;
  const graph = [organizationEntity()];
  const website = {
    "@type": "WebSite",
    "@id": WEBSITE_ID,
    url: site.baseURL,
    name: siteName,
    description: site.description,
    inLanguage: "en-US",
    publisher: { "@id": ORGANIZATION_ID },
  };
  if (isHome) {
    website.potentialAction = {
      "@type": "SearchAction",
      target: `${site.baseURL.replace(/\/$/, "")}/cve-database/?q={search_term_string}`,
      "query-input": "required name=search_term_string",
    };
  }
  graph.push(website);

  const webPage = {
    "@type": isSection ? "CollectionPage" : "WebPage",
    "@id": webPageId,
    url: canonical,
    name: pageTitle,
    description,
    inLanguage: "en-US",
    isPartOf: { "@id": WEBSITE_ID },
    publisher: { "@id": ORGANIZATION_ID },
    primaryImageOfPage: { "@type": "ImageObject", url: imageAbs },
  };
  if (datePublished) webPage.datePublished = datePublished;
  if (dateModified) webPage.dateModified = dateModified;
  graph.push(webPage);

  if (String(ctx.url || "") === "/cve-database/") {
    const datasetId = `${canonical}#dataset`;
    webPage.mainEntity = { "@id": datasetId };
    graph.push({
      "@type": "Dataset",
      "@id": datasetId,
      name: "Security Recipes CVE remediation catalog",
      description,
      url: canonical,
      creator: { "@id": ORGANIZATION_ID },
      license: "https://www.apache.org/licenses/LICENSE-2.0",
      isAccessibleForFree: true,
      keywords: [
        "CVE",
        "vulnerability remediation",
        "AI-assisted remediation",
        "security agents",
      ],
      includedInDataCatalog: {
        "@type": "DataCatalog",
        name: "Security Recipes CVE Database",
      },
      distribution: {
        "@type": "DataDownload",
        encodingFormat: "application/json",
        contentUrl: absURL("/api/cve-catalog/manifest.json"),
      },
    });
  }

  const howTo = howToEntity(ctx, canonical, description);
  if (howTo) {
    webPage.mainEntity = { "@id": howTo["@id"] };
    graph.push(howTo);
  }

  if (isArticle) {
    const articleId = `${canonical}#article`;
    const article = {
      "@type": "Article",
      additionalType: "https://schema.org/TechArticle",
      "@id": articleId,
      headline: pageTitle,
      description,
      url: canonical,
      image: imageAbs,
      inLanguage: "en-US",
      author: attribution.author,
      publisher: { "@id": ORGANIZATION_ID },
      isPartOf: { "@id": webPageId },
      mainEntityOfPage: { "@id": webPageId },
    };
    if (attribution.creditText) article.creditText = attribution.creditText;
    if (datePublished) article.datePublished = datePublished;
    if (dateModified) article.dateModified = dateModified;
    const keywords = (ctx.keywords && ctx.keywords.length ? ctx.keywords : ctx.tags) || [];
    if (keywords.length) article.keywords = keywords.join(", ");
    if (canonicalCve) {
      article.about = {
        "@type": "DefinedTerm",
        name: canonicalCve,
        termCode: canonicalCve,
        inDefinedTermSet: "https://www.cve.org/",
        sameAs: `https://nvd.nist.gov/vuln/detail/${canonicalCve}`,
      };
    }
    webPage.mainEntity = { "@id": articleId };
    graph.push(article);
  }

  const breadcrumb = breadcrumbEntity(ctx, canonical, pageTitle);
  if (breadcrumb) {
    webPage.breadcrumb = { "@id": breadcrumb["@id"] };
    graph.push(breadcrumb);
  }

  lines.push(jsonLd({ "@context": "https://schema.org", "@graph": graph }));
  return lines.filter(Boolean).join("\n");
}

module.exports = {
  articleDatesFor,
  descriptionFor,
  presentationText: cleanText,
  seoHead,
  seoTitle,
  shortenDescription,
};
