// Port of layouts/partials/custom/seo.html: Open Graph, Twitter Card,
// robots/canonical/keywords meta, and JSON-LD (WebSite + Organization on
// the home page, TechArticle + BreadcrumbList on content pages,
// CollectionPage on section pages). Same fallback chains.

const site = require("./site-config");
const { getIndex } = require("./content-index");
const { escapeHtml } = require("./util");
const { lastmodFor } = require("./git-lastmod");

const absURL = (p) => new URL(String(p).replace(/^\//, ""), site.baseURL).toString();

// ctx: { url, title, description, summary, tags, author, image, noindex,
//        keywords, date, sourcePath, isHome, isSection }
function seoHead(ctx) {
  const isHome = !!ctx.isHome;
  const isSection = !!ctx.isSection;
  const isPage = !isHome && !isSection;

  const pageTitle = ctx.title || site.title;
  let description = ctx.description || ctx.summary || site.description;
  description = String(description).replace(/\s+/g, " ").trim();
  if (description.length > 300) description = `${description.slice(0, 297)}…`;

  const canonical = absURL(ctx.url);
  const ogType = isPage ? "article" : "website";
  const imageAbs = absURL(ctx.image || site.seo.defaultImage);
  const imageW = ctx.imageWidth || site.seo.defaultImageWidth;
  const imageH = ctx.imageHeight || site.seo.defaultImageHeight;
  const author = ctx.author || site.seo.author || site.title;
  const robots = ctx.noindex
    ? "noindex,nofollow"
    : "index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1";
  const keywords =
    (ctx.keywords && ctx.keywords.length && ctx.keywords) ||
    (ctx.tags && ctx.tags.length && ctx.tags) ||
    site.seo.defaultKeywords;
  const siteName = site.seo.siteName || site.title;
  const dateIso = ctx.date ? new Date(ctx.date).toISOString() : "";
  const lastmod = ctx.sourcePath ? `${lastmodFor(ctx.sourcePath, ctx.date)}T00:00:00Z` : dateIso;

  const lines = [
    `<meta name="description" content="${escapeHtml(description)}">`,
    keywords.length ? `<meta name="keywords" content="${escapeHtml(keywords.join(", "))}">` : "",
    `<meta name="author" content="${escapeHtml(author)}">`,
    `<meta name="robots" content="${robots}">`,
    `<meta name="googlebot" content="${robots}">`,
    `<meta name="referrer" content="strict-origin-when-cross-origin">`,
    `<link rel="canonical" href="${canonical}">`,
    `<meta property="og:type" content="${ogType}">`,
    `<meta property="og:site_name" content="${escapeHtml(siteName)}">`,
    `<meta property="og:title" content="${escapeHtml(pageTitle)}">`,
    `<meta property="og:description" content="${escapeHtml(description)}">`,
    `<meta property="og:url" content="${canonical}">`,
    `<meta property="og:locale" content="en_US">`,
    `<meta property="og:image" content="${imageAbs}">`,
    `<meta property="og:image:url" content="${imageAbs}">`,
    `<meta property="og:image:width" content="${imageW}">`,
    `<meta property="og:image:height" content="${imageH}">`,
    `<meta property="og:image:alt" content="${escapeHtml(`${pageTitle} — ${siteName}`)}">`,
  ];

  if (ogType === "article") {
    if (dateIso) lines.push(`<meta property="article:published_time" content="${dateIso}">`);
    if (lastmod) lines.push(`<meta property="article:modified_time" content="${lastmod}">`);
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
    `<meta name="twitter:image:alt" content="${escapeHtml(`${pageTitle} — ${siteName}`)}">`
  );

  const ld = (obj) => {
    const json = JSON.stringify(obj)
      .replace(/</g, "\\u003c")
      .replace(/\u2028/g, "\\u2028")
      .replace(/\u2029/g, "\\u2029");
    return `<script type="application/ld+json">${json}</script>`;
  };

  if (isHome) {
    lines.push(
      ld({
        "@context": "https://schema.org",
        "@graph": [
          {
            "@type": "WebSite",
            "@id": `${site.baseURL}#website`,
            url: site.baseURL,
            name: siteName,
            description: site.description,
            inLanguage: "en-US",
            potentialAction: {
              "@type": "SearchAction",
              target: `${site.baseURL.replace(/\/$/, "")}/?q={search_term_string}`,
              "query-input": "required name=search_term_string",
            },
          },
          {
            "@type": "Organization",
            "@id": `${site.baseURL}#organization`,
            name: siteName,
            url: site.baseURL,
            logo: { "@type": "ImageObject", url: absURL("images/logo.svg") },
            sameAs: site.seo.sameAs,
          },
        ],
      })
    );
  }

  if (isPage) {
    const article = {
      "@context": "https://schema.org",
      "@type": "TechArticle",
      headline: pageTitle,
      description,
      url: canonical,
      image: imageAbs,
      author: { "@type": "Person", name: author },
      publisher: {
        "@type": "Organization",
        name: siteName,
        logo: { "@type": "ImageObject", url: absURL("images/logo.svg") },
      },
      mainEntityOfPage: { "@type": "WebPage", "@id": canonical },
    };
    if (dateIso) article.datePublished = dateIso;
    if (lastmod) article.dateModified = lastmod;
    if (ctx.tags && ctx.tags.length) article.keywords = ctx.tags.join(", ");
    lines.push(ld(article));

    // BreadcrumbList from the URL ancestry.
    const { byUrl } = getIndex();
    const segments = ctx.url.replace(/^\/|\/$/g, "").split("/");
    const crumbs = [{ name: siteName, item: site.baseURL }];
    let acc = "";
    for (let i = 0; i < segments.length; i += 1) {
      acc += `/${segments[i]}`;
      const page = byUrl.get(`${acc}/`);
      if (page) crumbs.push({ name: page.title || siteName, item: absURL(page.url) });
    }
    if (crumbs.length > 1) {
      lines.push(
        ld({
          "@context": "https://schema.org",
          "@type": "BreadcrumbList",
          itemListElement: crumbs.map((c, i) => ({
            "@type": "ListItem",
            position: i + 1,
            name: c.name,
            item: c.item,
          })),
        })
      );
    }
  }

  if (isSection) {
    lines.push(
      ld({
        "@context": "https://schema.org",
        "@type": "CollectionPage",
        name: pageTitle,
        description,
        url: canonical,
        inLanguage: "en-US",
        isPartOf: { "@type": "WebSite", url: site.baseURL, name: siteName },
      })
    );
  }

  return lines.filter(Boolean).join("\n");
}

module.exports = { seoHead };
