// Eleventy build for security-recipes.ai — replaces the Hugo + Hextra
// toolchain. content/*.md is consumed unchanged (Hugo shortcodes are
// translated by lib/hugo-preprocess.js); all JSON feeds, robots, sitemap,
// RSS, and tag pages are emitted as virtual templates so no build
// scaffolding lives inside content/.

const markdownIt = require("markdown-it");
const markdownItAnchor = require("markdown-it-anchor");
const markdownItContainer = require("markdown-it-container");
const syntaxHighlight = require("@11ty/eleventy-plugin-syntaxhighlight");

const site = require("./lib/site-config");
const contentIndex = require("./lib/content-index");
const { createPreprocessor } = require("./lib/hugo-preprocess");
const feeds = require("./lib/feeds");
const { escapeHtml, stripTags, isoDate } = require("./lib/util");
const { lastmodFor } = require("./lib/git-lastmod");
const { seoHead } = require("./lib/seo");
const { isDiscoveryPage } = contentIndex;

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
    "recipes", "security-remediation", "agents", "mcp-servers",
    "docs", "quickstart", "how-to-use", "fundamentals", "claude",
    "github_copilot", "cursor", "codex", "devin", "automation", "contribute",
  ];
  const rank = (p) => {
    const dir = p.sourcePath.split("/")[0];
    const i = topOrder.indexOf(dir);
    return i === -1 ? topOrder.length : i;
  };
  sidebarTreeCache = pages
    .filter((p) => /^[^/]+\/_index\.md$/.test(p.sourcePath))
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
        url: p.url,
        date: p.date,
        description: p.description,
      });
    }
  }
  const list = [...map.values()].sort((a, b) => a.slug.localeCompare(b.slug, "en"));
  for (const entry of list) {
    entry.pages.sort(
      (a, b) => (b.date?.getTime() || 0) - (a.date?.getTime() || 0) || a.title.localeCompare(b.title, "en")
    );
  }
  return list;
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
    const active = (nodeUrl) => pageUrl === nodeUrl || pageUrl.startsWith(nodeUrl);
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
  eleventyConfig.addFilter("isoDate", isoDate);
  eleventyConfig.addFilter("absURL", feeds.absURL);
  eleventyConfig.addFilter("tagSlug", slugifyTag);

  // Right-rail table of contents from the rendered page HTML (h2/h3).
  eleventyConfig.addFilter("tocEntries", (content) => {
    const entries = [];
    const re = /<h([23])[^>]*\sid="([^"]+)"[^>]*>([\s\S]*?)<\/h\1>/g;
    let m;
    while ((m = re.exec(content || ""))) {
      entries.push({
        level: Number(m[1]),
        id: m[2],
        text: stripTags(m[3]).trim(),
      });
    }
    return entries;
  });

  // Breadcrumb trail resolved against the content index.
  eleventyConfig.addFilter("breadcrumbs", (url) => {
    const { byUrl } = contentIndex.getIndex();
    const crumbs = [];
    const segments = url.replace(/^\/|\/$/g, "").split("/");
    let acc = "";
    for (let i = 0; i < segments.length - 1; i += 1) {
      acc += `/${segments[i]}`;
      const page = byUrl.get(`${acc}/`);
      if (page) crumbs.push({ title: page.linkTitle, url: page.url });
    }
    return crumbs;
  });

  // Previous/next among sibling pages in the same source directory.
  eleventyConfig.addFilter("pagerFor", (inputPath) => {
    const sourcePath = (inputPath || "").replace(/\\/g, "/").replace(/^\.\/?content\//, "");
    if (!sourcePath || sourcePath.endsWith("_index.md")) return {};
    const dir = sourcePath.split("/").slice(0, -1).join("/");
    const siblings = contentIndex.siblingsByDir().get(dir) || [];
    const i = siblings.findIndex((p) => p.sourcePath === sourcePath);
    if (i === -1) return {};
    return {
      prev: i > 0 ? { title: siblings[i - 1].linkTitle, url: siblings[i - 1].url } : null,
      next: i < siblings.length - 1 ? { title: siblings[i + 1].linkTitle, url: siblings[i + 1].url } : null,
    };
  });

  // ---------- virtual templates: feeds ----------
  const virtualFeeds = {
    "recipes-index.11ty.js": { permalink: "/recipes-index.json", build: feeds.recipesIndex },
    "recipes-browser.11ty.js": { permalink: "/recipes-browser.json", build: feeds.recipesBrowser },
    "api-recipes.11ty.js": { permalink: "/api/recipes.json", build: feeds.agentRecipes },
    "api-recipes-index.11ty.js": { permalink: "/api/recipes-index.json", build: feeds.recipesMcpIndex },
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

  // Marketplace globals as one cacheable script instead of ~100KB of JSON
  // inlined into every page head (which alone made the Hugo output huge).
  eleventyConfig.addTemplate("marketplace-globals.11ty.js", {
    data: () => ({ permalink: "/js/marketplace-globals.js", eleventyExcludeFromCollections: true }),
    render: () => {
      const data = require("./lib/site-data").marketplace();
      return (
        `window.__SECURITY_RECIPES_MARKETPLACE = {` +
        `catalog: ${JSON.stringify(data.catalog)},` +
        `inputChannels: ${JSON.stringify(data.input_channels)},` +
        `outputChannels: ${JSON.stringify(data.output_channels)},` +
        `reportProfiles: ${JSON.stringify(data.report_profiles)},` +
        `workflowTemplates: ${JSON.stringify(data.workflow_templates)},` +
        `readinessProfiles: ${JSON.stringify(data.readiness_profiles)}` +
        `};\n`
      );
    },
  });

  // robots.txt (port of layouts/robots.txt)
  eleventyConfig.addTemplate("robots.11ty.js", {
    data: () => ({ permalink: "/robots.txt", eleventyExcludeFromCollections: true }),
    render: () =>
      [
        `# robots.txt for ${site.title}`,
        `# Generated at build time.`,
        ``,
        `User-agent: *`,
        `Allow: /`,
        `Disallow: /search/`,
        `Disallow: /tags/null/`,
        `Disallow: /tags/Null/`,
        ``,
        `# AI / LLM crawlers — explicitly allowed.`,
        ...["GPTBot", "ClaudeBot", "Claude-Web", "Google-Extended", "PerplexityBot", "anthropic-ai", "cohere-ai", "CCBot"].flatMap(
          (ua) => [`User-agent: ${ua}`, `Disallow:`, ``]
        ),
        `Sitemap: ${feeds.absURL("/sitemap.xml")}`,
        ``,
        `Host: ${site.baseURL.replace(/^https?:\/\//, "").replace(/\/$/, "")}`,
        ``,
      ].join("\n"),
  });

  // sitemap.xml — every content page plus tag pages.
  eleventyConfig.addTemplate("sitemap.11ty.js", {
    data: () => ({ permalink: "/sitemap.xml", eleventyExcludeFromCollections: true }),
    render: () => {
      const { pages } = contentIndex.getIndex();
      const urls = [];
      const row = (loc, lastmod) =>
        `<url><loc>${feeds.absURL(loc)}</loc>` +
        (lastmod ? `<lastmod>${lastmod}</lastmod>` : "") +
        `<changefreq>weekly</changefreq><priority>0.7</priority></url>`;
      for (const p of pages.filter(isDiscoveryPage)) {
        urls.push(row(p.url, lastmodFor(p.sourcePath, p.date)));
      }
      const tags = buildTagList();
      urls.push(row("/tags/"));
      for (const t of tags) urls.push(row(`/tags/${t.slug}/`));
      return (
        `<?xml version="1.0" encoding="utf-8"?>` +
        `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
        urls.join("") +
        `</urlset>`
      );
    },
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
    }),
    render: () =>
      `<h1>404 — page not found</h1>\n<p>The page you were looking for doesn't exist. ` +
      `Try the <a href="/">home page</a> or browse the <a href="/recipes/">recipe library</a>.</p>`,
  });

  // Tag pages (/tags/ + /tags/<tag>/), replacing Hugo's tags taxonomy.
  eleventyConfig.addTemplate("tags.11ty.js", {
    data: () => ({
      permalink: "/tags/index.html",
      eleventyExcludeFromCollections: true,
      layout: "layouts/docs.njk",
      title: "Tags",
    }),
    render: () => {
      const tags = buildTagList();
      const items = tags
        .map(
          (t) =>
            `<a class="sr-tag-chip" href="/tags/${t.slug}/">${escapeHtml(t.tag)} <span>${t.pages.length}</span></a>`
        )
        .join("\n");
      return `<h1>Tags</h1>\n<div class="sr-tag-cloud">${items}</div>`;
    },
  });
  eleventyConfig.addTemplate("tag-pages.11ty.js", {
    data: () => ({
      pagination: { data: "tagList", size: 1, alias: "tagEntry" },
      tagList: buildTagList(),
      eleventyExcludeFromCollections: true,
      layout: "layouts/docs.njk",
      permalink: (data) => `/tags/${data.tagEntry.slug}/index.html`,
      eleventyComputed: {
        title: (data) => data.tagEntry.tag,
      },
    }),
    render: (data) => {
      const rows = data.tagEntry.pages
        .map(
          (p) =>
            `<li><a href="${p.url}">${escapeHtml(p.title)}</a>` +
            (p.date ? ` <time>${isoDate(p.date)}</time>` : "") +
            `</li>`
        )
        .join("\n");
      return `<h1>${escapeHtml(data.tagEntry.tag)}</h1>\n<ul class="sr-tag-list">${rows}</ul>`;
    },
  });

  // Section RSS feeds (index.xml under every section URL).
  eleventyConfig.addTemplate("section-rss.11ty.js", {
    data: () => {
      const { pages } = contentIndex.getIndex();
      const sections = pages
        .filter((p) => p.isSection)
        .map((sec) => {
          const dir = sec.sourcePath.replace(/_index\.md$/, "");
          const items = contentIndex
            .regularPagesUnder(dir)
            .filter((p) => p.date && isDiscoveryPage(p))
            .sort((a, b) => b.date - a.date);
          return { title: sec.title, url: sec.url, items };
        });
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
