const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  articleDatesFor,
  descriptionFor,
  presentationText,
  seoHead,
  seoTitle,
  shortenDescription,
} = require("../lib/seo");
const { getIndex, isDiscoveryPage } = require("../lib/content-index");
const site = require("../lib/site-config");
const contentComputed = require("../content/content.11tydata").eleventyComputed;

function structuredDocument(output) {
  const matches = [...output.matchAll(
    /<script type="application\/ld\+json">(.*?)<\/script>/gs,
  )];
  assert.equal(matches.length, 1, "expected one JSON-LD document");
  const document = JSON.parse(matches[0][1]);
  assert.equal(document["@context"], "https://schema.org");
  assert.ok(Array.isArray(document["@graph"]), "expected an @graph array");
  return document;
}

function graphEntity(document, type) {
  return document["@graph"].find((entry) => entry["@type"] === type);
}

function metaContent(output, attribute, value) {
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = output.match(
    new RegExp(`<meta ${attribute}="${escaped}" content="([^"]*)">`),
  );
  assert.ok(match, `expected ${attribute}="${value}" metadata`);
  return match[1];
}

function markdownPage(sourcePath, overrides = {}) {
  const stem = sourcePath.replace(/\.md$/u, "");
  return {
    page: {
      inputPath: `./content/${sourcePath}`,
      filePathStem: `/${stem}`,
    },
    ...overrides,
  };
}

test("JSON-LD serialization cannot break out of its script element", () => {
  const description = "risk </script><script>globalThis.PWNED=1</script> next line";
  const output = seoHead({
    url: "/security-test/",
    title: "Security test",
    description,
    isSection: true,
  });
  const match = output.match(/<script type="application\/ld\+json">(.*?)<\/script>/s);

  assert.ok(match, "expected a JSON-LD script element");
  assert.equal(match[1].includes("<"), false);
  assert.match(match[1], /\\u003c\/script>/);
  const document = structuredDocument(output);
  const page = graphEntity(document, "CollectionPage");
  assert.equal(page.description, description);
  assert.equal(page.name, "Security test");
});

test("articles use Google-supported schema and an accountable editorial organization", () => {
  const output = seoHead({
    url: "/quickstart/",
    title: "Quickstart",
    description: "A bounded remediation quickstart.",
  });
  const document = structuredDocument(output);
  const organization = graphEntity(document, "Organization");
  const website = graphEntity(document, "WebSite");
  const page = graphEntity(document, "WebPage");
  const article = graphEntity(document, "Article");

  assert.ok(organization);
  assert.equal(organization.name, "Security Recipes");
  assert.equal(organization.publishingPrinciples, "https://security-recipes.ai/about/#editorial-principles");
  assert.equal(article.additionalType, "https://schema.org/TechArticle");
  assert.deepEqual(article.author, {
    "@type": "Organization",
    name: "Security Recipes contributors",
    url: "https://security-recipes.ai/about/",
  });
  assert.deepEqual(article.publisher, { "@id": organization["@id"] });
  assert.deepEqual(website.publisher, { "@id": organization["@id"] });
  assert.deepEqual(page.publisher, { "@id": organization["@id"] });
});

test("collective and AI bylines are never represented as people", () => {
  const collective = graphEntity(structuredDocument(seoHead({
    url: "/collective-article/",
    title: "Collective article",
    description: "Collectively maintained guidance.",
    author: "Security Recipes Maintainers",
  })), "Article");
  assert.deepEqual(collective.author, {
    "@type": "Organization",
    name: "Security Recipes Maintainers",
    url: "https://security-recipes.ai/about/",
  });
  assert.equal(collective.creditText, undefined);

  const ai = graphEntity(structuredDocument(seoHead({
    url: "/ai-assisted-article/",
    title: "AI-assisted article",
    description: "Guidance drafted with model assistance.",
    author: "Codex",
  })), "Article");
  assert.equal(ai.author["@type"], "Organization");
  assert.equal(ai.author.name, "Security Recipes contributors");
  assert.equal(ai.author.url, "https://security-recipes.ai/about/");
  assert.equal(ai.creditText, "AI assistance: Codex");

  const person = graphEntity(structuredDocument(seoHead({
    url: "/person-article/",
    title: "Person article",
    description: "Individually authored guidance.",
    author: "Stephen M Abbott",
  })), "Article");
  assert.deepEqual(person.author, {
    "@type": "Person",
    "@id": "https://security-recipes.ai/about/#stephen-m-abbott",
    name: "Stephen M Abbott",
    url: "https://security-recipes.ai/about/#stephen-m-abbott",
    sameAs: ["https://github.com/stevologic"],
  });

  const unknownPerson = graphEntity(structuredDocument(seoHead({
    url: "/unknown-person-article/",
    title: "Unknown person article",
    description: "Individually authored guidance.",
    author: "Example Human",
  })), "Article");
  assert.deepEqual(unknownPerson.author, { "@type": "Person", name: "Example Human" });
});

test("known authors map to a public, stable identity page", () => {
  assert.deepEqual(site.seo.knownAuthors["Stephen M Abbott"], {
    name: "Stephen M Abbott",
    url: "/about/#stephen-m-abbott",
    sameAs: ["https://github.com/stevologic"],
  });

  const about = fs.readFileSync(
    path.join(__dirname, "..", "content", "about", "_index.md"),
    "utf8",
  );
  assert.match(about, /^## Stephen M Abbott$/mu);
  assert.match(about, /https:\/\/github\.com\/stevologic/u);
  assert.match(about, /https:\/\/github\.com\/stevologic\/security-recipes\.ai\/commits\/main/u);
});

test("article pages expose visible authorship, review methodology, and corrections links", () => {
  const template = fs.readFileSync(
    path.join(__dirname, "..", "_includes", "layouts", "docs.njk"),
    "utf8",
  );
  const config = fs.readFileSync(path.join(__dirname, "..", "eleventy.config.js"), "utf8");

  assert.match(template, /aria-label="Authorship and review"/u);
  assert.match(template, />Authorship and review</u);
  assert.match(template, /isArticle: isArticle/u);
  assert.match(template, /if isArticle and not isError/u);
  assert.match(template, /Editorial owner: <a href="\/about\/">/u);
  assert.match(template, /AI assistance: \{\{ attributionName \| escape \}\}/u);
  assert.match(template, /site\.seo\.knownAuthors\[attributionName\]/u);
  assert.match(template, /href="\{\{ knownAuthor\.url \| escape \}\}"/u);
  assert.match(template, /href="\/about\/#editorial-principles">Review methodology</u);
  assert.match(template, /href="\/about\/#corrections">Corrections policy</u);
  assert.match(template, /lastmod: lastmod/u);
  assert.match(template, /\| articleDates/u);
  assert.match(template, />Last updated <time datetime=/u);
  assert.match(config, /addFilter\("articleDates", articleDatesFor\)/u);
});

test("every indexable authored Article carries deterministic dates without Git", () => {
  const incomplete = getIndex().pages
    .filter((entry) => {
      if (!isDiscoveryPage(entry) || entry.fm.noindex === true) return false;
      return contentComputed.isArticle(markdownPage(entry.sourcePath, entry.fm));
    })
    .flatMap((entry) => {
      const dates = articleDatesFor({
        ...entry.fm,
        sourcePath: entry.sourcePath,
      }, () => new Map());
      return dates.datePublished && dates.dateModified
        ? []
        : [{
            sourcePath: entry.sourcePath,
            datePublished: dates.datePublished,
            dateModified: dates.dateModified,
          }];
    });

  assert.deepEqual(incomplete, []);
});

test("a CVE disclosure date is not mislabeled as the article publication date", () => {
  const output = seoHead({
    url: "/recipes/cve/example/",
    title: "CVE-2026-12345 example",
    description: "Example remediation guidance.",
    cve: "CVE-2026-12345",
    date: "2026-01-02",
    disclosed: "2026-01-02",
  });
  const article = graphEntity(structuredDocument(output), "Article");

  assert.equal(article.datePublished, undefined);
  assert.equal(article.dateModified, undefined);
  assert.doesNotMatch(output, /property="article:published_time"/u);
  assert.doesNotMatch(output, /property="article:modified_time"/u);
});

test("authored article dates choose the newest valid lastmod, git, or publication value", () => {
  const sourcePath = "docs/freshness-example.md";
  const gitDates = new Map([
    [`content/${sourcePath}`, "2026-07-21T18:30:00-07:00"],
  ]);
  const fromGit = articleDatesFor({
    sourcePath,
    date: "2026-05-02",
    lastmod: "2026-07-20",
  }, () => gitDates);

  assert.deepEqual(fromGit, {
    datePublished: "2026-05-02T00:00:00.000Z",
    dateModified: "2026-07-22T01:30:00.000Z",
  });

  const fromFrontMatter = articleDatesFor({
    sourcePath: `content\\${sourcePath}`,
    date: new Date("2026-05-02T00:00:00.000Z"),
    lastmod: "2026-07-23T09:15:00Z",
  }, () => gitDates);
  assert.equal(fromFrontMatter.dateModified, "2026-07-23T09:15:00.000Z");
});

test("authored article dates reject ambiguous, malformed, and impossible timestamps", () => {
  const dates = articleDatesFor({
    date: "05/02/2026",
    lastmod: "2026-02-30T00:00:00Z",
    sourcePath: "docs/invalid-freshness.md",
  }, () => new Map([
    ["content/docs/invalid-freshness.md", "2026-07-21T12:00:00"],
  ]));

  assert.deepEqual(dates, { datePublished: "", dateModified: "" });
});

test("CVE disclosure dates stay out of publication and modification metadata", () => {
  const sourcePath = "recipes/cve/cve-2026-12345-example.md";
  const dates = articleDatesFor({
    sourcePath,
    cve: "CVE-2026-12345",
    date: "2026-01-02T12:00:00Z",
    disclosed: "2026-01-02",
  }, () => new Map());

  assert.deepEqual(dates, { datePublished: "", dateModified: "" });

  const reviewed = articleDatesFor({
    sourcePath,
    cve: "CVE-2026-12345",
    date: "2026-01-02",
    disclosed: "2026-01-02",
  }, () => new Map([
    [`content/${sourcePath}`, "2026-07-21T12:00:00Z"],
  ]));
  assert.deepEqual(reviewed, {
    datePublished: "",
    dateModified: "2026-07-21T12:00:00.000Z",
  });
});

test("Article metadata uses explicit authored lastmod when it is newest", () => {
  const output = seoHead({
    url: "/docs/freshness-example/",
    title: "Freshness example",
    description: "A dated article used to verify freshness metadata.",
    date: "2026-05-02",
    lastmod: "2026-06-03T09:15:00Z",
  });
  const document = structuredDocument(output);
  const page = graphEntity(document, "WebPage");
  const article = graphEntity(document, "Article");

  assert.equal(article.datePublished, "2026-05-02T00:00:00.000Z");
  assert.equal(article.dateModified, "2026-06-03T09:15:00.000Z");
  assert.equal(page.datePublished, article.datePublished);
  assert.equal(page.dateModified, article.dateModified);
  assert.equal(
    metaContent(output, "property", "article:published_time"),
    article.datePublished,
  );
  assert.equal(
    metaContent(output, "property", "article:modified_time"),
    article.dateModified,
  );
});

test("reviewed CVEs use the clean canonical route, CVE breadcrumbs, and DefinedTerm", () => {
  const sourceUrl = "/recipes/cve/cve-2024-3400-reviewed-title/";
  const canonical = "https://security-recipes.ai/cve/CVE-2024-3400/";
  const output = seoHead({
    url: sourceUrl,
    title: "CVE-2024-3400 reviewed recipe",
    description: "Reviewed product-specific guidance.",
    cve: "cve-2024-3400",
    isSection: false,
  });

  assert.match(output, new RegExp(`<link rel="canonical" href="${canonical}">`));
  assert.match(output, new RegExp(`<meta property="og:url" content="${canonical}">`));

  const document = structuredDocument(output);
  const page = graphEntity(document, "WebPage");
  const article = graphEntity(document, "Article");
  const breadcrumbs = graphEntity(document, "BreadcrumbList");

  assert.equal(page.url, canonical);
  assert.equal(article.url, canonical);
  assert.deepEqual(article.about, {
    "@type": "DefinedTerm",
    name: "CVE-2024-3400",
    termCode: "CVE-2024-3400",
    inDefinedTermSet: "https://www.cve.org/",
    sameAs: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
  });
  assert.ok(breadcrumbs, "expected a BreadcrumbList for the CVE record");
  assert.deepEqual(
    breadcrumbs.itemListElement.map((entry) => new URL(entry.item).pathname),
    ["/", "/cve-database/", "/cve/CVE-2024-3400/"],
  );
  assert.equal(breadcrumbs.itemListElement[1].name, "CVE Database");
  assert.deepEqual(page.breadcrumb, { "@id": breadcrumbs["@id"] });
});

test("homepage structured search targets the standalone CVE database", () => {
  const output = seoHead({
    url: "/",
    title: "Security Recipes",
    description: "Open security intelligence.",
    isHome: true,
  });
  const document = structuredDocument(output);
  const website = graphEntity(document, "WebSite");

  assert.deepEqual(website.potentialAction, {
    "@type": "SearchAction",
    target: "https://security-recipes.ai/cve-database/?q={search_term_string}",
    "query-input": "required name=search_term_string",
  });
});

test("CVE database identifies its downloadable catalog as a Dataset", () => {
  const output = seoHead({
    url: "/cve-database/",
    title: "CVE Database",
    description: "Search sourced CVE records and remediation guidance.",
    isSection: true,
  });
  const document = structuredDocument(output);
  const page = graphEntity(document, "CollectionPage");
  const dataset = graphEntity(document, "Dataset");

  assert.ok(dataset);
  assert.deepEqual(page.mainEntity, { "@id": dataset["@id"] });
  assert.equal(dataset.url, "https://security-recipes.ai/cve-database/");
  assert.equal(
    dataset.distribution.contentUrl,
    "https://security-recipes.ai/api/cve-catalog/manifest.json",
  );
  assert.equal(dataset.distribution.encodingFormat, "application/json");
});

test("CVE archive pages expose the database hierarchy as structured breadcrumbs", () => {
  const output = seoHead({
    url: "/cve/archive/2026/page/2/",
    title: "2026 CVE Archive — Page 2",
    description: "Browse the second page of 2026 vulnerability records.",
    noindex: true,
    noindexFollow: true,
    isSection: true,
  });
  const breadcrumbs = graphEntity(structuredDocument(output), "BreadcrumbList");

  assert.equal(metaContent(output, "name", "robots"), "noindex,follow");
  assert.equal(metaContent(output, "name", "googlebot"), "noindex,follow");
  assert.match(
    output,
    /<link rel="canonical" href="https:\/\/security-recipes\.ai\/cve\/archive\/2026\/page\/2\/">/u,
  );

  assert.deepEqual(
    breadcrumbs.itemListElement.map((entry) => entry.name),
    ["Security Recipes", "CVE Database", "CVE Archive", "2026 CVEs", "Page 2"],
  );
  assert.deepEqual(
    breadcrumbs.itemListElement.map((entry) => new URL(entry.item).pathname),
    ["/", "/cve-database/", "/cve/archive/", "/cve/archive/2026/", "/cve/archive/2026/page/2/"],
  );
});

test("virtual collection templates retain explicit section semantics", () => {
  const virtualPage = {
    page: {
      inputPath: "./cve-archive-pages.11ty.js",
      filePathStem: "/cve-archive-pages.11ty",
    },
    isSection: true,
    isHome: false,
  };

  assert.equal(contentComputed.isSection(virtualPage), true);
  assert.equal(contentComputed.isHome(virtualPage), false);
  assert.equal(contentComputed.sectionFeed(virtualPage), false);
  assert.equal(contentComputed.pageKind(virtualPage), "collection");

  const cveDatabaseSection = {
    page: {
      inputPath: "./content/cve-database/_index.md",
      filePathStem: "/cve-database/_index",
    },
    page_kind: "collection",
  };
  assert.equal(contentComputed.sectionFeed(cveDatabaseSection), true);

  const output = seoHead({
    url: "/cve/archive/2026/",
    title: "2026 CVE Archive",
    description: "Browse canonical CVE records published in 2026.",
    isSection: contentComputed.isSection(virtualPage),
  });
  const document = structuredDocument(output);

  assert.ok(graphEntity(document, "CollectionPage"));
  assert.equal(graphEntity(document, "Article"), undefined);
  assert.equal(metaContent(output, "property", "og:type"), "website");
});

test("semantic page kinds distinguish guide articles, collections, and utility pages", () => {
  const leafGuide = markdownPage("codex/_index.md");
  const guideCollection = markdownPage("security-remediation/_index.md");
  const explicitCollection = markdownPage("cve-database/_index.md", {
    page_kind: "collection",
  });
  const utilityPage = markdownPage("about/_index.md", {
    page_kind: "webpage",
  });
  const regularArticle = markdownPage("docs/cve-intelligence-intake.md");

  assert.equal(contentComputed.pageKind(leafGuide), "article");
  assert.equal(contentComputed.isSection(leafGuide), false);
  assert.equal(contentComputed.isArticle(leafGuide), true);
  assert.equal(contentComputed.sectionFeed(leafGuide), false);
  assert.equal(contentComputed.pageKind(guideCollection), "collection");
  assert.equal(contentComputed.isSection(guideCollection), true);
  assert.equal(contentComputed.isArticle(guideCollection), false);
  assert.equal(contentComputed.pageKind(explicitCollection), "collection");
  assert.equal(contentComputed.isSection(explicitCollection), true);
  assert.equal(contentComputed.pageKind(utilityPage), "webpage");
  assert.equal(contentComputed.isSection(utilityPage), false);
  assert.equal(contentComputed.isArticle(utilityPage), false);
  assert.equal(contentComputed.pageKind(regularArticle), "article");
  assert.equal(contentComputed.isSection(regularArticle), false);
  assert.throws(
    () => contentComputed.pageKind(markdownPage("example/_index.md", { page_kind: "landing" })),
    /Expected article, collection, or webpage/u,
  );

  const articleOutput = seoHead({
    url: "/codex/",
    title: "Codex vulnerability remediation",
    description: "Use Codex to remediate vulnerabilities with bounded evidence and tests.",
    isSection: false,
    isArticle: true,
  });
  assert.ok(graphEntity(structuredDocument(articleOutput), "Article"));
  assert.equal(metaContent(articleOutput, "property", "og:type"), "article");

  const utilityOutput = seoHead({
    url: "/about/",
    title: "About Security Recipes",
    description: "Editorial ownership, review methodology, and corrections policy.",
    isSection: false,
    isArticle: false,
  });
  const utilityDocument = structuredDocument(utilityOutput);
  assert.ok(graphEntity(utilityDocument, "WebPage"));
  assert.equal(graphEntity(utilityDocument, "Article"), undefined);
  assert.equal(metaContent(utilityOutput, "property", "og:type"), "website");
});

test("semantic page-kind overrides are explicit in the authored front matter", () => {
  const expected = new Map([
    ["about/_index.md", "webpage"],
    ["agents/_index.md", "collection"],
    ["contribute/_index.md", "webpage"],
    ["cve-database/_index.md", "collection"],
    ["docs/marketplace-gallery/_index.md", "collection"],
    ["recipes/sources/_index.md", "collection"],
  ]);
  const authored = getIndex().pages
    .filter((page) => page.fm.page_kind)
    .map((page) => [page.sourcePath, page.fm.page_kind]);

  assert.deepEqual(new Map(authored), expected);
  for (const [sourcePath, kind] of expected) {
    const page = getIndex().pages.find((entry) => entry.sourcePath === sourcePath);
    assert.ok(page, `missing authored page ${sourcePath}`);
    assert.equal(contentComputed.pageKind(markdownPage(sourcePath, page.fm)), kind);
  }
});

test("visible remediation steps can define a HowTo main entity", () => {
  const output = seoHead({
    url: "/security-remediation/",
    title: "AI Vulnerability Remediation Playbooks",
    description: "Use an AI coding agent to remediate one vulnerability safely.",
    isSection: true,
    howTo: {
      name: "How to remediate a vulnerability with an AI coding agent",
      steps: [
        { name: "Establish exposure", text: "Prove the affected component is present." },
        { name: "Verify the fix", text: "Test, rebuild, and rescan the artifact." },
      ],
    },
  });
  const document = structuredDocument(output);
  const page = graphEntity(document, "CollectionPage");
  const howTo = graphEntity(document, "HowTo");

  assert.ok(howTo);
  assert.deepEqual(page.mainEntity, { "@id": howTo["@id"] });
  assert.equal(howTo.step.length, 2);
  assert.deepEqual(
    howTo.step.map((step) => step["@type"]),
    ["HowToStep", "HowToStep"],
  );
  assert.deepEqual(
    howTo.step.map((step) => step.position),
    [1, 2],
  );
});

test("error pages force noindex and omit canonical and article metadata", () => {
  const output = seoHead({
    url: "/404.html",
    title: "Page not found",
    description: "The requested page does not exist.",
    isError: true,
  });
  const document = structuredDocument(output);

  assert.equal(metaContent(output, "name", "robots"), "noindex,nofollow");
  assert.equal(metaContent(output, "name", "googlebot"), "noindex,nofollow");
  assert.doesNotMatch(output, /<link rel="canonical"/);
  assert.doesNotMatch(output, /property="article:/);
  assert.equal(graphEntity(document, "Article"), undefined);
  assert.ok(graphEntity(document, "WebPage"));
});

test("seoTitle keeps branded titles concise without duplicating the brand", () => {
  assert.equal(seoTitle("Security Recipes"), "security-recipes.ai");
  assert.equal(seoTitle("CVE-2026-14956"), "CVE-2026-14956 | Security Recipes");
  assert.equal(
    seoTitle("CVE-2026-14956 Example Gateway RCE"),
    "CVE-2026-14956 Example Gateway RCE | Security Recipes",
  );
  assert.equal(
    seoTitle("AI agent runtime controls"),
    "AI agent runtime controls | Security Recipes",
  );

  const title = seoTitle(
    "Runtime controls for telemetry-driven AI agent session disablement",
  );
  assert.ok(title.length <= 70, `expected at most 70 characters, got ${title.length}`);
  assert.doesNotMatch(title, /Security Recipes/u);
  assert.doesNotMatch(title, /…/u);

  const cveTitle = seoTitle(
    "CVE-2026-14956 Critical Remote Code Execution in an Extremely Long Product Name",
  );
  assert.ok(cveTitle.length <= 70, `expected at most 70 characters, got ${cveTitle.length}`);
  assert.match(cveTitle, /^CVE-2026-14956\b/u);
  assert.doesNotMatch(cveTitle, /Security Recipes/u);
});

test("titles and descriptions expose presented text instead of Markdown source markers", () => {
  const title = "CVE-2017-18342 — PyYAML default `load` resolves **arbitrary tags**";
  const description =
    "Replace `yaml.load` with **safe loading** and follow the [reviewed recipe](https://example.test/recipe).";
  const cleanTitle = "CVE-2017-18342 — PyYAML default load resolves arbitrary tags";
  const cleanDescription =
    "Replace yaml.load with safe loading and follow the reviewed recipe.";

  assert.equal(presentationText(title), cleanTitle);
  assert.equal(presentationText(description), cleanDescription);
  assert.equal(presentationText("Keep package_name and safe_load intact"), "Keep package_name and safe_load intact");
  assert.equal(seoTitle(title), cleanTitle);

  const output = seoHead({
    url: "/recipes/cve/cve-2017-18342-pyyaml/",
    title,
    description,
    cve: "CVE-2017-18342",
    canonicalCveRoute: false,
  });
  const document = structuredDocument(output);
  assert.equal(metaContent(output, "property", "og:title"), cleanTitle);
  assert.equal(metaContent(output, "name", "description"), cleanDescription);
  assert.equal(graphEntity(document, "Article").headline, cleanTitle);
  assert.equal(graphEntity(document, "Article").description, cleanDescription);
});

test("the docs layout uses presentation-safe text for visible headings", () => {
  const template = fs.readFileSync(
    path.join(__dirname, "..", "_includes", "layouts", "docs.njk"),
    "utf8",
  );

  assert.match(template, /detailTitle \| presentationText \| escape/u);
  assert.match(template, /<h1 class="sr-page-title">\{\{ title \| presentationText \| escape \}\}<\/h1>/u);
  assert.match(template, /description \| presentationText \| escape/u);
});

test("description shortening prefers complete sentences and never adds an ellipsis", () => {
  const firstSentence =
    "Apply the vendor patch after validating compatibility in a representative staging environment.";
  const sentenceAware = descriptionFor({
    description: `${firstSentence} Then verify every affected deployment with retained scanner evidence and an independently reviewed rollback procedure before closing the finding.`,
  });
  assert.equal(sentenceAware, firstSentence);
  assert.doesNotMatch(sentenceAware, /…$/u);

  const wordBound = descriptionFor({ description: "bounded ".repeat(40) });
  assert.ok(wordBound.length <= 165);
  assert.equal(wordBound.slice(0, -1).split(" ").every((word) => word === "bounded"), true);
  assert.match(wordBound, /[.!?]$/u);
  assert.doesNotMatch(wordBound, /…$/u);
});

test("description shortening drops a trailing dependent phrase", () => {
  const description =
    "Use an AI coding agent to establish repository exposure, apply the narrowest safe fix, preserve scanner evidence, and record an independently reviewed rollback procedure before closing the finding with the responsible owner.";
  const shortened = shortenDescription(description, 170);

  assert.equal(
    shortened,
    "Use an AI coding agent to establish repository exposure, apply the narrowest safe fix, preserve scanner evidence.",
  );
  assert.ok(shortened.length <= 170);
  assert.match(shortened, /[.!?]$/u);
  assert.doesNotMatch(
    shortened,
    /\b(?:a|an|and|as|at|before|by|for|from|in|of|on|or|the|to|via|with)$/iu,
  );
  assert.doesNotMatch(shortened, /…$/u);
});

test("description shortening removes dangling groups and dependent clauses", () => {
  const metrics = shortenDescription(
    "The measurement layer for an agentic remediation program — what to count, how to compute it, and what the numbers have to show before leadership (or a regulator) will let you scale further.",
    180,
  );
  assert.equal(metrics, "The measurement layer for an agentic remediation program.");

  const reviewer = shortenDescription(
    "The human-in-the-loop operating manual — what a reviewer is actually checking when they approve (or reject) an agent-opened PR or triage ticket, and how to keep that checklist from degrading into a rubber stamp.",
    180,
  );
  assert.equal(
    reviewer,
    "The human-in-the-loop operating manual — what a reviewer is actually checking when they approve (or reject) an agent-opened PR.",
  );

  const image = shortenDescription(
    "A tool-agnostic prompt that takes a CVE finding scoped to a base image or an OS-package layer, and produces a reviewer-ready PR that bumps the FROM line (or the package install layer), rebuilds and rescans the image.",
    180,
  );
  assert.doesNotMatch(image, /(?:[,;:]|\(|\[|\{)\s*[.!?]$/u);
  assert.equal((image.match(/\(/g) || []).length, (image.match(/\)/g) || []).length);
});

test("high-intent pages publish deliberate complete descriptions", () => {
  const sourcePaths = [
    "recipes/devin/scheduled-vulnerability-remediation.md",
    "recipes/general/base-image-bump.md",
    "security-remediation/metrics/_index.md",
    "security-remediation/reviewer-playbook/_index.md",
    "security-remediation/secure-context-value-model/_index.md",
    "security-remediation/secure-context-customer-proof-pack/_index.md",
  ];
  for (const sourcePath of sourcePaths) {
    const description = descriptionFor({ sourcePath });
    assert.ok(description.length >= 80, `${sourcePath} description is too thin`);
    assert.ok(description.length <= 165, `${sourcePath} description is too long`);
    assert.match(description, /[.!?]$/u, `${sourcePath} description is incomplete`);
    assert.doesNotMatch(description, /(?:[,;:]|\(|\[|\{)\s*[.!?]$/u);
    assert.doesNotMatch(description, /\breviewers,\s+and\s+reviewers\b/iu);
  }
});

test("the recipe recommender example cannot become a second HTML title element", () => {
  const source = fs.readFileSync(
    path.join(
      __dirname,
      "..",
      "content",
      "security-remediation",
      "recipe-recommender",
      "_index.md",
    ),
    "utf8",
  );

  assert.doesNotMatch(source, /<title(?:\s|>)/iu);
  assert.match(source, /Recommended recipe: \[recipe title\] — https:\/\/security-recipes\.ai\//u);
});

test("descriptions within the metadata limit are preserved", () => {
  const description = "Explicit reviewed remediation guidance remains unchanged.";
  assert.equal(descriptionFor({ description }), description);
});

test("missing descriptions are derived from indexed page content and shared across metadata", () => {
  const sourcePath = "recipes/claude/cve-triage-skill.md";
  const description = descriptionFor({ sourcePath });

  assert.match(description, /^A Claude Code skill that turns a fresh CVE or Dependabot alert/);
  assert.ok(description.length <= 165);
  assert.notEqual(description, descriptionFor({}));

  const output = seoHead({
    url: "/recipes/claude/cve-triage-skill/",
    title: "CVE triage skill",
    sourcePath,
  });
  const article = graphEntity(structuredDocument(output), "Article");
  assert.equal(metaContent(output, "name", "description"), description);
  assert.equal(article.description, description);
});

test("social metadata carries the supplied image type, dimensions, and Twitter parity", () => {
  const image = "https://security-recipes.ai/images/cve-database-social.png";
  const output = seoHead({
    url: "/cve-database/",
    title: "CVE Database",
    description: "Search CVE records.",
    image: "/images/cve-database-social.png",
    imageWidth: 1727,
    imageHeight: 911,
    isSection: true,
  });

  assert.equal(metaContent(output, "property", "og:image"), image);
  assert.equal(metaContent(output, "property", "og:image:type"), "image/png");
  assert.equal(metaContent(output, "property", "og:image:width"), "1727");
  assert.equal(metaContent(output, "property", "og:image:height"), "911");
  assert.equal(metaContent(output, "name", "twitter:image"), image);
  assert.equal(metaContent(output, "name", "twitter:card"), "summary_large_image");
});

test("the default social card is a real raster asset with exact metadata dimensions", () => {
  assert.match(site.seo.defaultImage, /\.png$/u);
  const imagePath = path.join(__dirname, "..", "static", site.seo.defaultImage);
  const image = fs.readFileSync(imagePath);
  assert.ok(
    image.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])),
    "default social card must have a PNG signature",
  );
  assert.equal(image.toString("ascii", 12, 16), "IHDR");
  assert.equal(image.readUInt32BE(16), site.seo.defaultImageWidth);
  assert.equal(image.readUInt32BE(20), site.seo.defaultImageHeight);

  const output = seoHead({
    url: "/security-remediation/",
    title: "AI Vulnerability Remediation Playbooks",
    description: "Evidence-gated vulnerability remediation for AI coding agents.",
    isSection: true,
  });
  assert.equal(
    metaContent(output, "property", "og:image"),
    "https://security-recipes.ai/images/og-card.png",
  );
  assert.equal(metaContent(output, "property", "og:image:type"), "image/png");
  assert.equal(metaContent(output, "property", "og:image:width"), "1731");
  assert.equal(metaContent(output, "property", "og:image:height"), "909");
  assert.equal(
    metaContent(output, "name", "twitter:image"),
    "https://security-recipes.ai/images/og-card.png",
  );
});

test("historical reviewed CVEs outside the dynamic catalog remain self-canonical", () => {
  const url = "/recipes/cve/cve-2014-0160-heartbleed/";
  const output = seoHead({
    url,
    title: "CVE-2014-0160 — Heartbleed",
    description: "Reviewed Heartbleed remediation guidance.",
    cve: "CVE-2014-0160",
    canonicalCveRoute: false,
    isSection: false,
  });

  assert.match(
    output,
    /<link rel="canonical" href="https:\/\/security-recipes\.ai\/recipes\/cve\/cve-2014-0160-heartbleed\/">/,
  );
  assert.doesNotMatch(output, /rel="canonical" href="[^"]*\/cve\/CVE-2014-0160\/"/);
  const article = graphEntity(structuredDocument(output), "Article");
  assert.equal(article.url, "https://security-recipes.ai/recipes/cve/cve-2014-0160-heartbleed/");
  assert.equal(article.about.termCode, "CVE-2014-0160");
});
