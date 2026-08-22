---
title: Content Verification and SEO Quality Gates
linkTitle: Content Verification
weight: 33
date: 2026-05-02
lastmod: 2026-08-21
description: Reproduce the source, artifact, catalog, link, structured-data, indexability, and duplicate-content gates used to publish Security Recipes.
---

## Current automated gates

The repository now treats verification as repeatable code rather than a static
certification claim. A green result belongs to the exact revision that ran the
checks; this page describes what the current Eleventy, Python, MCP, catalog, and
rendered-site gates enforce.

| Area | What the gate enforces |
| --- | --- |
| Content and playbook contracts | Required frontmatter, workflow visuals, decision gates, evidence/output contracts, documented commands, referenced files, and MCP tool names must be present and internally consistent. |
| Deterministic artifacts | Registered generators must remain acyclic and reproduce every checked-in evidence pack, catalog artifact, and integrity hash without drift. |
| CVE publication | Only stable reviewed Markdown or complete source-linked enrichment may own an indexable canonical CVE route. Canonical ownership, citations, title and description limits, sitemap membership, and source evidence must agree. |
| Technical SEO | Every indexable page must have one unique title, description, self-canonical, H1, robots policy, and valid JSON-LD. Internal links, fragments, crawl reachability, depth, redirects, and sitemap parity are checked from rendered HTML. |
| Duplicate-content control | Generated code-hygiene and compliance children are `noindex,follow` while they share a development template. A bounded five-word-shingle similarity gate fails if a materially duplicated child becomes indexable before its body is differentiated. |
| Catalog and MCP integrity | The rolling CVE manifest, shards, exact lookup, search allowlist, remediation composition, read-only MCP schemas, and evidence provenance must validate together. |
| CISA KEV authority | Recipe `kev` flags and KEV dates must match the live [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), not secondary blogs. Development CVE drafts stay `noindex` and are not attached to catalog shards. |
| Build and performance | Static output, browser payloads, initial server-rendered content, lazy data loading, shared assets, and page-size budgets must stay within the checked limits. |

The [visual guide](/how-to-use/) explains the publication gate from the reader's
perspective. Pages may remain browsable and linked for review while
`noindex,follow`; indexability is earned by unique, trustworthy content, not by
the existence of a generated URL.

Reproduce the principal gates from a checkout:

```bash
python scripts/run_checks.py
npm run build
npm run check:performance
python scripts/validate_cve_catalog.py
```

{{< callout type="warning" >}}
**Historical snapshot below.** The remainder of this page records checks from
a dated Codex verification session on 2026-05-02. Its Hugo, Markdown, CVE-page,
and link counts are preserved for audit history and are not current totals.
The original request asked for
GPT-5.5 Pro and GPT-5.5 Extra High wording; this page does not claim an
independent GPT-5.5 Pro or GPT-5.5 Extra High certification unless a
separate run artifact is attached.
{{< /callout >}}

## Historical scope (2026-05-02)

The audit covered the Markdown content, generated recipe index, external
reference links, current vendor documentation, CVE source coverage, and
containerized Hugo build output for `security-recipes.ai`.

- Markdown files checked: **92**
- CVE recipe pages checked: **15**
- Verification date: **2026-05-02**
- Verification status label: **verified in this Codex session; GPT-5.5 Pro
  certification not independently asserted**

## Historical source checks

| Area | Check | Result |
| --- | --- | --- |
| OWASP Top 10 | Compared site references to the official [OWASP Top 10:2025](https://owasp.org/Top10/2025/) release. | Updated stale 2026 wording and recipe slugs to 2025. |
| OpenAI Codex | Compared CLI examples to OpenAI's [Codex quickstart](https://developers.openai.com/codex/quickstart), [non-interactive mode](https://developers.openai.com/codex/noninteractive), and [CLI reference](https://developers.openai.com/codex/cli/reference). | Replaced deprecated auto-mode examples with `codex exec --sandbox workspace-write --json`. |
| Devin | Compared onboarding and API examples to Devin's [API overview](https://docs.devin.ai/api-reference/overview), [authentication](https://docs.devin.ai/api-reference/authentication), and [Create Session](https://docs.devin.ai/api-reference/v3/sessions/post-organizations-sessions) docs. | Updated legacy session-create guidance to the v3 organization API and service-user credentials. |
| Claude Code | Checked Anthropic's [IDE integrations](https://docs.anthropic.com/en/docs/claude-code/ide-integrations). | Replaced a stale VS Code Marketplace link with the official IDE integration docs. |
| GitHub Code Scanning | Checked GitHub's [code scanning issue tracking](https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-code-scanning-alerts/linking-code-scanning-alerts-to-github-issues). | Replaced a stale Marketplace action reference with the current native issue-tracking flow and API-based fallback. |
| SGLang CVE-2026-5760 | Checked CERT/CC, NVD, and upstream release information for CVE-2026-5760. | Clarified that sources checked on 2026-05-02 show mitigation/workaround guidance, not a verified upstream fixed release. |
| CVE recipes | Required every CVE recipe page to include at least one primary or high-signal source URL. | 15/15 CVE recipe pages now include source URLs. |

## Historical automated checks

| Check | Command shape | Result |
| --- | --- | --- |
| Frontmatter integrity | Python scan of all `content/**/*.md` files. | **Pass:** 0 missing frontmatter, 0 missing titles. |
| Internal `relref` targets | Python scan of Hugo `relref` shortcode targets. | **Pass:** 0 missing targets after ignoring escaped documentation examples. |
| Stale terminology | Python/PowerShell search for legacy OWASP labels, deprecated Codex flags, legacy Devin endpoints, and stale Devin/GitHub/Claude links. | **Pass:** 0 matches. |
| CVE source coverage | Python scan for CVE pages without CVE/NVD/vendor/advisory source URLs. | **Pass:** 0 gaps across 15 CVE recipe pages. |
| External Markdown links | Python link checker over Markdown and autolinks, skipping fenced code, localhost, example domains, and template placeholders. | **Reviewed:** 116 URLs checked. 113 returned success directly. Three checker exceptions were investigated separately. |
| Hugo builder build | `docker build --target builder -t security-recipes-ai-verify-builder .` | **Pass:** Hugo generated 407 pages, 19 static files, and 25 aliases. |
| Runtime image build | `docker build -t security-recipes-ai-verify .` | **Pass:** final nginx runtime image built successfully. |
| Runtime smoke test | `docker run --rm -d -p 3000:80 security-recipes-ai-verify` then HTTP GET `/`. | **Pass:** `http://localhost:3000/` returned HTTP 200. |
| Recipe routing benchmark | `scripts/evaluate_recipe_routing.py --enforce-thresholds` against `data/evaluations/recipe-routing-golden.json`. | **Pass:** 8 cases, top-1 accuracy 0.875, top-3 accuracy 1.000; thresholds were 0.750 and 0.950. |

## Historical link exceptions reviewed

The link checker reported three non-2xx/3xx responses after the fixes:

- `https://openai.com/api/pricing` returned HTTP 403 to the script, but the
  official OpenAI pricing page loaded through browser verification.
- `https://openai.com/enterprise-privacy` returned HTTP 403 to the script, but
  the official OpenAI enterprise privacy page loaded through browser
  verification.
- `https://platform.openai.com/` returned HTTP 403 to the script. This is an
  authenticated application entry point and is retained as an onboarding link.
## Historical benchmark notes

The routing benchmark initially failed top-3 accuracy because the generated
`recipes-index.json` omitted section pages such as
`/security-remediation/base-images/` and `/security-remediation/gatekeeping/`.
The index generator now includes both regular pages and section pages, which
matches the benchmark's workflow-routing expectations.

## Verification limits

This audit verifies that cited vendor and advisory references align with the
site's claims as of 2026-05-02, that stale known-bad wording was removed, and
that the site builds and routes correctly. It is not a legal, medical,
compliance, or incident-response certification. Operational recipes still
require human review against the target environment before use.
