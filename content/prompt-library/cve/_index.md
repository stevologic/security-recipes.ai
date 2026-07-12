---
title: CVE Recipes
linkTitle: CVE Recipes
weight: 9
sidebar:
  open: false
description: >
  Complete ten-year High and Critical CVE intelligence, joined to
  conservative remediation recipes for agents and human reviewers.
---

{{< callout type="info" >}}
**Complete facts, careful remediation.** The catalog covers every non-rejected
NVD record published in the rolling ten-year window that has at least one
NVD-supplied CVSS v2, v3, or v4 score of 7.0 or higher. Each record composes
with one or more reviewed remediation archetypes. A product-specific Markdown
recipe overrides that baseline only after it reaches `stable` maturity and has
important patch history, exposure conditions, or mitigations that a generic
workflow cannot safely infer.
{{< /callout >}}

## Two recipe tiers

1. **Complete composed catalog.** NVD identity, descriptions, CVSS
   observations, CWE data, affected CPE ranges, references, and CISA KEV
   metadata are normalized without guessing missing fixed versions. A vetted
   archetype supplies exposure checks, remediation and containment steps,
   verification, stop conditions, and common failure modes.
2. **Stable Markdown overrides.** High-value CVEs can carry a reviewed,
   bespoke page with product-specific commands and partial-fix history. A
   development page remains supplemental until review promotes it to `stable`;
   it cannot silently replace the conservative composed recipe.

The machine-readable [coverage manifest](/api/cve-catalog/manifest.json),
[complete index](/api/cve-catalog/index.json), and
[remediation archetypes](/api/cve-catalog/archetypes.json) are public API
artifacts for companies and agents. Full records are stored in integrity-hashed
shards referenced by the index. The interactive browser uses a separate
compact [runtime summary](/api/cve-catalog/runtime-summary.json) for its initial
coverage and content-version metadata, then loads the compressed
[worker search index](/api/cve-catalog/browser-index.json.gz) only for a title
or filter search. It never parses the full machine index on the page's main
thread.

## What a CVE recipe contains

Every recipe follows the same outline:

- **Frontmatter** — `cve` or `ghsa`, `known_as`, `kev` flag
  (CISA Known Exploited Vulnerability), severity, ecosystem,
  dates.
- **Summary** — what the CVE is and what it lets an attacker
  do. Plain language.
- **Affected versions** — the canonical version range, with a
  note if vendor advisories disagree.
- **Indicator-of-exposure** — how to know whether your code is
  actually exposed (vs. just having the package installed).
- **Remediation strategy** — the right fix. When the right fix
  is "upgrade," the recipe says so plainly. When upgrade isn't
  possible, the recipe gives a documented mitigation.
- **The prompt** — agent-runnable, with explicit boundaries.
- **Stop conditions** — when the agent must triage instead of
  fixing.
- **Verification** — how the agent (and the reviewer) confirm
  the CVE is gone after the fix.
- **Watch for** — common failure shapes (partial fixes, new
  CVEs introduced by the upgrade, behaviour regressions).

## Source freshness and review standard

SecurityRecipes treats NVD, CISA KEV, GitHub Advisory Database, OSV, and vendor
advisories as evidence sources, not interchangeable final copy. Generated
catalog records preserve the source fields and stop when a product-specific
fixed version is not authoritative. A Markdown override should only land when
the remediation path is specific enough for a production reviewer to trust an
agent-authored PR.

For product-specific high and critical overrides, that means each prompt must
include:

- the model context used to generate it, currently `GPT 5.5 Extra High
  reasoning`;
- the exact affected surface and the version, configuration, or runtime signal
  that proves exposure;
- the safest default fix and a documented containment path when upgrade is
  blocked;
- explicit stop conditions that produce `TRIAGE.md` instead of an unsafe patch;
- verification a reviewer can run without exposing secrets, tenant data,
  customer content, or exploit payloads;
- source links back to GHAD, NVD/CVE, vendor advisories, or release evidence.

## Before remediation: intake the signal

When a CVE, GHSA, OSV, vendor bulletin, scanner row, or ticket is incomplete,
run the
[CVE intelligence intake gate]({{< relref "/prompt-library/general/cve-intelligence-intake-gate" >}})
before asking an agent to patch.

The intake gate turns the advisory signal into one of five outcomes:
remediation, containment, not-exposed suppression, human triage, or rejected
unverified signal. It is backed by the local policy file
`data/intelligence/cve-intelligence-intake-gates.json` and documented in
[CVE Intelligence Intake]({{< relref "/docs/cve-intelligence-intake" >}}).

## How to use a CVE recipe

Start with the exact CVE ID in the complete catalog:

1. Confirm the **identity, publication date, severity observations, affected
   products, and references**. Conflicting CVSS observations remain visible;
   the catalog does not silently discard them.
2. Follow the composed recipe's **exposure checks**. An installed package or
   product is not automatically a reachable vulnerable deployment.
3. Use the **stable Markdown override** when one exists. A development page is
   a draft, not an override. Otherwise use the composed archetypes, and resolve
   the exact fixed release from a linked vendor source before changing
   versions.
4. Obey the **stop conditions**. Produce `TRIAGE.md` when ownership, affected
   scope, a supported fixed version, or safe verification cannot be proved.
5. Review the resulting PR or triage note and retain the catalog record, vendor
   evidence, tests, and deployed-artifact verification with the change.

## When to prefer a Markdown override

- The CVE is **named** and high-blast-radius — Log4Shell,
  Heartbleed, Spring4Shell, regreSSHion, xz-utils, the
  headline CVE of the month.
- The naive fix is wrong or insufficient — for example,
  Log4Shell's first published CVE had a follow-up CVE
  (CVE-2021-45046) because the first patch was incomplete.
  The recipe knows that; the generic workflow doesn't.
- The CVE has a known **mitigation** that's faster to deploy
  than the upgrade (formatMsgNoLookups for Log4Shell, removing
  `cups-browsed` for the CUPS RCE chain, disabling the
  affected feature flag for Spring4Shell). The recipe captures
  the mitigation alongside the upgrade.

## When to route to an adjacent workflow

- A routine CVE in a routine package can use the catalog recipe together with
  the
  [vulnerable-dependency workflow]({{< relref "/security-remediation/vulnerable-dependencies" >}}).
- A CVE in a base image — use the
  [base-image workflow]({{< relref "/security-remediation/base-images" >}}).
- A CVE that's actually a malicious-package compromise — use
  the [cache-quarantine workflow]({{< relref "/security-remediation/artifact-cache-purge" >}}).

## Complete CVE catalog

Search every in-scope record. Exact CVE lookups fetch one derived compressed
shard. Title and filter searches run against a smaller compressed index in a
Web Worker, outside the page's main thread. Expanding a result fetches its full
source record and all applicable remediation archetypes from one shard.

<div data-cve-catalog data-cve-catalog-base="/api/cve-catalog/"></div>

<noscript>
JavaScript is required for interactive search. The complete catalog remains
available through the machine-readable
<a href="/api/cve-catalog/index.json">index</a> and
<a href="/api/cve-catalog/manifest.json">coverage manifest</a>.
</noscript>

## Stable Markdown overrides

The catalogue below is **auto-generated** from product-specific Markdown
recipe files with `maturity: "stable"`, grouped by ecosystem and sorted by
disclosure date. Development pages retain their direct URLs for compatibility,
but are deliberately omitted from generic search, recipe feeds, tags, RSS, the
sitemap, and this authoritative override list. The generated catalog and its
dedicated MCP tools are the discovery surface until a Markdown recipe passes
review. The list may also retain reviewed legacy pages outside the
rolling ten-year window; those pages do not count toward the manifest's
in-scope override total. A reviewed, stable
`cve-XXXX-YYYYY-<short-name>.md` file with the frontmatter
fields below, and it will appear here on the next build —
no edits to this hub or to site config required.

{{< cve-toc >}}

These pages use the same review process as any other prompt. Only a page with
`maturity: "stable"` is authoritative over the composed catalog recipe;
development pages stay supplemental and are not listed here. A catalog record
does not need a Markdown page to be complete: normalized facts and remediation
archetypes remain available for every in-scope CVE.

Required frontmatter for contributors:

- `cve` or `ghsa` — the canonical ID (e.g.,
  `"CVE-2021-44228"` or `"GHSA-v4p8-mg3p-g94g"`). Use `ghsa`
  only when GitHub has not assigned a CVE.
- `severity` — `critical` / `high` / `medium` / `low`.
- `maturity` — `development` while under review; `stable` only after source,
  safety, version, containment, stop-condition, and verification review.
- `ecosystem` — the rough family the recipe targets (e.g.,
  `java/maven`, `python/pypi`, `linux/system`,
  `openssh/system`). New ecosystems automatically become
  new groups.
- `kev` — `true` / `false`. CISA Known Exploited
  Vulnerability flag; renders as a badge.
- `disclosed` — date string the listing sorts by within
  each ecosystem.
- `known_as` — popular names (`["Log4Shell"]`); the first
  alias renders as a quick visual identifier.

## Anatomy of a good CVE recipe submission

If you're writing a new entry, the test is: a developer who
has never read the CVE before should be able to apply the
recipe end-to-end and produce a reviewable PR. That means:

- **Don't paraphrase the NVD entry.** Link to it, and write a
  plain-language summary that explains what the attacker does
  and why the fix works.
- **Distinguish "vulnerable installation" from "exposed
  application."** A package being installed is not the same as
  the vulnerable code being reachable from an untrusted input.
  The recipe should say which is which.
- **Document the partial-fix history.** If the first patch was
  incomplete (Log4Shell, Heartbleed-adjacent CVEs), the recipe
  must say so and direct the upgrade past the incomplete fix.
- **Treat upgrade and mitigation as siblings.** Some
  environments can't upgrade immediately; a documented
  mitigation gets them out of the live-fire phase. Recipes
  that only have an upgrade path are a hard sell to a team
  with a frozen runtime.
- **Make quick checks cross-platform when commands differ.**
  If a recipe includes shell commands, provide macOS/Linux and
  Windows variants so reviewers and operators can verify
  exposure without rewriting the check on the fly.
- **Verification is a step, not a wish.** Add the exact
  command(s) (a re-scan, a `strings` check, a service probe)
  that confirm the fix.

## Completeness boundary

- The rolling window is based on the NVD **publication timestamp**, not the
  year embedded in the CVE ID. Every identifier-year feed is scanned so late
  publication of an older ID is not lost.
- A record is included when it is not rejected and at least one NVD-supplied
  CVSS v2, v3, or v4 observation has a base score of 7.0 or higher. The
  effective label uses the highest supported severity while retaining up to
  four source observations for review.
- CISA KEV enriches exploitation priority but never manufactures or upgrades a
  severity. Vendor and CNA score disagreements stay visible.
- Full records retain up to 12 vulnerable CPE/version entries and preserve the
  source match total plus an explicit truncation flag. A truncated slice is
  never a complete affected-version list; resolve scope from the linked NVD
  record and vendor advisory before changing or suppressing a finding.
- Catalog coverage is complete for this declared source policy. It is not a
  claim that NVD has scored every newly published CVE, that every vendor has
  supplied a fixed version, or that a metadata-backed recipe has received the
  same manual validation as a stable Markdown override.
- Generated recipes intentionally refuse to invent code patterns, exploit
  payloads, affected versions, or fixes that are absent from authoritative
  evidence.

## See also

- [Vulnerable Dependency Remediation]({{< relref "/security-remediation/vulnerable-dependencies" >}})
  — the generic workflow most CVEs route through.
- [Classic Vulnerable Defaults]({{< relref "/prompt-library/general/classic-vulnerable-defaults" >}})
  — durable patterns that aren't single-CVE-shaped.
- [Reputable Prompt Sources]({{< relref "/prompt-library/sources" >}})
  — external CVE-fix collections worth borrowing from.
