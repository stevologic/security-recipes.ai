---
title: CVE Recipes
linkTitle: CVE Recipes
weight: 9
sidebar:
  open: true
description: >
  Per-CVE agent recipes — pick one up, run it, get a
  reviewer-ready PR or a structured triage note. Each recipe
  ships with a CVE summary, a remediation strategy, the exact
  prompt, the boundaries the agent must not cross, and the
  failure modes that should stop the run cleanly.
---

{{< callout type="info" >}}
**Why per-CVE.** The
[generic remediation workflows]({{< relref "/security-remediation" >}})
cover the bulk of advisories. But some CVEs are special:
load-bearing across the industry, with quirks the generic
workflow won't catch ("just bumping isn't enough — you also
have to remove `JndiLookup.class`"). For those, a targeted
recipe is more reliable than a generic one. This section is
where those recipes live.
{{< /callout >}}

## What a CVE recipe contains

Every recipe follows the same outline:

- **Frontmatter** — `cve`, `aliases`, `kev` flag (CISA Known
  Exploited Vulnerability), severity, ecosystem, dates.
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

## How to use a CVE recipe

The same pattern as any other prompt on this site:

1. Read the **Summary** and **Affected versions** to confirm
   the recipe is for the CVE you're looking at — vendor
   advisories sometimes ship multiple CVE IDs for the same
   underlying bug, and not every one has its own recipe.
2. Read the **Indicator-of-exposure**. If your codebase isn't
   actually exposed (the vulnerable code path isn't reached),
   the right action might be a documented suppression, not a
   bump. The recipe says when that's appropriate.
3. Copy the **prompt block** into the agent of your choice.
4. Review the PR or the triage note the agent produces. The
   recipe's **Verification** section tells the reviewer what
   to look for.

## When to use these instead of the generic workflows

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

## When *not* to use these

- A routine CVE in a routine package — use the
  [vulnerable-dependency workflow]({{< relref "/security-remediation/vulnerable-dependencies" >}}).
- A CVE in a base image — use the
  [base-image workflow]({{< relref "/security-remediation/base-images" >}}).
- A CVE that's actually a malicious-package compromise — use
  the [cache-quarantine workflow]({{< relref "/security-remediation/artifact-cache-purge" >}}).

## Catalogue

The catalogue below is **auto-generated** from the recipe
files in this section, grouped by ecosystem and sorted by
disclosure date. Drop a new
`cve-XXXX-YYYYY-<short-name>.md` file with the frontmatter
fields below, and it will appear here on the next build —
no edits to this hub or to `hugo.yaml` required.

Required frontmatter for the listing to be useful:

- `cve` — the canonical ID (e.g., `"CVE-2021-44228"`).
- `severity` — `critical` / `high` / `medium` / `low`.
- `ecosystem` — the rough family the recipe targets (e.g.,
  `java/maven`, `python/pypi`, `linux/system`,
  `openssh/system`). New ecosystems automatically become
  new groups.
- `kev` — `true` / `false`. CISA Known Exploited
  Vulnerability flag; renders as a badge.
- `disclosed` — date string the listing sorts by within
  each ecosystem.
- `aliases` — popular names (`["Log4Shell"]`); the first
  alias renders as a quick visual identifier.

{{< cve-toc >}}

This catalogue grows. New entries land via the same review
process as any other prompt.

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
- **Verification is a step, not a wish.** Add the exact
  command(s) (a re-scan, a `strings` check, a service probe)
  that confirm the fix.

## What this section is not

- A vulnerability database. NVD, OSV, GHSA, vendor advisories,
  and the CVE feeds your scanner consumes already serve that
  purpose. This section is a **fix cookbook**, not a CVE
  index.
- A complete archive. Most CVEs don't need their own recipe —
  the generic workflows are enough. Recipes here are reserved
  for the load-bearing, repeatedly-relevant ones.
- Auto-generated. Each recipe is reviewed before merge.

## See also

- [Vulnerable Dependency Remediation]({{< relref "/security-remediation/vulnerable-dependencies" >}})
  — the generic workflow most CVEs route through.
- [Classic Vulnerable Defaults]({{< relref "/prompt-library/general/classic-vulnerable-defaults" >}})
  — durable patterns that aren't single-CVE-shaped.
- [Reputable Prompt Sources]({{< relref "/prompt-library/sources" >}})
  — external CVE-fix collections worth borrowing from.
