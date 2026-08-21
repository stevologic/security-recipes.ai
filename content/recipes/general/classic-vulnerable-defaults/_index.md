---
title: Classic Vulnerable Default Security Recipes
linkTitle: Classic Vulnerable Defaults
weight: 20
lastmod: 2026-08-21
sidebar:
  open: false
description: >
  Browse agent-ready security recipes for replacing unsafe defaults such as
  pickle, unsafe YAML, JNDI, JWT `none`, XXE, polymorphic deserialization,
  `eval`, and similar language and framework patterns.
---

{{< callout type="info" >}}
**Start with the [classic vulnerable defaults remediation guide]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
when you need the decision model.** That guide explains why these patterns
belong together, when to mitigate versus uplift, and which cross-cutting
guardrails apply. This page is the companion collection of executable,
agent-ready security recipes.
{{< /callout >}}

Each prompt below is **agent-runnable**: a developer, a
security partner, or a security-team agentic workflow can pick
it up against a single call site and produce a reviewer-ready
PR (or a triage note). All of them follow the same outline —
read the call site, classify, mitigate or uplift, prove
behaviour preservation, open a PR.

## Anatomy of a recipe

Every recipe has:

- **When to use it** — how to choose this recipe over a broader audit.
- **Pattern** — the exact call shape it targets.
- **Why it matters** — what the unsafe default does to a real
  attack.
- **Mitigation** — how to harden the existing call without
  removing it (typically a monkey-patch, a config flag, or a
  filter).
- **Uplift** — how to replace the call with a safer
  construct.
- **Behaviour-preservation test** — the round-trip test the
  PR must include.
- **The prompt** — what the agent runs.
- **Watch for** — the failure modes to call out in the PR
  body.

## Catalogue

The catalogue below is **auto-discovered** from the recipe
files in this section. Drop a new markdown file with the
standard prompt frontmatter (`title`, `description`,
`maturity`, `model`, `tags`, `team`, `author`, `weight`) and
it will appear here on the next build — no edits to this
hub or to site config required.

{{< prompt-toc >}}

This list grows. Submissions land via the same review path as
any other prompt — see [Contribute]({{< relref "/contribute#contributing-a-prompt" >}}).

## When to use these prompts

- A pattern hunt or manual review surfaced a call site of one
  of the catalogued shapes.
- A SAST rule fired on the same shape (Semgrep / CodeQL rules
  for these defaults are well-established).
- A new repo or migration brought legacy code into a project
  where the default used to be acceptable and is no longer.
- An incident-response finding traced a breach back to one of
  these calls.

## When *not* to use these prompts

- The unsafe call is on a path that genuinely consumes
  trusted-only data (a checkpoint loader for an internal
  training pipeline, a config parser run only on local files).
  Flag and document; don't auto-replace.
- The uplift would force a coordinated, multi-repo migration
  the program owner hasn't sequenced. Mitigate now, schedule
  the uplift.
- The repo has no test coverage on the call path. The PR
  needs a behaviour-preservation test before any change ships.

## Cross-cutting guardrails

- **Behaviour-preservation test.** Every PR adds a round-trip
  test that exercises the old payload format under the new
  code path. No test, no PR.
- **No silent compat shims.** When the uplift requires reading
  legacy data via the old call, the legacy read-path is named
  explicitly and dated for removal.
- **Audit the rejections.** Mitigations log every rejection so
  attackers and false-positives are both visible.
- **One pattern, one PR.** A repo with three different
  classic-default findings produces three PRs.
