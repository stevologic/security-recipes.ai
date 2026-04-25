---
title: Classic Vulnerable Defaults
linkTitle: Classic Vulnerable Defaults
weight: 20
sidebar:
  open: true
description: >
  Prompts that mitigate or replace the durable, unsafe-by-default
  patterns that show up in new code year after year — pickle,
  unsafe YAML, JNDI, JWT `none`, XXE, polymorphic
  deserialization, `eval`, and friends.
---

{{< callout type="info" >}}
**Read [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
first.** It explains why these patterns belong in their own
section, the mitigate-vs.-uplift decision, and the guardrails
that apply across all of them. The prompts here are the
executables; that page is the operating context.
{{< /callout >}}

Each prompt below is **agent-runnable**: a developer, a
security partner, or a security-team agentic workflow can pick
it up against a single call site and produce a reviewer-ready
PR (or a triage note). All of them follow the same outline —
read the call site, classify, mitigate or uplift, prove
behaviour preservation, open a PR.

## Anatomy of a recipe

Every recipe has:

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
hub or to `hugo.yaml` required.

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
