---
title: "SAST finding — triage and fix"
linkTitle: "SAST finding triage and fix"
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["sast", "triage", "false-positive", "remediate", "pr"]
weight: 12
date: 2026-04-25
---

A tool-agnostic prompt that takes a single SAST finding and
either opens a reviewer-ready PR (true positive, fixable),
opens a suppression PR with justification and an expiry
(confirmed false positive), or writes a triage note (uncertain
or out-of-scope).

Designed to slot into the
[SAST Finding Remediation]({{< relref "/security-remediation/sast-findings" >}})
workflow, where the SAST scanner is the source of truth and
the agent is bounded to a named catalogue of fix shapes.

## What this prompt does

1. **Reads the finding** — rule ID, file, line range, data flow.
2. **Reproduces the data flow** locally — confirms the source,
   the sink, and the path between them on the current code.
3. **Classifies** the finding as true positive / false positive /
   uncertain. Defaults to true-positive under doubt.
4. **For true positives**, picks a fix shape from the workflow's
   pre-approved catalogue and applies it. Adds a test that fails
   on the old code and passes on the new code. Re-runs the
   scanner and confirms the finding is gone.
5. **For false positives**, opens a *suppression PR* with an
   inline comment explaining the data flow that makes the finding
   benign and an explicit expiry date (default 6 months).
6. **For everything else**, writes a triage note and stops.

## When to use it

- A SAST scanner has produced a structured finding (Semgrep,
  CodeQL, SonarQube, Snyk Code, etc.) with a stable rule ID.
- The repo has a passing CI pipeline and a test target.
- The finding's data flow is local — confined to one function
  or one module.

**Don't use it for:**

- Findings where the data flow crosses a module boundary.
- Findings whose fix would require an API contract change, a
  schema migration, or new infrastructure.
- Vendored or generated code.
- Findings labelled "exploit available, in the wild" — those go
  through your incident playbook, not this prompt.

## Inputs

Infer from session where possible.

- **Finding** — rule ID, file path, line range, data-flow
  description.
- **Catalogue path** — the path in this repo (or a sibling)
  where the workflow's fix-shape catalogue lives. The agent
  reads it but does not edit it.
- **Test runner** — inferred from repo (`pytest`, `npm test`,
  `go test`, etc.).

## The prompt

~~~markdown
You are triaging and (when appropriate) fixing a single SAST
finding in this repository. Your output is exactly one of:

- A pull request with a fix and a regression test.
- A pull request that adds a scoped suppression with a written
  justification and an expiry date.
- A triage note (`TRIAGE.md`) explaining why neither option is
  safe and what a human should do next.

Do not auto-merge. Do not bundle multiple findings.

## Step 0 — Read the finding and the catalogue

1. Read the rule ID, the affected file, the line range, and the
   data flow the scanner emitted.
2. Read the fix-shape catalogue at the path the operator
   provided. The catalogue maps rule IDs (or rule families) to
   named fix shapes, each with an edit pattern and a test
   template. **The catalogue is the policy.** If no shape
   matches, treat the finding as out-of-scope.

## Step 1 — Reproduce the data flow

1. Open the file and trace the data flow described by the
   scanner against the current code.
2. If the code has been refactored such that the flow no longer
   exists, classify as a stale finding and stop with a triage
   note (do not invent a new finding to fix).
3. Confirm the source, the sink, and any sanitizers / validators
   in the path. Note any confidence-reducing facts.

## Step 2 — Classify

Pick exactly one:

- **True positive.** The data flow is real, the sanitization is
  insufficient or absent, and a fix shape from the catalogue
  matches. Continue to Step 3a.
- **True positive, no shape.** The flow is real but the catalogue
  has no shape for it. Stop and write a triage note.
- **False positive.** A sanitizer / validator / type constraint
  on the path makes the flow safe in practice. Continue to Step
  3b. Default to true-positive under any doubt.
- **Cross-module flow.** The flow leaves this function/module.
  Stop and triage.
- **Uncertain.** Stop and triage.

## Step 3a — Apply the fix shape

1. Apply the catalogue's edit pattern to the file. Stay within
   the function boundary unless the catalogue explicitly says
   otherwise.
2. Instantiate the catalogue's test template against this
   finding. The test must fail on the old code and pass on the
   new code.
3. Run the repo's test target. If anything unrelated breaks,
   revert and triage — do not fix unrelated breakage.
4. Re-run the SAST scanner against the sandbox. The original
   finding must be gone, and no new finding may have appeared
   in the same file. If a new finding appears, revert and
   triage.
5. Open a PR (do not merge):
   - Branch: `remediate/sast-<rule-id-slug>-<short-slug>`.
   - Title: `[Security][SAST][<rule-id>] <short description>`.
   - Body: rule ID, fix shape applied, before/after snippet,
     blast radius, "how to verify locally," follow-up checklist
     for adjacent issues you noticed but did not fix.
   - Label: `sec-auto-remediation` (or your repo's equivalent).

## Step 3b — Suppress with justification (false positive)

1. Add an inline suppression comment in the syntax the scanner
   expects (e.g., `# nosem: <rule-id>`,
   `// codeql[js/sql-injection]: ignore`, `// NOSONAR`).
2. The comment **must** include:
   - The rule ID.
   - A one-paragraph explanation of the data flow that makes
     the finding benign.
   - The link to the data-flow trace you walked in Step 1.
   - An explicit expiry date 6 months from today, written as
     `expires: YYYY-MM-DD`.
3. Open a PR (do not merge):
   - Branch: `remediate/sast-suppress-<rule-id-slug>`.
   - Title: `[Security][SAST][suppress][<rule-id>] <short description>`.
   - Body: rule ID, why this is a false positive, the expiry
     date, and a link to the workflow page.
4. Tag with the auto-remediation label.

## Stop conditions (write a TRIAGE.md and exit)

- The data flow crosses a module boundary.
- No catalogue fix shape matches the rule ID.
- The fix would require an API change, a schema migration, or
  a credential / infra change.
- The scanner re-run after your fix shows new findings in the
  same file.
- You cannot make tests pass without editing unrelated code.
- The finding looks like a logic bug rather than the syntactic
  pattern the rule fires on.

## Scope

- Do not touch files outside the affected function and its
  test.
- Do not bundle multiple findings.
- Do not invent new fix shapes — only use the catalogue.
- Do not silently broaden the suppression scope (e.g.,
  file-level when the finding is line-level).
- Do not modify CI, secrets, or release pipelines.
~~~

## Output contract

- Either a PR (fix or suppression) with the structure above, or a
  `TRIAGE.md` note. Never an auto-merge.
- Suppression PRs always include an explicit expiry; the workflow's
  expiry-sweep job re-fires findings whose suppressions have aged
  out.

## Guardrails

- **Catalogue-only fixes.** The agent will never apply an edit
  pattern that isn't in the catalogue, even when it knows one
  that "would work."
- **Default to true-positive.** False-negative cost (real bug
  marked benign) is much higher than false-positive cost (a
  human looks at a real false positive). The prompt is biased
  accordingly.
- **Re-scan required.** No PR opens without a clean re-scan of
  the patched sandbox.
- **One finding, one PR.** Never bundle. Each PR is independently
  revertible.
- **Suppression has a half-life.** No `forever` suppressions.
  Every suppression is dated and re-fires.

## Related

- [SAST Finding Remediation]({{< relref "/security-remediation/sast-findings" >}})
  — the workflow this prompt slots into.
- [Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}})
  — what the reviewer reads before approving.
- [Emerging Patterns → AI-assisted SAST triage]({{< relref "/fundamentals/emerging-patterns#ai-assisted-sast-triage" >}})
  — the pattern this prompt implements.
