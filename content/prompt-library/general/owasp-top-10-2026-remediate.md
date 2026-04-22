---
title: "OWASP Top 10 (2026) — remediate"
linkTitle: "OWASP Top 10 2026 remediate"
tool: "general"
author: "Stephen M Abbott"
team: "InfoSec"
maturity: "development"
model: "Opus 4.7"
tags: ["owasp", "top-10", "remediate", "pr", "fix"]
weight: 11
date: 2026-04-22
---

A tool-agnostic **remediation prompt** that takes a single finding
from an OWASP Top 10 (2026) audit — or any equivalent source — and
turns it into a reviewer-ready pull request. Includes category-specific
"how to fix this well" guidance so the agent doesn't apply a naive
patch that looks right and isn't.

Works with the hunt side at
[OWASP Top 10 (2026) — audit]({{< relref "/prompt-library/general/owasp-top-10-2026-audit" >}}),
but does not require it — any clear finding (SAST result, pen-test
note, internal review comment) is a valid input.

## What this prompt does

1. **Reproduces** the finding — confirms the weakness exists on the
   specified file and lines.
2. **Plans** a fix using the category-appropriate pattern.
3. **Applies** the fix on a new branch with small, reviewable commits.
4. **Adds tests** that would have caught the original weakness.
5. **Opens a PR** with blast-radius notes, before/after snippets, and
   a link back to the finding.

If the fix is out of scope for a safe agent change — needs a data
migration, API contract change, or cross-repo coordination — the
agent writes a triage note and stops.

## When to use it

- You have a specific finding with a file + category + fix direction.
- The fix is a code change in the repo the agent has access to.
- A human will review the PR before merge.

**Don't use it for:**

- Runtime-only fixes (WAF rules, IAM policies in a separate repo).
- Findings that require behavioural changes in a downstream consumer.
- Anything labelled "critical, exploit in the wild" — go straight to
  your incident playbook.

## Inputs

Infer what you can from the session; prompt only when ambiguous.

- **Finding** — category (e.g., `A01 — Broken Access Control`), file
  path, line range, and a short description. If the user only pasted
  a finding title and a file, that is enough; do not refuse.
- **Recommended fix** — optional. If present, treat it as a starting
  point, not a mandate.
- **Repo** — the working directory the agent is running in.
- **Test runner** — infer from the repo (`pytest`, `go test`, `npm
  test`, etc.). If there is no test setup, note it and proceed with
  manual verification only.

## The prompt

~~~markdown
You are remediating a single OWASP Top 10 (2026) finding in this
repository. Open one reviewer-ready PR or write a triage note. Do
not auto-merge.

## Step 0 — Reproduce and confirm

1. Read the file and surrounding context.
2. Confirm the weakness is present as described. If it is not
   reproducible (e.g., the code has been refactored), write a
   one-paragraph note and stop — do not invent a different finding
   to remediate.
3. Identify the minimum scope required to fix it. If the scope
   expands beyond ~200 lines or multiple unrelated files, stop and
   triage.

## Step 1 — Apply the category-appropriate pattern

Do not default to "add a check and ship it." Use the pattern that
fits the category.

- **A01 Broken Access Control** — Add authorization at the
  controller/handler layer, not the view layer. Prefer
  centralized middleware / policy objects over ad-hoc `if` checks
  scattered across routes. Verify the check runs on every code
  path, including error and retry paths.
- **A02 Cryptographic Failures** — Replace weak primitives with
  the library's current recommended default. Never roll your own.
  For password hashing, use argon2id or bcrypt with current cost
  parameters. For data-at-rest, prefer envelope encryption with a
  KMS-managed key. Remove the old cipher path — do not leave a
  fallback.
- **A03 Injection** — Parameterize. For SQL, use prepared
  statements or the ORM's parameter binding. For shell, prefer
  `execFile`/`subprocess.run(args=[...])` with an explicit
  allowlist over string concatenation. For templates, escape at
  render time, not at input time. For LLM prompt injection,
  treat model output as untrusted and keep untrusted text out of
  system prompts and tool-call arguments.
- **A04 Insecure Design** — If the fix is design-level (missing
  rate limit, enumeration oracle), add the minimum control:
  server-side rate limit keyed on account + IP, uniform response
  for valid and invalid enumerable inputs, etc. Flag the larger
  design gap in the PR body.
- **A05 Security Misconfiguration** — Turn the defaults right.
  Tighten CORS to explicit origins, disable debug in production
  paths, add the standard security headers (CSP, HSTS,
  X-Content-Type-Options, Referrer-Policy). If the config is
  environment-specific, fix the *default* and override only where
  needed.
- **A06 Vulnerable and Outdated Components** — Bump to the
  lowest non-vulnerable version that keeps the repo's major /
  minor contract. Run tests. If a transitive dep is the problem
  and the direct dep cannot be bumped, add a resolution/override
  if the ecosystem supports one; otherwise triage.
- **A07 Authentication Failures** — Add the missing control
  (MFA requirement on sensitive op, account lockout on repeated
  failures, secure session cookie flags). Invalidate existing
  sessions if the old behaviour made them trust-on-first-use.
- **A08 Software/Data Integrity Failures** — Pin third-party CI
  actions by SHA, require signatures on release artifacts,
  replace `pickle`/`unsafe-eval`/`Marshal` on untrusted input
  with a safe serialization format.
- **A09 Logging/Monitoring Failures** — Add structured audit
  events for sensitive operations (auth, authz, privilege
  escalation, data export). Scrub PII and secrets from the log
  pipeline — not from the log statement.
- **A10 SSRF** — Validate and allowlist outbound URLs against a
  deny-by-default list. Block link-local and metadata-endpoint
  IPs. Resolve the hostname once, then connect to the resolved
  IP — do not pass a hostname that could resolve differently on
  second lookup.

If the 2026 list introduces or renames a category, apply the
nearest fitting pattern above and note the category name in the
PR description.

## Step 2 — Tests that would have caught this

Add at least one test that *fails against the old code* and
*passes against the new code*. If the project has no test setup,
add a minimal one; do not skip the test step silently.

## Step 3 — Commit and open the PR

- Branch: `remediate/owasp-<category>-<short-slug>`.
- Small commits that tell a story: reproduction test, fix, any
  supporting refactor, docstring/config updates.
- PR title: `[Security][<category>] <short description>`.
- PR body must include:
  - OWASP category and link to the source finding.
  - Summary of the weakness and the exploitation path.
  - What was changed, per file.
  - Blast radius — who and what this PR affects.
  - A "how to verify" section with the commands a reviewer
    should run locally.
  - Out-of-scope items discovered along the way, as checklist
    items for follow-up.
- Do not merge. Label as `security-review` (or the repo's
  equivalent).

## Stop conditions

Stop and write a triage note at `TRIAGE.md` (and ping the PR
reviewer channel) instead of forcing a PR if:

- The fix requires a data migration.
- The fix changes an externally-observable API contract.
- The finding turns out to be a false positive (explain briefly
  why).
- Tests fail and you cannot fix them without touching unrelated
  code.
- The fix requires credentials or infra you do not have.

## Scope

- Do not touch files outside the direct fix and its tests.
- Do not rewrite unrelated code "while you're in there."
- Do not update dependencies other than the one the finding
  targets (if any).
- Do not modify CI pipelines, release automation, or secrets.
~~~

## Output contract

- Either a PR (happy path) with the structure above, or a
  `TRIAGE.md` note (stop condition) with a short justification and
  a recommendation for the human next step.
- No auto-merge. Ever.

## Guardrails

- **Single-finding scope.** One finding → one PR. If the agent
  notices adjacent issues, it lists them in the PR body's
  follow-up checklist — it does not quietly fix them.
- **Tests-before-ship.** A PR without a new or updated test is an
  automatic block. If no test framework exists, the PR adds one
  minimally.
- **Sensitive-data handling.** The agent must never include
  secrets, keys, or PII in the PR description, commits, or test
  fixtures. Use obvious dummies.
- **Reversibility.** Every change should be reversible via a
  single revert. No data migrations bundled in.

## Related

- [OWASP Top 10 (2026) — audit]({{< relref "/prompt-library/general/owasp-top-10-2026-audit" >}}) — the hunt side
- [Fundamentals]({{< relref "/fundamentals" >}}) — vocabulary used
  in the PR body
- [Agentic Security Remediation]({{< relref "/security-remediation" >}})
  — how InfoSec runs prompts like this in production
