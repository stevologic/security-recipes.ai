---
title: "Sensitive data element remediation skill"
linkTitle: "Sensitive data remediation skill"
tool: "claude"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["sde", "secrets", "pii", "dlp", "skill", "claude"]
weight: 20
date: 2026-04-21
---

A Claude Code **skill** that triages a sensitive-data-element (SDE)
finding — hard-coded secrets, PII in logs, credentials committed to
source — and produces either (a) a PR that removes the SDE and
replaces it with a vetted retrieval pattern, or (b) a structured
triage note explaining why this finding needs a human.

## What this prompt does

Claude reads the finding id, locates the offending occurrence in the
current working tree (not in history — history rewriting is out of
scope for this skill and handled by a separate runbook), replaces
the literal value with a reference to the approved secret-store /
config source, adds a regression guard (ignore-rule or unit test
depending on class), runs the repo's test + lint commands, and
opens a PR. Where the SDE is already-exposed (commit history,
public log, vendored artifact), the skill stops and writes a
`TRIAGE.md` with the rotation + disclosure checklist instead of
quietly papering over it.

**Inputs:** `FINDING_ID`, optional `FILE_PATH` + `LINE` hint,
`SDE_CLASS` (secret / pii / pci / phi / token).<br/>
**Outputs:** either a PR (happy path) **plus** a rotation ticket
referenced in the PR body, or a `TRIAGE.md` triage note with a
rotation + disclosure checklist.

## When to use it

- A secret scanner (GitHub push protection, GitLeaks, TruffleHog,
  Wiz, Snyk) raised a finding on a current-tree file.
- A PII / DLP scanner flagged a log-line or test fixture shipping
  real user data.
- Dependabot-style SDE sweeps where the team already has an
  approved secret store (Vault, AWS Secrets Manager, GCP Secret
  Manager, 1Password) the replacement can point at.

**Don't use it for:**

- Secrets already pushed to a remote branch or public repo — the
  rotation path is the primary fix; this skill will refuse and
  create a triage note.
- Binary artifacts or images with embedded SDEs — use a separate
  image-sanitization runbook.
- Cross-repo propagation (the same key appears in ten repos) — run
  it per-repo, after the rotation ticket is open.

## The prompt

Save as `.claude/skills/sde-remediation/SKILL.md` at the repo root:

~~~markdown
---
name: sde-remediation
description: |
  Remediate a sensitive-data-element (SDE) finding in the current
  working tree — hard-coded secrets, PII in logs, credentials in
  source. Replace the literal with a reference to the approved
  secret store, add a regression guard, and open a PR. If the SDE
  is already-exposed (in history, a public log, or a shipped
  artifact), stop and write TRIAGE.md with a rotation + disclosure
  checklist.
---

# Sensitive data element remediation

## Inputs

All inputs are optional. Infer first from session context — the
chat message / slash-command arguments, a linked GitHub issue or
scanner payload, the triggering push-protection block. When
nothing provides a finding and no scanner MCP is wired in,
discover candidate SDEs yourself using local tooling.

- `FINDING_ID`   — scanner id (e.g. `GITLEAKS-AWS-001`,
                   `WIZ-SECRET-42931`). If absent, synthesize a
                   local id after discovery (e.g. `LOCAL-GITLEAKS-<rule>-<sha>`).
- `FILE_PATH`    — take from the scanner payload or prompt body.
                   Otherwise produced by discovery.
- `LINE`         — same sources as `FILE_PATH`.
- `SDE_CLASS`    — one of `secret`, `pii`, `pci`, `phi`, `token`.
                   Take from the prompt body or the scanner's
                   rule id; otherwise classify from the
                   discovery output (AWS-access-key rule →
                   `secret`; Stripe-live-key → `secret`;
                   email-in-logs → `pii`; etc.).

## Discovery path (no finding provided)

When nothing is supplied and no scanner MCP is available:

1. Run the lightest-weight secret/PII scanner installed, in this
   order: `gitleaks detect --source . --no-banner`,
   `trufflehog filesystem . --json`,
   `detect-secrets scan --all-files`, `trivy fs --scanners secret .`
   as a multi-scanner fallback.
2. Restrict discovery to the working tree only — do NOT scan
   commit history. History-resident SDEs are a rotation
   problem, not a code-edit problem, and require a separate
   runbook.
3. Pick one high-confidence finding per run and proceed as if
   it had been supplied. Note in the PR body that it was
   self-discovered and which scanner produced it.
4. If no scanner is available, stop and write `TRIAGE.md`
   listing what to install (with a one-line justification per
   tool) so a human can wire it up.

Never grep for a secret literal yourself — leave pattern
matching to the scanner so the literal never enters your
reasoning trace.

## Procedure

1. **Confirm the finding is live in the working tree.**
   - Read `FILE_PATH:LINE`; if the literal value is not present,
     the finding may have been fixed already. Write `TRIAGE.md`
     with "not-reproduced" and stop.
   - Do **not** grep the commit history — that's the
     secret-rotation runbook's job.

2. **Classify the exposure scope.**
   - If the file is in a **public** repo, or has been pushed to a
     shared remote branch, OR the secret appears in CI logs: this
     is an **exposed** SDE. Skip to step 7.
   - Otherwise, this is a **pre-exposure** SDE and you may
     remediate in-place.

3. **Pick the replacement pattern from the allowlist.**
   - `secret` / `token` → read from the repo's approved secret
     store client. Consult `docs/security/secrets.md` for the
     project's chosen store; if absent, stop and triage.
   - `pii` / `pci` / `phi` → replace with a synthetic fixture in
     tests; in runtime code, route through the project's
     redaction helper (grep for `redact(`, `Redactor`, or
     `mask_pii`). If none exists, stop and triage — do not invent
     one.

4. **Apply the replacement.**
   - Minimal edit: remove the literal, insert the reference /
     redaction call, update the smallest surrounding context
     needed to compile.
   - Never rename files, never reformat unrelated code in the
     same commit.

5. **Add a regression guard.**
   - If the repo has `gitleaks` / `trufflehog` / `detect-secrets`
     config, add an allowlist entry **only for the
     synthetic-fixture path**, with a comment citing the finding
     id.
   - For code paths: add a unit test that asserts the offending
     value is no longer present (string match against the
     removed literal).

6. **Verify and open a PR.**
   - Run the project's lint + test commands.
   - Commit message: `fix(sec): remove <SDE_CLASS> <FINDING_ID>`.
   - PR title: `fix(sec): remove <SDE_CLASS> from <file>
     (<FINDING_ID>)`.
   - PR body:
     - Finding id.
     - **Rotation status:** "N/A — pre-exposure, no rotation
       required" (only for pre-exposure fixes; an exposed SDE
       never reaches this step).
     - Blast radius (files touched, callers changed).
   - Apply labels: `security`, `sde-remediation`.

7. **Exposed SDE — stop and triage.**
   - Write `TRIAGE.md` on a fresh branch `sde-triage/<FINDING_ID>`
     with:
     - Finding id, file, line.
     - **Rotation checklist** (tick each when done):
       - [ ] Revoke the credential at the issuer.
       - [ ] Rotate in the approved secret store.
       - [ ] Re-deploy consumers.
       - [ ] Invalidate any cached sessions / tokens.
     - **Disclosure checklist:**
       - [ ] File an incident in the IR tracker.
       - [ ] Notify the service owner.
       - [ ] Determine if a customer / regulator notification is
         required (route to legal).
     - Suggested next owner (team / on-call rotation).
   - Do **not** edit the offending file yet — rotation happens
     first.

## Guardrails

- **Never** edit git history from this skill. History rewrites
  require a documented runbook and a human.
- **Never** inline the replacement value you just retrieved from
  the secret store into a log line, an error message, or a
  comment.
- **Never** bypass a `PreToolUse` hook that blocks writing to
  secret-material paths — record the block in `TRIAGE.md` and
  stop.
- **Never** commit a `.env` or `credentials.json` file, even to
  remove it — those need `git filter-repo` treatment, not a
  normal commit.

## Output contract

- Success (pre-exposure): a pushed branch + opened PR, plus a
  passing regression-guard test.
- Exposed SDE: a triage branch with `TRIAGE.md`, zero code
  edits on the offending file.
~~~

## Related recipes

- [Source code secrets and data exposure audit]({{< relref "/prompt-library/general/source-code-secrets-data-exposure-audit" >}})
- [Sensitive data remediation]({{< relref "/security-remediation/sensitive-data" >}})
- [Context egress boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
- [NIST SSDF repository evidence check]({{< relref "/prompt-library/general/compliance-standards/nist-ssdf-repo-evidence-check" >}})

## Known limitations

- **History rewrites are out of scope.** If the SDE was ever
  committed, rotation is the primary fix; use the separate
  `secret-rotation` runbook before cleaning history.
- **Cross-repo propagation isn't detected.** The skill only looks
  at the current working tree. Pair it with an org-wide grep in
  your SOAR step before closing the finding.
- **Synthetic-fixture quality varies.** For PII fixtures, prefer
  Faker-style libraries over hand-rolled mocks — hand-rolled data
  tends to leak structural hints (same byte lengths as real data)
  that defeat the redaction.
- **Detectors with high false-positive rates** (e.g. broad regex
  patterns for "api_key") will send the skill to triage more often
  than needed. Tune scanner rules upstream.

## Changelog

- 2026-04-21 — v1, first published. Covers hard-coded secrets,
  PII in logs, and test fixtures containing real user data.
  History rewrite path intentionally out of scope.
