---
title: "Sensitive data element remediation (rule + command)"
linkTitle: "Sensitive data remediation"
tool: "cursor"
author: "Stephen M Abbott"
team: "InfoSec"
maturity: "development"
model: "Opus 4.7"
tags: ["sde", "secrets", "pii", "dlp", "cursor", "rules", "commands"]
weight: 20
date: 2026-04-21
---

A Cursor **project rule** + **custom slash command** pair for
remediating a sensitive-data-element (SDE) finding — hard-coded
secrets, PII in logs, credentials in source. The rule locks in
the house posture ("rotation first for exposed SDEs, no history
rewrites, one finding per PR"); the command is the one-liner an
engineer or Cursor Automation invokes.

## What this prompt does

When `/remediate-sde <finding-id> <class>` runs, the Cursor Agent
(interactive or Background) confirms the literal is in the
current working tree, classifies the exposure scope, and — if
pre-exposure — replaces the literal with a reference to the
approved secret store (or a redaction helper for PII), adds a
regression guard, runs tests, and opens a draft PR. For exposed
findings, the rule forces the agent to stop, write a triage note
with a rotation + disclosure checklist, and not touch code.

**Inputs:** finding id and SDE class (one of `secret`, `token`,
`pii`, `pci`, `phi`) as command arguments. Optional file-path
hint in the chat body.<br/>
**Outputs:** a draft PR (pre-exposure path) or a triage branch +
summary in chat (exposed path).

## When to use it

- GitHub push protection / GitLeaks / TruffleHog / Wiz fires on a
  pre-exposure finding and the developer wants to fix it without
  leaving Cursor.
- Cursor Automations watches an issue label (`security:sde`) and
  needs a consistent command to dispatch.
- A PII scanner flags a test fixture containing real user data
  and the replacement is a Faker-style synthetic value.

**Don't use it for:**

- Any SDE already pushed to a shared remote or published log —
  the rule forces triage + rotation. This is the correct
  behavior, not a bug.
- Cross-repo sweeps — run once per finding after dedup.
- Binary artifacts — the rule refuses.

## The prompt

Two files, checked in to the repo.

### `.cursor/rules/remediate-sde.mdc`

~~~markdown
---
description: >
  Sensitive-data-element remediation house rules. Applies whenever
  the agent is asked to remove a hard-coded secret, PII, or
  credential from source.
alwaysApply: true
---

# SDE remediation — house rules

## Exposure scope — always classify first
- PRE-EXPOSURE: literal exists only in the current working tree,
  never committed to a shared remote, never printed in CI logs.
- EXPOSED: anything else. If in doubt, it's exposed.

**Exposed SDEs are rotation problems, not code-edit problems.**
For any EXPOSED finding: do NOT edit the offending file. Stop,
create a triage branch, and write TRIAGE.md per the template
below. Rotation happens first; code hygiene second.

## Pre-exposure remediation
- Replace the literal with a reference to the project's approved
  secret store (read `docs/security/secrets.md` to identify the
  client). For PII, route through the project's redaction
  helper (grep for `redact(`, `mask_pii`, `scrubPII`). If the
  project has neither, stop and triage — do not invent one.
- For test fixtures containing real user data, replace with
  Faker-style synthetic values and comment the finding id.
- Minimal edit only. Never rename files, never reformat unrelated
  code.

## Regression guard
- Add a unit test or a scanner-config rule that fails if the
  literal reappears. Allowlist the synthetic-fixture path
  specifically (never a broad path allowlist).

## What you may NEVER do
- Rewrite git history (`filter-repo`, force-push, commit
  amends on anyone else's branch).
- Echo the SDE literal in commit messages, chat output, PR
  bodies, or logs. When referring to it, hash it.
- Commit or delete `.env` / `credentials.json` — those require
  a `git filter-repo` runbook + human sign-off.
- Merge your own PR.

## PR shape (pre-exposure path)
- Branch: `fix/<finding-id>`.
- Commit: `fix(sec): remove <class> <finding-id>`.
- Title: `fix(sec): remove <class> from <file> (<finding-id>)`.
- Body: finding id, exposure scope = "pre-exposure",
  replacement pattern used, test pass evidence, one-line revert.
- Labels: `security`, `sde-remediation`.
- DRAFT. Never ready-for-review, never auto-merge.

## Triage template (exposed path)
Write TRIAGE.md on a `sde-triage/<finding-id>` branch with YAML
frontmatter including: finding_id, sde_class, exposure_scope,
first_seen_commit, first_seen_date; and body sections for:
- Rotation checklist (revoke, rotate, re-deploy, invalidate
  cached sessions).
- Disclosure checklist (IR ticket, service owner, legal routing).
~~~

### `.cursor/commands/remediate-sde.md`

Filename is the command name — no frontmatter required.

~~~markdown
# Remediate a single SDE finding

Arguments (both optional):
1. Finding id (e.g. `GITLEAKS-AWS-001`, `WIZ-SECRET-42931`).
2. SDE class: `secret`, `token`, `pii`, `pci`, or `phi`.

Infer everything else from the session: the repo root you're
already in, the default branch (from the git remote), the
approved secret store (from `docs/security/secrets.md` or
`SECURITY.md`), the redaction helper (grep for it), and the
test and lint commands (from the README, `package.json`
scripts, or `Makefile`).

If no finding id is provided AND no scanner MCP is wired in,
discover a target yourself before touching code:

- Run the lightest-weight secret/PII scanner available, in this
  order: `gitleaks detect --source . --no-banner`,
  `trufflehog filesystem . --json`, `detect-secrets scan
  --all-files`, `trivy fs --scanners secret .`.
- Restrict to the WORKING TREE only — never scan commit
  history. Exposed SDEs are rotation problems, handled by the
  exposed-path branch of the rule.
- Pick the highest-confidence finding. Synthesize a local id:
  `LOCAL-<scanner>-<rule>-<short-sha>`. Classify the SDE class
  from the rule id (e.g. AWS-access-key → `secret`,
  email-in-logs → `pii`).
- Note in the PR body that the finding was self-discovered and
  which scanner produced it.
- If no scanner is installed, stop and post a summary in chat
  naming what to install — do not guess.

Never grep for a secret literal yourself — leave pattern
matching to the scanner so the literal never enters chat
context.

Using the house rules in `.cursor/rules/remediate-sde.mdc`:

1. Confirm the literal appears in the current working tree. If
   the chat message includes a file path + line, start there.
   If the literal isn't present, stop and summarize
   "not-reproduced".
2. Classify exposure scope.
   - Run `git log --all -S '<literal hash>' -- <file>` to detect
     prior commits. NEVER echo the literal — refer to it by a
     hash only.
   - Check the finding source: was it seen in CI logs or a
     public repo?
   - Any of the above → EXPOSED. Otherwise PRE-EXPOSURE.
3. EXPOSED path: do not edit the file. Create
   `sde-triage/<finding-id>` branch, write TRIAGE.md per the
   rule's template, push, and summarize the rotation +
   disclosure checklist in chat.
4. PRE-EXPOSURE path:
   a. Pick the replacement pattern per the rule (secret store
      client for secrets/tokens; redaction helper for PII).
   b. Apply the minimal edit. Add a regression guard (unit
      test or scanner-config rule).
   c. Run lint and tests. If either fails because of the edit,
      revert and summarize.
   d. Open a DRAFT PR per the rule's PR shape. Do not mark
      ready-for-review.

Whenever you need to refer to the SDE literal, use a hash or an
abstract description. Never echo the value.
~~~

Invoke from chat with `/remediate-sde WIZ-SECRET-42931 secret`.
From Cursor Automations, the same command is wired to the
`security:sde` label trigger.

## Known limitations

- **Exposure detection is git-history-shaped.** The `git log -S`
  heuristic can miss a secret that was renamed between commits;
  pair with the scanner's own "first seen" metadata when
  possible.
- **Hashing literals in chat.** Cursor's chat surface doesn't
  natively redact — the agent must remember to hash. Treat any
  copy-paste of chat transcripts as sensitive until you've
  verified the agent obeyed the rule.
- **History cleanup is out of scope.** That lives in a separate
  `secret-rotation` runbook; this prompt refuses to try.
- **Redaction-helper detection** relies on a grep list. Teams
  with non-obvious helper names should record them in
  `docs/security/secrets.md` so the rule can cite them.

## Changelog

- 2026-04-21 — v1, first published. Covers secret / token /
  pii / pci / phi. Exposed-SDE path deliberately refuses code
  edits and routes to rotation.
