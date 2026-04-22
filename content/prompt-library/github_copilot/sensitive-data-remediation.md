---
title: "Sensitive data element remediation (issue template + instructions)"
linkTitle: "Sensitive data remediation"
tool: "github_copilot"
author: "Stephen M Abbott"
team: "InfoSec"
maturity: "development"
model: "Opus 4.7"
tags: ["sde", "secrets", "pii", "dlp", "copilot", "coding-agent", "issue-template"]
weight: 20
date: 2026-04-21
---

A three-part bundle for the Copilot coding agent — a
`.github/copilot-instructions.md` addendum, an issue template,
and a repository policy — that shapes Copilot into a careful
SDE remediator: pre-exposure findings get a minimal code fix in
a draft PR; exposed findings get a structured triage issue and
no code edits at all.

## What this prompt does

When an engineer (or a scanner's issue projector) creates an
issue from the `security-remediation-sde.yml` template and it
lands labeled `copilot-remediate`, the Copilot coding agent
picks it up. Guided by the repo-level instructions, it:

1. Confirms the SDE literal still appears in the current
   working tree.
2. Classifies the exposure scope using the issue's metadata +
   a git-history check.
3. **Pre-exposure:** replaces the literal with a reference to
   the approved secret store (or redaction helper), adds a
   regression guard, runs CI, and opens a draft PR linked to
   the issue.
4. **Exposed:** does not edit code. Instead it comments on the
   issue with a rotation + disclosure checklist and adds the
   `needs-rotation` label, routing the work to the on-call.

**Inputs:** finding id, SDE class, exposure hint (from the
issue body); repo-level `copilot-instructions.md`.<br/>
**Outputs:** either a draft PR (pre-exposure) or an issue
comment with a rotation checklist + `needs-rotation` label
(exposed).

## When to use it

- GitHub push protection, GitLeaks, TruffleHog, or Wiz already
  writes findings into Issues (or has a webhook you can fan
  into Issues via `repository_dispatch`).
- Your repo has an approved secret-store client documented in
  `docs/security/secrets.md` and (for PII) a redaction helper.
- Branch protection on `main` requires a human reviewer —
  critical because this class of change benefits from a second
  pair of eyes.

**Don't use it for:**

- Already-exposed SDEs as primary-fix — the rule forces
  rotation first. The comment + label is the correct outcome.
- History cleanup — that's a `git filter-repo` runbook, not a
  Copilot job.
- Binary artifact scrubbing.

## The prompt

Three files, checked in to the repo.

### `.github/copilot-instructions.md` — SDE remediation addendum

Append this to your existing `copilot-instructions.md`:

~~~markdown
## Sensitive data element remediation

When working on an issue labeled `copilot-remediate` whose body
declares an SDE class (`secret`, `token`, `pii`, `pci`, `phi`),
follow these rules.

### Exposure scope — classify first
- PRE-EXPOSURE: literal exists only in the current working
  tree. Never committed to a shared remote. Never printed in
  CI logs.
- EXPOSED: anything else. If in doubt, it's EXPOSED.

Determine scope by:
- Reading the "Exposure" field of the issue body.
- Running `git log --all -S '<literal-hash>'` (hash the
  literal; never echo it).

### EXPOSED — do NOT edit code
If scope is EXPOSED:
- Do not open a PR.
- Do not modify the offending file.
- Post a single comment on the issue with:
  - The rotation checklist (revoke, rotate, re-deploy,
    invalidate cached sessions).
  - The disclosure checklist (IR ticket, service owner, legal
    routing).
  - The first-seen commit sha + date.
- Add the `needs-rotation` label.
- Remove the `copilot-remediate` label (the finding is now a
  rotation task, not an agent task).

### PRE-EXPOSURE — minimal code fix
- Branch: `copilot/<finding-id>`.
- Commit: `fix(sec): remove <class> <finding-id>`.
- Replacement patterns:
  - `secret` / `token` → reference the project's approved
    secret store. Identify the client from
    `docs/security/secrets.md`. If that document doesn't
    exist or names no client, comment on the issue explaining
    why remediation is blocked and stop.
  - `pii` / `pci` / `phi` → route through the project's
    redaction helper (grep for `redact(`, `mask_pii`,
    `scrubPII`). If none exists, comment on the issue and
    stop — do not invent one.
  - Test fixtures with real user data → replace with
    Faker-style synthetic values. Comment each fixture with
    the finding id.
- Add a regression guard: a unit test that fails if the
  literal reappears, or a scanner-config entry that flags it.
  Allowlist only the synthetic-fixture path.
- Minimal edit only. No renames. No reformatting unrelated
  code.

### What you must NEVER do
- Rewrite git history.
- Echo the SDE literal in commit messages, PR bodies, chat
  output, or logs. When referring to it, hash it.
- Commit or remove `.env` / `credentials.json` files —
  those require a `git filter-repo` runbook + human sign-off.
- Merge your own PR. Never enable auto-merge.

### PR shape (pre-exposure path)
- Title: `fix(sec): remove <class> from <file> (<finding-id>)`.
- Body: link the issue (`Closes #NNN`), exposure scope
  (`pre-exposure`), replacement pattern used, test pass
  evidence, one-line revert instructions. Never include the
  literal.
- Labels: `security`, `sde-remediation`.
- Keep the PR as DRAFT. Never mark ready-for-review.
~~~

### `.github/ISSUE_TEMPLATE/security-remediation-sde.yml`

~~~yaml
name: Security — Sensitive data element remediation
description: Open a remediation task for a single SDE finding.
title: "Remediate: <finding-id> (<sde-class>)"
labels: ["copilot-remediate", "security"]
assignees: ["copilot"]
body:
  - type: input
    id: finding_id
    attributes:
      label: Finding id
      placeholder: GITLEAKS-AWS-001
    validations:
      required: true
  - type: dropdown
    id: sde_class
    attributes:
      label: SDE class
      options: [secret, token, pii, pci, phi]
    validations:
      required: true
  - type: dropdown
    id: exposure
    attributes:
      label: Exposure scope
      description: Best-known answer at the time of filing. The agent will re-verify.
      options:
        - pre-exposure (literal only in working tree)
        - exposed (committed / pushed / seen in CI logs / public)
        - unknown
    validations:
      required: true
  - type: input
    id: file_path
    attributes:
      label: File path
      placeholder: src/config/stripe.ts
    validations:
      required: true
  - type: input
    id: line
    attributes:
      label: Line number
      placeholder: "42"
    validations:
      required: false
  - type: textarea
    id: notes
    attributes:
      label: Notes for the agent
      description: |
        DO NOT paste the literal SDE value in this field. Hash or
        abstract it. Example: "STRIPE_LIVE_KEY_sk_live_*** (last
        4 chars: abcd)".
    validations:
      required: false
~~~

### `CODEOWNERS` pairing

Make sure your `CODEOWNERS` routes SDE-relevant paths to the
security team so branch protection blocks merges until they
review:

~~~
# CODEOWNERS excerpt
src/config/**       @org/security @org/platform
**/.env.example     @org/security
docs/security/**    @org/security
~~~

## Known limitations

- **Issue templates accept free-form text.** If a reporter
  pastes the SDE literal into the notes field by mistake, it
  becomes part of the issue history. Gate the template with a
  CI step that scans `issue.body` and auto-edits if a known
  secret pattern appears — don't rely on the reporter.
- **Git-history check is a heuristic.** Renames, whitespace
  normalization, or format changes can hide a secret from
  `git log -S`. Prefer the scanner's own "first seen"
  metadata when it's provided.
- **Exposure classification still benefits from a human.** If
  `Exposure` is `unknown`, the agent will treat it as exposed
  (safer default) — which may feel conservative on
  false-positive findings.
- **Needs-rotation label is the handoff.** Make sure on-call
  rotates actually subscribe to it.

## Changelog

- 2026-04-21 — v1, first published. Exposed-SDE path
  deliberately refuses code edits. Pair with `CODEOWNERS` to
  make path protections enforceable at the branch level.
