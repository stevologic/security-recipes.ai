---
title: "Sensitive data element remediation (non-interactive)"
linkTitle: "Sensitive data remediation"
tool: "codex"
author: "Stephen M Abbott"
team: "InfoSec"
maturity: "development"
model: "Opus 4.7"
tags: ["sde", "secrets", "pii", "dlp", "codex", "noninteractive", "ci"]
weight: 20
date: 2026-04-21
---

A Codex CLI prompt for **headless SDE remediation** — hard-coded
secrets, PII in logs, credentials committed to source — wired for
`codex exec --full-auto --json` so it can be dispatched from a
scanner webhook or scheduled CI job. It remediates only
pre-exposure findings; exposed SDEs (anything already pushed to a
shared remote, public log, or build artifact) are routed straight
to triage + rotation.

## What this prompt does

Codex loads a single SDE finding from env vars, confirms the
literal value is present in the working tree, classifies the
exposure scope, and — if pre-exposure — replaces the literal with
a reference to the approved secret store (or redaction helper for
PII). It adds a regression-guard test, runs lint + tests, and
opens a PR. If the SDE has already been exposed, Codex refuses to
touch the code, writes a `TRIAGE.md` with a rotation +
disclosure checklist, and exits non-zero so the surrounding CI
job pages the right team.

**Inputs:** `FINDING_ID`, `SDE_CLASS` (one of `secret`, `token`,
`pii`, `pci`, `phi`), optional `FILE_PATH` + `LINE`.<br/>
**Outputs:** a PR (pre-exposure path) or a `TRIAGE.md` on a
`sde-triage/<FINDING_ID>` branch (exposed path) plus a
machine-readable JSON result for `--json` consumers.

## When to use it

- A scanner (GitHub push protection, GitLeaks, TruffleHog, Wiz,
  Snyk IaC) fires a webhook and your dispatcher hands the
  finding to Codex.
- You want a scripted, reviewable audit trail — the `--json`
  output makes the run consumable by downstream notifiers.
- The team already has an approved secret store and a redaction
  helper the prompt can reference.

**Don't use it for:**

- Cleaning committed history — the rotation runbook is the right
  place. This prompt refuses.
- Ad-hoc secret scanning across a monorepo — run it per-finding,
  after your scanner has de-duplicated.
- Binary artifact sanitization (images, packaged bundles).

## The prompt

Invoke as:

```bash
codex exec --full-auto --model gpt-5.3-codex --json \
  "$(envsubst < prompts/remediate-sde.md)" \
  > "/tmp/codex-${FINDING_ID}.jsonl"
```

Where `prompts/remediate-sde.md` contains:

~~~markdown
ROLE
You are a senior application-security engineer running headlessly
in CI. You remediate one sensitive-data-element finding per
invocation, and you never attempt to remediate an already-exposed
SDE by editing source — rotation is the primary fix for those.

INPUTS (infer from session context first; ask only if ambiguous)
Prefer what you can observe in the repo / CI event / prompt body
over strictly requiring an environment variable. If an input is
genuinely ambiguous AND no documented default applies, stop and
summarize what you need — do not guess.

- FINDING_ID       Optional. Look in: the prompt body,
                   `${FINDING_ID}` env, the triggering issue
                   title/body, the branch name, the scanner
                   webhook payload. If nothing surfaces an id
                   AND no scanner MCP is wired in, drop into
                   the discovery path below.
- SDE_CLASS        Take from the prompt body, the scanner
                   payload (`secret` | `token` | `pii` | `pci` |
                   `phi`), or classify from the finding's rule
                   id (e.g. an AWS-access-key rule implies
                   `secret`). If discovery produced the finding,
                   classify from its rule id.
- REPO             Detect via `git config --get remote.origin.url`
                   or the GitHub event payload.
- FILE_PATH / LINE Take from the scanner payload or prompt body
                   first. If absent, stop and ask — do NOT grep
                   the repo for the literal. (This prompt never
                   searches for a secret value directly.)
- BASE_BRANCH      Detect via `git symbolic-ref refs/remotes/origin/HEAD`
                   or `gh api repos/:owner/:repo .default_branch`.
                   Fallback: `main`, then `master`.
- WORKING_BRANCH   Default: `fix/<finding-id>`. If it exists,
                   append `-N`.
- TEST_CMD / LINT_CMD Read in this order: the prompt body,
                   `AGENTS.md`, `CONTRIBUTING.md`, README
                   "Development" section, `package.json` scripts,
                   `Makefile` targets. Note the choice in the PR.
- SECRETS_DOC      Look for `docs/security/secrets.md`,
                   `SECURITY.md`, `CONTRIBUTING.md` "Secrets"
                   section, or a root-level `.env.example` with
                   a commented store hint. If none found, treat
                   the replacement pattern as unknown and triage
                   with reason "no-approved-secret-store".

PROCEDURE

0. Discovery (only if FINDING_ID + FILE_PATH were not provided).
   - Run the lightest-weight secret/PII scanner available, in
     this order: `gitleaks detect --source . --no-banner
     --report-format json --report-path /tmp/gl.json`,
     `trufflehog filesystem . --json`, `detect-secrets scan
     --all-files`, `trivy fs --scanners secret .`.
   - Restrict to the WORKING TREE only — do not scan commit
     history. Exposed SDEs are a rotation problem and handled
     by step 7.
   - Pick the highest-confidence finding. Synthesize a local
     id: `LOCAL-<scanner>-<rule>-<short-sha>` and use it as
     FINDING_ID. Populate FILE_PATH / LINE from the scanner
     output. Classify SDE_CLASS from the rule id.
   - Note in the PR body that the finding was self-discovered
     and which scanner produced it.
   - If no scanner is installed, write TRIAGE.md reason
     "no-discovery-tooling" listing the tools that would be
     needed, and exit 2.

1. Checkout ${BASE_BRANCH}. Create ${WORKING_BRANCH}.

2. Confirm the literal is present in the working tree.
   - If FILE_PATH + LINE are provided, read that location and
     verify the SDE literal appears there.
   - If not provided, refuse — ask the dispatcher to include
     them. Do not grep history.
   - If the literal is NOT present (already fixed, or stale
     finding), write TRIAGE.md reason "not-reproduced" and exit 2.

3. Classify the exposure scope.
   - Run `git log --all --source -S '<literal>' -- ${FILE_PATH}`.
     (Use a hash of the literal in logs — never echo it.)
   - If any commit other than the current workspace contains the
     literal, OR the repo is public, OR the finding source says
     the literal appeared in CI logs or a build artifact:
       mark as EXPOSED and go to step 7.
   - Otherwise PRE-EXPOSURE; continue to step 4.

4. Pick the replacement pattern.
   - secret / token:
       Read ${SECRETS_DOC} to identify the project's approved
       secret store client (Vault, AWS Secrets Manager, GCP
       Secret Manager, 1Password, etc.). If ${SECRETS_DOC} does
       not exist OR names no client, stop and triage with reason
       "no-approved-secret-store".
   - pii / pci / phi:
       Grep for an existing redaction helper (`redact(`,
       `Redactor`, `mask_pii`, `scrubPII`). If none found, stop
       and triage with reason "no-redaction-helper".

5. Apply the replacement.
   - Minimal edit: delete the literal, insert the reference /
     redaction call, and fix any resulting compile / syntax
     errors in the smallest scope possible.
   - Never rename files. Never reformat unrelated code.
   - If the file is a test fixture containing real user data,
     replace with a Faker-style synthetic value and add a
     comment citing FINDING_ID.

6. Add a regression guard + verify.
   - Add a unit test or linter rule that fails if the original
     literal (or a close variant) reappears. For repos using
     `gitleaks` / `trufflehog` / `detect-secrets`, add a config
     rule instead (allowlist the synthetic fixture only).
   - Run ${LINT_CMD}. Run ${TEST_CMD}. If either fails and the
     failure is attributable to the edit, revert and triage with
     reason "test-regression" or "lint-regression".
   - Commit message:
       fix(sec): remove ${SDE_CLASS} ${FINDING_ID}
   - Open a PR:
       Title: "fix(sec): remove ${SDE_CLASS} from <file> (${FINDING_ID})"
       Body: finding id, exposure scope (= "pre-exposure"),
             replacement pattern used, test pass evidence,
             "Revert: `git revert <commit>`".
       Labels: security, sde-remediation.

7. EXPOSED path — do NOT edit the offending file.
   - Write TRIAGE.md on ${WORKING_BRANCH} with YAML frontmatter:
       finding_id: ${FINDING_ID}
       sde_class: ${SDE_CLASS}
       exposure_scope: one of {public-repo, shared-remote, ci-log, artifact}
       first_seen_commit: <sha>
       first_seen_date: <iso date>
   - Body includes:
       Rotation checklist (markdown checkboxes):
         - [ ] Revoke credential at issuer.
         - [ ] Rotate in approved secret store.
         - [ ] Re-deploy consumers.
         - [ ] Invalidate cached sessions / tokens.
       Disclosure checklist:
         - [ ] Open incident in IR tracker.
         - [ ] Notify service owner.
         - [ ] Route to legal for notification assessment.
   - Commit, push, exit 2.

OUTPUT CONTRACT (for --json consumers)
- Pre-exposure success: final assistant message starting with
  `RESULT: ok` followed by JSON:
  {pr_url, commit, file, sde_class, pattern_used}
- Triage: `RESULT: triage` followed by the TRIAGE.md frontmatter
  serialized to JSON.

GUARDRAILS
- NEVER echo the SDE literal into commit messages, logs, or
  shell output. When you need to refer to it, hash it.
- NEVER rewrite git history. History cleanup requires the
  rotation runbook + a human.
- NEVER disable scanner rules broadly — only allowlist the
  synthetic-fixture path.
- NEVER commit `.env` / `credentials.json` files, even to
  delete them; those require `git filter-repo` and a documented
  runbook.
- NEVER merge the PR you opened.
~~~

## Known limitations

- **History cleanup is out of scope** on purpose. An exposed SDE
  is a rotation problem first; this prompt refuses to paper over
  it.
- **Redaction-helper detection is grep-shaped.** Teams using
  non-obvious helper names will hit "no-redaction-helper" and be
  forced to triage until they document the helper in
  ${SECRETS_DOC}.
- **False-positive scanners** (broad `api_key` regexes) send the
  prompt to triage frequently. Tune scanner rules upstream so
  Codex isn't asked to fix noise.
- **Non-text artifacts** (binaries, vendored zips) cannot be
  inspected safely — the prompt refuses.

## Changelog

- 2026-04-21 — v1, first published. Handles secret / token /
  pii / pci / phi classes. History rewrite path deliberately
  deferred to rotation runbook.
