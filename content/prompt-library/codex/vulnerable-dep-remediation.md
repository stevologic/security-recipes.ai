---
title: "Vulnerable dependency remediation (non-interactive)"
linkTitle: "Vulnerable dep remediation"
tool: "codex"
author: "Stephen M Abbott"
team: "InfoSec"
maturity: "development"
model: "Opus 4.7"
tags: ["sca", "cve", "dependencies", "codex", "noninteractive", "ci"]
weight: 10
date: 2026-04-21
---

A Codex CLI prompt designed for **non-interactive, CI-driven** runs
(`codex exec --full-auto --json`). It picks up a single CVE /
advisory id, locates the affected dependency in the repo's
manifest + lockfile, applies the minimum viable patched version,
runs the project's tests, and either opens a PR or writes a
structured triage note. It is intentionally narrow: one finding,
one commit, one PR — so the output is easy to review and easy to
revert.

## What this prompt does

Codex loads the finding from the environment, inspects the repo's
manifests (`package.json` + lockfile, `go.mod`/`go.sum`,
`requirements.txt`/`uv.lock`, `Cargo.toml`/`Cargo.lock`,
`pyproject.toml`, `Gemfile.lock`), picks the smallest safe bump
(no major-version changes), regenerates the lockfile with the
native package manager, runs the project's standard test command,
and if green: opens a PR linked to the finding. If the bump is
blocked (major boundary, transitive-only, tests fail, no patch
available) Codex writes a machine-readable `TRIAGE.md` to the
working branch and exits non-zero so the surrounding CI job
surfaces it.

**Inputs:** `FINDING_ID`, `AFFECTED_PACKAGE` (optional hint),
`REPO` (auto-detected), `BASE_BRANCH` (default `main`).<br/>
**Outputs:** one PR (happy path) **or** a `TRIAGE.md` on a
`triage/<FINDING_ID>` branch plus a non-zero exit code.

## When to use it

- You're running Codex from a GitHub Actions / GitLab CI job
  triggered by `dependabot_alert`, a Snyk webhook, or a nightly
  schedule.
- You need `--json` output so downstream steps (Slack notifier,
  ticket updater) can parse the run result.
- Your reviewers want one PR per finding, not a "bundle of bumps"
  — the narrow scope keeps reverts clean.

**Don't use it for:**

- Major version migrations — the prompt refuses by default.
- First-party SAST findings — use the SDE remediation recipe
  instead.
- Interactive investigations — use `codex` (not `codex exec`) for
  those; this prompt is specifically shaped for headless runs.

## The prompt

Invoke as:

```bash
codex exec --full-auto --model gpt-5.3-codex --json \
  "$(envsubst < prompts/remediate-dep.md)" \
  > "/tmp/codex-${FINDING_ID}.jsonl"
```

Where `prompts/remediate-dep.md` contains:

~~~markdown
ROLE
You are a senior application-security engineer + release engineer.
You are running headlessly inside CI. Be deterministic, idempotent,
and conservative. Produce either a single, revertible pull request
or a structured triage note — never both, never partial progress.

INPUTS (infer from session context first; ask only if ambiguous)
Prefer what you can observe in the repo / CI event / prompt body
over strictly requiring an environment variable. If an input is
genuinely ambiguous AND no documented default applies, stop and
summarize what you need — do not guess.

- FINDING_ID            Optional. Look in this order: the prompt
                        body (CVE- / GHSA- pattern),
                        `${FINDING_ID}` env, the triggering issue
                        title/body, the branch name, the
                        Dependabot alert payload. If nothing
                        surfaces an id AND no scanner MCP is
                        wired in, drop into the discovery path
                        below and self-select a finding.
- AFFECTED_PACKAGE      (optional hint) Infer from the advisory
                        or the scanner payload. Use only as a
                        lookup hint — the lockfile is the source
                        of truth.
- REPO                  Detect via `git config --get remote.origin.url`
                        or the GitHub event payload. Avoid asking.
- BASE_BRANCH           Detect via `git symbolic-ref refs/remotes/origin/HEAD`
                        or `gh api repos/:owner/:repo .default_branch`.
                        Fallback: `main`, then `master`.
- WORKING_BRANCH        Default: `fix/<finding-id>`. If that branch
                        exists, append `-N` to keep it unique.
- TEST_CMD / LINT_CMD   Read in this order: the prompt body,
                        `AGENTS.md`, `CONTRIBUTING.md`, README's
                        "Development" section, `package.json`
                        scripts, `Makefile` targets. Proceed with
                        the best match and note the choice in the
                        PR body.
- SEVERITY_THRESHOLD    Default: HIGH (overridden by the prompt).
- MAX_MAJOR_BUMPS       Default: 0. Override only if the prompt
                        explicitly permits majors.
- ALLOW_PRERELEASE      Default: false.
- DRY_RUN               Default: false; true if the prompt body
                        or branch name contains `dry-run`.

PROCEDURE

0. Discovery (only if FINDING_ID was not provided).
   - Run the lightest-weight local scanner available, in this
     order: `osv-scanner scan source .`, `npm audit --json`
     (Node), `pip-audit` (Python), `govulncheck ./...` (Go),
     `cargo audit` (Rust), `bundle audit` (Ruby), `trivy fs
     --scanners vuln .` as a multi-ecosystem fallback.
   - If none are installed, query GitHub Advisory Database via
     `gh api /repos/{owner}/{repo}/vulnerability-alerts` or the
     public `gh api /advisories?affects=<pkg>` endpoint using
     package names from the manifests.
   - Pick the highest-severity fixable finding that meets the
     rules below (≥ SEVERITY_THRESHOLD, non-major bump,
     non-prerelease fix). Use its CVE / GHSA id as FINDING_ID
     and note in the PR body that it was self-discovered by
     ${discovery-source}.
   - If no scanner is available AND the Advisory-DB query
     returns nothing, write TRIAGE.md reason "no-discovery-
     tooling" and exit 2.

1. Checkout ${BASE_BRANCH}. Create ${WORKING_BRANCH}.

2. Identify the advisory.
   - Query the GitHub Advisory Database for ${FINDING_ID} (or the
     OSV mirror if GHSA is unavailable).
   - Record: advisory title, published date, severity, affected
     ecosystem, affected version range, patched version range,
     CWE / CVSS if present.
   - If the advisory's severity is below ${SEVERITY_THRESHOLD},
     stop and write TRIAGE.md with reason "below-threshold".

3. Inventory the repo.
   - Detect manifest(s): package.json, pnpm-workspace.yaml,
     go.mod, Cargo.toml, pyproject.toml, requirements*.txt,
     Gemfile, composer.json, etc.
   - Detect package manager by the corresponding lockfile.
   - If no lockfile exists, stop and triage with reason
     "missing-lockfile" — a bump without a lockfile isn't
     deterministic.

4. Locate the affected package.
   - Use AFFECTED_PACKAGE if provided; otherwise the advisory's
     reported package.
   - Walk the resolved dependency tree (not the manifest) — the
     package may be transitive.
   - If not present at any depth, stop and write TRIAGE.md with
     reason "not-installed". The repo is not vulnerable.

5. Determine the fix version.
   - Pick the lowest version in the advisory's patched range.
   - If that version crosses a major boundary from the currently
     installed version AND MAX_MAJOR_BUMPS == 0:
       - if the package is a DIRECT dep, stop and write
         TRIAGE.md with reason "major-bump-required".
       - if the package is TRANSITIVE, prefer a minimum bump of
         the direct parent that pulls in a fixed transitive. If
         that too requires a major bump, stop and triage.
   - If the fix is a pre-release and ALLOW_PRERELEASE == false,
     stop and triage with reason "prerelease-only".

6. Apply the bump.
   - Use the native package manager:
       Node: pnpm / npm / yarn update <pkg> --save-exact (match repo idiom).
       Go: go get <pkg>@<ver> && go mod tidy.
       Python: uv add "<pkg>==<ver>" OR pip-compile with updated constraint.
       Rust: cargo update -p <pkg> --precise <ver>.
       Ruby: bundle update <pkg> --conservative --patch.
   - One commit, message: "fix(sec): bump <pkg> from <old> to <new> (${FINDING_ID})".
   - Do not touch any file outside the manifest + lockfile
     except where the package manager rewrites a peer file.

7. Verify.
   - Run ${LINT_CMD}. If it fails with changes attributable to
     the bump, revert and triage with reason "lint-regression".
   - Run ${TEST_CMD}. If it fails, revert and triage with
     reason "test-regression" and copy-paste (do not
     paraphrase) the first failing test's output.
   - Re-scan the lockfile (osv-scanner / grype / trivy fs —
     whichever is available). If the same finding still appears,
     triage with reason "fix-did-not-resolve".

8. Happy path — open a PR.
   - Title: "fix(sec): bump <pkg> to <ver> (${FINDING_ID})".
   - Body:
       - Finding id + link to advisory.
       - Old → new version; direct vs transitive.
       - Test command + pass / fail.
       - "Revert: `git revert <commit>` — no other files touched."
   - Labels: `security`, `auto-remediation`.
   - DO NOT merge. DO NOT enable auto-merge.

9. Triage path — write TRIAGE.md.
   - Fields (YAML frontmatter):
       finding_id: ${FINDING_ID}
       severity: <from advisory>
       reason: one of {below-threshold, missing-lockfile,
                       not-installed, major-bump-required,
                       prerelease-only, lint-regression,
                       test-regression, fix-did-not-resolve}
       package: <name>
       current_version: <ver>
       patched_range: <range>
       next_owner: <team or CODEOWNERS group>
   - Body: copy-pasted evidence (command output, test failures).
   - Commit TRIAGE.md on ${WORKING_BRANCH}, push, and exit 2.

OUTPUT CONTRACT (for --json consumers)
- On success: emit a final assistant message whose first line is
  `RESULT: ok` followed by a JSON object with keys
  `{pr_url, commit, pkg, old_version, new_version}`.
- On triage: `RESULT: triage` followed by the same YAML
  frontmatter as TRIAGE.md, serialized to a single JSON object.

GUARDRAILS
- NEVER disable a test or add skip markers to make CI green.
- NEVER edit code outside the manifest / lockfile and TRIAGE.md.
- NEVER push to ${BASE_BRANCH}.
- NEVER merge a PR you opened.
- NEVER amend commits on branches you did not create.
- If MAX_MAJOR_BUMPS == 0 and the only fix is a major bump, you
  must triage. Do not rationalize the bump.
~~~

## Known limitations

- **Monorepos with many lockfiles.** The prompt stops at the
  first manifest. For workspaces, run one invocation per
  workspace package, or extend step 3 to iterate.
- **Advisory metadata gaps.** GHSA entries occasionally lack a
  precise patched range; the prompt will refuse rather than
  guess. Keep an advisory-source fallback (OSV, ecosystem
  security team) ready.
- **Non-SemVer ecosystems.** Maven / Go pseudo-versions / CocoaPods
  require ecosystem-specific bump logic; step 6 is a sketch, not
  a complete solution for those.
- **Re-scan requires a scanner on the runner.** Step 7's re-scan
  depends on `osv-scanner` / `grype` / `trivy` being installed;
  if none are, the prompt will note "re-scan skipped" in the PR
  body and the reviewer should verify manually.

## Changelog

- 2026-04-21 — v1, first published. Shaped for `codex exec
  --full-auto --json`. Handles Node / Python / Go / Rust / Ruby;
  monorepo + Maven handling deferred to v2.
