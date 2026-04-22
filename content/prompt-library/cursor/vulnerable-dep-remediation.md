---
title: "Vulnerable dependency remediation (rule + command)"
linkTitle: "Vulnerable dep remediation"
tool: "cursor"
author: "Stephen M Abbott"
team: "InfoSec"
maturity: "development"
model: "Opus 4.7"
tags: ["sca", "cve", "dependencies", "cursor", "rules", "commands"]
weight: 10
date: 2026-04-21
---

A Cursor **project rule** + **custom slash command** pair for
remediating a vulnerable open-source dependency. The rule encodes
the house constraints (conservative bumps only, one PR per
finding, no auto-merge). The slash command is the one-line trigger
engineers invoke interactively — or that Cursor Automations
invokes on a schedule / webhook.

## What this prompt does

When an engineer runs `/remediate-dep CVE-2026-1234` in Cursor's
chat (or Cursor Automations invokes it on a schedule), the
underlying Agent / Background Agent reads the finding, locates
the affected package, applies the lowest-viable bump, runs the
project's tests, and opens a PR scoped to that single finding.
The rule file guarantees the constraints are applied on every
invocation regardless of who typed the command.

**Inputs:** the finding id (as the command argument), optional
package hint in the chat body.<br/>
**Outputs:** either a branch + draft PR (happy path), or a
summary in chat + no commits (triage path). Cursor Background
Agents surface the run in the sidebar for review.

## When to use it

- A developer already has Cursor open and wants to knock out a
  Dependabot / Snyk finding without leaving the editor.
- Cursor Automations is wired to a GitHub issue label
  (`security:remediate`) and needs a consistent command to
  invoke.
- Nightly Background Agent sweeps through the top-N open
  findings, opening up to 5 PRs per run.

**Don't use it for:**

- Major version migrations — the rule refuses by default.
- Cross-repo fanouts — invoke per repo so the rule scope applies.
- Interactive "is this CVE real" triage conversations — those
  are human work; this command jumps to fix mode.

## The prompt

Two files, checked in to the repo.

### `.cursor/rules/remediate-dep.mdc`

~~~markdown
---
description: >
  Conservative vulnerable-dep remediation house rules. Applies
  whenever the agent is asked to bump a dep in response to a CVE
  or advisory id.
globs:
  - "package.json"
  - "pnpm-lock.yaml"
  - "package-lock.json"
  - "yarn.lock"
  - "go.mod"
  - "go.sum"
  - "requirements*.txt"
  - "uv.lock"
  - "poetry.lock"
  - "Cargo.toml"
  - "Cargo.lock"
  - "Gemfile"
  - "Gemfile.lock"
---

# Vulnerable dependency remediation — house rules

## Scope
- ONE finding per run. One commit. One PR. No bundling.
- Branch: `fix/<finding-id>` (use the CVE / GHSA id verbatim).
- Commit: Conventional Commits: `fix(sec): bump <pkg> from <old>
  to <new> (<finding-id>)`.

## Version bump policy
- Always pick the LOWEST version in the advisory's patched range.
- NEVER cross a major-version boundary unless the user has
  explicitly written "major ok" in the task brief.
- For transitive-only fixes, prefer bumping the direct parent to
  pull in the patched transitive. If both options require a
  major bump, stop and explain — do not guess.
- Pre-release / rc / beta versions are off by default. If the
  advisory only lists a pre-release fix, stop and triage.

## Verification
- Use the NATIVE package manager to apply the bump; never
  hand-edit the lockfile.
- After the bump: run the repo's lint and test commands. Look
  for `pnpm test`, `make test`, `go test ./...`, `uv run pytest`,
  `cargo test`, `bundle exec rspec` — whichever the repo uses.
- If lint or tests fail because of the bump, REVERT the bump
  and summarize what failed. Do not try to fix the test.
- If a scanner (`osv-scanner`, `grype`, `trivy fs`) is available,
  re-scan to confirm the finding is gone.

## What you may NOT touch
- Anything outside the manifest and its lockfile, except where
  the package manager rewrites a peer file (e.g. `go.sum` after
  `go mod tidy`).
- Any file under `db/migrations/` or `infra/terraform/`.
- Generated files (`**/*.generated.*`).
- CI workflows, except to change a pinned action version in
  response to a CVE on that action.

## PR shape
- Title: `fix(sec): bump <pkg> to <ver> (<finding-id>)`.
- Body: finding id + link, old → new version, direct/transitive,
  test command + pass evidence, one-line revert instructions.
- Labels: `security`, `auto-remediation`.
- DRAFT PR. Never mark ready-for-review. Never auto-merge.
~~~

### `.cursor/commands/remediate-dep.md`

Filename is the command name — no frontmatter required.

~~~markdown
# Remediate a single vulnerable dependency

Argument (optional): a CVE id or GHSA id (e.g. `CVE-2026-1234`,
`GHSA-xxxx-xxxx-xxxx`).

Infer everything else from the session: the repo root you're
already in, the default branch (from the git remote), the test
and lint commands (from `package.json` scripts, `Makefile`
targets, or the README).

If no finding id is provided AND no scanner MCP is wired in,
discover a target yourself before touching code:

- Run the lightest-weight local scanner available, in this
  order: `osv-scanner scan source .`, `npm audit --json`,
  `pip-audit`, `govulncheck ./...`, `cargo audit`,
  `bundle audit`, `trivy fs --scanners vuln .`.
- If none are available, query the GitHub Advisory Database via
  `gh api /repos/{owner}/{repo}/vulnerability-alerts` or the
  public advisories endpoint using package names from the
  manifests.
- Pick the highest-severity fixable finding per the rules
  below. Note in the PR body that the finding was
  self-discovered and which scanner produced it.
- If no discovery tooling is available, stop and post a summary
  in chat naming what to install — do not guess.

Using the house rules in `.cursor/rules/remediate-dep.mdc`:

1. Fetch the advisory details from the GitHub Advisory Database
   (or OSV if the GHSA isn't available there yet). Record the
   affected package, affected range, and patched range.
2. Locate the affected package in this repo's resolved
   dependency tree (direct AND transitive). If not installed,
   stop and summarize "not-vulnerable: package not installed".
3. Pick the lowest version in the patched range. If it crosses a
   major boundary, refuse per the rule file and summarize why.
4. Apply the bump via the native package manager. Commit once.
5. Run lint and tests. If either fails because of the bump,
   revert and summarize the failure.
6. Open a DRAFT pull request per the rule file's PR shape. Link
   the advisory in the PR body. Do not mark ready-for-review.

If any of 1–5 require human judgment (ambiguous patched range,
major bump required, pre-release only, yanked version), stop and
post a structured summary in chat instead of committing.
~~~

Invoke from chat with `/remediate-dep CVE-2026-1234`. In Cursor
Automations, the same command is the entry point for scheduled
sweeps and issue-labeled triggers.

## Known limitations

- **Rule-scope globs** must match the manifests actually touched;
  if your repo uses an unusual layout (e.g. manifests under
  `tooling/*/`) extend the `globs:` list so the rule loads.
- **Multi-ecosystem repos.** The command is fine for one
  ecosystem per run. For monorepos with mixed Node/Python/Go, run
  one invocation per affected workspace.
- **Draft-PR policy is enforced by the rule, not by the PR API.**
  Pair it with a repo-level branch protection that blocks merges
  from `@cursor[bot]`-authored PRs until a human reviewer
  approves.
- **Background Agent context budget.** Very large monorepos can
  push the agent past its retrieval budget. Pin the
  `.cursor/mcp.json` allowlist to only the MCP tools this flow
  needs.

## Changelog

- 2026-04-21 — v1, first published. Covers Node / Python / Go /
  Rust / Ruby. Monorepo fanout handled by invoking per-workspace.
