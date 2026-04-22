---
title: "Vulnerable dependency remediation (issue template + instructions)"
linkTitle: "Vulnerable dep remediation"
tool: "github_copilot"
author: "Stephen M Abbott"
team: "InfoSec"
maturity: "development"
model: "Opus 4.7"
tags: ["sca", "cve", "dependencies", "copilot", "coding-agent", "issue-template"]
weight: 10
date: 2026-04-21
---

A three-part bundle — a `.github/copilot-instructions.md`
addendum, a GitHub issue template, and the issue body that gets
created when a scanner projects a finding. Together they shape
the Copilot coding agent into a narrow, reviewable dependency
remediator: one finding per issue, one draft PR per issue, no
auto-merge.

## What this prompt does

When the scanner (or a developer) creates an issue from the
`security-remediation-dep.yml` template and labels it
`copilot-remediate`, the Copilot coding agent picks it up, reads
the repository-level instructions, applies the minimum viable
version bump in the affected manifest + lockfile, runs CI, and
opens a draft PR linked back to the issue. The agent respects
the house rules — no major bumps, no lockfile-only edits, no
disabling of tests.

**Inputs:** finding id + affected package (from the issue body),
repository-level instructions (from `.github/copilot-instructions.md`).<br/>
**Outputs:** a draft PR linked to the issue, passing CI, and a
human reviewer assigned via `CODEOWNERS`.

## When to use it

- You want the shortest-setup remediation path. GitHub-native, no
  separate orchestration layer.
- Your scanner already supports projecting findings into GitHub
  Issues (CodeQL, Snyk, Semgrep, Dependabot alerts converted to
  issues).
- You have branch protection on `main` that requires review and
  green CI, so the "agent opens a draft PR" pattern is safe.

**Don't use it for:**

- Major version migrations — the repository instructions refuse.
- Cross-repo fanouts — each repo needs its own label + workflow;
  this prompt is per-repo.
- First-party SAST findings — use the SDE remediation recipe.

## The prompt

Three files, checked in to the repo.

### `.github/copilot-instructions.md` — dependency remediation addendum

Append this to your existing `copilot-instructions.md`:

~~~markdown
## Vulnerable dependency remediation

When working on an issue labeled `copilot-remediate` whose body
includes a finding id (CVE- / GHSA-), follow these rules.

### Scope
- ONE finding per PR. Never bundle multiple advisories.
- Branch: `copilot/<finding-id>`.
- Commit: Conventional Commits: `fix(sec): bump <pkg> from <old>
  to <new> (<finding-id>)`.

### Version bump policy
- Pick the LOWEST version in the advisory's patched range.
- NEVER bump across a major-version boundary. If the only fix
  is a major bump, post a comment on the issue explaining why
  (direct dep vs transitive, breaking changes expected) and
  stop — do not push a PR.
- Pre-release / rc / beta versions are off by default. If the
  advisory lists only a pre-release fix, comment on the issue
  and stop.

### Tooling
- Use the native package manager to apply the bump. Never
  hand-edit the lockfile.
- After the bump, run the lint and test commands documented at
  the top of this file. If they fail because of the bump,
  revert, comment on the issue with the failing tests, and stop.

### Paths you may NOT touch
- `db/migrations/**` — any DB migration.
- `infra/terraform/**` — infra-as-code.
- `**/*.generated.*` — generated code.
- Any CI workflow, except to update a pinned action version in
  response to a CVE on that action.

### PR shape
- Title: `fix(sec): bump <pkg> to <ver> (<finding-id>)`.
- Body: link the issue (`Closes #NNN`), finding id + link to
  advisory, old → new version, direct vs transitive, test
  command + pass evidence, one-line revert instructions.
- Keep the PR as DRAFT. Never mark ready-for-review. Never
  enable auto-merge.
~~~

### `.github/ISSUE_TEMPLATE/security-remediation-dep.yml`

~~~yaml
name: Security — Dependency remediation
description: Open a remediation task for a single CVE / GHSA finding.
title: "Remediate: <finding-id> in <package>"
labels: ["copilot-remediate", "security"]
assignees: ["copilot"]
body:
  - type: input
    id: finding_id
    attributes:
      label: Finding id
      description: CVE id, GHSA id, or scanner-assigned id.
      placeholder: CVE-2026-1234
    validations:
      required: true
  - type: input
    id: package
    attributes:
      label: Affected package
      description: Package name (best-effort hint from the scanner).
      placeholder: "@example/unsafe-parser"
    validations:
      required: true
  - type: dropdown
    id: severity
    attributes:
      label: Advisory severity
      options: [critical, high, medium, low]
    validations:
      required: true
  - type: textarea
    id: advisory_url
    attributes:
      label: Advisory link(s)
      description: Paste the GHSA / CVE / NVD URL.
    validations:
      required: true
  - type: textarea
    id: notes
    attributes:
      label: Notes for the agent
      description: Anything the scanner couldn't auto-populate.
      placeholder: |
        - Dependency is transitive via "express@4".
        - Workspace package `apps/web` is the caller.
    validations:
      required: false
~~~

### What gets dispatched

When the issue is created (or labeled), the
`assign-copilot.yml` Action from the recipe page assigns
`@copilot`. The coding agent reads:

1. The repo-level `copilot-instructions.md` (house rules + the
   dependency addendum above).
2. The issue body (finding id, package, advisory link).

And produces: a draft PR on `copilot/<finding-id>` that either
fixes the finding or posts a comment explaining why the fix was
refused (major bump required, pre-release only, tests fail).

## Known limitations

- **Instructions are a prompt, not enforcement.** Pair this with
  strict branch protection + `CODEOWNERS` routing on any path
  the agent must not touch. The addendum's "paths you may NOT
  touch" list is advisory; `CODEOWNERS` makes it a hard gate.
- **Single-manifest assumption.** For monorepos, file one issue
  per affected workspace so the agent has a narrow scope.
- **Transitive fixes.** The agent can only hoist a transitive
  fix by bumping a parent; if the parent requires a major bump,
  the addendum forces a stop. That's the correct behavior, but
  expect more "refused" comments than raw PRs for older
  ecosystems.
- **Scanner projection cadence matters.** If your scanner
  projects every low-severity finding into an issue, the Copilot
  review queue will balloon. Gate projection on severity
  `high | critical` and label drift manually.

## Changelog

- 2026-04-21 — v1, first published. Covers Node / Python / Go
  lockfiles. Major-bump refusal is intentional.
