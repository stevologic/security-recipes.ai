---
title: Automation, not agentic
linkTitle: Automation
weight: 11
toc: true
sidebar:
  open: true
description: >
  Deterministic, well-worn automation for risk reduction — Dependabot,
  Renovate, npm audit, pip-audit, code scanning, and friends. Use these
  before (and alongside) your agentic flows.
---

{{< callout type="info" >}}
**Before you reach for a model, reach for a `--fix` flag.** A huge
amount of remediation work is deterministic, well-understood, and
already solved by tools that don't need an LLM in the loop. Agentic
flows earn their keep on the problems these tools can't touch —
not the ones they already handle.
{{< /callout >}}

## When automation beats agents

A dependency bump that a lockfile resolver can produce byte-for-byte is
not a job for a reasoning model. Neither is a lint auto-fix, a formatter
run, or a mechanical rename. Deterministic tools give you three things
an agent cannot:

- **Reproducibility.** The same input produces the same output, every
  time, on every developer machine and every CI runner.
- **Zero cost at scale.** No token bill, no rate limits, no per-repo
  opt-in. They run on every push, cheerfully, forever.
- **A trust surface you already have.** Dependabot PRs have been
  reviewed in your org for years. Your reviewer muscle memory works.

The rule of thumb: if the fix is mechanical and the diff is the same
for everyone, automation wins. If the fix requires reading the
surrounding code to decide *whether* to apply it, *where* to apply
it, or *how* to migrate callers, an agent is earning its keep.

## The catalog

### Version bumps & SCA

- **GitHub Dependabot** — version updates, security updates, grouped
  updates. Native to GitHub; configuration lives in
  `.github/dependabot.yml`. Great first line of defense against known
  CVEs in `package.json`, `requirements.txt`, `go.mod`, `Gemfile`,
  `composer.json`, and more.
- **Renovate** — the open-source competitor to Dependabot with
  substantially more configuration surface: custom schedules, auto-
  merge rules per dep, regex managers for arbitrary manifests, and
  presets. Worth the setup if you need fine control.
- **npm audit / pnpm audit / yarn audit** — built-in CVE reports.
  `npm audit fix` applies lockfile-only upgrades within your semver
  ranges; `npm audit fix --force` also crosses major versions (review
  carefully).
- **pip-audit** — `pip-audit --fix` rewrites `requirements.txt`
  pinning against PyPI's vulnerability database. Pair with a
  `requirements.in` / `pip-compile` workflow for clean diffs.
- **uv / Poetry** — both expose `add`/`lock` commands that resolve
  bumps deterministically; Poetry has a `poetry update` and uv has
  `uv lock --upgrade-package`.
- **Go** — `go get -u ./...` followed by `go mod tidy` gives you a
  clean, verifiable bump. `govulncheck` reports reachable CVEs.
- **Cargo** — `cargo update` for bumps; `cargo audit` for CVE
  reporting via RustSec.
- **Bundler** — `bundle update --conservative <gem>` bumps a single
  gem without cascading the rest of the lockfile.

### Code scanning & lint auto-fix

- **GitHub code scanning (CodeQL)** — SARIF output, PR annotations,
  default setup for most languages. Starts showing value the same day
  you flip it on.
- **ESLint / Prettier / Biome** — `--fix` flags. Wire into a
  pre-commit hook and a CI job; most style drift disappears on its
  own.
- **Ruff** — `ruff check --fix` and `ruff format` for Python. Fast
  enough that there's no reason not to run it on every save.
- **gofmt / goimports** — the table stakes for Go style.
- **Clippy** — `cargo clippy --fix` for Rust.

### Secrets & DLP

- **Gitleaks** — pre-commit + CI scan for secret patterns. Free,
  well-tuned, easy to allowlist.
- **TruffleHog** — credential detection with verified / unverified
  confidence tiers.
- **GitHub secret scanning** — built into GitHub for supported
  partners, with push protection. Flip it on.

### Policy-as-code

- **OPA / Conftest** — deterministic policy checks against Terraform
  plans, Kubernetes manifests, Dockerfiles. The fix is usually "edit
  the file"; the automation is the *enforcement* of what "correct"
  means.
- **tfsec / Checkov / kube-linter** — category-specific scanners
  that ship with sensible defaults and `--fix` in many cases.

### CI-level auto-remediation

- **GitHub Actions** — a tiny workflow that runs `npm audit fix` /
  `pip-audit --fix` / `go mod tidy` on a schedule and opens a PR is
  often enough to close the long tail of low-severity findings
  without touching a single agent.
- **Scheduled `make fix`** — if you have a `Makefile` target that
  runs every `--fix` flag you trust, a weekly scheduled job that
  commits the result to a branch and opens a PR is a surprisingly
  powerful pattern.

## How automation and agentic flows compose

The two patterns are complementary, not competitive. A healthy setup
looks roughly like this:

1. **Automation runs first and closes the easy cases.** Dependabot
   grouped updates merge themselves when CI is green and the diff is
   lockfile-only.
2. **The remainder lands in the agentic queue.** Findings that
   require code edits — a deprecated API migration, a policy
   violation that needs refactoring, a transitive CVE with no upstream
   patch — route to the agent recipes on this site.
3. **The agent uses the same deterministic tools you do.** The PR an
   agent opens should still pass `eslint --fix`, `ruff`, `go vet`,
   your OPA policies, and your test suite — because those are the
   gate, whether a human or an agent produced the diff.

Agents don't replace automation. They *extend* the reach of
automation into problems that need judgment.

## Getting started

A minimal "automation first" posture, in order of return on effort:

1. **Turn on Dependabot security updates.** Zero config required,
   immediate CVE-closing PRs.
2. **Add `.github/dependabot.yml`** for grouped version updates so
   you're not reviewing 40 bumps a week.
3. **Enable GitHub secret scanning + push protection.**
4. **Enable GitHub code scanning (CodeQL default setup).**
5. **Wire `npm audit` / `pip-audit` / `go vet` / `govulncheck` into
   CI** with a non-blocking "report" job first, then promote to
   blocking once the noise floor is manageable.
6. **Add a scheduled auto-fix PR workflow** that runs your trusted
   `--fix` commands and commits the result.
7. **Only then** layer the agent recipes on top — they'll have much
   less to do, and the work that's left is genuinely the work that
   needs judgment.

## See also

- [Agents]({{< relref "/agents" >}}) — per-tool remediation recipes for the problems automation can't handle
- [MCP Server Access]({{< relref "/mcp-servers" >}}) — how agents reach the context that deterministic tools don't need
- [Agentic Security Remediation]({{< relref "/security-remediation" >}}) — InfoSec-run workflows that combine both patterns
- [Prompt Library]({{< relref "/prompt-library" >}}) — community prompts that extend automation into judgment calls
