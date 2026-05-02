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

- **[GitHub Dependabot](https://docs.github.com/en/code-security/dependabot)** — version updates, security updates, grouped
  updates. Native to GitHub; configuration lives in
  `.github/dependabot.yml`. Great first line of defense against known
  CVEs in `package.json`, `requirements.txt`, `go.mod`, `Gemfile`,
  `composer.json`, and more.
- **[Renovate](https://docs.renovatebot.com/)** — the open-source competitor to Dependabot with
  substantially more configuration surface: custom schedules, auto-
  merge rules per dep, regex managers for arbitrary manifests, and
  presets. Worth the setup if you need fine control.
- **npm audit / pnpm audit / yarn audit** — built-in CVE reports.
  `npm audit fix` applies lockfile-only upgrades within your semver
  ranges; `npm audit fix --force` also crosses major versions (review
  carefully).
- **[pip-audit](https://github.com/pypa/pip-audit)** — `pip-audit --fix` rewrites `requirements.txt`
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
- **[Mend](https://www.mend.io/)** / **[Black Duck](https://www.blackduck.com/)** / **[JFrog Xray](https://jfrog.com/xray/)** — enterprise SCA platforms with broad ecosystem coverage, policy workflows, and license compliance.
- **[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)** / **[OSV-Scanner](https://google.github.io/osv-scanner/)** — free/open-source SCA options that fit well in CI for teams that want self-managed scanning.

### Code scanning & lint auto-fix

- **[GitHub code scanning (CodeQL)](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql)** — SARIF output, PR annotations,
  default setup for most languages. Starts showing value the same day
  you flip it on.
- **ESLint / Prettier / Biome** — `--fix` flags. Wire into a
  pre-commit hook and a CI job; most style drift disappears on its
  own.
- **[Ruff](https://docs.astral.sh/ruff/)** — `ruff check --fix` and `ruff format` for Python. Fast
  enough that there's no reason not to run it on every save.
- **[gofmt](https://pkg.go.dev/cmd/gofmt) / [goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports)** — the table stakes for Go style.
- **[Clippy](https://doc.rust-lang.org/clippy/)** — `cargo clippy --fix` for Rust.
- **[Semgrep](https://semgrep.dev/)** — fast OSS + enterprise SAST with managed rule packs, custom rules, and autofix support for many findings.
- **[SonarQube](https://www.sonarsource.com/products/sonarqube/) / [SonarCloud](https://www.sonarsource.com/products/sonarcloud/)** — widely adopted code quality + security gates for pull requests and release branches.

### Secret detection

- **[Gitleaks](https://github.com/gitleaks/gitleaks)** — open-source SAST for secrets. Detects hardcoded
  credentials, API keys, tokens, and high-entropy strings across
  source code, git history, and uncommitted changes. Configuration
  lives in `.gitleaks.toml` (rules, allowlists, path filters).
  Typical deployment:
  - **Pre-commit hook** — `gitleaks protect --staged` blocks a
    commit before the secret ever lands in history.
  - **CI job** — `gitleaks detect --source . --log-opts="--all"`
    scans the full history on every PR and fails the build if a
    new secret appears.
  - **GitHub Action** — the official `gitleaks/gitleaks-action` is
    a drop-in; enable `GITLEAKS_ENABLE_UPLOAD_ARTIFACT` to get the
    SARIF into the Security tab.

  Tune the ruleset: the defaults are generous, and allowlisting
  legitimate fixtures / test data (via `[allowlist]` entries with
  `paths`, `regexes`, or `stopwords`) is what makes Gitleaks usable
  in a large repo. Pair with `gitleaks git` in the pre-receive hook
  if you run a self-hosted git server.

- **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** — credential detection with **verified / unverified**
  confidence tiers. The killer feature is live verification: when
  TruffleHog finds what looks like an AWS key, it calls AWS to
  confirm the key is active before flagging it. Dramatically cuts
  false positives but requires the scanner to have outbound network
  access.
- **[GitHub secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning)** — built into GitHub for supported
  partners, with push protection. Flip it on — zero config, and
  the push-protection path stops secrets at the git-push boundary
  rather than after the fact.

### Sensitive Data Element (SDE) detection

Secret scanners catch credentials. **SDE scanners** catch the
broader category — PII, PHI, PCI data, and other regulated
content that shouldn't live in source, logs, or shared configs.

- **Earlybird** (American Express,
  [github.com/americanexpress/earlybird](https://github.com/americanexpress/earlybird))
  — open-source SDE scanner with a deliberately broad module set:
  credentials (API keys, tokens, private keys), PII (SSNs, credit
  card numbers, email addresses, phone numbers), PHI patterns, and
  language-specific hotspots (SQL-in-strings, hard-coded IPs, weak
  crypto calls). Written in Go, fast enough to run in a pre-commit
  hook on monorepos.

  Where Earlybird earns its keep:
  - **Pre-commit.** `earlybird scan --path .` with `--severity
    high` as a blocking gate; lower severities report but don't
    block. Install via the project's binary release or `go install`.
  - **CI.** Run against the diff (`--git-staged` or `--git-tracked`)
    to catch regressions on PR. Full-repo scans belong on a
    schedule, not on every push.
  - **Custom modules.** The `.ge_ignore` file and
    `config/*.json` rule packs make it straightforward to add
    organisation-specific sensitive patterns (internal account
    ID shapes, proprietary identifiers) without forking.
  - **Output formats.** JSON, JUnit XML, and human-readable —
    JUnit plugs directly into most CI dashboards.

  Earlybird overlaps with Gitleaks on the credential side. Running
  both is common — Gitleaks for git-history-aware secret sweeps,
  Earlybird for the wider SDE surface on the working tree. Dedupe
  downstream if you route both into the same triage queue.

- **[detect-secrets](https://github.com/Yelp/detect-secrets)** (Yelp) — the original audit-style scanner
  with a `.secrets.baseline` file so reviewers can snooze known
  findings deliberately rather than by allowlist regex.
- **[Presidio](https://microsoft.github.io/presidio/)** (Microsoft) — PII detection and redaction library
  aimed at structured and unstructured text (logs, free-form
  fields, CSV exports), with named-entity and regex recognizers
  bundled. Heavier to stand up than Earlybird but the right tool
  when the SDE surface is data flowing through services, not just
  code in a repo.

**Where this pairs with the agentic workflow.** The
[Sensitive Data Element remediation workflow]({{< relref
"/security-remediation/sensitive-data" >}}) assumes a deterministic
scanner like Earlybird (or the equivalent) is already surfacing
findings; the agent's job is the *fix-and-PR* step, not the
detection step. Running a good SDE scanner is a prerequisite, not
an alternative.

### Policy-as-code

- **[OPA](https://www.openpolicyagent.org/) / [Conftest](https://www.conftest.dev/)** — deterministic policy checks against Terraform
  plans, Kubernetes manifests, Dockerfiles. The fix is usually "edit
  the file"; the automation is the *enforcement* of what "correct"
  means.
- **[tfsec](https://aquasecurity.github.io/tfsec/) / [Checkov](https://www.checkov.io/) / [kube-linter](https://github.com/stackrox/kube-linter)** — category-specific scanners
  that ship with sensible defaults and `--fix` in many cases.
- **[Spectral](https://github.com/stoplightio/spectral) / [42Crunch API Security Testing](https://42crunch.com/)** — API contract linting and security checks for OpenAPI specs in CI.

### Container image scanning

- **[Trivy](https://trivy.dev/latest/)** (Aqua) — fast, open-source scanner for OS packages,
  language dependencies, IaC, and secrets inside container
  images. `trivy image <image>` on every build is the default
  starting point.
- **[Grype](https://github.com/anchore/grype)** (Anchore) — companion to Syft (SBOM) and widely used
  in CI. Integrates cleanly with Sigstore and Cosign for signed
  SBOM attestations.
- **[Clair](https://github.com/quay/clair)** (Quay) — registry-side scanning; pairs well with
  Harbor / Quay-style private registries.
- **[Docker Scout](https://docs.docker.com/scout/)** — Docker Hub–native scanning with
  vulnerability policy and base-image recommendations.
- **[Snyk Container](https://docs.snyk.io/scan-with-snyk/snyk-container) / [Wiz](https://www.wiz.io/) / [Prisma Cloud](https://www.paloaltonetworks.com/prisma/cloud) / [Aqua](https://www.aquasec.com/)** — commercial
  scanners with richer prioritization, context, and
  registry-level reporting. All layer on top of the same CVE
  feeds; the differentiator is usually prioritization, not
  detection.

### Golden images and base-image hygiene

Container image scanning is where most security programs first
experience "alert fatigue from findings we can't meaningfully
fix." A stock Debian / Alpine / Ubuntu base image carries
hundreds of CVEs at any given moment, almost none of which are
exploitable against your service, and almost all of which are
fixed only when the upstream distro rebuilds. **Golden images**
are the industry pattern for turning that noise into a small,
owned, actionable fix loop.

**What a golden image is:**

- A **pre-hardened base image** owned by the platform or security
  team (not the application team).
- **Minimal by design** — distroless, scratch-plus-libc, or a
  small-footprint distribution like Alpine / Wolfi. The fewer
  packages, the fewer CVEs.
- **Signed** with Sigstore / Cosign so downstream consumers can
  verify provenance.
- **SBOM-embedded** (CycloneDX or SPDX) so a scanner can report
  on contents without re-analysing layers.
- **Rebuilt on a known cadence** — nightly, weekly, or on any
  upstream CVE landing in the base packages — so fixes flow
  downstream automatically.
- **Versioned and lifecycled** — `myorg/base:python-3.12-2026.04`
  rather than `:latest`; old versions deprecate on a documented
  schedule.

**Why golden images make container scanning transparent:**

- **One rebuild fixes many.** A CVE in the base image is
  remediated once, by the platform team, and every downstream
  service picks up the fix on its next deploy.
- **Application-team triage collapses to a yes/no question.**
  "Is the image on the current golden version?" is binary.
  Application teams don't re-triage base-layer CVEs — they just
  rebuild.
- **Scan reports become actionable.** Findings that are *not*
  in the golden image are findings the application team
  introduced — which is the small, focused fix set they can
  actually own.
- **Supply-chain provenance is inherited.** A service built on a
  signed golden image inherits that signature in its attestation
  chain; auditors can trace a running container all the way
  back to a known-good base.

**Where this pairs with agentic remediation.** The
[Vulnerable Dependency Remediation]({{< relref
"/security-remediation/vulnerable-dependencies" >}})
workflow becomes almost trivial when golden images are in
place: the agent's PR is usually a single-line `FROM
myorg/base:python-3.12-2026.04 → 2026.05` bump, fully
verifiable by CI, with the remediation reasoning carried in the
golden image's own changelog. Where there's no golden image,
the same agent has to reason about individual package bumps
across a layered Dockerfile — much more blast radius, much
harder to gate safely.

**Representative tooling:**

- **Chainguard Images** — distroless, minimal-CVE, signed,
  SBOM-embedded base images rebuilt continuously. Commercial
  with a free tier.
- **Wolfi** (Chainguard) — open-source distro purpose-built for
  container images; widely used as the foundation for custom
  golden images.
- **Google Distroless** — open-source minimal images for the
  common language runtimes. The original distroless lineage.
- **Red Hat Universal Base Images (UBI)** — enterprise-supported
  base images with a stable CVE-remediation SLA.
- **Microsoft CBL-Mariner / Azure Linux** — minimal-footprint
  distribution used as a base in Azure and CI environments.
- **Sigstore Cosign + Syft** — open-source signing + SBOM
  tooling; the ecosystem standard for signed, SBOM-carrying
  golden images.

**A starter policy.** Even before a full platform team owns the
program, a small policy wins disproportionately:

1. **One approved base image per language runtime.** No mixing.
2. **No `:latest` tags.** Pinned versions only, with a
   deprecation window.
3. **CI fails any image that doesn't start from the approved
   base.** OPA / Conftest / a Dockerfile linter all do this.
4. **Scheduled rebuild workflow** that publishes new versions of
   each golden image on a regular cadence, with a changelog.
5. **A dashboard** of downstream consumers ("services still on
   `:python-3.12-2026.03` after 30 days"). Stale consumers are
   the canary for golden-image adoption health.

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
- [Agentic Security Remediation]({{< relref "/security-remediation" >}}) — security-team-operated workflows that combine both patterns
- [Prompt Library]({{< relref "/prompt-library" >}}) — community prompts that extend automation into judgment calls
