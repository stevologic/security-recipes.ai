---
title: "GHSA-fr4h-3cph-29xv: pnpm hoisted lockfile alias traversal"
linkTitle: "GHSA-fr4h pnpm hoisted alias"
description: "GHSA-fr4h-3cph-29xv is pnpm hoisted lockfile alias traversal. Upgrade to 10.34.4+ or 11.7.0+ and reject escaped aliases."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "pnpm", "nodejs", "path-traversal", "supply-chain", "high"]
weight: 94
date: 2026-06-27
lastmod: 2026-08-21
ghsa: "GHSA-fr4h-3cph-29xv"
known_as: ["pnpm hoisted lockfile alias traversal"]
kev: false
severity: "high"
ecosystem: "javascript/npm"
disclosed: "2026-06-27"
ai_enrichment_review_status: human-reviewed-development-draft
---

GHSA-fr4h-3cph-29xv is **not** a protocol-specifier integrity bypass. GitHub
describes a hoisted-install lockfile alias issue: a crafted alias can be
joined under a hoisted `node_modules` directory. Traversal aliases can escape
that directory, and reserved aliases such as `.bin` or `.pnpm` can overwrite
pnpm-owned layout.

GitHub names **10.34.4** and **11.7.0**. Do not invent 10.34.5, 11.7.1, or
the sibling **11.8.0** floor from GHSA-qrv3. This page stays a development
draft. Do not prove exposure by installing a lockfile that writes outside
`node_modules`.

## When to use it

Use this recipe when a repository pins pnpm and runs hoisted installs, or
when untrusted lockfile aliases can reach CI or developer machines. Use it
to upgrade pnpm and reject escaped or reserved aliases. Do not use it to
materialize malicious lockfile aliases on a secret-bearing host.

## Inputs

- `packageManager`, Corepack, CI setup, Dockerfiles, devcontainers, and docs
  that pin pnpm.
- Hoisted install configuration and lockfile aliases that become `dep.name`
  or equivalent graph sinks.
- Available version checks, trusted install/test jobs, and SBOM refresh
  commands.

## Affected versions

- **Vulnerable:** `pnpm <10.34.4`
- **Vulnerable:** `pnpm >=11.0.0, <11.7.0`
- **Fixed:** `pnpm 10.34.4+` or `pnpm 11.7.0+`
- **Affected surface:** hoisted lockfile alias join under `node_modules`

## Indicator-of-exposure

- Controlled environments pin pnpm below `10.34.4` or in `11.0.0` through
  `11.6.x`.
- Untrusted lockfiles can supply hoisted aliases.
- Install jobs treat pnpm path joining as a trust boundary.

## Remediation strategy

- Upgrade every controlled pnpm pin to GitHub-named `10.34.4+` or `11.7.0+`.
- Fail closed on traversal, absolute, platform-specific, and reserved package
  aliases before graph insertion or filesystem work.
- Keep untrusted hoisted installs away from privileged publish or deploy
  credentials.

## The prompt

~~~markdown
You are remediating GHSA-fr4h-3cph-29xv. GitHub names this as pnpm hoisted
lockfile alias traversal, not a protocol-specifier bypass. Produce exactly
one output:

- A reviewer-ready PR that upgrades every controlled pnpm runtime to
  10.34.4+ or 11.7.0+ and documents residual risk, or
- TRIAGE.md if this repository does not control the affected pnpm runtime.

## Rules

- Scope only pnpm pins, hoisted install alias handling, lockfile policy, and
  related images or docs.
- Do not invent 11.8.0 as the 11.x floor for this advisory.
- Do not install attacker-controlled lockfiles to prove escape.
- Do not auto-merge.

## Steps

1. Inventory all pnpm pins and bootstrap paths.
2. Treat `pnpm <10.34.4` and `pnpm >=11.0.0, <11.7.0` as vulnerable.
3. Upgrade every controlled pin to 10.34.4+ or 11.7.0+.
4. Confirm malformed or traversal-shaped aliases fail closed in owned
   validation.
5. Use PR title `fix(sec): remediate pnpm hoisted lockfile alias traversal`.
~~~

## Output contract

- A reviewer-ready PR that upgrades controlled pnpm pins to `10.34.4+` or
  `11.7.0+`, or `TRIAGE.md` when no controlled runtime exists.
- The output must not invent an 11.8.0 floor or write files outside
  `node_modules`.

## Verification

- No controlled environment resolves `pnpm <10.34.4` or `pnpm >=11.0.0,
  <11.7.0`.
- Reviewers did not copy the sibling GHSA-qrv3 11.8.0 floor onto this page.

## Rollback and recovery

Prefer forward recovery to another GitHub-named pnpm 10.34.4+ or 11.7.0+
release. If an operational rollback restores a vulnerable pin, stop untrusted
hoisted installs until the matching named floor is restored.

## Related recipes

- [GHSA-qrv3-253h-g69c: pnpm configDependencies symlink traversal]({{< relref "/recipes/cve/ghsa-qrv3-253h-g69c-pnpm-configdependencies-symlink-traversal" >}})
- [Source-code supply chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit" >}})

## References

- GitHub Advisory: <https://github.com/advisories/GHSA-fr4h-3cph-29xv>
- Vendor advisory: <https://github.com/pnpm/pnpm/security/advisories/GHSA-fr4h-3cph-29xv>
