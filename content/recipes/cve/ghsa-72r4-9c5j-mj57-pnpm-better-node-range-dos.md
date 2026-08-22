---
title: "GHSA-72r4-9c5j-mj57: pnpm patch-remove path deletion"
linkTitle: "GHSA-72r4 pnpm patch-remove"
description: "GHSA-72r4-9c5j-mj57 is pnpm patch-remove path deletion. Upgrade to 10.34.4+ or 11.7.0+ and reject out-of-tree patch paths."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "pnpm", "nodejs", "path-traversal", "supply-chain", "high"]
weight: 94
date: 2026-06-27
lastmod: 2026-08-21
ghsa: "GHSA-72r4-9c5j-mj57"
known_as: ["pnpm patch-remove deletion-scope escape"]
kev: false
severity: "high"
ecosystem: "javascript/npm"
disclosed: "2026-06-27"
ai_enrichment_review_status: human-reviewed-development-draft
---

GHSA-72r4-9c5j-mj57 is **not** a `better-node-range` CPU issue. GitHub
describes a `pnpm patch-remove` deletion-scope failure: a crafted
`patchedDependencies` path could resolve outside the configured patches
directory and delete a reachable file.

GitHub names **10.34.4** and **11.7.0**. Do not invent 10.34.5, 11.7.1, or
the sibling **11.8.0** floor from GHSA-qrv3. This page stays a development
draft. Do not prove exposure by deleting files outside a test root.

## When to use it

Use this recipe when a repository pins pnpm, runs `pnpm patch-remove`, or
lets untrusted lockfiles or `patchedDependencies` entries reach CI or
developer machines. Use it to upgrade pnpm and reject out-of-tree patch
paths. Do not use it to delete files outside a disposable test directory.

## Inputs

- `packageManager`, Corepack, CI setup, Dockerfiles, devcontainers, and docs
  that pin pnpm.
- `pnpm-lock.yaml` and `patchedDependencies` paths that `patch-remove` can
  resolve.
- Available version checks, trusted install/test jobs, and SBOM refresh
  commands.

## Affected versions

- **Vulnerable:** `pnpm <10.34.4`
- **Vulnerable:** `pnpm >=11.0.0, <11.7.0`
- **Fixed:** `pnpm 10.34.4+` or `pnpm 11.7.0+`
- **Affected surface:** `pnpm patch-remove` path resolution and unlink

## Indicator-of-exposure

- Controlled environments pin pnpm below `10.34.4` or in `11.0.0` through
  `11.6.x`.
- Untrusted lockfiles or patch entries can reach `pnpm patch-remove`.
- CI or developer hosts run patch-remove against a workspace that can see
  files outside the intended patches directory.

## Remediation strategy

- Upgrade every controlled pnpm pin to GitHub-named `10.34.4+` or `11.7.0+`.
- Reject patch paths that resolve outside the configured patches directory
  before unlink.
- Keep untrusted patch-remove jobs away from privileged publish or deploy
  credentials.

## The prompt

~~~markdown
You are remediating GHSA-72r4-9c5j-mj57. GitHub names this as pnpm
patch-remove deletion-scope escape, not better-node-range CPU exhaustion.
Produce exactly one output:

- A reviewer-ready PR that upgrades every controlled pnpm runtime to
  10.34.4+ or 11.7.0+ and documents residual risk, or
- TRIAGE.md if this repository does not control the affected pnpm runtime.

## Rules

- Scope only pnpm pins, patch-remove usage, lockfile/patch path policy, and
  related images or docs.
- Do not invent 11.8.0 as the 11.x floor for this advisory.
- Do not delete files outside a disposable test root.
- Do not auto-merge.

## Steps

1. Inventory `packageManager`, Corepack, CI, Dockerfiles, and docs for pnpm
   pins.
2. Treat `pnpm <10.34.4` and `pnpm >=11.0.0, <11.7.0` as vulnerable.
3. Upgrade every controlled pin to 10.34.4+ or 11.7.0+.
4. Confirm untrusted patch-remove jobs cannot reach privileged credentials.
5. Use PR title `fix(sec): remediate pnpm patch-remove path deletion`.
~~~

## Output contract

- A reviewer-ready PR that upgrades controlled pnpm pins to `10.34.4+` or
  `11.7.0+`, or `TRIAGE.md` when no controlled runtime exists.
- The output must not invent an 11.8.0 floor or delete files outside a test
  root.

## Verification

- No controlled environment resolves `pnpm <10.34.4` or `pnpm >=11.0.0,
  <11.7.0`.
- Reviewers did not copy the sibling GHSA-qrv3 11.8.0 floor onto this page.

## Rollback and recovery

Prefer forward recovery to another GitHub-named pnpm 10.34.4+ or 11.7.0+
release. If an operational rollback restores a vulnerable pin, stop
`pnpm patch-remove` on untrusted lockfiles until the matching named floor is
restored.

## Related recipes

- [GHSA-qrv3-253h-g69c: pnpm configDependencies symlink traversal]({{< relref "/recipes/cve/ghsa-qrv3-253h-g69c-pnpm-configdependencies-symlink-traversal" >}})
- [Source-code supply chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit" >}})

## References

- GitHub Advisory: <https://github.com/advisories/GHSA-72r4-9c5j-mj57>
- Vendor advisory: <https://github.com/pnpm/pnpm/security/advisories/GHSA-72r4-9c5j-mj57>
- pnpm 10.34.4 commit: <https://github.com/pnpm/pnpm/commit/352ae489f1b14ffdc19d2c6eacb1b06b098c2ddc>
- pnpm 11.7.0 commit: <https://github.com/pnpm/pnpm/commit/612a2e6a7333f2b061f452a21b6e62c1c161747f>
