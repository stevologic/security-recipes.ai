---
title: "GHSA-54pg-9963-v8vg - Intercom client package compromise"
linkTitle: "GHSA-54pg Intercom compromise"
description: "Critical Intercom npm and Composer package compromise. Quarantine intercom-client 7.0.4 and intercom-php 5.0.2 installs, clear caches, verify lockfile provenance, and rotate exposed credentials."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "intercom", "npm", "composer", "supply-chain", "critical"]
weight: 64
date: 2026-05-10
ghsa: "GHSA-54pg-9963-v8vg"
known_as: ["Intercom client package compromise", "GHSA-gr3r-crp5-qrrm"]
kev: false
severity: "critical"
ecosystem: "npm/composer"
disclosed: "2026-05-07"
---

Intercom disclosed a supply-chain compromise affecting `intercom-client` on npm
and `intercom/intercom-php` on Composer. The malicious versions were removed
and safe versions restored, but any repository, CI runner, developer machine,
or production build that installed the malicious artifacts during the exposure
window should be treated as potentially credential-exposed.

This recipe covers both GitHub Security Advisories because production cleanup
is the same shape: identify whether the bad package versions or commit hashes
entered the environment, clear package caches, reinstall from clean artifacts,
and rotate secrets that were reachable from affected build or runtime hosts.

## When to use it

Use this recipe when a repository depends on Intercom SDK packages, maintains
JavaScript or PHP dependency locks, builds images with Intercom clients, or
owns CI/developer caches that may have installed compromised Intercom package
artifacts. It is for supply-chain compromise cleanup, not ordinary dependency
version drift.

Use it to quarantine suspicious package artifacts, regenerate clean lockfiles,
and document credential rotation. Do not use it to execute package lifecycle
scripts from suspicious cached artifacts.

## Inputs

- JavaScript and PHP manifests, lockfiles, vendor directories, package caches,
  Dockerfiles, CI workflows, SBOMs, generated dependency reports, deployment
  artifacts, and image layers that reference `intercom-client` or
  `intercom/intercom-php`.
- Exact package coordinates, resolved URLs, integrity hashes, source commit
  references, and install timestamps around the April 30, 2026 compromise
  window.
- Cache ownership for npm, pnpm, Yarn, Composer, Docker layers, CI caches,
  build caches, and developer package stores.
- Build/install environment secret classes: `.env`, SSH keys, cloud
  credentials, CI tokens, package registry tokens, production deploy tokens,
  Composer credentials, and API keys.
- Existing supply-chain controls: install-script policy, egress restrictions,
  lockfile review, provenance checks, and cache quarantine procedures.

## Affected versions

| Package | Ecosystem | Risky version | Safe default |
| --- | --- | --- | --- |
| `intercom-client` | npm | `7.0.4` installed from the compromised publish window | Downgrade to `7.0.3` or reinstall after cache purge from the restored clean package |
| `intercom/intercom-php` | Composer | `5.0.2` from malicious commit `e69bf4b3` | Downgrade to `5.0.1` or clear Composer cache and reinstall the restored clean `5.0.2` |

## Indicator-of-exposure

- The repository, CI image, developer bootstrap, lockfile, package cache, or
  deployment artifact references `intercom-client@7.0.4`.
- The repository, Composer cache, `composer.lock`, vendor directory, or image
  references `intercom/intercom-php` `5.0.2`, especially malicious commit
  `e69bf4b3`.
- Builds or installs occurred around the April 30, 2026 compromise window.
- Affected install contexts had access to environment variables, `.env` files,
  SSH keys, cloud credentials, CI tokens, package registry tokens, production
  secrets, or deployment credentials.

Quick checks:

```bash
rg -n "intercom-client|intercom/intercom-php|e69bf4b3|9371eba9" package*.json pnpm-lock.yaml yarn.lock npm-shrinkwrap.json composer.json composer.lock Dockerfile* .github .gitlab-ci.yml deploy charts .
npm ls intercom-client
pnpm why intercom-client
yarn why intercom-client
composer show intercom/intercom-php --version
composer clear-cache --dry-run
```

## Remediation strategy

- Remove malicious package versions and regenerate lockfiles from clean
  registry state after clearing npm, pnpm, Yarn, Composer, CI, and Docker
  caches that may contain compromised artifacts.
- Prefer pinning to known-safe versions (`intercom-client@7.0.3` and
  `intercom/intercom-php@5.0.1`) until the organization intentionally accepts
  restored versions with verified provenance.
- Rebuild images and artifacts from clean dependency caches.
- Rotate any credentials reachable from install or build environments that may
  have executed the malicious package code.
- Add package provenance controls: lockfile review, publish-time pinning,
  package-manager cache quarantine, dependency install egress limits, and
  secret-minimized build runners.

## The prompt

~~~markdown
You are remediating the Intercom package compromise tracked as
GHSA-54pg-9963-v8vg (`intercom-client`) and GHSA-gr3r-crp5-qrrm
(`intercom/intercom-php`). Produce exactly one output:

- A reviewer-ready PR/change request that removes risky package artifacts,
  refreshes clean lockfiles and generated artifacts, adds supply-chain
  guardrails, and documents credential-rotation actions, or
- TRIAGE.md if this repository does not own any affected Intercom dependency
  or cannot safely patch.

## Rules

- Scope only the Intercom package compromise and directly related dependency
  cache, lockfile, image, and credential-exposure cleanup.
- Do not run suspicious package scripts, Composer plugins, postinstall scripts,
  or downloaded payloads to prove exposure.
- Do not print, commit, or attach secrets, `.env` contents, SSH keys, cloud
  credentials, npm tokens, Composer credentials, CI logs with secrets, or
  package-cache payloads.
- Do not delete forensic artifacts automatically from shared environments;
  quarantine or document operator action instead.
- Do not auto-merge.

## Steps

1. Inventory every JavaScript and PHP package manifest, lockfile, vendor
   directory, package cache reference, Dockerfile, CI workflow, SBOM, and
   deployment artifact controlled by this repository.
2. Search for:
   - `intercom-client`;
   - `intercom-client@7.0.4`;
   - `intercom/intercom-php`;
   - `intercom/intercom-php` version `5.0.2`;
   - malicious commit `e69bf4b3`;
   - clean commit `9371eba9`.
3. Determine whether this repository built or installed dependencies during
   the April 30, 2026 compromise window. If timestamps are not available, mark
   exposure as unknown and choose the conservative cleanup path.
4. If no affected dependency or generated artifact is present, stop with
   `TRIAGE.md` explaining what was checked.
5. Clear or document clearing of npm, pnpm, Yarn, Composer, Docker layer, CI,
   and build caches that may contain malicious artifacts. Do not run package
   scripts from suspicious cached packages.
6. Pin to known-safe versions or reinstall restored clean artifacts:
   - prefer `intercom-client@7.0.3` unless the owner accepts a verified clean
     restored version;
   - prefer `intercom/intercom-php@5.0.1` unless `composer.lock` proves the
     restored clean `5.0.2` source.
7. Regenerate lockfiles, package-manager metadata, SBOMs, images, deployment
   manifests, and dependency reports from clean caches.
8. Add guardrails where the repository owns them:
   - block dependency install scripts in CI unless explicitly needed;
   - minimize secrets available during dependency installation;
   - pin package provenance or commit references for high-risk SDKs;
   - add lockfile diff review for package source, integrity, and resolved URL
     changes.
9. Add a PR body section named `Intercom package compromise operator actions`
   that states:
   - affected Intercom packages and versions found;
   - whether builds occurred during the compromise window;
   - package caches that must be cleared;
   - images or artifacts that must be rebuilt;
   - credentials that should be rotated because they were reachable from
     affected install or build environments;
   - logs that should be reviewed for unexpected network calls or package
     lifecycle execution.
10. Run the relevant validation: package install from clean cache, Composer
    install from clean cache, lockfile integrity checks, tests, lint/typecheck,
    image build, SBOM refresh, and dependency/security scans available in this
    repository.
11. Use PR title:
    `fix(sec): quarantine Intercom package compromise`.

## Stop conditions

- No affected Intercom package is used by any controlled manifest, lockfile,
  image, vendor directory, or generated artifact.
- Package versions are clean but cache and build timestamps cannot be checked;
  produce `TRIAGE.md` with conservative operator rotation guidance.
- The repository cannot clear shared CI or developer package caches; document
  the responsible owner and exact commands.
- Cleanup would require exposing secrets or executing suspicious package code.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled lockfile, vendor directory, image, SBOM, or deployment artifact
  references the malicious Intercom artifacts.
- Package caches and generated artifacts are either refreshed in the PR or
  called out as required operator actions.
- The PR does not run or preserve suspicious lifecycle scripts.
- Credential-rotation guidance is specific to the install/build environments
  that were exposed.
- Supply-chain guardrails reduce recurrence risk without breaking legitimate
  dependency installation.

## Watch for

- Composer plugins or npm lifecycle scripts executing during verification.
- Docker layers, CI caches, or package-manager stores that keep malicious
  packages after lockfiles are fixed.
- Build jobs where cloud credentials or production deploy tokens are available
  during dependency install.
- Treating restored package names as proof that existing cached artifacts are
  clean.

## Output contract

Return one of:

- A reviewer-ready PR/change request that removes risky Intercom artifacts,
  pins or reinstalls known-clean package versions from clean caches, regenerates
  lockfiles/images/SBOMs, adds supply-chain guardrails, and documents
  credential-rotation and cache-quarantine actions.
- `TRIAGE.md` when no controlled affected Intercom dependency, lockfile, image,
  vendor directory, generated artifact, cache path, or install environment is
  in scope.

The output must list affected packages and versions, whether build/install
activity overlapped the compromise window, caches to clear, artifacts to
rebuild, credentials to rotate by class, validation commands, and owner actions
for shared caches. It must not run suspicious lifecycle scripts, print secrets,
attach package-cache payloads, delete shared forensic artifacts automatically,
or treat restored registries as proof that local caches are clean.

## Related recipes

- [Compromised package cache quarantine]({{< relref "/prompt-library/general/compromised-package-cache-quarantine" >}})
- [Source-code supply chain build integrity audit]({{< relref "/prompt-library/general/source-code-supply-chain-build-integrity-audit" >}})
- [CVE-2026-45321 - TanStack npm supply-chain compromise]({{< relref "/prompt-library/cve/cve-2026-45321-tanstack-npm-supply-chain-compromise" >}})

## References

- GitHub Advisory: <https://github.com/advisories/GHSA-54pg-9963-v8vg>
- Intercom npm advisory: <https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg>
- Intercom PHP advisory: <https://github.com/intercom/intercom-php/security/advisories/GHSA-gr3r-crp5-qrrm>
- Intercom status update: <https://www.intercomstatus.com/us-hosting/incidents/01KQFN6VS6ARP1XBR1K1SBYY59>
- Companion GHSA: <https://github.com/advisories/GHSA-gr3r-crp5-qrrm>

