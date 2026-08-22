---
title: "GHSA-gv7w-rqvm-qjhr: withdrawn esbuild Deno advisory"
linkTitle: "GHSA-gv7w withdrawn esbuild"
description: "GHSA-gv7w-rqvm-qjhr is a withdrawn esbuild Deno-binary advisory. Do not treat npm esbuild 0.28.1 as a live GHAD floor."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "esbuild", "deno", "npm", "supply-chain", "binary-integrity", "withdrawn"]
weight: 55
date: 2026-06-13
lastmod: 2026-08-21
ghsa: "GHSA-gv7w-rqvm-qjhr"
known_as: ["esbuild Deno binary integrity RCE", "esbuild NPM_CONFIG_REGISTRY binary download RCE"]
kev: false
severity: "high"
ecosystem: "typescript/npm"
disclosed: "2026-06-11"
ai_enrichment_review_status: human-reviewed-development-draft
---

GitHub **withdrew GHSA-gv7w-rqvm-qjhr on 2026-06-17**. GHAD says the affected
package was incorrectly identified and the actual Deno module is not in a
supported ecosystem. Do not treat npm `esbuild` **0.28.1** as a live GHAD
floor for this advisory. Recheck GHAD before using this page as an MCP
override.

The original report described a Deno install path that downloaded a native
binary from `NPM_CONFIG_REGISTRY` without a SHA-256 check. The Node.js install
path already verified hashes. This page stays a development draft so leftover
product text cannot become a catalog floor. Do not prove the withdrawn claim
by downloading or executing a registry binary.

## When to use it

Use this recipe when a repository uses esbuild from Deno, vendors esbuild's
Deno module, or runs Deno-based build wrappers in CI, devcontainers, shared
runners, or release jobs. It is most important when `NPM_CONFIG_REGISTRY` can
be set by environment, CI variables, Docker build args, internal npm mirrors,
or untrusted job context.

Use it to recheck GHAD, confirm whether a Deno-only binary path is still in
scope, and avoid inventing an npm `esbuild` floor from a withdrawn advisory.
Do not use it to serve a malicious registry or execute downloaded test
binaries.

## Inputs

- Manifests, lockfiles, Deno imports, scripts, Dockerfiles, build images, CI
  definitions, SBOMs, internal wrappers, vendored `lib/deno/mod.ts`, and
  cache seeds that reference esbuild.
- Evidence of whether the Deno install path is used, rather than only the
  Node.js package-manager path.
- Registry trust inputs: `NPM_CONFIG_REGISTRY`, `.npmrc`, runner environment,
  Docker build args, task runners, Deno launch scripts, internal mirrors, and
  artifact repositories.
- Build-job secret exposure: signing keys, publish tokens, deployment
  credentials, package tokens, cloud credentials, writable artifact stores, and
  source access.
- Safe integrity-test fixtures or mocks proving mismatched binaries are never
  cached, chmodded, or spawned.

## Affected versions

- **GHAD status:** withdrawn on 2026-06-17
- **Withdrawn product mapping:** GHAD says the original `esbuild` npm range
  was incorrect; do not treat `0.28.1` as a live GHAD floor
- **Original claimed surface:** Deno consumers of an esbuild install path that
  inherited `NPM_CONFIG_REGISTRY`
- **Recheck:** GHAD and the esbuild/deno-esbuild repos before any upgrade or
  suppression

## Indicator-of-exposure

- The repository still treats withdrawn GHSA-gv7w as a live npm `esbuild`
  floor, or vendors a Deno install path that fetches binaries from
  `NPM_CONFIG_REGISTRY`.
- Deno build or bundling workflows import `esbuild` from the Deno path rather
  than only using the Node.js package manager path.
- CI, developer shells, wrappers, or container images set or inherit
  `NPM_CONFIG_REGISTRY`.
- The environment trusts internal npm mirrors, artifact repositories, or
  mutable proxy registries without additional binary verification.
- Build jobs that run esbuild have access to source code, signing keys,
  deployment credentials, package publish tokens, or writable artifact stores.

Quick checks:

```bash
rg -n "esbuild|NPM_CONFIG_REGISTRY|deno run|deno task|import .*esbuild|npm_config_registry" .
npm ls esbuild
pnpm why esbuild
yarn why esbuild
rg -n "NPM_CONFIG_REGISTRY|npm_config_registry|registry.npmjs.org|artifactory|verdaccio|nexus" .github Dockerfile* docker-compose*.yml compose*.yaml scripts ci build deploy
```

Windows:

```powershell
rg -n "esbuild|NPM_CONFIG_REGISTRY|deno run|deno task|import .*esbuild|npm_config_registry" .
npm ls esbuild
pnpm why esbuild
yarn why esbuild
rg -n "NPM_CONFIG_REGISTRY|npm_config_registry|registry.npmjs.org|artifactory|verdaccio|nexus" .github Dockerfile* docker-compose*.yml compose*.yaml scripts ci build deploy
```

Do not validate exposure by serving a malicious registry or executing a
trojaned binary on a live runner.

## Remediation strategy

- Recheck GHAD first. This advisory is withdrawn; do not invent an npm
  `esbuild` 0.28.1 floor from the original report.
- If this repository still vendors a Deno binary-download path, confirm it
  performs hash verification before `writeFile(..., 0o755)` and before
  spawning the binary.
- Treat `NPM_CONFIG_REGISTRY` as a privileged supply-chain input. Pin it to a
  reviewed HTTPS registry, avoid mutable job-level overrides, and document who
  can change it.
- Reduce build-job blast radius: remove unnecessary credentials from esbuild
  jobs, scope publish tokens, and isolate artifact signing from untrusted
  build steps.
- Add policy checks only for owned Deno download paths. Do not treat a version
  bump as proof this withdrawn GHSA is still live.

## The prompt

~~~markdown
You are remediating GHSA-gv7w-rqvm-qjhr. GitHub withdrew this advisory on
2026-06-17 because the affected package was incorrectly identified. Do not
invent an npm esbuild 0.28.1 floor. Produce exactly one output:

- A reviewer-ready PR/change request that records the withdrawal, removes any
  invented npm floor, hardens an owned Deno binary-download path if one exists,
  and documents residual risk, or
- TRIAGE.md if this repository does not control a Deno binary-download path
  and no invented floor needs to be removed.

## Rules

- Scope only GHSA-gv7w-rqvm-qjhr and directly related esbuild Deno install,
  binary verification, registry trust, and build-credential exposure.
- Treat source code, build logs, artifact contents, registry credentials,
  publish tokens, signing keys, cloud credentials, and CI secrets as sensitive.
- Do not prove exposure by serving a malicious registry, downloading a trojaned
  binary, or executing attacker-supplied code on a real build runner.
- Do not weaken TLS, disable integrity checks, or keep mutable registry
  overrides just to preserve compatibility.
- Do not auto-merge.

## Steps

1. Inventory every controlled `esbuild` reference in manifests, lockfiles,
   Deno imports, scripts, Dockerfiles, build images, CI definitions, generated
   SBOMs, and internal wrappers.
2. Determine whether the repository uses the Deno install path. Search for Deno
   build scripts, direct Deno imports, vendored `lib/deno/mod.ts`, and internal
   wrappers that call esbuild from Deno.
3. Recheck GHAD. If the advisory is still withdrawn, do not invent an npm
   `esbuild` 0.28.1 floor from the original version range.
4. Identify every place `NPM_CONFIG_REGISTRY` or related npm registry config
   can be set: CI variables, runner environment, Docker build args, shell
   wrappers, task runners, `.npmrc`, and Deno launch scripts.
5. If this repository does not control a Deno binary-download path and does
   not encode a withdrawn-GHSA floor, stop with `TRIAGE.md`.
6. Do not upgrade npm `esbuild` solely because this withdrawn GHSA once named
   `0.28.1`.
7. If the repository vendors a Deno download path, ensure it:
   - computes a SHA-256 hash for downloaded binaries;
   - compares it against a trusted manifest bundled with the release;
   - refuses to cache, chmod, or execute mismatched binaries;
   - preserves the verification on every platform path.
8. Harden registry trust:
   - pin registry URLs to reviewed HTTPS endpoints;
   - remove mutable per-job overrides unless explicitly needed;
   - document who can change registry settings;
   - avoid sharing high-value credentials with build jobs that fetch native
     binaries from registries.
9. Add safe tests or policy checks only for owned Deno download paths:
   - install code rejects a mismatched hash using fixtures or mocks;
   - CI or build policy rejects insecure or unapproved registry overrides;
   - generated reports do not invent a withdrawn GHSA floor.
10. Add a PR body section named `GHSA-gv7w-rqvm-qjhr operator actions` that
    states:
    - esbuild versions before and after;
    - whether the Deno path was used;
    - where `NPM_CONFIG_REGISTRY` was controlled before and after;
    - whether signing keys, publish tokens, or deployment credentials were
      exposed to affected build jobs;
    - which build logs and artifact provenance records operators should review.
11. Run relevant validation: dependency install, Deno/Node build tests, CI
    policy tests, SBOM refresh, dependency scans, and safe unit tests for hash
    verification.
12. Use PR title:
    `fix(sec): remediate esbuild Deno binary integrity gap`.

## Stop conditions

- No controlled Deno-based esbuild usage exists.
- A vendored or forked copy cannot be patched safely without a larger build
  migration.
- Verification would require executing a malicious binary or modifying a live
  registry path.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- Reviewers rechecked GHAD and did not invent an npm `esbuild` 0.28.1 floor
  from this withdrawn advisory.
- Any owned Deno esbuild install code verifies the binary before marking it
  executable or spawning it.
- Registry trust is explicit and reviewed rather than inheriting mutable
  environment values by default.
- Build jobs that fetch native binaries no longer hold unnecessary high-value
  secrets.
- Tests prove integrity-check failure stops execution.

## Watch for

- Upgrading npm `esbuild` to 0.28.1 solely because this withdrawn GHSA once
  named that floor.
- Treating HTTPS transport alone as an integrity control for downloaded
  executables.
- Leaving `NPM_CONFIG_REGISTRY` writable by untrusted pull requests or shared
  runner contexts.
- Fixing a package version but not regenerating SBOMs, dependency snapshots,
  or build images.

## Rollback and recovery

Do not invent a rollback floor from this withdrawn advisory. Recheck GHAD
before changing versions. If a Deno binary-download path remains owned, keep
registry URLs reviewed and do not execute unverified binaries.

## Output contract

Return one of:

- A reviewer-ready PR/change request that records the GHAD withdrawal, removes
  invented npm `esbuild` 0.28.1 floors, hardens any owned Deno binary-download
  path, minimizes build-job credentials, and documents residual risk.
- `TRIAGE.md` when no controlled affected esbuild dependency, Deno build path,
  vendored code copy, cache seed, or safe mitigation exists.

The output must list versions before/after, whether the Deno path is used,
where registry settings are controlled, credentials exposed to affected build
jobs, validation commands, and artifacts refreshed. It must not execute a
trojaned binary, modify a live registry path, weaken TLS/integrity checks, or
preserve mutable unreviewed registry overrides.

## Related recipes

- [Source-code supply chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit" >}})
- [CVE-2026-45321 - TanStack npm supply-chain compromise]({{< relref "/recipes/cve/cve-2026-45321-tanstack-npm-supply-chain-compromise" >}})
- [Compromised package cache quarantine]({{< relref "/recipes/general/compromised-package-cache-quarantine" >}})

## References

- GitHub Advisory Database (withdrawn): <https://github.com/advisories/GHSA-gv7w-rqvm-qjhr>
- GitHub repository: <https://github.com/evanw/esbuild>
