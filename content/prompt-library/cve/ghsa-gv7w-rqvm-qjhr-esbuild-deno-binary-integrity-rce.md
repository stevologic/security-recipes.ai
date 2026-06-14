---
title: "GHSA-gv7w-rqvm-qjhr - esbuild Deno binary integrity RCE"
linkTitle: "GHSA-gv7w-rqvm-qjhr esbuild Deno RCE"
description: "High-severity esbuild Deno module RCE via unverified binary downloads from attacker-influenced npm registries. Upgrade to 0.28.1+, restore hash verification, and lock registry trust in CI."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "esbuild", "deno", "npm", "supply-chain", "binary-integrity", "rce", "high"]
weight: 55
date: 2026-06-13
ghsa: "GHSA-gv7w-rqvm-qjhr"
aliases: ["esbuild Deno binary integrity RCE", "esbuild NPM_CONFIG_REGISTRY binary download RCE"]
kev: false
severity: "high"
ecosystem: "typescript/npm"
disclosed: "2026-06-11"
---

`GHSA-gv7w-rqvm-qjhr` covers a high-severity remote code execution path in the
esbuild Deno module. Affected versions download a native esbuild binary from an
npm registry URL derived from `NPM_CONFIG_REGISTRY`, write it to disk with
execute permissions, and run it without any integrity check.

The Node.js install path already had SHA-256 verification, but the Deno module
did not. That gap matters most in CI/CD, shared development environments, and
enterprise networks that route npm traffic through internal registries or
registry mirrors. If an attacker can control the registry URL, the mirror, or
the network path used by the Deno process, they can supply a trojaned binary
that esbuild will execute with the privileges of the build job or developer
process.

## Affected versions

- **Vulnerable:** `esbuild >= 0.17.0, < 0.28.1`
- **Fixed:** `esbuild 0.28.1+`
- **Affected surface:** Deno consumers of `esbuild`, especially CI jobs,
  Deno-based build scripts, devcontainers, shared runners, and internal build
  wrappers that inherit `NPM_CONFIG_REGISTRY`
- **Fixed code shape:** the Deno module verifies the downloaded binary against
  a trusted hash manifest before marking it executable or spawning it

## Indicator-of-exposure

- The repository resolves `esbuild >= 0.17.0, < 0.28.1`.
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

- Upgrade every controlled `esbuild` dependency, lockfile, image, cache seed,
  and generated SBOM to `0.28.1+`.
- If this repository vendors, forks, or mirrors esbuild, confirm the Deno
  module now performs binary hash verification before `writeFile(..., 0o755)`
  and before spawning the binary.
- Treat `NPM_CONFIG_REGISTRY` as a privileged supply-chain input. Pin it to a
  reviewed HTTPS registry, avoid mutable job-level overrides, and document who
  can change it.
- Reduce build-job blast radius until rollout completes: remove unnecessary
  credentials from esbuild jobs, scope publish tokens, and isolate artifact
  signing from untrusted build steps where possible.
- Add regression tests or policy checks proving the Deno install path rejects a
  mismatched binary rather than executing it.

## The prompt

~~~markdown
You are remediating GHSA-gv7w-rqvm-qjhr, a high-severity esbuild Deno-module
remote code execution issue caused by downloading and executing native binaries
without integrity verification when `NPM_CONFIG_REGISTRY` is attacker
influenced. Produce exactly one output:

- A reviewer-ready PR/change request that upgrades esbuild, restores binary
  integrity verification in any owned forks or vendored code, hardens registry
  trust in CI/build paths, adds safe verification, refreshes generated
  artifacts, and documents operator follow-up, or
- TRIAGE.md if this repository does not control an affected esbuild dependency,
  Deno build path, vendored code copy, or safe mitigation.

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
3. Resolve all installed versions. Anything on `>= 0.17.0, < 0.28.1` is
   affected for the Deno path.
4. Identify every place `NPM_CONFIG_REGISTRY` or related npm registry config
   can be set: CI variables, runner environment, Docker build args, shell
   wrappers, task runners, `.npmrc`, and Deno launch scripts.
5. If this repository does not control an affected Deno esbuild path, stop with
   `TRIAGE.md` naming the external owner and required version `0.28.1+`.
6. Upgrade all controlled dependencies and lockfiles to `esbuild 0.28.1+`.
7. If the repository vendors or forks esbuild, ensure the Deno module now:
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
9. Add safe tests or policy checks:
   - lockfiles resolve `0.28.1+`;
   - Deno install code rejects a mismatched hash using fixtures or mocks;
   - CI or build policy rejects insecure or unapproved registry overrides;
   - generated dependency reports and SBOMs reflect the upgraded version.
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

- No controlled manifest, lockfile, image, or SBOM resolves `esbuild < 0.28.1`
  for the affected Deno path.
- Any owned Deno esbuild install code verifies the binary before marking it
  executable or spawning it.
- Registry trust is explicit and reviewed rather than inheriting mutable
  environment values by default.
- Build jobs that fetch native binaries no longer hold unnecessary high-value
  secrets.
- Tests prove integrity-check failure stops execution.

## Watch for

- Upgrading the npm dependency while a vendored Deno copy or cache seed still
  contains the vulnerable installer.
- Treating HTTPS transport alone as an integrity control for downloaded
  executables.
- Leaving `NPM_CONFIG_REGISTRY` writable by untrusted pull requests or shared
  runner contexts.
- Fixing the package version but not regenerating SBOMs, dependency snapshots,
  or build images.

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-gv7w-rqvm-qjhr>
- esbuild `v0.28.1` release: <https://github.com/evanw/esbuild/releases/tag/v0.28.1>
- GitHub repository: <https://github.com/evanw/esbuild>
