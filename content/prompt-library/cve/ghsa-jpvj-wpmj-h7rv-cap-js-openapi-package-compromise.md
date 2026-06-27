---
title: "GHSA-jpvj-wpmj-h7rv - @cap-js/openapi package compromise"
linkTitle: "GHSA-jpvj @cap-js/openapi"
description: "Critical malicious @cap-js/openapi 1.4.1 package compromise. Upgrade to 1.4.2+, purge caches and build artifacts, and rotate credentials reachable from affected SAP CAP dependency installs."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "cap-js", "sap-cap", "openapi", "npm", "supply-chain", "malware", "credential-theft", "critical"]
weight: 93
date: 2026-06-09
ghsa: "GHSA-jpvj-wpmj-h7rv"
aliases: ["@cap-js/openapi package compromise"]
kev: false
severity: "critical"
ecosystem: "npm/supply-chain"
disclosed: "2026-05-19"
---

On 2026-05-19, a compromised `@cap-js/openapi@1.4.1` package was published.
The advisory states that the malicious package harvested credentials and
attempted self-propagation. Repositories that installed the compromised version
must treat the affected runner, workstation, image, or package cache as
potentially credential-exposed.

This is not a normal vulnerable dependency bump. The right fix combines a clean
upgrade to `@cap-js/openapi >=1.4.2`, package-cache quarantine, artifact
rebuilds, and credential rotation for secrets reachable during dependency
installation.

## When to use it

Use this recipe when a repository depends on `@cap-js/openapi`, runs SAP CAP
OpenAPI generation, builds images with npm dependency installs, or owns caches
that may have retained `@cap-js/openapi@1.4.1`. It is for supply-chain
compromise cleanup, not a normal version bump.

Use it to remove the compromised package, purge caches and generated artifacts,
and create a credential-rotation packet. Do not use it to install or execute
the compromised package.

## Inputs

- npm manifests, lockfiles, workspaces, vendored modules, Dockerfiles, image
  build contexts, SBOMs, generated dependency reports, SAP CAP OpenAPI
  generation paths, package mirrors, CI caches, and release workflows.
- Exact package evidence for `@cap-js/openapi@1.4.1`, fixed `1.4.2+`, registry
  URLs, package-manager cache keys, build logs, and install timestamps on or
  after 2026-05-19.
- Secrets reachable during dependency install: npm, GitHub, cloud, SAP BTP,
  SSH, Kubernetes, Vault, package-registry, deployment, and local developer
  credentials.
- Cache and artifact ownership for `node_modules`, npm/pnpm/Yarn stores, CI
  workspaces, Actions caches, Docker layers, package mirrors, generated
  CAP/OpenAPI output, and deploy bundles.
- Existing supply-chain guardrails: lifecycle-script policy, minimal-secret CI
  installs, trust-boundary cache keys, and lockfile integrity review.

## Affected versions

| Package | Ecosystem | Compromised version | Fixed version |
| --- | --- | --- | --- |
| `@cap-js/openapi` | npm | `1.4.1` | `1.4.2+` |

There is no workaround for a host that installed the compromised package. If
`1.4.1` was ever installed in a secret-bearing environment, cleanup must include
credential rotation and cache or artifact purge.

## Indicator-of-exposure

- A manifest, lockfile, SBOM, generated dependency report, package mirror,
  Docker layer, CI cache, or build log references `@cap-js/openapi@1.4.1`.
- CI, developer bootstrap, container builds, SAP CAP code generation, OpenAPI
  generation, or deployment packaging ran `npm install`, `npm ci`,
  `pnpm install`, or `yarn install` while the compromised package could be
  resolved.
- Install or build environments had access to npm tokens, GitHub tokens, cloud
  credentials, SAP BTP credentials, SSH keys, Kubernetes service-account
  tokens, Vault tokens, package-registry credentials, deployment secrets,
  `.env` files, or local developer credentials.
- Internal mirrors, pull-through caches, offline artifact stores, or base images
  may have retained the `1.4.1` tarball after the upstream package was fixed.

Quick checks:

```bash
rg -n "@cap-js/openapi|cap-js/openapi|1\\.4\\.1|1\\.4\\.2|npmrc|NPM_TOKEN|SAP_|BTP_|id-token: write|actions/cache|restore-keys" package*.json pnpm-lock.yaml yarn.lock npm-shrinkwrap.json Dockerfile* .github .gitlab-ci.yml deploy charts data .
npm ls @cap-js/openapi
pnpm why @cap-js/openapi
yarn why @cap-js/openapi
```

Windows:

```powershell
rg -n "@cap-js/openapi|cap-js/openapi|1\.4\.1|1\.4\.2|npmrc|NPM_TOKEN|SAP_|BTP_|id-token: write|actions/cache|restore-keys" package*.json pnpm-lock.yaml yarn.lock npm-shrinkwrap.json Dockerfile* .github .gitlab-ci.yml deploy charts data .
npm ls @cap-js/openapi
pnpm why @cap-js/openapi
yarn why @cap-js/openapi
```

Do not install, execute, import, or inspect a suspected malicious tarball in a
secret-bearing environment. Use a disposable offline directory if package
forensics are required by incident responders.

## Remediation strategy

- Remove `@cap-js/openapi@1.4.1` from manifests, lockfiles, generated
  dependency reports, SBOMs, vendored modules, package caches, mirrors, Docker
  layers, and build artifacts.
- Upgrade to `@cap-js/openapi 1.4.2+` and regenerate lockfiles from a clean
  dependency graph.
- Delete and recreate repository-controlled `node_modules`, npm/pnpm/Yarn
  stores, CI caches, Docker layers, build outputs, and generated CAP/OpenAPI
  artifacts that may have been produced after the compromised install.
- Invoke the
  [artifact cache quarantine workflow]({{< relref "/security-remediation/artifact-cache-purge" >}})
  for internal mirrors, proxy registries, pull-through caches, and offline
  package stores.
- Rotate credentials reachable from affected install environments: npm,
  GitHub, cloud, SAP BTP, SSH, Kubernetes, Vault, package-registry, deployment,
  and local developer credentials.
- Reduce recurrence risk by minimizing secrets during dependency install,
  blocking lifecycle scripts unless required, segregating CI caches by trust
  boundary, and reviewing lockfile integrity/source changes.

## The prompt

~~~markdown
Model context: this prompt was generated by GPT 5.5 Extra High reasoning.

You are remediating GHSA-jpvj-wpmj-h7rv, the malicious
`@cap-js/openapi@1.4.1` npm package compromise. Produce exactly one output:

- A reviewer-ready PR/change request that removes compromised package
  references, upgrades to a clean fixed version, purges repository-controlled
  caches and generated artifacts, adds safe supply-chain guardrails, and
  documents credential-rotation/operator actions, or
- TRIAGE.md if this repository does not own an affected npm dependency graph,
  SAP CAP/OpenAPI build path, package cache, image, or CI workflow.

## Rules

- Scope only GHSA-jpvj-wpmj-h7rv and directly related `@cap-js/openapi`
  dependency, package-cache, generated-artifact, CI, image, and credential
  exposure cleanup.
- Treat npm tokens, GitHub tokens, cloud credentials, SAP BTP credentials, SSH
  keys, Kubernetes service-account tokens, Vault tokens, package-registry
  credentials, deployment secrets, `.env` files, and local developer secrets as
  sensitive.
- Do not install, execute, import, sandbox-run, or preserve the compromised
  `@cap-js/openapi@1.4.1` tarball during remediation.
- Do not print secrets, package payloads, `.env` files, CI secret values, or
  suspicious network endpoints in PR output.
- Do not delete shared forensic artifacts automatically; quarantine or document
  operator action.
- Do not auto-merge.

## Steps

1. Inventory every npm package manifest, lockfile, workspace, vendored module,
   Dockerfile, image build context, SBOM, generated dependency report, SAP CAP
   OpenAPI generation path, package mirror, CI cache, and release workflow
   controlled by this repository.
2. Search for `@cap-js/openapi`, exact version `1.4.1`, fixed version
   `1.4.2`, npm registry URLs, package-manager cache keys, and build logs that
   show dependency installation during or after 2026-05-19.
3. If no affected dependency graph, cache, mirror, image, or generated artifact
   is controlled by this repository, stop with `TRIAGE.md` listing checked
   paths and the external owner if another platform supplies the dependency.
4. If `@cap-js/openapi@1.4.1` is present or plausibly installed, remove it from
   manifests and regenerate lockfiles from a clean environment with lifecycle
   scripts disabled unless the repository explicitly requires them.
5. Upgrade every controlled reference to `@cap-js/openapi 1.4.2+`. Refresh
   package-manager metadata, generated dependency reports, SBOMs, images, and
   deployment artifacts.
6. Purge repository-controlled caches and artifacts that may retain or have
   executed the compromised tarball: `node_modules`, npm/pnpm/Yarn stores,
   CI workspaces, Actions caches, Docker layers, package mirrors, generated
   CAP/OpenAPI output, and deploy bundles.
7. For shared package mirrors, proxy registries, base images, or developer
   workstations outside repository control, write explicit operator actions
   using the compromised coordinate `@cap-js/openapi@1.4.1`.
8. Draft the credential-rotation packet for every exposed install/build
   environment. Include npm, GitHub, cloud, SAP BTP, SSH, Kubernetes, Vault,
   package-registry, deployment, and local developer credentials reachable by
   the install process.
9. Add guardrails where this repository owns them:
   - dependency guard rejects `@cap-js/openapi@1.4.1`;
   - CI install jobs run with minimal secrets;
   - lifecycle scripts are disabled unless required and documented;
   - cache keys are segregated by trust boundary;
   - lockfile reviews flag source, integrity, resolved URL, and script changes.
10. Add a PR body section named `GHSA-jpvj-wpmj-h7rv operator actions` that
    states:
    - whether `@cap-js/openapi@1.4.1` was found;
    - which manifests, locks, images, caches, and artifacts were cleaned;
    - whether any install occurred on or after 2026-05-19;
    - which credentials require rotation and who owns it;
    - which package mirrors or developer caches need quarantine;
    - which validation commands passed.
11. Run available validation: clean package install, lockfile integrity,
    dependency guard tests, CI workflow lint, unit tests, build, SBOM refresh,
    image build, and dependency/security scans.
12. Use PR title:
    `fix(sec): quarantine @cap-js/openapi package compromise`.

## Stop conditions

- No controlled manifest, lockfile, image, generated artifact, CI cache, or
  package mirror can contain `@cap-js/openapi@1.4.1`.
- The only exposure is an externally owned build environment; write
  `TRIAGE.md` naming the owner, evidence, required cache purge, and rotation
  due date.
- Safe verification would require executing the compromised package, contacting
  suspicious infrastructure, or exposing secrets.
- Credential rotation is required but cannot be performed from this repository;
  document the rotation packet and stop short of claiming full remediation.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled manifest, lockfile, SBOM, image, generated report, cache
  policy, or registry mirror references `@cap-js/openapi@1.4.1`.
- Lockfiles and generated artifacts are rebuilt from a clean dependency graph
  resolving `@cap-js/openapi 1.4.2+`.
- The PR does not install or execute the compromised package while validating.
- Cache purge and credential-rotation actions are specific to the environments
  that could have installed the compromised package.
- Supply-chain guardrails reduce recurrence risk without blocking legitimate
  SAP CAP/OpenAPI generation.

## Watch for

- Treating this as a simple version bump while leaving CI caches, package
  mirrors, Docker layers, or generated artifacts untouched.
- Regenerating lockfiles on a runner or workstation that may still hold the
  compromised package in its package-manager store.
- Forgetting SAP BTP, cloud, SSH, Vault, Kubernetes, or local developer
  credentials after rotating npm and GitHub tokens.
- Running package lifecycle scripts during investigation.
- Omitting operator actions for package mirrors and developer workstations that
  are outside repository control.

## Output contract

Return one of:

- A reviewer-ready PR/change request that removes `@cap-js/openapi@1.4.1`,
  upgrades to `1.4.2+`, regenerates lockfiles from a clean dependency graph,
  purges controlled caches and generated artifacts, adds supply-chain
  guardrails, and documents credential rotation.
- `TRIAGE.md` when no controlled npm dependency graph, SAP CAP/OpenAPI build
  path, package cache, image, CI workflow, generated artifact, or mirror can
  contain the compromised package.

The output must list whether `@cap-js/openapi@1.4.1` was found, manifests,
locks, images, caches, and artifacts cleaned, install timing, credentials to
rotate, mirror/developer-cache owners, and validation commands. It must not
execute the compromised package, contact suspicious infrastructure, expose
secrets, or claim rotation is complete when it is only assigned.

## Related recipes

- [Compromised package cache quarantine]({{< relref "/prompt-library/general/compromised-package-cache-quarantine" >}})
- [Source-code supply chain build integrity audit]({{< relref "/prompt-library/general/source-code-supply-chain-build-integrity-audit" >}})
- [GHSA-54pg-9963-v8vg - Intercom client package compromise]({{< relref "/prompt-library/cve/ghsa-54pg-9963-v8vg-intercom-package-compromise" >}})

## References

- GitHub Advisory: <https://github.com/advisories/GHSA-jpvj-wpmj-h7rv>
- cap-js/openapi vendor advisory: <https://github.com/cap-js/openapi/security/advisories/GHSA-jpvj-wpmj-h7rv>
- SAP Note 3747787: <https://me.sap.com/notes/3747787>
- SAP Developer FAQ: <https://www.sap.com/documents/2026/05/8203a8b9-4d7f-0010-bca6-c68f7e60039b.html>
- [Artifact Cache & Mirror Quarantine]({{< relref "/security-remediation/artifact-cache-purge" >}})
