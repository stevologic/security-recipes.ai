---
title: "Source code audit - dependency and build integrity"
linkTitle: "Source code build integrity audit"
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["source-code", "audit", "supply-chain", "dependencies", "ci", "build-integrity"]
weight: 17
date: 2026-06-06
---

A source-code audit recipe for dependency hygiene, lockfile integrity,
build and CI trust boundaries, generated artifacts, package publishing,
and release provenance.

This is not a dependency scanner. It complements SCA by reviewing the
source-controlled build decisions that scanners often cannot reason
about: unpinned actions, install scripts, custom package mirrors, build
secrets, generated code, and release mutation paths.

## What this prompt does

1. Maps package manifests, lockfiles, build scripts, CI workflows, and
   release paths.
2. Reviews where third-party code or untrusted build input enters the
   system.
3. Flags source-controlled choices that weaken integrity or provenance.
4. Produces a report with scanner follow-ups and concrete hardening
   recommendations.

## When to use it

- Before granting CI jobs access to deployment, signing, or package
  publishing credentials.
- After adding a new package manager, build tool, code generator, or CI
  workflow.
- Before publishing an SDK, container image, action, plugin, model
  adapter, MCP server, or agent skill.
- After SCA finds repeated vulnerable transitive dependencies and you need
  to inspect build policy.

Do not use it as a replacement for SCA, SBOM generation, or signature
verification tools. Run those separately and attach their output when
available.

## Inputs

Infer where possible:

- Repo scope.
- Package managers and build systems.
- CI providers and release workflows.
- Artifact types: packages, containers, binaries, generated docs, models,
  plugins, agent skills, or MCP servers.
- Any SCA/SBOM/signing reports supplied by the operator.

## The prompt

~~~markdown
You are performing a read-only source-code audit for dependency and build
integrity. Do not edit files. Do not run package installs that execute
scripts. Do not publish, deploy, sign, or upload artifacts.

Your job is to identify integrity risks visible from source-controlled
manifests, workflows, scripts, and release configuration.

## Step 0 - Inventory build surfaces

Find and record:

- Package manifests and lockfiles.
- Build scripts, task runners, Makefiles, shell scripts, Dockerfiles,
  compose files, and language-specific build config.
- CI workflows and reusable workflow references.
- Code generation, schema generation, protobuf/OpenAPI generation, model
  download, plugin install, and asset pipeline steps.
- Container build contexts and base images.
- Release, signing, publishing, deployment, and provenance steps.
- Package mirrors, registries, artifact caches, and dependency proxies.

For each surface, record file path and purpose.

## Step 1 - Review dependency trust

Check for:

- Missing lockfiles where the ecosystem normally supports them.
- Lockfiles not committed or ignored by CI.
- Wildcard, floating, branch, tag, local path, or git dependencies where
  immutable versions are expected.
- Dependency confusion risk from private package names without scoped
  registry configuration.
- Custom registries, mirrors, or install URLs without TLS and provenance
  expectations.
- Postinstall/preinstall/build scripts that execute third-party code.
- Vendored code without origin, version, license, or update process.
- Transitive dependency overrides that pin vulnerable or abandoned code.
- Package-manager config that disables integrity checks or scripts
  unexpectedly.

If SCA output is present, cross-check whether manifests and lockfiles
match the scanned state.

## Step 2 - Review CI and workflow integrity

Check CI workflows for:

- Third-party actions or reusable workflows pinned by mutable tag instead
  of commit SHA.
- Pull-request workflows that expose write tokens, secrets, deploy keys,
  cloud credentials, package tokens, or signing keys to untrusted code.
- `pull_request_target` or equivalent privileged triggers that check out
  attacker-controlled code.
- Build scripts that fetch and execute remote scripts.
- Cache restore keys that allow untrusted branches to poison trusted
  builds.
- Missing least-privilege permissions for repo tokens.
- Missing separation between test, build, sign, publish, and deploy jobs.
- Secrets printed in logs or passed through command-line args.
- Release jobs that can be triggered by unreviewed branches, tags, or
  user-controlled metadata.

Record exact workflow file paths and job names.

## Step 3 - Review artifact and release provenance

Check for:

- Unsigned packages, containers, binaries, or generated artifacts where
  signing is expected.
- Missing SBOM or provenance generation for release artifacts.
- Container base images not pinned by digest.
- Dockerfiles that copy broad build contexts, `.git`, secrets, or local
  config into images.
- Multi-stage builds that leak build secrets into final layers.
- Generated code committed without a reproducible generation command.
- Release notes, package metadata, or version files generated from
  untrusted input.
- Model, plugin, skill, extension, or MCP-server artifacts loaded from
  unverified sources.

## Step 4 - Review build-time secret handling

Identify where CI/build code can access:

- Cloud credentials.
- Package publishing tokens.
- Signing keys.
- Deployment credentials.
- Source-control tokens.
- Model-provider keys.
- Scanner or security-tool tokens.

For each, check whether access is limited to trusted jobs and whether
the job can be influenced by untrusted code or metadata.

## Step 5 - Score findings

Assign:

- Severity: critical, high, medium, low.
- Integrity boundary: dependency, CI, cache, artifact, release, signing,
  registry, generated code, or build secret.
- Exploit preconditions.
- Blast radius.
- Confidence.

Raise severity for paths that let untrusted contributors affect signed,
published, deployed, or production-trusted artifacts.

## Step 6 - Write the report

Write `SECURITY_BUILD_INTEGRITY_AUDIT.md` at the repo root. If the
session is read-only, print the same content to stdout.

Use this structure:

```markdown
# Dependency and build-integrity audit - <repo name>

Generated on <date>. Scope: <scope>.

## Build Surface Inventory
- ...

## Findings

### <Severity> - <Boundary> - <short title>
- **File:** `path/to/file.ext:line`
- **Surface:** ...
- **Why it is flagged:** ...
- **Exploit sketch:** ...
- **Blast radius:** ...
- **Confidence:** ...
- **Recommended fix:** ...
- **Verification:** ...

## Scanner Follow-Ups
- ...

## Surfaces Reviewed With No Finding
- ...

## Gaps
- ...
```

## Stop conditions

Stop and report rather than continuing if:

- Validation would require running install scripts from untrusted
  dependencies.
- Validation would require publish, deploy, signing, or credential access.
- You discover live secrets in workflow files, package config, Docker
  layers, or build logs.
- CI policy is managed in another repo and cannot be inspected.
~~~

## Output contract

- `SECURITY_BUILD_INTEGRITY_AUDIT.md` or equivalent stdout report.
- Findings include file path, boundary, exploit sketch, blast radius, and
  verification suggestion.
- No package installs that execute scripts.
- No code edits.

## Guardrails

- Prefer static inspection over running build steps.
- If commands are needed, use read-only commands such as lockfile parsing,
  `npm ls --ignore-scripts`, `pip-audit --dry-run` equivalents, or scanner
  output supplied by the operator.
- Do not publish, deploy, upload, sign, or mutate caches.
- Do not assume a mutable tag is safe because it belongs to a well-known
  project; record the integrity trade-off.

## Related

- [Source code audit - attack surface map]({{< relref "/recipes/general/source-code-attack-surface-map" >}})
- [Vulnerable Dependency Remediation]({{< relref "/security-remediation/vulnerable-dependencies" >}})
- [Base Image Remediation]({{< relref "/security-remediation/base-images" >}})
