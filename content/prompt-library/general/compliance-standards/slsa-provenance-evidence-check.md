---
title: "SLSA provenance evidence check"
linkTitle: "SLSA provenance"
description: "Read-only recipe for checking build provenance, artifact integrity, and supply-chain evidence against SLSA expectations."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["compliance", "slsa", "provenance", "supply-chain", "build-integrity", "artifacts"]
weight: 60
date: 2026-06-25
severity: "high"
---

A read-only supply-chain evidence check for SLSA-style build provenance and
artifact integrity. It inventories how artifacts are built, whether provenance
exists, and whether the build platform and release process create trustworthy
attestations.

## When to use it

- Before publishing packages, containers, binaries, plugins, models, or MCP
  servers.
- After adding a new build system, CI provider, release job, or artifact
  registry.
- When a customer asks how release artifacts trace back to source.

## Inputs

- Repository path and artifact types.
- CI provider and release workflow names if known.
- Artifact registry, container registry, package registry, or signing tool hints.
- Existing SBOM, provenance, signature, or attestation artifacts if available.

## The prompt

~~~markdown
You are running a SLSA provenance evidence check. Run read-only. Do not build,
publish, sign, upload, deploy, rotate credentials, or modify workflows.

## Step 0 - Artifact and build inventory

Record:

- Artifact types produced: package, container, binary, extension, plugin, model,
  MCP server, documentation bundle, or generated SDK.
- Build entry points: CI workflows, Makefiles, package scripts, Dockerfiles,
  release scripts, generator configs, or manual steps.
- Release and registry targets.
- Signing, SBOM, provenance, attestation, and checksum files or jobs.
- Credentials available to build, sign, publish, or deploy jobs.

## Step 1 - Check provenance existence

For each artifact type, determine whether provenance exists and records:

- source repository and commit;
- build workflow or builder identity;
- build parameters and environment;
- artifact digest;
- dependencies or materials when available;
- timestamp and issuer;
- signature or attestation storage location.

If provenance is missing, state what artifact has no traceable build record.

## Step 2 - Check build trust boundary

Review CI and release workflows for:

- hosted or hardened builder versus local/manual build;
- mutable third-party actions or reusable workflows;
- untrusted pull requests reaching privileged jobs;
- cache poisoning risks;
- broad write tokens or secrets in build jobs;
- manual release steps without reproducible command or recorded approval;
- generated code, model, plugin, or dependency downloads from unverified
  sources.

## Step 3 - Check artifact integrity

Review:

- artifact signing;
- container image digests;
- package checksums;
- SBOM generation and storage;
- release tag signing or protected tags;
- registry permissions and publish approvals;
- provenance verification commands in docs or CI.

## Step 4 - Produce candidate SLSA posture

For each artifact, produce a candidate posture:

- `no provenance`: no trustworthy build record found;
- `provenance exists`: build record exists but trust boundary or signing needs
  review;
- `signed hosted provenance`: provenance is signed by a hosted build system;
- `hardened build candidate`: provenance, hosted build, restricted secrets, and
  protected release flow are all evidenced.

Do not assert a formal SLSA level unless the operator supplied an approved
assessment method. Provide evidence and gaps instead.

## Step 5 - Write the report

Write `SLSA_PROVENANCE_EVIDENCE_CHECK.md` at the repo root, or print to stdout
if write access is unavailable.

Use this structure:

```markdown
# SLSA provenance evidence check - <repo>

Generated on <date>.

## Artifact Inventory
- ...

## Provenance Matrix
| Artifact | Build source | Provenance | Signing | Trust boundary | Gaps |
| ... |

## Findings
### <Severity> - <short title>
- **Artifact:** ...
- **Evidence:** ...
- **Gap:** ...
- **Risk:** ...
- **Recommended next action:** ...
- **Verification:** ...

## Candidate Posture
- ...

## Out-of-Repository Evidence Needed
- ...
```

## Stop conditions

Stop and write a partial report if:

- verification would require building, publishing, or signing artifacts;
- release credentials or signing keys are exposed;
- artifacts are built manually with no source trace and the operator asked for
  a formal SLSA level.
~~~

## Output contract

- Artifact provenance matrix and gap report.
- No builds, publishes, signatures, uploads, deployments, or credential use.
- Candidate posture only unless a formal assessment method is supplied.

## Guardrails

- Treat provenance as incomplete unless it binds source, builder, and artifact
  digest.
- Do not trust mutable tags or manual release notes as provenance.
- Prefer verification commands that reviewers can run without publish rights.

## References

- [SLSA framework overview](https://slsa.dev/)
- [SLSA specification](https://slsa.dev/spec/v1.1/)
- [Source code audit - dependency and build integrity]({{< relref "/prompt-library/general/source-code-supply-chain-build-integrity-audit" >}})

