---
title: "Base image — bump and rebuild"
linkTitle: "Base image bump"
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["containers", "docker", "base-image", "cve", "remediate"]
weight: 13
date: 2026-04-25
---

A tool-agnostic prompt that takes a CVE finding scoped to a
base image or an OS-package layer, and produces a reviewer-ready
PR that bumps the `FROM` line (or the package install layer),
rebuilds the image, runs the smoke test, and confirms the CVE
is gone — or stops cleanly with a triage note.

Designed to slot into the
[Base Image & Container Layer Remediation]({{< relref "/security-remediation/base-images" >}})
workflow.

## What this prompt does

1. **Reads the finding** — the affected image, the CVE, the
   package, the patched version (or the patched image tag).
2. **Locates the affected layer** — the `FROM` line, the
   `apt-get install` line, or the `RUN apt-get upgrade` step
   that introduces the vulnerable package.
3. **Picks a bump strategy** — tag bump, digest pin update,
   package upgrade, or curated-base bump — from the workflow's
   declared policy.
4. **Edits the Dockerfile**, rebuilds the image with
   `--no-cache` for the affected layer, runs the repo's smoke
   test.
5. **Re-scans the rebuilt image** and confirms the CVE is gone
   and no new CVEs were introduced.
6. **Opens a PR** with a structured body — affected images,
   affected services, rollout shape, rollback plan.

## When to use it

- A container image scanner has produced a structured CVE finding
  scoped to the base image or to a package the Dockerfile
  installs.
- The repo owns the Dockerfile (CODEOWNERS resolves cleanly).
- The repo's CI builds the image and exposes a smoke test the
  agent can invoke.

**Don't use it for:**

- Application-package CVEs (npm, pip, Go modules, etc.) — those
  go through the [vulnerable-dependency workflow]({{< relref "/security-remediation/vulnerable-dependencies" >}}).
- Curated-base creation, distroless rebases, or OS-family changes
  — those are human-driven.
- Images built outside the repo.
- CVEs in the kernel or host runtime.

## Inputs

- **CVE** — ID, affected package, fixed version (or fixed image
  tag).
- **Image** — registry path, current tag, current digest.
- **Dockerfile path** — repo-relative path.
- **Smoke test command** — inferred from CI (`make smoke`, `docker
  run … && curl /health`, etc.).
- **Policy file** — `.sec-auto-remediation.yml` declaring which
  bump magnitudes (patch / minor / major) are auto-eligible.

## The prompt

~~~markdown
You are remediating a single base-image or OS-package CVE in
this repository. Output exactly one of:

- A PR with a Dockerfile edit and a successful rebuild + scan.
- A `TRIAGE.md` note explaining why the bump is unsafe or
  ineffective.

Do not auto-merge. Do not bundle multiple CVEs.

## Step 0 — Read the finding and the policy

1. Read the CVE ID, the affected package, the fixed version
   (or fixed image tag), and the image coordinate.
2. Read the policy file. Confirm the bump magnitude implied by
   the fix is auto-eligible. If the policy says "human only"
   for this magnitude, stop and triage.

## Step 1 — Locate the affected layer

1. Read the Dockerfile. Identify the `FROM` line(s) and any
   package-install layers (`apt-get install`, `apk add`,
   `dnf install`, `microdnf install`, `yum install`).
2. Determine which layer introduces the vulnerable package.
   Multi-stage builds may have multiple `FROM` lines; identify
   only the one(s) affected.
3. If the image derives from an internal curated base
   (`internal/...:tag`), confirm the curated base has been
   bumped upstream first. If not, stop and triage with a link
   to the upstream-bump request.

## Step 2 — Pick the bump strategy

Choose exactly one (and only one):

- **Tag bump.** Edit the `FROM` line to the patched tag.
- **Digest pin update.** When the repo pins to
  `image@sha256:…`, edit the digest to the registry's
  current tag-resolved digest for the same logical version.
- **Package upgrade.** Edit the package-install line to pin
  the patched version (preferred) or add an explicit
  `apt-get upgrade <pkg>` step before the install.
- **Curated base bump.** Edit the `FROM` tag to the new
  curated tag and link the upstream curated-base PR in the
  body.

Do not refactor the Dockerfile. Do not "clean up while you're
in there." If a clean fix requires more than the bump, stop and
triage.

## Step 3 — Rebuild

1. Rebuild the image with `--no-cache` for the affected layer.
   If the cache state is uncertain, rebuild the whole image.
2. Capture the new digest.
3. Run the repo's smoke test against the rebuilt image. The
   image must start, the health check must pass.
4. If the smoke test fails, revert and stop with a triage note
   that includes the failure log.

## Step 4 — Rescan

1. Re-run the image scanner against the rebuilt image.
2. The original CVE must be gone.
3. The total CVE count must not have increased. If new CVEs
   appeared, list them in the PR body — do not silently ship.
4. If the original CVE is still present (e.g., the patched
   version was not actually fixed in the new tag), stop and
   triage.

## Step 5 — Open the PR

- Branch: `remediate/cve-<cve-id>-<image-slug>`.
- Title: `[Security][CVE-XXXX-YYYYY] bump <image> for <pkg>`.
- Body must include:
  - **CVE summary** — ID, package, severity, link to the
    advisory.
  - **Strategy used** — which of the four bump shapes.
  - **Affected images** — the registry paths that will rebuild.
  - **Affected services** — the manifests / Helm values /
    Kustomize overlays that pin to those images.
  - **Rollout shape** — canary, blue/green, rolling.
  - **Rollback plan** — the previous tag/digest.
  - **New CVEs introduced (if any)** — listed with severity.
  - **How to verify locally** — exact build + smoke commands.
- Label: `sec-auto-remediation`.

## Stop conditions

- Bump magnitude is not auto-eligible per policy.
- The repo's CI does not have a smoke test.
- The Dockerfile uses `latest`, a moving major-version tag, or
  a missing tag (flag and triage; do not silently pin).
- Rebuilt image fails the smoke test.
- Re-scan still shows the original CVE or shows new CVEs the
  policy treats as blocking.
- The fix would require a multi-stage refactor or an OS-family
  change.

## Scope

- Do not edit application source.
- Do not edit CI, deploy manifests (the reviewer drives those),
  or release pipelines.
- Do not push to the registry — the agent's credentials are
  pull-only.
- Do not bundle multiple CVEs.
~~~

## Output contract

- Either a PR (happy path) with a successfully rebuilt and
  rescanned image, or a `TRIAGE.md` note (stop condition).
- Audit record includes the new digest, the scanner output, and
  the smoke-test result.

## Verification

- Rebuilt image digest is captured and differs from the vulnerable
  baseline digest.
- Scanner output shows the target CVE is absent, and any newly
  introduced critical/high findings are listed as blockers.
- Smoke test or service health check result is attached to the PR
  or recorded in `TRIAGE.md`.
- Rollback context includes the previous digest and confirms the
  agent did not push to a registry or introduce a moving tag.

## Guardrails

- **One CVE, one image, one PR.** Bundling masks regressions.
- **Rescan required.** No PR opens until the rebuilt image
  scans clean for the target CVE.
- **Smoke test required.** "It builds" is not "it works."
- **Layer cache is not a fix.** Rebuild with `--no-cache` for
  the affected layer.
- **No `latest`.** The agent never introduces or relies on a
  moving tag.
- **Pull-only credentials.** Push happens from CI, not from
  the agent.

## Related

- [Base Image & Container Layer Remediation]({{< relref "/security-remediation/base-images" >}})
  — the workflow this prompt slots into.
- [Vulnerable Dependency Remediation]({{< relref "/security-remediation/vulnerable-dependencies" >}})
  — the lockfile-shaped sibling.
- [Artifact Cache & Mirror Quarantine]({{< relref "/security-remediation/artifact-cache-purge" >}})
  — when the bump is the wrong fix because the *publisher* is
  compromised.
