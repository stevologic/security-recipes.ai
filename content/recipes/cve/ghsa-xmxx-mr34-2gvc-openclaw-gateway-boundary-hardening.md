---
title: "CVE-2026-43585: OpenClaw gateway boundary hardening"
linkTitle: "CVE-2026-43585 OpenClaw gateway"
description: "CVE-2026-43585 is OpenClaw stale gateway bearer auth. Upgrade to 2026.4.15+ for SecretRef, Matrix, and webchat floors."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["cve", "ghsa", "openclaw", "agentic-ai", "mcp", "typescript", "npm", "authorization", "secret-rotation", "path-traversal", "high"]
weight: 54
date: 2026-05-08
lastmod: 2026-08-21
cve: "CVE-2026-43585"
ghsa: "GHSA-xmxx-7p24-h892"
known_as: ["GHSA-mr34-9552-qr95", "GHSA-2gvc-4f3c-2855", "OpenClaw gateway boundary hardening", "CVE-2026-41389", "CVE-2026-44110"]
kev: false
severity: "high"
ecosystem: "typescript/npm"
disclosed: "2026-04-17"
ai_enrichment_review_status: human-reviewed-development-draft
---

OpenClaw `2026.4.15` is the GitHub-named floor for this gateway-boundary
cluster. GitHub now tracks the three reviewed advisories as CVEs. Do not
invent a later 2026.4.16 floor. This page stays a development draft because
the affected windows differ. Do not prove exposure with live tokens or rooms.

- **CVE-2026-43585 / GHSA-xmxx-7p24-h892** (GitHub critical): gateway HTTP and
  WebSocket handlers could keep accepting an old bearer token after SecretRef
  rotation because auth was resolved at startup.
- **CVE-2026-41389 / GHSA-mr34-9552-qr95** (GitHub medium): webchat media
  embedding could attempt local file or Windows UNC reads before enforcing
  configured local-root containment. Affected `>=2026.4.7, <2026.4.15`.
- **CVE-2026-44110 / GHSA-2gvc-4f3c-2855** (GitHub high): Matrix room
  control-command authorization could trust sender IDs learned from a DM
  pairing store. Affected `>2026.3.28, <2026.4.15`.

## When to use it

Use this recipe when a repository, OpenClaw deployment, or agent-control
gateway needs to review Gateway bearer auth, webchat media containment, or
Matrix room command authorization together. It is aimed at source-code
remediation, agent gateway boundary hardening, multi-surface audit, and
evidence that fail-closed controls survive token rotation and room/media edge
cases.

## Inputs

- OpenClaw version, Gateway HTTP/WebSocket config, SecretRef rotation behavior,
  webchat media settings, Matrix pairing store, and room command policy.
- Source paths for per-request auth resolution, WebSocket auth, media path
  containment, Matrix sender/room checks, and boundary regression tests.
- Regression fixtures for stale bearer tokens, rotated secrets, local/UNC media
  paths, DM-paired senders, room commands, and missing authorization context.
- Runtime boundary evidence: Gateway exposure, media roots, Matrix rooms,
  tokens, logs, tenant/session ownership, and operator cleanup requirements.

## Affected versions

- **Bearer auth after SecretRef rotation:** `openclaw <2026.4.15`
  (`CVE-2026-43585` / `GHSA-xmxx-7p24-h892`)
- **Webchat media local-root containment:** `openclaw >=2026.4.7, <2026.4.15`
  (`CVE-2026-41389` / `GHSA-mr34-9552-qr95`)
- **Matrix room control-command authorization:** `openclaw >2026.3.28,
  <2026.4.15` (`CVE-2026-44110` / `GHSA-2gvc-4f3c-2855`)
- **Fixed:** `openclaw 2026.4.15+`

## Indicator-of-exposure

- The repository builds, deploys, vendors, or documents OpenClaw below
  `2026.4.15`.
- Gateway HTTP or WebSocket endpoints use bearer authentication backed by
  SecretRef/runtime secret rotation.
- Operators rotate gateway bearer tokens without restarting every gateway
  process.
- Webchat or tool-result media can include local `file://`, absolute path, or
  UNC-style references, especially from agent/tool output.
- Matrix integration enables room control commands and also supports DM pairing
  or pairing-store state.
- The OpenClaw process can read repository files, model credentials, cloud
  tokens, SSH material, user files, mounted volumes, or internal network paths.

Quick checks:

```bash
rg -n "openclaw|SecretRef|bearer|runtime secret|webchat|tool-result|localRoots|file://|UNC|matrix|pairing-store|control command" .
rg -n "openclaw|@openclaw|2026\\.4\\.(7|8|9|1[0-4])|2026\\.3\\." package*.json pnpm-lock.yaml yarn.lock npm-shrinkwrap.json Dockerfile* docker-compose*.yml charts deploy k8s helm .github .
rg -n "Authorization|Bearer|upgrade|WebSocket|localRoots|assertLocalMediaAllowed|commandAllowFrom|pairing" .
```

## Remediation strategy

- Upgrade every controlled OpenClaw dependency, image, chart, deployment, and
  generated SBOM to `2026.4.15+`.
- Rebuild and redeploy gateway processes so stale startup-time bearer auth is
  eliminated.
- Rotate gateway bearer tokens again after patched deployment if any old token
  might have remained accepted after a prior SecretRef rotation.
- Ensure gateway HTTP requests and WebSocket upgrades resolve bearer auth from
  the current runtime secret snapshot on every request.
- Reject remote-host `file://` URLs, Windows UNC paths, and local path
  references outside configured `localRoots` before `stat`, read, embed, or
  preview operations.
- Keep Matrix room command authorization separate from DM pairing state.
  Room commands should require configured sender IDs, effective room users, or
  explicit group allow-lists.
- Add tests that prove all three boundaries fail closed.

## The prompt

~~~markdown
You are remediating the OpenClaw high-severity gateway boundary cluster:
GHSA-xmxx-7p24-h892, GHSA-mr34-9552-qr95, and GHSA-2gvc-4f3c-2855. Produce
exactly one output:

- A reviewer-ready PR/change request that upgrades OpenClaw, closes stale-auth,
  local-media, and Matrix command boundary gaps, adds regression coverage, and
  documents operator cleanup, or
- TRIAGE.md if this repository does not own an affected OpenClaw runtime or
  safe remediation path.

## Rules

- Scope only these OpenClaw advisories.
- Treat bearer tokens, SecretRef values, runtime secret snapshots, tool-result
  media, local files, UNC paths, Matrix sender IDs, pairing-store state, room
  IDs, model/provider credentials, and gateway logs as sensitive.
- Do not test with production tokens, production Matrix rooms, customer files,
  real UNC shares, or real local secret paths.
- Do not log bearer tokens, media file contents, Matrix message bodies, or
  secret values.
- Do not rely on process restart as the only stale-token fix.
- Do not auto-merge.

## Steps

1. Inventory every OpenClaw asset controlled by this repository: npm manifests,
   lockfiles, vendored source, Dockerfiles, compose files, Helm charts,
   Kubernetes manifests, SecretRef/runtime-secret config, Matrix integration
   config, MCP or agent gateway docs, SBOMs, and runbooks.
2. Determine every resolved OpenClaw version. A target is vulnerable if it
   resolves to:
   - `<2026.4.15` for stale gateway bearer auth after SecretRef rotation;
   - `>=2026.4.7, <2026.4.15` for webchat media local-root containment;
   - `>2026.3.28, <2026.4.15` for Matrix room command authorization.
3. Determine exposure without using real secrets or customer rooms:
   - Do gateway HTTP or WebSocket paths use SecretRef-backed bearer auth?
   - Are bearer tokens rotated without gateway process restart?
   - Can tool-result or webchat media include local paths, `file://` URLs, or
     Windows UNC paths?
   - Are `localRoots` configured, and are they checked before any filesystem
     probing?
   - Are Matrix room control commands enabled?
   - Can DM-paired sender IDs coexist with room traffic in the pairing store?
4. If OpenClaw is absent or this repository only contains unrelated docs, stop
   with `TRIAGE.md` naming the files checked, likely runtime owner, and fixed
   version `2026.4.15+`.
5. Upgrade OpenClaw to `2026.4.15+` everywhere this repository controls it.
   Regenerate lockfiles, image digests, SBOMs, deployment renders, and
   dependency reports.
6. Patch or verify gateway auth behavior:
   - resolve active bearer auth from the current runtime secret snapshot for
     every HTTP request;
   - resolve active bearer auth again for every WebSocket upgrade;
   - reject old bearer tokens immediately after SecretRef rotation;
   - avoid caching resolved secret values in long-lived request handlers.
7. Patch or verify media containment:
   - reject remote-host `file://` URLs;
   - reject Windows UNC/network paths;
   - require configured `localRoots` containment before `stat`, read, preview,
     transcode, embed, or copy operations;
   - apply one shared resolver across audio, image, and trusted passthrough
     paths.
8. Patch or verify Matrix authorization:
   - build room command authorizers only from configured room sender IDs,
     effective room users, and explicit group allow-lists;
   - do not use DM pairing-store sender IDs to authorize room commands;
   - skip pairing-store reads on room traffic unless used only as non-authority
     metadata.
9. Add safe regression tests:
   - after SecretRef rotation, the old token receives 401/403 without restart;
   - HTTP and WebSocket upgrade paths both re-resolve auth;
   - local media paths outside `localRoots`, remote-host `file://`, and UNC
     paths are rejected before filesystem access;
   - a DM-paired Matrix sender cannot authorize room control commands;
   - configured room allow-list behavior still works.
10. Add a PR body section named `OpenClaw operator actions` that states:
    - OpenClaw versions before and after the change;
    - whether gateway bearer auth used SecretRef rotation;
    - whether old tokens may have remained valid and need re-rotation;
    - whether tool-result media could reference local or UNC paths;
    - whether Matrix room commands and DM pairing were enabled together;
    - which gateway, secret-rotation, media, filesystem, Matrix, and audit logs
      should be reviewed;
    - which bearer tokens, credentials, or room permissions should be rotated
      or cleaned up.
11. Run relevant validation: package install, lockfile integrity, unit tests,
    integration tests for gateway auth/media/Matrix, lint/typecheck, container
    build, deployment render, SBOM refresh, and dependency/security scans
    available here.
12. Use PR title:
    `fix(sec): remediate OpenClaw gateway boundary advisories`.

## Stop conditions

- No OpenClaw runtime, dependency, image, gateway config, Matrix integration,
  or webchat media path is controlled by this repository.
- A fixed OpenClaw version cannot be consumed without a broader platform
  migration.
- The only verification path requires production bearer tokens, customer
  files, real UNC shares, or real Matrix rooms.
- Product behavior intentionally permits DM-paired senders to run room
  commands or permits local file media outside approved roots; require a
  product/security decision.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Output contract

- A reviewer-ready PR or change request that upgrades OpenClaw, enforces
  per-request auth after SecretRef rotation, contains media reads, hardens room
  command authorization, adds regression tests, and documents cleanup.
- Or a `TRIAGE.md` file that lists inspected files, owner, observed version,
  gateway/media/room boundaries, required fix, and residual risk.
- The output must include exact validation commands and must not expose real
  bearer tokens, local files, Matrix room contents, customer data, or logs.

## Verification - what the reviewer looks for

- No controlled OpenClaw dependency, image, SBOM, or deployment target remains
  below `2026.4.15`.
- HTTP and WebSocket gateway auth reject an old bearer token immediately after
  SecretRef rotation.
- Media tests prove disallowed `file://`, UNC, and outside-root paths are
  rejected before filesystem access.
- Matrix tests prove DM pairing-store state cannot authorize room control
  commands.
- Operator actions cover token re-rotation, filesystem/media log review, and
  Matrix room authorization cleanup.

## Watch for

- Updating package manifests while a container image, Helm chart, global
  install, or SBOM still pins an older OpenClaw build.
- Fixing HTTP request auth while WebSocket upgrade auth still uses cached
  startup-time state.
- Checking `localRoots` after `stat` or read has already touched a path.
- Treating a Matrix DM pairing record as proof that the sender can control a
  room.
- Logging sensitive media references or bearer-token values while adding tests.

## Rollback and recovery

Prefer forward recovery to another GitHub-named `openclaw` 2026.4.15+ release.
If an operational rollback restores a build before `2026.4.15`, isolate
Gateway HTTP/WebSocket, disable webchat local media, and stop Matrix room
control commands until the named floor is restored.

## Related recipes

- [Source code authz tenant boundary audit]({{< relref "/recipes/general/source-code-authz-tenant-boundary-audit" >}})
- [Source code secrets and data exposure audit]({{< relref "/recipes/general/source-code-secrets-data-exposure-audit" >}})
- [Source code attack surface map]({{< relref "/recipes/general/source-code-attack-surface-map" >}})
- [AI governance oversight evidence check]({{< relref "/recipes/general/compliance-standards/ai-governance-oversight-evidence-check" >}})

## References

- GitHub Advisory `GHSA-xmxx-7p24-h892`: <https://github.com/advisories/GHSA-xmxx-7p24-h892>
- NVD `CVE-2026-43585`: <https://nvd.nist.gov/vuln/detail/CVE-2026-43585>
- GitHub Advisory `GHSA-mr34-9552-qr95`: <https://github.com/advisories/GHSA-mr34-9552-qr95>
- NVD `CVE-2026-41389`: <https://nvd.nist.gov/vuln/detail/CVE-2026-41389>
- GitHub Advisory `GHSA-2gvc-4f3c-2855`: <https://github.com/advisories/GHSA-2gvc-4f3c-2855>
- NVD `CVE-2026-44110`: <https://nvd.nist.gov/vuln/detail/CVE-2026-44110>
- OpenClaw project: <https://github.com/openclaw/openclaw>

