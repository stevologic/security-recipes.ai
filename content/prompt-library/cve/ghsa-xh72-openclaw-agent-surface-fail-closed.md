---
title: "GHSA-xh72/GHSA-xmxx - OpenClaw agent-surface fail-closed bypasses"
linkTitle: "GHSA OpenClaw agent surface"
description: "Critical OpenClaw agent-surface vulnerabilities across Feishu webhook auth, gateway bearer-token rotation, Matrix room authorization, and webchat media file containment. Upgrade to 2026.4.15+, fail closed at every external agent input, and add trust-boundary regression tests."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "openclaw", "agentic-ai", "npm", "webhook", "authorization", "secret-rotation", "critical"]
weight: 59
date: 2026-05-02
ghsa: "GHSA-xh72-v6v9-mwhc"
aliases: ["OpenClaw 2026.4.15 agent-surface hardening", "GHSA-xmxx-7p24-h892", "GHSA-2gvc-4f3c-2855", "GHSA-mr34-9552-qr95"]
kev: false
severity: "critical"
ecosystem: "typescript/npm"
disclosed: "2026-04-17"
---

OpenClaw published a cluster of GitHub-reviewed High/Critical advisories around
external agent inputs and runtime authorization boundaries. They matter because
they sit exactly where agentic systems are most exposed: chat/webhook ingress,
gateway bearer auth, chat-room command authorization, and tool-result media
normalization.

The four advisories covered by this recipe are:

- `GHSA-xh72-v6v9-mwhc` (Critical): Feishu webhook mode and card-action
  callbacks could fail open when signing configuration or callback tokens were
  missing or blank, allowing unauthenticated traffic to reach command dispatch.
- `GHSA-xmxx-7p24-h892` (High): gateway HTTP and WebSocket handlers could keep
  accepting an old bearer token after SecretRef rotation because auth was
  resolved at server startup instead of per request.
- `GHSA-2gvc-4f3c-2855` (High): Matrix room control-command authorization could
  trust sender IDs learned from the DM pairing store, crossing the DM/room
  command boundary.
- `GHSA-mr34-9552-qr95` (High): webchat tool-result media handling could pass
  local or UNC-style paths into host-side embedding before enforcing
  `localRoots`, risking host file reads or Windows network credential exposure.

## Affected versions

- **OpenClaw Feishu webhook/card-action validation:**
  `openclaw <2026.4.15`; fixed in `2026.4.15`.
- **OpenClaw gateway bearer auth re-resolution:**
  `openclaw <2026.4.15`; fixed in `2026.4.15`.
- **OpenClaw Matrix room control-command authorization:**
  `openclaw >2026.3.28, <2026.4.15`; fixed in `2026.4.15`.
- **OpenClaw webchat media local-root containment:**
  `openclaw >=2026.4.7, <2026.4.15`; fixed in `2026.4.15`.

## Indicator-of-exposure

- The repository installs, builds, deploys, vendors, or documents
  `openclaw` before `2026.4.15`.
- Feishu webhook mode is enabled, especially if `encryptKey` is optional,
  missing, read from a SecretRef, or configured differently per environment.
- Feishu card-action callbacks are accepted, and blank or malformed lifecycle
  callback tokens can reach action dispatch.
- Gateway bearer tokens are provided through SecretRef or another dynamic
  secret source, and operators expect rotation to revoke old tokens without a
  process restart.
- Matrix integration is enabled, room control commands are available, and DM
  pairing is used for the same bot account.
- Webchat renders tool-result media, especially if agents, tools, or users can
  submit `file://`, local filesystem, Windows drive, or UNC-style media paths.

Quick checks:

```bash
rg -n "openclaw|@openclaw|OPENCLAW|Feishu|encryptKey|card-action|SecretRef|bearer|Matrix|commandAllowFrom|pairing|webchat|localRoots|file://|UNC" .
npm ls openclaw
pnpm why openclaw
yarn why openclaw
rg -n "openclaw|feishu|matrix|gateway|webchat|localRoots|SecretRef|bearer" Dockerfile* docker-compose*.yml charts deploy k8s helm .github config* .
```

## Remediation strategy

- Upgrade every controlled OpenClaw package, image, deployment manifest, and
  generated SBOM to `2026.4.15+`.
- Fail closed for Feishu ingress: webhook mode must not start without
  `encryptKey`, missing signing config must be invalid, invalid signatures must
  return `401`, and blank card-action callback tokens must be rejected before
  dispatch.
- Re-resolve gateway bearer authentication from the current runtime secret
  snapshot on every HTTP request and WebSocket upgrade.
- Enforce separate Matrix authorization boundaries: DM pairing-store entries
  must not authorize room control commands.
- Reject remote-host `file://` URLs, Windows network paths, and local-root
  bypasses before any media `stat`, read, transform, or embed operation.
- Until the fixed build is live, disable Feishu webhook/card-action ingress,
  disable Matrix room control commands, block local-file media embedding, and
  rotate/restart gateway bearer-token consumers where old tokens may remain
  accepted.

## The prompt

~~~markdown
You are remediating the OpenClaw 2026.4.15 agent-surface advisory cluster:
GHSA-xh72-v6v9-mwhc, GHSA-xmxx-7p24-h892, GHSA-2gvc-4f3c-2855, and
GHSA-mr34-9552-qr95. Produce exactly one output:

- A reviewer-ready PR/change request that upgrades OpenClaw, adds containment
  for exposed agent ingress, adds trust-boundary regression tests, and
  documents operator cleanup, or
- TRIAGE.md if this repository does not own an affected OpenClaw runtime or
  cannot make a safe change.

## Rules

- Scope only the four OpenClaw advisories named above.
- Treat Feishu signing keys, callback tokens, Matrix access tokens, gateway
  bearer tokens, SecretRefs, tool-result media paths, local file paths, prompt
  logs, command logs, and workspace paths as sensitive.
- Do not send forged webhook traffic, room commands, WebSocket upgrades, or
  file-read payloads to production, staging, shared dev, or real customer
  tenants.
- Do not keep any fail-open behavior because an integration was historically
  optional.
- Do not auto-merge.

## Steps

1. Inventory every OpenClaw runtime controlled by this repository: npm manifests,
   lockfiles, Dockerfiles, compose files, Helm charts, Kubernetes manifests,
   Terraform, Ansible, CI images, SBOMs, gateway config, chat integration config,
   exported agent/workflow definitions, and runbooks.
2. Determine every resolved `openclaw` version. Treat any controlled runtime
   below `2026.4.15` as vulnerable to at least one advisory in this cluster.
3. Map exposure by integration:
   - Feishu webhook mode, `encryptKey`, signature validation, replay protection,
     and card-action lifecycle token handling;
   - gateway HTTP and WebSocket bearer auth, especially dynamic SecretRef
     rotation behavior;
   - Matrix room control commands, DM pairing-store use, room allowlists, group
     allowlists, and configured sender IDs;
   - webchat tool-result media embedding, `localRoots`, `file://` handling,
     Windows drive paths, and UNC/network paths.
4. If the repository does not deploy OpenClaw or only contains unrelated client
   code, stop with `TRIAGE.md` listing files checked, affected advisory IDs,
   and the runtime owner.
5. Upgrade every controlled OpenClaw package, image, and deployment target to
   `2026.4.15+`. Regenerate lockfiles, image digests, SBOMs, deployment render
   output, and dependency reports.
6. Add Feishu fail-closed controls where this repository owns config or code:
   - refuse webhook mode when `encryptKey` is absent;
   - return invalid/unauthorized for missing signing config and invalid
     signatures;
   - reject blank card-action callback tokens before any handler dispatch;
   - add explicit startup or policy checks so unsafe config cannot ship.
7. Add gateway bearer-token rotation controls:
   - resolve auth from the current runtime secret snapshot per request and per
     WebSocket upgrade;
   - reject old bearer tokens after SecretRef rotation without requiring a
     process restart;
   - add a readiness or probe test that demonstrates old-token rejection.
8. Add Matrix room authorization controls:
   - ensure room command authorizers use configured room senders, room members,
     and group allowlists only;
   - exclude DM pairing-store sender IDs from room command authorization;
   - skip DM pairing-store reads for room traffic where practical.
9. Add webchat media containment controls:
   - reject remote-host `file://` URLs;
   - reject Windows UNC/network paths and Windows drive paths outside
     configured roots;
   - call local-root containment checks before any filesystem `stat`, read,
     transform, embed, or metadata probe;
   - fail closed when media path type cannot be classified safely.
10. Add regression tests that do not read real sensitive files or call real chat
    providers:
    - missing Feishu `encryptKey` fails startup or policy validation;
    - invalid Feishu signatures return unauthorized before JSON/action dispatch;
    - blank card-action tokens are rejected before handler dispatch;
    - old gateway bearer tokens fail immediately after SecretRef rotation;
    - DM-paired Matrix senders cannot authorize room control commands;
    - remote-host `file://`, UNC, and local-root bypass media paths are rejected
      before filesystem access.
11. Add temporary containment for any rollout that is not atomic:
    - disable Feishu webhook/card-action routes;
    - disable Matrix room control commands;
    - block local-file webchat media embedding;
    - restart gateway pods after bearer-token rotation until per-request
      re-resolution is verified.
12. Add a PR body section named `OpenClaw operator actions` that states:
    - OpenClaw versions before and after the change;
    - which integrations were enabled and externally or tenant reachable;
    - which tokens or signing keys should be rotated;
    - whether process restarts are required during rollout;
    - which webhook, gateway, Matrix, command-dispatch, and media logs should
      be reviewed for suspicious activity.
13. Run relevant validation: package install, lockfile integrity, unit tests,
    integration tests with mocked providers, policy checks, gateway/ingress
    render tests, image build, deployment diff, SBOM refresh, and
    dependency/security scans available in this repository.
14. Use PR title:
    `fix(sec): remediate OpenClaw agent-surface advisories`.

## Stop conditions

- No affected OpenClaw deployment is controlled by this repository.
- A fixed OpenClaw version cannot be consumed without a broader platform
  migration.
- Product requirements intentionally depend on fail-open webhook auth, stale
  bearer-token validity, DM-to-room command trust, or host-file media embedding;
  document the risk and require a product/security decision.
- Verification would require forged traffic against real integrations or
  reading sensitive host files.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled lockfile, image, SBOM, or deployment target resolves OpenClaw
  below `2026.4.15`.
- Feishu webhook mode fails closed when signing configuration is absent or
  invalid, and blank card-action tokens cannot reach dispatch.
- Gateway bearer auth is resolved from the current secret snapshot per request
  and per WebSocket upgrade.
- Matrix DM pairing-store entries cannot authorize room control commands.
- Webchat media containment rejects `file://`, UNC, and local-root bypass paths
  before filesystem access.
- Operator actions cover token/key rotation, log review, temporary route
  blocks, and rollout restarts where exposure was possible.

## Watch for

- Upgrading the main package while old OpenClaw images or globally installed
  CLI/runtime packages remain in deployment manifests.
- Testing only normal Feishu signed messages and missing missing-config,
  invalid-signature, blank-token, and malformed-callback paths.
- Rotating a SecretRef while the running gateway still holds startup-time auth.
- Treating Matrix DM pairing as equivalent to room command authorization.
- Checking local-root containment after `stat`, preview generation, or media
  metadata probing has already touched the path.

## References

- GitHub Advisory `GHSA-xh72-v6v9-mwhc`: <https://github.com/advisories/GHSA-xh72-v6v9-mwhc>
- GitHub Advisory `GHSA-xmxx-7p24-h892`: <https://github.com/advisories/GHSA-xmxx-7p24-h892>
- GitHub Advisory `GHSA-2gvc-4f3c-2855`: <https://github.com/advisories/GHSA-2gvc-4f3c-2855>
- GitHub Advisory `GHSA-mr34-9552-qr95`: <https://github.com/advisories/GHSA-mr34-9552-qr95>
- OpenClaw project: <https://github.com/openclaw/openclaw>
