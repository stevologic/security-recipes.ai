---
title: "GHSA-6xcp-7mpr-m7wm - Open WebUI CORS and session RCE chain"
linkTitle: "GHSA-6xcp Open WebUI CORS"
description: "High-severity Open WebUI CORS and session validation issue that can enable one-click admin-origin RCE. Upgrade to 0.3.33+, restrict origins, rotate sessions on logout, and test browser-origin boundaries."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "open-webui", "python", "cors", "session", "rce", "high", "agentic-ai"]
weight: 74
date: 2026-05-12
ghsa: "GHSA-6xcp-7mpr-m7wm"
known_as: ["Open WebUI CORS misconfiguration and session validation issue"]
kev: false
severity: "high"
ecosystem: "python/pypi"
disclosed: "2026-05-11"
---

Open WebUI shipped broad CORS behavior and weak session invalidation in older
versions. A malicious site could make authenticated browser requests against an
admin's Open WebUI instance, including function/filter creation paths capable
of running code in the Open WebUI container. Logout did not reliably invalidate
session cookies, increasing the practical exposure window.

For agentic AI workbenches, this is a control-plane issue: browser-origin
policy, admin code-extension features, and session lifecycle must be treated as
production security boundaries.

## When to use it

- A repository deploys Open WebUI before `0.3.33`.
- Admin users access Open WebUI from browsers that also visit untrusted sites.
- Credentialed CORS, session invalidation, or admin code-extension routes are
  configured or overridden by app, proxy, or ingress layers.
- You need a bounded PR or triage note that upgrades Open WebUI and proves
  browser-origin/session boundaries for admin routes.

## Inputs

- Open WebUI package/image versions, compose/Helm/K8s manifests, reverse-proxy
  config, environment variables, SBOMs, and generated deployment artifacts.
- CORS settings, trusted origins, session/cookie config, logout behavior,
  function/filter/tool creation routes, and admin exposure model.
- Available auth/CORS/session tests, container build, deployment render, SBOM,
  and dependency/security scan commands.

## Affected versions

| Package | Vulnerable versions | Fixed versions |
| --- | --- | --- |
| `open-webui` | `<0.3.33` | `0.3.33` |

## Indicator-of-exposure

- The repository deploys `open-webui <0.3.33`.
- Open WebUI is accessed by admins from normal browsing sessions.
- CORS allows broad origins with credentials.
- Admin users can create functions, filters, tools, or other server-side code
  extension points.
- Logout/session rotation behavior is not tested.

Quick checks:

```bash
rg -n "open-webui|OPEN_WEBUI|allow_origins|allow_credentials|CORSMiddleware|functions/create|session|logout|WEBUI_AUTH" .
python -m pip show open-webui
pip freeze | rg -i "open-webui"
docker images | rg -i "open-webui"
```

## Remediation strategy

- Upgrade Open WebUI to `0.3.33+`, preferably the latest patched release.
- Configure an explicit origin allow-list; do not use wildcard origins with
  credentials.
- Ensure logout invalidates server-side session state and rotates cookies.
- Gate code-extension/admin routes behind CSRF/origin checks and admin-only
  authorization.
- Add browser-origin and session lifecycle tests for admin routes.
- Review logs and rotate secrets if a vulnerable admin browser session could
  have reached exposed Open WebUI instances.

## The prompt

~~~markdown
You are remediating GHSA-6xcp-7mpr-m7wm in Open WebUI. Produce exactly one
output:

- A reviewer-ready PR/change request that upgrades Open WebUI, restricts CORS,
  fixes session invalidation, hardens admin code-extension routes, refreshes
  generated artifacts, and adds regression tests, or
- TRIAGE.md if this repository does not control an affected Open WebUI
  deployment.

## Rules

- Scope only GHSA-6xcp-7mpr-m7wm and directly related browser-origin, session,
  and admin route hardening.
- Do not run browser-based RCE payloads, create malicious functions, or write
  proof files in containers.
- Do not print or commit session cookies, admin tokens, model provider keys,
  Open WebUI config secrets, database contents, chat history, uploaded files,
  or container environment variables.
- Do not leave wildcard credentialed CORS enabled.
- Do not auto-merge.

## Steps

1. Inventory Open WebUI dependencies, images, compose files, Helm charts,
   Kubernetes manifests, reverse-proxy config, environment variables, admin
   route exposure, CORS config, session config, docs, and SBOMs.
2. Determine every Open WebUI version. A target is vulnerable if it resolves to
   `<0.3.33`.
3. Search for CORS middleware/config that permits `*`, broad patterns, or
   reflected origins with credentials. Search for function/filter/tool creation
   routes and logout/session handling.
4. Upgrade Open WebUI to `0.3.33+` or a newer patched release. Regenerate image
   tags, lockfiles, SBOMs, deployment manifests, and generated docs.
5. Configure browser-origin policy:
   - exact allowed origins only;
   - no wildcard with credentials;
   - admin/code-extension routes require same-origin or explicit trusted
     origin plus CSRF protections;
   - reverse proxy does not re-add broad CORS headers.
6. Configure session lifecycle:
   - logout invalidates server-side state;
   - cookies rotate after login/logout and privilege changes;
   - secure, httpOnly, sameSite, and domain/path attributes are explicit.
7. Add safe tests:
   - untrusted origin cannot call admin routes with credentials;
   - trusted origin still works;
   - logout invalidates the old session;
   - function/filter creation requires admin authorization and origin checks.
8. Add a PR body section named `GHSA-6xcp-7mpr-m7wm operator actions` covering:
   affected instances, before/after version, allowed origins, admin route
   exposure, session invalidation behavior, and whether logs/secrets should be
   reviewed.
9. Run validation: deployment render, container build, auth/CORS/session tests,
   lint/typecheck, SBOM refresh, and dependency/security scans.
10. Use PR title:
    `fix(sec): harden Open WebUI browser-origin controls`.

## Stop conditions

- Open WebUI is not present or is managed outside this repository.
- All controlled deployments already run patched versions with explicit CORS
  and session controls.
- Verification would require creating malicious admin functions or exposing
  cookies/secrets.
- Required trusted origins are unknown; produce TRIAGE.md with the exact
  decision needed.
~~~

## Verification - what the reviewer looks for

- Open WebUI is patched in all controlled deployments.
- Credentialed CORS is exact-origin only.
- Logout/session invalidation is tested.
- Admin code-extension routes are not callable from untrusted browser origins.
- No exploit code or secrets are committed.

## Output contract

- Reviewer-ready PR upgrading Open WebUI to `0.3.33+` and refreshing images,
  manifests, SBOMs, docs, and generated artifacts.
- Exact-origin credentialed CORS, tested logout/session invalidation, and
  admin route checks for code-extension surfaces.
- Operator notes for allowed origins, exposed instances, logs/secrets review,
  session invalidation, and remaining rollout targets.
- `TRIAGE.md` when trusted origins or deployment ownership require an external
  decision.

## Watch for

- Reverse proxies or ingress controllers that override application CORS.
- Admin users who access Open WebUI from the same browser used for untrusted
  sites.
- Separate Open WebUI worker images that lag behind the main service tag.

## Related recipes

- [CVE-2026-5760 SGLang GGUF template RCE]({{< relref "/prompt-library/cve/cve-2026-5760-sglang-gguf-rce" >}})
- [Browser agent boundary]({{< relref "/security-remediation/browser-agent-boundary" >}})
- [CVE intelligence intake gate]({{< relref "/prompt-library/general/cve-intelligence-intake-gate" >}})

## References

- GitHub Advisory: <https://github.com/advisories/GHSA-6xcp-7mpr-m7wm>
- Vendor advisory: <https://github.com/open-webui/open-webui/security/advisories/GHSA-6xcp-7mpr-m7wm>
- Open WebUI source: <https://github.com/open-webui/open-webui>
