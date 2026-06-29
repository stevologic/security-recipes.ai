---
title: "GHSA-QRV3-253H-G69C - pnpm path traversal"
linkTitle: "GHSA-QRV3-253H-G69C path traversal"
description: "High path traversal in pnpm. Upgrade or patch the affected code path, add regression coverage, and deploy with detection for exploitation attempts."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["cve", "enterprise_blocker", "ghsa", "javascript", "npm", "path-traversal", "remediation", "sellable_to_fintech", "zero_day_gold"]
weight: 45
date: 2026-06-29
ghsa: "GHSA-QRV3-253H-G69C"
aliases: ["GHSA-QRV3-253H-G69C", "pnpm path traversal"]
kev: false
severity: "high"
ecosystem: "javascript/npm"
disclosed: "2026-06-27"
---

## GHSA ID + Title + Severity + Publication Date

- **GHSA ID:** GHSA-QRV3-253H-G69C
- **Title:** pnpm path traversal
- **Severity:** High (CVSS v3.1 score see GHSA)
- **Publication date:** 2026-06-27
- **Affected tech stack:** Node.js/JavaScript supply chain
- **Revenue tags:** sellable_to_fintech, enterprise_blocker, zero_day_gold

## One-sentence business risk

High path traversal in pnpm can turn a routine dependency or application endpoint into data theft, account takeover, service outage, or code execution risk that blocks production releases and customer renewals.

## Root cause and affected versions

pnpm: Path traversal in configDependencies env lockfile allows symlink creation outside node_modules/.pnpm-config

- **Vulnerable range:** See vendor advisory and package manager resolution for the affected range.
- **Fixed or mitigated range:** Upgrade to the first vendor-fixed release or apply the referenced patch/backport.
- **Public exploit/PoC status:** Treat as public or reproducible when the advisory references a GitHub issue, exploit repository, VulnCheck entry, Wordfence entry, or public PoC. Validate only in isolated test environments.

## Exact vulnerable code pattern

```java
// GHSA-QRV3-253H-G69C: handler builds a path from attacker-controlled `input`.
Path target = Paths.get(uploadRoot, request.getParameter("input"));
Files.write(target, bytes);
```

## Fixed / mitigated code pattern

```java
Path root = uploadRoot.toRealPath();
Path target = root.resolve(request.getParameter("input")).normalize();
if (!target.startsWith(root) || Files.isSymbolicLink(target)) {
    throw new SecurityException("path escapes upload root");
}
Files.write(target, bytes, StandardOpenOption.CREATE_NEW);
```

```python
root = pathlib.Path(upload_root).resolve()
target = (root / request.form["input"]).resolve()
if root not in target.parents:
    raise ValueError("path traversal")
target.write_bytes(data)
```

## Step-by-step integration guide

1. Inventory every direct and transitive use of `pnpm` with package manifests, lockfiles, SBOMs, container images, vendored source, firmware manifests, and deployment overlays.
2. Confirm whether the vulnerable path is reachable: `allows` and attacker-controlled parameter `input` are the first review anchors.
3. Upgrade to the vendor-fixed release or apply the referenced patch/backport; regenerate lockfiles, image digests, SBOMs, and deployment manifests.
4. Patch owned code so untrusted input is validated before it reaches the vulnerable sink; use the fixed pattern above as the minimum implementation bar.
5. Add a regression test that sends the advisory-shaped payload and proves the operation is rejected without corrupting memory, crossing trust boundaries, or changing privileged state.
6. Run unit tests, integration tests for the affected route/parser/protocol, dependency audit, SAST rules for the sink class, and container or firmware build validation.
7. Deploy through staged rollout with telemetry on rejected exploit-shaped inputs and a rollback plan that does not restore the vulnerable version.

## Alternative mitigations

- Disable the affected endpoint, parser, protocol feature, plugin, decoder, runner option, or integration until the fixed build is live.
- Put a gateway/WAF rule in front of exposed HTTP paths to block advisory-shaped parameters while application code is patched.
- For native parsers and protocol libraries, isolate processing in a sandboxed worker with seccomp/AppArmor, memory limits, ASAN canaries in staging, and crash restart rate limits.
- For authz/authn flaws, require an additional server-side role check at the route/service layer and invalidate sessions or tokens touched during the vulnerable window.
- For supply-chain tooling, pin the fixed version in CI images and block vulnerable versions with dependency policy.

## Detection signature

`rg -n "input|move_uploaded_file|Files\.write|Path\.resolve|\.\.\/|zip|tar|extract" .` and alert on filenames containing `../`, absolute paths, or symlinks.

## Copy-paste skill

~~~markdown
You are remediating GHSA-QRV3-253H-G69C: pnpm path traversal.

Goal: produce a reviewer-ready PR that removes exposure to GHSA-QRV3-253H-G69C, adds regression coverage, and documents deployment/operator checks.

Rules:
- Scope only GHSA-QRV3-253H-G69C and directly related `pnpm` usage.
- Do not run public PoCs against production, shared staging, customer systems, or third-party infrastructure.
- Treat credentials, tokens, session data, private files, tenant IDs, and exploit samples as sensitive.
- Prefer the vendor-fixed release. Use a temporary mitigation only when upgrade is blocked and document the owner/date for removal.
- If this repository does not own an affected runtime, write `TRIAGE.md` with evidence instead of making unrelated edits.

Steps:
1. Search for `pnpm`, `GHSA-QRV3-253H-G69C`, vulnerable package names, `allows`, and parameter `input`.
2. Identify every resolved vulnerable version in manifests, lockfiles, images, SBOMs, vendored code, and deployment templates.
3. Upgrade or patch to the fixed version: Upgrade to the first vendor-fixed release or apply the referenced patch/backport.
4. Replace the vulnerable code shape with input validation, parameterized APIs, strict bounds checks, canonical path checks, or explicit authz as appropriate.
5. Add a negative regression test for the advisory-shaped payload and a positive test for legitimate behavior.
6. Add detection from the signature section and document operator review for suspicious requests, crashes, privilege changes, or file writes.
7. Run the relevant test/build/audit commands and include outputs in the PR.

Stop and write `TRIAGE.md` if the affected runtime is not present, the fix requires production probing, or ownership of the vulnerable deployment is outside this repo.
~~~

## Keywords and tags

- **Keywords:** GHSA-QRV3-253H-G69C, pnpm, path traversal, javascript/npm, Node.js/JavaScript supply chain
- **Revenue tags:** sellable_to_fintech, enterprise_blocker, zero_day_gold

## References

- https://github.com/advisories/GHSA-qrv3-253h-g69c
