---
title: "GHSA-72R4-9C5J-MJ57 - pnpm security control bypass"
linkTitle: "GHSA-72R4-9C5J-MJ57 security control bypass"
description: "High security control bypass in pnpm. Upgrade or patch the affected code path, add regression coverage, and deploy with detection for exploitation attempts."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["cve", "enterprise_blocker", "ghsa", "javascript", "npm", "remediation", "security-control-bypass", "sellable_to_fintech", "zero_day_gold"]
weight: 45
date: 2026-06-29
ghsa: "GHSA-72R4-9C5J-MJ57"
aliases: ["GHSA-72R4-9C5J-MJ57", "pnpm security control bypass"]
kev: false
severity: "high"
ecosystem: "javascript/npm"
disclosed: "2026-06-27"
---

## GHSA ID + Title + Severity + Publication Date

- **GHSA ID:** GHSA-72R4-9C5J-MJ57
- **Title:** pnpm security control bypass
- **Severity:** High (CVSS v3.1 score see GHSA)
- **Publication date:** 2026-06-27
- **Affected tech stack:** Node.js/JavaScript supply chain
- **Revenue tags:** sellable_to_fintech, enterprise_blocker, zero_day_gold

## One-sentence business risk

High security control bypass in pnpm can turn a routine dependency or application endpoint into data theft, account takeover, service outage, or code execution risk that blocks production releases and customer renewals.

## Root cause and affected versions

pnpm: `patch-remove` could delete project-selected files outside the patches directory

- **Vulnerable range:** See vendor advisory and package manager resolution for the affected range.
- **Fixed or mitigated range:** Upgrade to the first vendor-fixed release or apply the referenced patch/backport.
- **Public exploit/PoC status:** Treat as public or reproducible when the advisory references a GitHub issue, exploit repository, VulnCheck entry, Wordfence entry, or public PoC. Validate only in isolated test environments.

## Exact vulnerable code pattern

```text
GHSA-72R4-9C5J-MJ57: review the affected handler `handler` / `affected endpoint` and remove trust in attacker-controlled `input` before it reaches privileged code.
```

## Fixed / mitigated code pattern

```text
Upgrade to the fixed release, then add a regression test that sends the advisory-shaped input and proves the protected operation is rejected.
```

## Step-by-step integration guide

1. Inventory every direct and transitive use of `pnpm` with package manifests, lockfiles, SBOMs, container images, vendored source, firmware manifests, and deployment overlays.
2. Confirm whether the vulnerable path is reachable: `pnpm` and attacker-controlled parameter `input` are the first review anchors.
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

`rg -n "pnpm|GHSA-72R4-9C5J-MJ57|pnpm|input" .` and add an integration test for the advisory-shaped input.

## Copy-paste skill

~~~markdown
You are remediating GHSA-72R4-9C5J-MJ57: pnpm security control bypass.

Goal: produce a reviewer-ready PR that removes exposure to GHSA-72R4-9C5J-MJ57, adds regression coverage, and documents deployment/operator checks.

Rules:
- Scope only GHSA-72R4-9C5J-MJ57 and directly related `pnpm` usage.
- Do not run public PoCs against production, shared staging, customer systems, or third-party infrastructure.
- Treat credentials, tokens, session data, private files, tenant IDs, and exploit samples as sensitive.
- Prefer the vendor-fixed release. Use a temporary mitigation only when upgrade is blocked and document the owner/date for removal.
- If this repository does not own an affected runtime, write `TRIAGE.md` with evidence instead of making unrelated edits.

Steps:
1. Search for `pnpm`, `GHSA-72R4-9C5J-MJ57`, vulnerable package names, `affected handlers`, and parameter `input`.
2. Identify every resolved vulnerable version in manifests, lockfiles, images, SBOMs, vendored code, and deployment templates.
3. Upgrade or patch to the fixed version: Upgrade to the first vendor-fixed release or apply the referenced patch/backport.
4. Replace the vulnerable code shape with input validation, parameterized APIs, strict bounds checks, canonical path checks, or explicit authz as appropriate.
5. Add a negative regression test for the advisory-shaped payload and a positive test for legitimate behavior.
6. Add detection from the signature section and document operator review for suspicious requests, crashes, privilege changes, or file writes.
7. Run the relevant test/build/audit commands and include outputs in the PR.

Stop and write `TRIAGE.md` if the affected runtime is not present, the fix requires production probing, or ownership of the vulnerable deployment is outside this repo.
~~~

## Keywords and tags

- **Keywords:** GHSA-72R4-9C5J-MJ57, pnpm, security control bypass, javascript/npm, Node.js/JavaScript supply chain
- **Revenue tags:** sellable_to_fintech, enterprise_blocker, zero_day_gold

## References

- https://github.com/advisories/GHSA-72r4-9c5j-mj57
