---
title: "CIS Controls safeguard implementation check"
linkTitle: "CIS Controls safeguards"
description: "Read-only recipe for checking repository and workflow evidence against CIS Controls safeguard themes."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["compliance", "cis-controls", "safeguards", "security-baseline", "audit"]
weight: 50
date: 2026-06-25
severity: "medium"
---

A read-only implementation-evidence check for CIS Critical Security Controls
v8.1 themes. It helps a security team identify which safeguards are evidenced
by repository, CI, deployment, and agent-workflow artifacts.

## When to use it

- Before a baseline security review.
- When moving a service from pilot to production.
- When a team needs a practical gap list aligned to common safeguard themes.

## Inputs

- Repository path, service owner, and environment type.
- Optional implementation group target: IG1, IG2, IG3, or unknown.
- Optional asset inventory, CI logs, scanner output, or deployment inventory.

## The prompt

~~~markdown
You are running a CIS Controls safeguard implementation check. Run read-only.
Do not edit files, change cloud resources, install agents, or claim compliance.

## Step 0 - Scope and implementation group

Record:

- Repository, service, owner, and environment.
- Implementation group target if supplied: IG1, IG2, IG3, or unknown.
- Evidence sources available locally.
- Evidence sources outside the repo, such as EDR, IAM, asset inventory, SIEM,
  MDM, cloud control plane, vulnerability scanner, or ticket system.

If implementation group is unknown, produce a general evidence check and label
IG-specific conclusions as `owner review needed`.

## Step 1 - Inventory repository-evidenced safeguards

Inspect evidence for:

- Asset and software inventory: SBOMs, package manifests, container images,
  deployment manifests, service ownership, and runtime components.
- Data protection: classification notes, secret management, encryption config,
  backup/recovery notes, and sensitive-data handling.
- Secure configuration: hardening baselines, Dockerfiles, IaC, deployment
  manifests, security headers, TLS config, and default settings.
- Access control: CODEOWNERS, branch protection, CI token permissions, service
  account scopes, environment approvals, and secret access.
- Vulnerability management: SCA/SAST/container scanning, CVE intake, patch SLA,
  suppression/exception process, and remediation evidence.
- Audit logs: application audit events, CI logs, deployment logs, agent run logs,
  MCP gateway logs, and retention notes.
- Malware and data recovery controls when visible from build or deployment
  config.
- Application software security: secure coding, tests, review gates, dependency
  integrity, and release provenance.
- Incident response: runbooks, escalation, pause/kill switches, rollback, and
  post-incident evidence.

For each evidence item, record file path and status.

## Step 2 - Mark what cannot be proven from the repo

List safeguards that usually require external evidence:

- Endpoint protection and EDR coverage.
- Network monitoring and DNS filtering.
- Cloud account configuration and centralized IAM.
- SIEM alerting and log retention.
- Physical assets, user awareness training, and enterprise policy evidence.

Do not guess. Mark these `out of repo`.

## Step 3 - Score gaps

For each gap:

- Control theme.
- Evidence status: observed, partial, missing, out of repo.
- Risk: high, medium, low.
- Implementation group dependency if known.
- Owner or system of record.
- Smallest next action.

## Step 4 - Write the report

Write `CIS_CONTROLS_SAFEGUARD_CHECK.md` at the repo root, or print to stdout
if write access is unavailable.

Use this structure:

```markdown
# CIS Controls safeguard implementation check - <repo>

Generated on <date>. CIS version: v8.1. Implementation group: <IG or unknown>.

## Evidence Sources Reviewed
- ...

## Safeguard Evidence Matrix
| Theme | Status | Evidence | Gap | System of record |
| ... |

## Findings
### <Risk> - <theme> - <short title>
- **Evidence:** ...
- **Gap:** ...
- **Why it matters:** ...
- **Next action:** ...

## Out-of-Repository Evidence Needed
- ...
```

## Stop conditions

Stop and write a partial report if:

- The operator asks for cloud, IAM, endpoint, or SIEM changes.
- Evidence requires privileged system access not already available.
- You find secrets, private keys, or regulated data.
~~~

## Output contract

- Evidence matrix and gap report.
- No cloud, endpoint, IAM, or code changes.
- No final CIS conformance claim.
- Clear `out of repo` marking for evidence that cannot be checked locally.

## Guardrails

- Repository evidence is not enterprise evidence. Do not imply EDR, SIEM, IAM,
  or asset-inventory controls pass because code config looks good.
- Prefer implementation evidence over policy statements.

## References

- [CIS Critical Security Controls v8.1](https://www.cisecurity.org/controls/v8-1)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)

