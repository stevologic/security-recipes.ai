---
title: "PCI DSS CDE and agent boundary check"
linkTitle: "PCI DSS CDE boundary"
description: "Read-only recipe for checking whether agents, CI, logs, and repositories cross cardholder-data environment boundaries."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["compliance", "pci-dss", "cde", "cardholder-data", "agent-boundary", "audit"]
weight: 30
date: 2026-06-25
severity: "high"
---

A bounded PCI DSS boundary check for repositories and agentic remediation
workflows. It focuses on whether code, CI, logs, scanners, model providers, or
MCP tools can touch cardholder data environment (CDE) assets or account data.

## When to use it

- Before enabling coding agents on repositories that might touch payment flows.
- When a service is newly marked CDE-adjacent.
- During PCI DSS evidence collection for change management, access control, or
  logging requirements.

## Inputs

- Repository path and payment-related service name.
- Known CDE scope statement if available.
- Payment routes, tokenization provider, vault, gateway, or PSP hints.
- CI, scanner, agent, and model-provider configuration.

## The prompt

~~~markdown
You are running a PCI DSS CDE and agent boundary check. Run read-only. Do not
edit code, run payment transactions, call production systems, rotate secrets,
change access, or claim PCI DSS compliance.

## Step 0 - Scope statement

Record:

- Repository and service name.
- Whether the operator supplied a CDE scope statement.
- Payment functions found in the repo: collection, processing, transmission,
  storage, tokenization, vaulting, reconciliation, dispute handling, or reporting.
- Third-party payment providers, gateways, PSP SDKs, token vaults, or webhooks.
- Agent, CI, scanner, MCP, model-provider, and log sinks that can read this repo.

If no CDE scope is available, treat the report as a boundary-discovery packet.

## Step 1 - Search for account-data and payment surfaces

Search source, config, docs, tests, fixtures, and logs for:

- PAN, cardholder data, sensitive authentication data, track data, CVV/CVC, PIN,
  expiry, cardholder name, payment token, network token, and gateway customer
  identifiers.
- Payment SDKs, hosted fields, redirect flows, webhooks, reconciliation jobs,
  chargeback flows, and admin payment tools.
- Database columns, log fields, analytics events, and data exports that may
  carry account data or tokens.

Do not print full card numbers, tokens, or customer data. Redact values and
reference only file paths and field names.

## Step 2 - Check agent and CI access paths

For each agent, CI workflow, scanner, MCP server, or model-provider integration,
record:

- What repository data it can read.
- Whether it can reach payment config, logs, fixtures, secrets, or production
  credentials.
- Whether it has write permissions, deployment permissions, secret access, or
  ticket/PR creation permissions.
- Whether access is scoped per run and logged.
- Whether human review is required before merge, deploy, or data access.

Flag any path that can expose account data or CDE secrets to a model provider,
third-party SaaS, broad CI job, or unapproved MCP connector.

## Step 3 - Check PCI-relevant evidence

Collect repository evidence for:

- Change review and testing before production release.
- Least-privilege access to payment code and secrets.
- Logging and monitoring around payment-sensitive actions.
- Secret management and masking.
- Vulnerability scanning, dependency review, and patch flow.
- Segmentation or boundary documentation between CDE, connected-to-CDE, and
  non-CDE systems.

Mark each item `observed`, `partial`, `missing`, or `out of repo`.

## Step 4 - Score boundary findings

Assign severity:

- `critical`: live account data or CDE secrets are exposed to unauthorized
  systems or logs.
- `high`: an agent/CI path can access CDE-sensitive code or credentials without
  scoped approval and logging.
- `medium`: evidence exists but is incomplete, inconsistent, or missing an
  owner.
- `low`: documentation or metadata cleanup.

## Step 5 - Write the report

Write `PCI_DSS_CDE_AGENT_BOUNDARY_CHECK.md` at the repo root, or print to
stdout if write access is unavailable.

Use this structure:

```markdown
# PCI DSS CDE and agent boundary check - <repo>

Generated on <date>. Scope note: <scope note>.

## Payment Surface Inventory
- ...

## Agent and CI Access Matrix
| Actor | Read scope | Write scope | Secret/data access | Logging | Status |
| ... |

## PCI-Relevant Evidence
| Evidence area | Status | Evidence | Gap |
| ... |

## Findings
### <Severity> - <short title>
- **Path:** ...
- **Boundary:** ...
- **Why it matters:** ...
- **Recommended next action:** ...
- **Verification:** ...

## Data Redactions
- Values were redacted from: ...

## Out-of-Scope Evidence Needed
- ...
```

## Stop conditions

Stop immediately and write an incident-style top finding if you find:

- unmasked PAN, CVV/CVC, track data, PIN data, or live payment credentials in
  source, logs, tests, or generated artifacts;
- a workflow that sends account data to an unapproved model/provider/tool;
- instructions requiring a live payment or production query.
~~~

## Output contract

- Boundary-discovery and evidence report only.
- No live payment actions.
- No unredacted account data in output.
- No final PCI DSS compliance claim.

## Verification

Before handing the report to a PCI or payment-platform owner, verify that:

- every payment surface, agent, CI workflow, MCP server, and model-provider
  path has a repository path, configuration reference, or `out of scope`
  marker;
- PAN, CVV/CVC, track data, PIN data, payment credentials, gateway tokens, and
  customer IDs are redacted in all examples;
- ambiguous payment-adjacent paths are marked `CDE-adjacent` rather than
  excluded without owner review;
- each finding states whether it affects data, secrets, logging, build access,
  deployment access, or review/approval evidence;
- no validation step required a live payment, production query, credential
  test, or external model upload.

## Guardrails

- Treat payment tokens and gateway customer IDs as sensitive even when they are
  not PAN.
- Default to "CDE-adjacent" when evidence is ambiguous.
- Require human compliance-owner review before changing CDE scope.

## Related recipes

- [Source code audit - secrets and data exposure]({{< relref "/prompt-library/general/source-code-secrets-data-exposure-audit" >}})
- [Source code audit - auth and tenant boundaries]({{< relref "/prompt-library/general/source-code-authz-tenant-boundary-audit" >}})
- [SOC 2 change-management evidence check]({{< relref "/prompt-library/general/compliance-standards/soc2-change-management-evidence-check" >}})
- [Context egress boundary]({{< relref "/security-remediation/context-egress-boundary" >}})

## References

- [PCI DSS overview](https://www.pcisecuritystandards.org/standards/pci-dss/)
- [PCI Security Standards Council document library](https://www.pcisecuritystandards.org/document_library/)
- [Security Remediation - Compliance & Audit]({{< relref "/security-remediation/compliance" >}})
