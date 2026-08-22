---
title: Evidence Bundles
linkTitle: Evidence Bundles
weight: 14
date: 2026-07-10
lastmod: 2026-08-21
sidebar:
  open: true
description: >
  Package agentic remediation receipts, source evidence, approvals, tests, and
  rollback records into audit-ready exports for security and GRC review.
---

{{< callout type="info" >}}
**Why this page exists.** Agentic remediation does not become
enterprise-ready when the agent opens a PR. It becomes
enterprise-ready when a security leader can prove what the agent
saw, what it did, who reviewed it, and why the workflow was
allowed to run.
{{< /callout >}}

This is the operational export companion to
[Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}}).
Receipts define the per-run proof contract; bundles normalize and package those
receipts for an audit period or workflow cohort. Rechecked August
21, 2026: a bundle that cites leftover draft version text is not
ready for export.

## The product idea

SecurityRecipes should be more than a cookbook. The durable
enterprise value is the **evidence layer** around agentic security:
structured proof that every remediation run was scoped, policy
checked, verified, and reviewed. That is the piece a buyer,
auditor, model provider, or GRC platform cannot reconstruct from
prompts alone.

An evidence bundle is the portable record for one audit period or
one workflow cohort. It gives teams a single artifact they can
attach to SOC 2, ISO 27001, PCI DSS, NIST SSDF, FedRAMP, or
internal AI governance reviews.

{{< playbook-workflow >}}

## What belongs in a bundle

The minimum viable bundle includes:

- **Normalized event stream.** One ordered record per intake,
  dispatch, tool call, verification, PR, review, stop, or close
  event.
- **Run manifest.** One row per agent run with workflow, finding
  IDs, repositories, outcome, reviewer, PR links, tools called,
  and chain hash.
- **Control gap report.** Runs missing terminal, verification, or
  review events are called out explicitly.
- **Hashes.** Source and normalized event hashes so the bundle can
  be archived and later checked for tampering.
- **Human-readable report.** A Markdown summary that GRC and
  security leadership can read without querying a warehouse.

## Event schema

Start boring. Every event should carry these required fields after
normalization:

| Field | Purpose |
| --- | --- |
| `run_id` | Correlates the full chain of custody for one agent attempt. |
| `workflow_id` | Owns the run under one workflow, for example `vulnerable-dependencies`. Legacy `workflow` is accepted as an alias. |
| `timestamp` | UTC timestamp, ISO 8601 preferred. |
| `event_class` | Canonical receipt class such as `human_approval`, `verifier_result`, or `run_closed`. Legacy `event_type` is accepted as an alias. |

Every event in one run must use the same workflow identifier; missing or mixed
workflow ownership is rejected instead of producing an ambiguous audit record.
If `timestamp` is omitted, the generator derives it from an event-specific field
such as `issued_at`, `approved_at`, `completed_at`, `closed_at`, or `revoked_at`
and normalizes it to UTC.

Strongly recommended fields:

| Field | Purpose |
| --- | --- |
| `finding_id` | Scanner, ticket, advisory, or case identifier. |
| `repository` | Repository affected by the run. |
| `actor` | Human, agent, gateway, or system principal that emitted the event. |
| `tool` | MCP or local tool name for tool-call events. |
| `pr_url` | Pull request opened or reviewed by the workflow. |
| `decision` | Reviewer or policy decision when applicable. |

The schema intentionally accepts additional keys. Enterprise teams
will add tenant ID, environment, data classification, model,
prompt version, MCP gateway policy version, ticket URL, and cost
fields as their program matures.

The current Agentic Run Receipt vocabulary includes `identity_issued`,
`context_retrieval_decision`, `context_poisoning_scan`, `mcp_tool_decision`,
`context_egress_decision`, `human_approval`, `verifier_result`,
`evidence_attached`, `run_closed`, and `identity_revoked`.

## Generate a starter bundle

This repository includes a local generator:

```bash
python scripts/generate_agent_evidence_bundle.py \
  --events audit-events.jsonl \
  --output-dir evidence/2026-05 \
  --program agentic-security-remediation \
  --period 2026-05
```

The input may be JSON Lines or a JSON array. The output directory
contains:

- `events.normalized.json`
- `manifest.json`
- `evidence-report.md`

Those three files are one transactionally published bundle. Regeneration
replaces the prior owned bundle as a unit, removes files that no longer belong,
rolls back if publication fails, and recovers stale staging or backup directories
without touching unrelated sibling paths.

The generator is intentionally not tied to one vendor. Feed it
GitHub webhooks, orchestrator events, MCP gateway logs, CI status
events, and scanner lifecycle events after normalizing them into
the schema above.

## Enterprise control mapping

Evidence bundles turn the abstract controls in
[Compliance & Audit]({{< relref "/security-remediation/compliance" >}})
into a repeatable operating artifact.

| Control need | Bundle evidence |
| --- | --- |
| Change management | Finding ID, PR URL, diff link, reviewer decision, timestamps. |
| Separation of duties | Agent actor vs. reviewer actor, plus branch protection evidence. |
| Logged access | Tool-call events from the MCP gateway with run ID attribution. |
| Verification | Test, scanner rerun, and policy-check events before review. |
| AI governance | Model, prompt version, tool policy version, and data classification fields. |

## Acquisition-grade direction

The forward-looking product surface is a premium MCP feature:
`evidence.generate_bundle`. An agent, GRC system, or security
orchestrator requests a bundle for a workflow and period; the MCP
server returns a signed manifest, summary report, and deep links
to retained logs.

That feature is valuable because it makes AI adoption easy for
enterprises without hiding the control surface:

- Security teams get a clean chain of custody per finding.
- GRC teams get exportable evidence without learning the agent
  stack.
- Platform teams get a stable schema for gateway, CI, and ticket
  events.
- Model and agent vendors get a credible enterprise control story
  for autonomous remediation.

## Operating rules

- **Generate bundles on a schedule.** Monthly for active
  workflows; quarterly for audit archive.
- **Fail closed on missing events.** A merged PR with no
  verification event is a control gap, not a reporting nuance.
- **Keep raw logs elsewhere.** The bundle is an index and summary;
  retention systems still hold full gateway, CI, and repository
  logs.
- **Version the schema.** Add fields freely, but never silently
  change the meaning of an existing field.
- **Treat the bundle as evidence.** Store it with write-once or
  immutable-retention settings where your compliance program
  requires it.

## See also

- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}}) - the per-run evidence contract that bundles package
- [Agentic Approval Receipt Pack]({{< relref "/security-remediation/agentic-approval-receipts" >}}) - signed approval and denial evidence across gated actions
- [Secure Context Evidence Contract]({{< relref "/security-remediation/secure-context-evidence-contract" >}}) - the portable contract for source lineage, policy, and validation evidence
- [Compliance & Audit]({{< relref "/security-remediation/compliance" >}}) - control mapping and auditor questions
- [Program Metrics & KPIs]({{< relref "/security-remediation/metrics" >}}) - operational measurements that complement evidence bundles
- [MCP Server Access]({{< relref "/mcp-servers" >}}) - where tool-call logs and policy events originate
