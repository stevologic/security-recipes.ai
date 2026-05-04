---
title: Agentic Incident Response Pack
linkTitle: Incident Response Pack
weight: 14
sidebar:
  open: true
description: >
  A generated incident response, containment, forensics, replay, and
  disclosure pack for secure-context and MCP-backed agentic AI failures.
---

{{< callout type="info" >}}
**What this is.** SecurityRecipes should not stop at prevention. This
pack gives an enterprise team a deterministic way to classify an
agentic incident, correlate run receipts and context hashes, contain MCP
authority, preserve evidence, replay the failure, and produce a
trust-center-ready readout.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **The Secure Context Layer for
Agentic AI**. A credible secure context layer must answer two questions:

- Can the platform prevent unsafe context, authority, and tool use
  before an agent acts?
- When prevention fails, can the platform prove what happened, contain
  authority, and replay the failure before the workflow scales again?

The **Agentic Incident Response Pack** fills that second gap. It turns
the generated control-plane evidence into a response model for
context-poisoning, MCP tool misuse, authorization confused-deputy
events, token passthrough, agent handoff leakage, memory or skill
compromise, high-impact autonomy near misses, and receipt integrity
gaps.

This makes AI easier for enterprises because SOC, AI platform, security
engineering, GRC, and procurement teams can inspect one machine-readable
artifact instead of reverse-engineering a failure from chat transcripts.

## What was added

- `data/assurance/agentic-incident-response-profile.json` - source
  contract for incident classes, response phases, required evidence,
  severity thresholds, standards alignment, and commercial packaging.
- `scripts/generate_agentic_incident_response_pack.py` - deterministic
  generator and `--check` validator.
- `scripts/evaluate_agentic_incident_response_decision.py` -
  deterministic monitor, triage, hold, contain, or kill evaluator.
- `data/evidence/agentic-incident-response-pack.json` - generated
  incident response pack for MCP clients, CI drift checks, and buyer
  diligence.
- `recipes_agentic_incident_response_pack` - MCP lookup by incident
  class, workflow, severity, or response decision.
- `recipes_evaluate_agentic_incident_response_decision` - MCP runtime
  evaluator for one incident signal.

Run it from the repo root:

```bash
python3 scripts/generate_agentic_incident_response_pack.py
python3 scripts/generate_agentic_incident_response_pack.py --check
```

Evaluate a token passthrough incident:

```bash
python3 scripts/evaluate_agentic_incident_response_decision.py \
  --incident-id inc-ci-token \
  --workflow-id vulnerable-dependency-remediation \
  --run-id run-ci-token \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --tenant-id tenant-demo \
  --correlation-id corr-ci-token \
  --incident-class-id mcp-authorization-confused-deputy \
  --severity-signal sev1 \
  --source-event-id event-authz-1 \
  --receipt-id receipt-ci-token \
  --context-source-id workflow-manifest \
  --context-source-hash hash-ci \
  --mcp-namespace repo.contents \
  --authorization-decision allow_authorized_mcp_request \
  --containment-action-id freeze_mcp_namespace_or_scope \
  --indicator raw_token_passthrough \
  --token-passthrough \
  --expect-decision kill_session_and_escalate_board
```

## What is inside

| Section | Purpose |
| --- | --- |
| `incident_response_summary` | Class counts, response phase counts, workflow coverage, decision distribution, severe incident coverage, required evidence count, and source failure count. |
| `incident_contract` | Default fail-closed state, required runtime fields, required evidence sources, and severity thresholds for SEV0 through SEV3. |
| `incident_classes` | Response models for context poisoning, MCP tool misuse, identity abuse, token passthrough, handoff leakage, memory or skill compromise, high-impact autonomy, and evidence gaps. |
| `response_phases` | Detect, contain, preserve, eradicate, replay, recertify, disclose, and learn phases mapped to minimum evidence and MCP tools. |
| `workflow_response_matrix` | Per-workflow incident classes, severity floor, containment actions, readiness state, risk tier, MCP namespaces, and replay requirements. |
| `tabletop_cases` | Ready-made tabletop cases for poisoned context, token forwarding, production writes without approval, and missing receipts after drift. |
| `source_artifacts` | Hashes and paths for the source evidence packs used to build the incident response model. |

## MCP examples

Get the executive summary and workflow matrix:

```json
{}
```

Inspect a specific incident class:

```json
{
  "incident_class_id": "mcp-authorization-confused-deputy"
}
```

Inspect incident response coverage for a workflow:

```json
{
  "workflow_id": "artifact-cache-quarantine"
}
```

Find SEV0-class response surfaces:

```json
{
  "severity": "sev0"
}
```

Evaluate one runtime incident signal:

```json
{
  "incident_id": "inc-2026-ctx-001",
  "workflow_id": "sensitive-data-remediation",
  "run_id": "run-ctx-001",
  "agent_id": "sr-agent::sensitive-data-remediation::codex",
  "identity_id": "sr-agent::sensitive-data-remediation::codex",
  "tenant_id": "tenant-a",
  "correlation_id": "corr-ctx-001",
  "incident_class_id": "context-poisoning",
  "severity_signal": "sev1",
  "source_event_ids": ["poisoning-finding-1"],
  "receipt_id": "receipt-ctx-001",
  "context_source_hashes": ["sha256:example"],
  "mcp_namespaces": ["findings.sde", "repo.contents"],
  "authorization_decisions": ["allow_authorized_mcp_request"],
  "containment_action_ids": ["hold_context_source_promotion"],
  "indicators": ["critical_poisoning_finding"]
}
```

## Why it is acquisition-grade

The prevention layer creates trust. The incident layer creates
enterprise confidence.

For a $10-20M outcome, the product cannot be only a documentation site
or prompt library. It needs a control-plane story that an acquirer can
turn into hosted software. Agentic incident response is a natural paid
surface:

- hosted run-receipt vault,
- SIEM and SOAR exports,
- signed incident evidence bundles,
- MCP kill-switch automation,
- customer trust-center incident readouts,
- continuous replay of incident-derived eval cases,
- workflow recertification gates after context, connector, model, or
  policy drift.

That is a credible commercial layer around the open knowledge base:
public guidance creates distribution, generated evidence creates trust,
and hosted response automation creates enterprise value.

## Industry alignment

The pack is anchored in current primary guidance:

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
  for incident response integrated with CSF 2.0 risk management.
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  for agent identity, open protocols, secure multi-agent interactions,
  and security evaluations.
- [CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for prompt injection, data poisoning, misaligned action, measurement,
  and deployment interventions that constrain and monitor agent access.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for operational risks in agents that plan, act, make decisions, and
  execute across complex workflows.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected resource metadata, OAuth 2.1, audience binding, token
  handling, confused-deputy prevention, and scope restriction.
- [CISA Joint Guidance on Deploying AI Systems Securely](https://www.cisa.gov/news-events/alerts/2024/04/15/joint-guidance-deploying-ai-systems-securely)
  for controls to protect, detect, and respond to malicious activity
  against AI systems and related data and services.

## See also

- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Agentic Catastrophic Risk Annex]({{< relref "/security-remediation/agentic-catastrophic-risk-annex" >}})
- [Agentic Exposure Graph]({{< relref "/security-remediation/agentic-exposure-graph" >}})
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Agent Handoff Boundary]({{< relref "/security-remediation/agent-handoff-boundary" >}})
