---
title: Agent Handoff Boundary
linkTitle: Agent Handoff Boundary
weight: 12
sidebar:
  open: true
description: >
  Generated protocol trust evidence and runtime decisions for MCP,
  A2A, provider-native subagents, and human approval bridges before
  context crosses an agent boundary.
---

{{< callout type="info" >}}
**What this is.** Agent handoffs are egress events, not chat messages.
This pack makes the boundary explicit: what may cross, which protocol is
allowed, which data classes trigger redaction or approval, and which
payload fields terminate the session.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. That claim has to hold when one agent delegates to another agent,
not only when a single agent retrieves context through MCP.

The **Agent Handoff Boundary Pack** is the protocol trust layer between
secure context retrieval and multi-agent execution. It gives platform
teams a machine-readable contract for MCP tool calls, A2A task
delegations, provider-native subagents, and human approval bridges.

## What was added

- `data/assurance/agent-handoff-boundary-model.json` - source model for
  protocols, profiles, payload fields, data classes, and decisions.
- `scripts/generate_agent_handoff_boundary_pack.py` - deterministic
  generator and `--check` validator.
- `scripts/evaluate_agent_handoff_boundary_decision.py` - runtime
  evaluator for one proposed handoff.
- `data/evidence/agent-handoff-boundary-pack.json` - generated evidence
  pack for CI, MCP, platform review, and diligence.
- MCP tools:
  `recipes_agent_handoff_boundary_pack` and
  `recipes_evaluate_agent_handoff_decision`.

Regenerate and validate:

```bash
python3 scripts/generate_agent_handoff_boundary_pack.py
python3 scripts/generate_agent_handoff_boundary_pack.py --check
```

Evaluate a metadata-only A2A handoff:

```bash
python3 scripts/evaluate_agent_handoff_boundary_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --handoff-profile-id metadata-only \
  --protocol a2a_task_delegation \
  --target-trust-tier approved_vendor \
  --agent-card-signed \
  --authentication-scheme oauth2 \
  --payload-field task_summary \
  --payload-field workflow_id \
  --payload-field source_ids \
  --payload-field source_hashes \
  --payload-field correlation_id \
  --data-class curated_security_guidance \
  --expect-decision allow_metadata_handoff
```

## Handoff profiles

| Profile | Default decision | Use when |
| --- | --- | --- |
| `metadata-only` | `allow_metadata_handoff` | A remote agent needs a task summary, workflow ID, source IDs, source hashes, and correlation ID only. |
| `cited-evidence` | `allow_cited_evidence_handoff` | A delegated agent needs redacted evidence plus source hashes and egress decision state. |
| `approval-gated` | `allow_approved_handoff` | The target agent receives high-impact task context after explicit approval and scoped authority. |
| `prohibited-context` | `kill_session_on_secret_handoff` | Credential material, internal memory, hidden prompts, raw tool traces, or unrestricted customer data appear. |

## Why it is acquisition-grade

MCP and A2A are becoming the enterprise interoperability substrate for
agentic systems. A buyer or acquirer will ask whether SecurityRecipes can
govern that substrate, not just document it.

This pack answers concrete diligence questions:

- Can handoffs fail closed by default?
- Can a remote agent receive only the minimum context required?
- Can MCP and A2A controls be represented in the same decision model?
- Can high-impact delegated work require explicit approval?
- Can the product kill sessions when hidden prompts, memory, raw traces,
  credentials, or signing material are about to cross a boundary?

The commercial path is hosted handoff enforcement, signed Agent Card
trust, agent-to-agent replay, tenant evidence ingestion, approval
receipts, and trust-center exports.

## Industry alignment

This layer is anchored in current primary guidance:

- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  for interoperable agent protocols, agent identity, authentication, and
  security evaluations.
- [CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for constraining and monitoring agent access in deployment
  environments.
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, token audience validation, PKCE, protected
  resource metadata, Client ID Metadata Documents, and token-passthrough
  denial.
- [A2A Enterprise Implementation](https://a2a-protocol.org/latest/topics/enterprise-ready/)
  for TLS, HTTP-layer authentication, skill-based authorization, data
  minimization, tracing, auditing, and API management.
- [Linux Foundation A2A production milestone](https://www.linuxfoundation.org/press/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year)
  for signed Agent Cards, stable production adoption, cloud integration,
  and the MCP/A2A split between tool access and agent coordination.

## MCP examples

List handoff profiles:

```json
{}
```

Inspect one workflow map:

```json
{
  "workflow_id": "vulnerable-dependency-remediation"
}
```

Evaluate an approval-gated handoff:

```json
{
  "workflow_id": "artifact-cache-quarantine",
  "handoff_profile_id": "approval-gated",
  "protocol": "a2a_task_delegation",
  "target_trust_tier": "approved_vendor",
  "agent_card_signed": true,
  "authentication_schemes": ["oauth2"],
  "payload_fields": [
    "task_summary",
    "workflow_id",
    "source_ids",
    "source_hashes",
    "approval_record_id",
    "delegated_authority",
    "correlation_id"
  ],
  "data_classes": ["customer_ticket_summary", "approval_record"],
  "requested_capabilities": ["ticket_write"],
  "human_approval_record": {
    "approval_id": "approval-123",
    "status": "approved"
  }
}
```

## See also

- [Secure Context Evals]({{< relref "/security-remediation/secure-context-evals" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
- [A2A Agent Card Trust]({{< relref "/security-remediation/a2a-agent-card-trust" >}})
- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
