---
title: Agentic Entitlement Review Pack
linkTitle: Entitlement Review
weight: 16
sidebar:
  open: true
description: >
  A generated entitlement-review pack and deterministic evaluator for
  expiring, reviewable, revocable agent permissions across MCP scopes,
  A2A handoffs, action-runtime gates, and non-human identities.
---

{{< callout type="info" >}}
**What this is.** SecurityRecipes is positioned as **The Secure Context
Layer for Agentic AI**. This pack adds the access-lifecycle layer:
which agent identity has which MCP scope right now, when that authority
expires, who must review it, and what kills the session.
{{< /callout >}}

## The product bet

The next enterprise buyer question is not only "which agent can act?"
It is:

> Does this agent still have this permission right now?

The **Agentic Entitlement Review Pack** turns static non-human identity
contracts into expiring permission leases. It makes agent authorization
operational enough for IAM, AI platform, MCP gateway, SOC, GRC, and
procurement teams:

1. **Identity** - the registered agent identity and human owner.
2. **Scope** - the MCP namespace and access mode being requested.
3. **Lease** - the active permission grant, expiry, and lease id.
4. **Review** - current, due, overdue, or suspended access-review state.
5. **Authorization** - MCP authorization, audience, resource, and scope
   evidence.
6. **Receipt** - run, tenant, correlation, approval, and receipt fields
   needed to reconstruct the decision.

That is a high-value control surface. The open project can publish the
model; a production MCP server can sell hosted lease issuance,
continuous access review, step-up approval receipts, revocation
webhooks, and IdP/SIEM integrations.

## What was added

- `data/assurance/agentic-entitlement-review-profile.json` - source
  contract for entitlement tiers, review cadences, lease TTLs,
  standards alignment, buyer views, and commercialization path.
- `scripts/generate_agentic_entitlement_review_pack.py` - deterministic
  generator and `--check` validator.
- `scripts/evaluate_agentic_entitlement_decision.py` - deterministic
  allow, hold, deny, or kill evaluator.
- `data/evidence/agentic-entitlement-review-pack.json` - generated
  entitlement pack for MCP clients, CI drift checks, and buyer diligence.
- `recipes_agentic_entitlement_review_pack` - MCP lookup by entitlement,
  identity, workflow, namespace, risk tier, or access mode.
- `recipes_evaluate_agentic_entitlement_decision` - MCP runtime evaluator
  for one proposed agent entitlement use.

Run it from the repo root:

```bash
python3 scripts/generate_agentic_entitlement_review_pack.py
python3 scripts/generate_agentic_entitlement_review_pack.py --check
```

Evaluate an active scoped branch-write entitlement:

```bash
python3 scripts/evaluate_agentic_entitlement_decision.py \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --workflow-id vulnerable-dependency-remediation \
  --agent-class codex \
  --namespace repo.contents \
  --requested-access-mode write_branch \
  --lease-id lease-ci \
  --lease-status active \
  --lease-expires-at 2099-01-01T00:00:00Z \
  --review-status current \
  --authorization-decision allow_authorized_mcp_request \
  --run-id run-ci \
  --tenant-id tenant-ci \
  --correlation-id corr-ci \
  --receipt-id receipt-ci \
  --policy-pack-hash sha256:policy \
  --expect-decision allow_active_entitlement
```

Evaluate an expired lease:

```bash
python3 scripts/evaluate_agentic_entitlement_decision.py \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --workflow-id vulnerable-dependency-remediation \
  --agent-class codex \
  --namespace repo.contents \
  --requested-access-mode write_branch \
  --lease-id lease-expired \
  --lease-status expired \
  --lease-expires-at 2026-01-01T00:00:00Z \
  --review-status current \
  --authorization-decision allow_authorized_mcp_request \
  --run-id run-expired \
  --tenant-id tenant-ci \
  --correlation-id corr-expired \
  --receipt-id receipt-expired \
  --expect-decision deny_expired_or_missing_lease
```

## What is inside

| Section | Purpose |
| --- | --- |
| `entitlement_review_summary` | Entitlement count, workflow count, identity count, access-mode mix, risk-tier mix, approval-required count, and failure count. |
| `review_contract` | Default fail-closed state, required runtime fields, evidence sources, and allow / hold / deny / kill decision ladder. |
| `entitlements` | One lease-ready entitlement per identity, workflow, MCP namespace, and access mode. |
| `workflow_entitlement_rollups` | Per-workflow access summaries for quarterly reviews and platform intake. |
| `runtime_policy` | Lease status values, review status values, step-up triggers, and kill indicators. |
| `source_artifacts` | Hashes and paths for the identity, MCP authorization, connector, handoff, action runtime, telemetry, and receipt packs used to build the model. |

## MCP examples

Get the executive summary and workflow rollups:

```json
{}
```

Find entitlements for one workflow:

```json
{
  "workflow_id": "vulnerable-dependency-remediation"
}
```

Find entitlements for one identity:

```json
{
  "identity_id": "sr-agent::vulnerable-dependency-remediation::codex"
}
```

Evaluate one entitlement use:

```json
{
  "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
  "workflow_id": "vulnerable-dependency-remediation",
  "agent_class": "codex",
  "namespace": "repo.contents",
  "requested_access_mode": "write_branch",
  "lease_id": "lease-123",
  "lease_status": "active",
  "lease_expires_at": "2099-01-01T00:00:00Z",
  "review_status": "current",
  "authorization_decision": "allow_authorized_mcp_request",
  "run_id": "run-123",
  "tenant_id": "tenant-a",
  "correlation_id": "corr-123",
  "receipt_id": "receipt-123",
  "policy_pack_hash": "sha256:policy"
}
```

## Why it is acquisition-grade

Enterprise agent fleets will not scale on prompt text. They need
access lifecycle controls that look familiar to IAM and GRC teams but
are adapted for autonomous systems:

- agent permission leases,
- quarterly and event-driven access review,
- MCP scope and audience binding,
- step-up authorization for privileged scopes,
- A2A handoff and Agent Card trust evidence,
- action-runtime and catastrophic-risk linkage,
- revocation and kill-session decisions,
- run receipts and telemetry fields for audit.

That makes the project easier to buy, integrate, and diligence. It
also creates a natural paid surface: hosted entitlement review APIs
between agent hosts, IdPs, MCP gateways, approval systems, and SIEMs.

## Industry alignment

The pack is anchored in current primary guidance:

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for identity abuse, tool misuse, insecure inter-agent communication,
  cascading failures, and rogue-agent containment.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected resource metadata, resource indicators, token audience
  binding, PKCE, scope challenges, and token handling.
- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
  for Agent Card discovery, Agent Card signing, authentication,
  authorization, and extended Agent Card access control.
- [Microsoft Agent 365](https://www.microsoft.com/en-us/microsoft-agent-365)
  for the market move toward centralized agent registry, access control,
  observability, governance, security, analytics, and role-specific
  oversight.
- [OpenAI Safety in Building Agents](https://platform.openai.com/docs/guides/agent-builder-safety)
  for structured outputs, tool approvals, guardrails, trace grading, and
  eval evidence around agent workflows.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for governance, monitoring, measurement, incident response, and risk
  treatment.

## See also

- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Agentic Action Runtime Pack]({{< relref "/security-remediation/agentic-action-runtime" >}})
- [A2A Agent Card Trust]({{< relref "/security-remediation/a2a-agent-card-trust" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
