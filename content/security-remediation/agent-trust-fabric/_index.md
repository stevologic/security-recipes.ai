---
title: Agent Trust Fabric
linkTitle: Agent Trust Fabric
weight: 16
sidebar:
  open: true
description: >
  A generated zero-trust decision fabric for agent identity, context,
  scope, behavior, egress, telemetry, and containment evidence.
---

{{< callout type="info" >}}
**What this is.** SecurityRecipes is positioned as **The Secure Context
Layer for Agentic AI**. The Agent Trust Fabric is the single runtime
verdict that tells an agent host, MCP gateway, SOC workflow, or buyer:
this agent run is trusted, needs step-up, is untrusted, or must be
killed.
{{< /callout >}}

## The product bet

Enterprise buyers do not want a pile of agent safety checklists. They
want one answer before an agent touches tools or private context:

> Can we trust this agent, for this workflow, in this tenant, right now?

The **Agent Trust Fabric** composes six dimensions into that answer:

1. **Identity** - who the agent is, which delegated identity it is using,
   and whether that identity still has valid scope.
2. **Context** - what the agent is consuming, whether the context is
   fresh, and whether poisoning signals were found.
3. **Scope** - where the agent can go and which action class is being
   attempted.
4. **Behavior** - what the agent is doing in real time and whether
   telemetry can reconstruct the run.
5. **Data boundary** - what the agent is sending or serving outside the
   trust boundary.
6. **Containment** - whether kill switches, SOC detections, and hosted
   MCP controls can stop the run when prevention fails.

That is the acquisition-grade wedge: open knowledge creates adoption;
the production MCP server becomes the control point that signs trust
verdicts for customer-private agent runs.

## What was added

- `data/assurance/agent-trust-fabric-profile.json` - source contract for
  trust dimensions, tiers, runtime fields, source references, and
  commercialization path.
- `scripts/generate_agent_trust_fabric_pack.py` - deterministic generator
  and `--check` validator.
- `scripts/evaluate_agent_trust_fabric_decision.py` - deterministic
  allow, hold, deny, or kill evaluator.
- `data/evidence/agent-trust-fabric-pack.json` - generated MCP-readable
  trust fabric evidence.
- `recipes_agent_trust_fabric_pack` - MCP lookup by dimension, workflow,
  trust tier, or status.
- `recipes_evaluate_agent_trust_fabric_decision` - MCP runtime evaluator
  for one proposed agent run.

Run it from the repo root:

```bash
python3 scripts/generate_agent_trust_fabric_pack.py
python3 scripts/generate_agent_trust_fabric_pack.py --check
```

Evaluate a trusted scoped run:

```bash
python3 scripts/evaluate_agent_trust_fabric_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --run-id run-trust \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --tenant-id tenant-demo \
  --correlation-id corr-trust \
  --trust-event-id trust-evt-1 \
  --requested-trust-tier operator \
  --intent-summary "Patch dependency lockfiles on a scoped remediation branch" \
  --context-package-hash sha256:context \
  --policy-pack-hash sha256:policy \
  --authorization-decision allow_authorized_mcp_request \
  --egress-decision allow_internal_context \
  --action-runtime-decision allow_bounded_action \
  --telemetry-decision telemetry_ready \
  --soc-decision no_alert \
  --telemetry-event-id trace-1 \
  --receipt-id receipt-1 \
  --source-freshness-decision current \
  --approval-id approval-1 \
  --approval-status approved \
  --expect-decision allow_trusted_agent_context
```

Evaluate a trust break:

```bash
python3 scripts/evaluate_agent_trust_fabric_decision.py \
  --workflow-id sensitive-data-remediation \
  --run-id run-kill \
  --agent-id sr-agent::sensitive-data-remediation::codex \
  --identity-id sr-agent::sensitive-data-remediation::codex \
  --tenant-id tenant-demo \
  --correlation-id corr-kill \
  --trust-event-id trust-evt-2 \
  --requested-trust-tier operator \
  --intent-summary "Investigate a possible token in logs" \
  --context-package-hash sha256:context \
  --policy-pack-hash sha256:policy \
  --authorization-decision allow_authorized_mcp_request \
  --egress-decision hold_for_redaction_or_dpa \
  --telemetry-decision telemetry_ready \
  --telemetry-event-id trace-2 \
  --receipt-id receipt-2 \
  --source-freshness-decision current \
  --token-passthrough \
  --expect-decision kill_session_on_agent_trust_break
```

## What is inside

| Section | Purpose |
| --- | --- |
| `trust_fabric_summary` | Dimension count, workflow count, trust-tier distribution, source pack count, and failure count. |
| `trust_contract` | Default fail-closed state, required runtime fields, score thresholds, evidence sources, and kill signals. |
| `trust_dimensions` | The identity, context, scope, behavior, data-boundary, and containment checks, with MCP tools and evidence paths. |
| `trust_tiers` | Intern, Apprentice, Operator, and Principal tiers with score gates and allowed actions. |
| `workflow_trust_matrix` | Generated default trust tier and risk flags for every active workflow. |
| `tabletop_cases` | Ready-made allow, hold, deny, and kill cases for platform testing. |
| `source_artifacts` | Hashes and paths for each evidence pack used to build the trust fabric. |

## MCP examples

Get the executive summary and trust matrix:

```json
{}
```

Inspect one dimension:

```json
{
  "dimension_id": "identity"
}
```

Inspect a workflow:

```json
{
  "workflow_id": "vulnerable-dependency-remediation"
}
```

Find workflows that default to Operator:

```json
{
  "trust_tier": "operator"
}
```

Evaluate one agent trust request:

```json
{
  "workflow_id": "vulnerable-dependency-remediation",
  "run_id": "run-123",
  "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
  "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
  "tenant_id": "tenant-a",
  "correlation_id": "corr-123",
  "trust_event_id": "trust-123",
  "requested_trust_tier": "operator",
  "intent_summary": "Patch dependency lockfiles on a scoped remediation branch.",
  "context_package_hash": "sha256:context",
  "policy_pack_hash": "sha256:policy",
  "authorization_decision": "allow_authorized_mcp_request",
  "egress_decision": "allow_internal_context",
  "action_runtime_decision": "allow_bounded_action",
  "telemetry_decision": "telemetry_ready",
  "soc_decision": "no_alert",
  "telemetry_event_id": "trace-123",
  "receipt_id": "receipt-123",
  "source_freshness_decision": "current",
  "human_approval_record": {
    "approval_id": "approval-123",
    "status": "approved"
  }
}
```

## Why it is acquisition-grade

The trust fabric makes the site easier to understand and easier to sell.
It creates one cross-vendor primitive that xAI, Anthropic, OpenAI, an AI
platform vendor, or a security vendor could attach to agent hosts, MCP
gateways, customer telemetry, and trust-center exports:

- hosted trust scoring APIs,
- signed agent trust verdicts,
- customer policy adapters,
- SOC/SIEM export,
- procurement evidence export,
- runtime step-up and kill decisions,
- trust-center proof for design partners,
- a direct bridge from open knowledge to production MCP enforcement.

## Industry alignment

The pack is anchored in current primary guidance:

- [CSA ATF: Zero Trust for AI Agents](https://cloudsecurityalliance.org/blog/2026/04/03/every-rsac-keynote-asked-the-same-five-questions-here-s-the-framework-that-answers-them)
  for identity, behavior, data governance, least privilege, and
  containment.
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  for trusted, interoperable, secure agent standards.
- [NIST CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for indirect prompt injection, poisoning, misaligned actions, and
  constrained deployment access.
- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected-resource metadata, scope challenges, resource indicators,
  token audience validation, and token-passthrough denial.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
  for token exposure, scope creep, tool poisoning, command execution,
  insufficient auth, shadow MCP servers, and over-sharing.
- [OpenAI Agents SDK Guardrails](https://openai.github.io/openai-agents-js/guides/guardrails/)
  for guardrail placement around first input, final output, and
  function-tool calls.
- [OpenTelemetry GenAI agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/)
  for portable agent and tool execution traces.

## See also

- [Agentic Action Runtime Pack]({{< relref "/security-remediation/agentic-action-runtime" >}})
- [Agentic SOC Detection Pack]({{< relref "/security-remediation/agentic-soc-detection-pack" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Agentic Source Freshness Watch]({{< relref "/security-remediation/agentic-source-freshness-watch" >}})
- [Hosted MCP Readiness Pack]({{< relref "/security-remediation/hosted-mcp-readiness-pack" >}})
- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
