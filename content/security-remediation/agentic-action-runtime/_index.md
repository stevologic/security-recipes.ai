---
title: Agentic Action Runtime Pack
linkTitle: Action Runtime Pack
weight: 15
sidebar:
  open: true
description: >
  A generated action-runtime pack and deterministic evaluator for allow,
  hold, deny, or kill decisions before MCP-backed agents execute side
  effects.
---

{{< callout type="info" >}}
**What this is.** SecurityRecipes is positioned as **The Secure Context
Layer for Agentic AI**. This pack turns that context into a runtime
action gate: before an agent writes a branch, changes scope, delegates
to another agent, writes memory, installs a skill, deploys to
production, or touches irreversible systems, the host can ask for a
deterministic allow, hold, deny, or kill decision.
{{< /callout >}}

## The product bet

The next buyer question is not "do you have agent security docs?" It is:

> Can you stop an autonomous action before it becomes an incident?

The **Agentic Action Runtime Pack** is the answer. It binds six pieces of
evidence before action:

1. **Context** - the source package and trust state the agent used.
2. **Policy** - the workflow, MCP gateway, authorization, egress,
   handoff, memory, and skill boundaries.
3. **Intent** - the declared action class and purpose for this run.
4. **Behavior** - runtime indicators, telemetry, changed paths, data
   classes, and high-impact flags.
5. **Identity** - the delegated non-human identity and owner.
6. **Receipt** - the run receipt, approval, risk acceptance, and
   correlation id needed to reconstruct the decision.

That is the commercial control point. The open site creates trust and
distribution; the production MCP server can become the hosted action
firewall that enterprises put in front of agent hosts.

## What was added

- `data/assurance/agentic-action-runtime-profile.json` - source contract
  for action classes, required evidence, standards alignment, runtime
  policy, and commercialization path.
- `scripts/generate_agentic_action_runtime_pack.py` - deterministic
  generator and `--check` validator.
- `scripts/evaluate_agentic_action_runtime_decision.py` - deterministic
  allow, hold, deny, or kill evaluator.
- `data/evidence/agentic-action-runtime-pack.json` - generated action
  runtime pack for MCP clients, CI drift checks, and buyer diligence.
- `recipes_agentic_action_runtime_pack` - MCP lookup by action class,
  workflow, risk tier, or decision.
- `recipes_evaluate_agentic_action_runtime_decision` - MCP runtime
  evaluator for one proposed autonomous action.

Run it from the repo root:

```bash
python3 scripts/generate_agentic_action_runtime_pack.py
python3 scripts/generate_agentic_action_runtime_pack.py --check
```

Evaluate a bounded repository write:

```bash
python3 scripts/evaluate_agentic_action_runtime_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --action-class repo_branch_write \
  --run-id run-branch \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --tenant-id tenant-demo \
  --correlation-id corr-branch \
  --intent-summary "Patch dependency lockfiles on a scoped remediation branch" \
  --policy-pack-hash sha256:policy \
  --authorization-decision allow_authorized_mcp_request \
  --receipt-id receipt-branch \
  --expect-decision allow_bounded_action
```

Evaluate a secret-bearing action:

```bash
python3 scripts/evaluate_agentic_action_runtime_decision.py \
  --workflow-id sensitive-data-remediation \
  --action-class credential_or_secret_access \
  --run-id run-secret \
  --agent-id sr-agent::sensitive-data-remediation::codex \
  --identity-id sr-agent::sensitive-data-remediation::codex \
  --tenant-id tenant-demo \
  --correlation-id corr-secret \
  --intent-summary "Inspect whether a candidate finding contains a token" \
  --policy-pack-hash sha256:policy \
  --authorization-decision allow_authorized_mcp_request \
  --egress-decision hold_for_redaction_or_dpa \
  --receipt-id receipt-secret \
  --contains-secret \
  --expect-decision kill_session_on_runtime_action_signal
```

## What is inside

| Section | Purpose |
| --- | --- |
| `action_runtime_summary` | Action class count, workflow coverage, decision-floor distribution, high-impact action count, evidence source count, and failure count. |
| `action_contract` | Default fail-closed state, required runtime fields, required evidence sources, and decision ladder. |
| `action_classes` | Runtime action classes for branch writes, production deploys, identity and scope changes, secrets, egress, remote agent delegation, memory writes, skills, registry quarantine, and irreversible transactions. |
| `workflow_action_matrix` | Per-workflow action envelopes derived from the workflow manifest and MCP namespace coverage. |
| `runtime_policy` | Approval requirements, kill indicators, and the evidence gate agents must satisfy before the action is trusted. |
| `tabletop_cases` | Ready-made allow, hold, deny, and kill cases for platform testing. |
| `source_artifacts` | Hashes and paths for the evidence packs used to build the runtime action model. |

## MCP examples

Get the executive summary and workflow matrix:

```json
{}
```

Inspect an action class:

```json
{
  "action_class_id": "production_deployment"
}
```

Inspect the action envelope for one workflow:

```json
{
  "workflow_id": "artifact-cache-quarantine"
}
```

Find critical action classes:

```json
{
  "risk_tier": "critical"
}
```

Evaluate one runtime action:

```json
{
  "workflow_id": "vulnerable-dependency-remediation",
  "action_class": "repo_branch_write",
  "run_id": "run-123",
  "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
  "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
  "tenant_id": "tenant-a",
  "correlation_id": "corr-123",
  "intent_summary": "Patch package manifests on a scoped branch.",
  "policy_pack_hash": "sha256:policy",
  "authorization_decision": "allow_authorized_mcp_request",
  "receipt_id": "receipt-123"
}
```

## Why it is acquisition-grade

Documentation sites are useful. Runtime action control is a product.

For a $10-20M outcome, SecurityRecipes needs a path from open knowledge
to a production control plane that frontier labs, AI coding platforms,
and cloud security vendors could integrate. This pack is that path:

- hosted action firewall APIs for agent hosts and MCP gateways,
- signed action receipts,
- customer policy adapters,
- approval and risk-acceptance validation,
- SIEM/SOAR export,
- high-impact action inventory,
- runtime drift detection,
- buyer-ready evidence for autonomous action governance.

It also makes AI easier. Security teams do not need to write bespoke
agent policy from scratch; they can start from a concrete action
envelope and tune the thresholds.

## Industry alignment

The pack is anchored in current primary guidance:

- [CSA agentic control plane milestones](https://cloudsecurityalliance.org/press-releases/2026/04/29/csai-foundation-announces-key-milestones-to-secure-the-agentic-control-plane)
  for runtime action management across context, policy, intent, and
  behavior.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for tool misuse, goal hijacking, identity abuse, memory poisoning,
  unexpected code execution, and rogue-agent containment.
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  for confused-deputy prevention, least privilege, command review,
  sandboxing, and local-server boundaries.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected resource metadata, OAuth 2.1, resource indicators,
  audience validation, PKCE, and token handling.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for measurement, monitoring, third-party component risk, and risk
  treatment.
- [CISA AI Data Security Best Practices](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
  for securing data used to train and operate AI systems.

## See also

- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
- [Agentic Catastrophic Risk Annex]({{< relref "/security-remediation/agentic-catastrophic-risk-annex" >}})
- [Agentic Incident Response Pack]({{< relref "/security-remediation/agentic-incident-response-pack" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [MCP Runtime Decision Evaluator]({{< relref "/security-remediation/mcp-runtime-decision-evaluator" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
