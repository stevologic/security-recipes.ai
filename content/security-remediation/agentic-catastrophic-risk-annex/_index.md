---
title: Agentic Catastrophic Risk Annex
linkTitle: Catastrophic Risk Annex
weight: 18
toc: true
description: >
  Generated severe-risk annex for high-impact agentic AI decisions:
  loss of human oversight, uncontrolled behavior, token cascades,
  cross-agent failure, supply-chain blast radius, private-context
  leakage, and irreversible action gates.
---

{{< callout type="info" >}}
**What this is.** The annex is the high-impact autonomy layer above the
normal readiness scorecard. It answers the board and buyer question:
"Which agent actions must be held, denied, or killed before a rare but
severe failure becomes irreversible?"
{{< /callout >}}

SecurityRecipes already has workflow policy, MCP authorization,
non-human identity, context trust, handoff boundaries, egress policy, run
receipts, readiness scoring, and red-team drills. The **Agentic
Catastrophic Risk Annex** joins those controls into one generated packet
for severe-risk decisions.

This is intentionally practical. It does not claim to solve long-horizon
AI safety. It focuses on production-testable agentic controls that
enterprise buyers can inspect:

- Which action classes are high impact?
- Which scenarios require human approval and risk acceptance?
- Which missing evidence creates a hold?
- Which runtime signals kill the session?
- Which source packs prove the decision?
- Which MCP tools expose the evidence to an agent host or review portal?

## Generated artifact

- Source model:
  `data/assurance/agentic-catastrophic-risk-annex.json`
- Generator:
  `scripts/generate_agentic_catastrophic_risk_annex.py`
- Evidence pack:
  `data/evidence/agentic-catastrophic-risk-annex.json`
- Runtime evaluator:
  `scripts/evaluate_agentic_catastrophic_risk_decision.py`
- MCP tools:
  `recipes_agentic_catastrophic_risk_annex`,
  `recipes_evaluate_agentic_catastrophic_risk_decision`

Regenerate and validate the pack:

```bash
python3 scripts/generate_agentic_catastrophic_risk_annex.py
python3 scripts/generate_agentic_catastrophic_risk_annex.py --check
```

Evaluate a held high-impact deployment decision:

```bash
python3 scripts/evaluate_agentic_catastrophic_risk_decision.py \
  --workflow-id base-image-remediation \
  --action-class production_deployment \
  --run-id run-123 \
  --identity-id sr-agent::base-image-remediation::codex \
  --policy-pack-hash policy-hash \
  --authorization-decision allow_authorized_mcp_request \
  --flag affects_prod=true \
  --expect-decision hold_for_catastrophic_risk_review
```

Evaluate an approved high-impact action:

```bash
python3 scripts/evaluate_agentic_catastrophic_risk_decision.py \
  --workflow-id base-image-remediation \
  --action-class production_deployment \
  --run-id run-123 \
  --identity-id sr-agent::base-image-remediation::codex \
  --policy-pack-hash policy-hash \
  --authorization-decision allow_authorized_mcp_request \
  --risk-acceptance-id risk-accept-123 \
  --receipt-id receipt-123 \
  --approval-id approval-123 \
  --flag affects_prod=true \
  --expect-decision allow_reviewed_high_impact_action
```

## Why this matters now

The 2026 market has moved from "secure the prompt" to "secure the
autonomous action layer." NIST's AI Agent Standards Initiative centers
agent authentication, identity infrastructure, interoperable protocols,
and security evaluations. OWASP's Agentic Top 10 frames autonomous
systems around tool use, identity abuse, context poisoning, insecure
inter-agent communication, cascading failure, and rogue behavior. The MCP
authorization specification now makes resource indicators, audience
validation, protected resource metadata, least-privilege scopes, and
token handling explicit. CSAI's April 2026 work adds the strongest signal:
catastrophic-risk assurance for loss of oversight, uncontrolled behavior,
and large-scale irreversible consequences that can be tested in
production.

SecurityRecipes should own the operational middle: not abstract safety
claims, but generated evidence and runtime gates that tell an agent host
when to allow, hold, deny, or kill.

## Severe scenarios

| Scenario | Default decision | What it proves |
| --- | --- | --- |
| Loss of human oversight | `hold_for_catastrophic_risk_review` | High-impact action stops when approval, identity, policy, receipt, or readiness evidence is missing. |
| Uncontrolled system behavior | `kill_session_on_catastrophic_signal` | Tool loops, deny-after-deny behavior, and uncontrolled action cascades terminate the session. |
| Credential and token cascade | `deny_unbounded_autonomy` | Agents cannot pass tokens, request broader audiences, or silently inherit user authority. |
| Cross-agent cascading failure | `hold_for_catastrophic_risk_review` | Handoffs cannot move hidden prompts, memory, raw traces, credentials, or unstated authority. |
| Supply-chain autonomy blast radius | `hold_for_catastrophic_risk_review` | Fleet-impacting dependency, image, cache, release, or generated-code changes require risk evidence. |
| Private-context exfiltration | `kill_session_on_catastrophic_signal` | Secrets, unredacted PII, private memory, and trust evidence cannot leave approved boundaries. |
| Irreversible financial or critical action | `deny_unbounded_autonomy` | Funds movement, critical-infrastructure control, identity administration, and mass deletion stay denied unless separately accepted. |

## Runtime decision contract

Use the evaluator before a separate gateway or orchestrator allows a
high-impact action. The evaluator returns:

| Decision | Meaning |
| --- | --- |
| `allow_bounded_agent_action` | The request does not match high-impact action classes or severe flags and has baseline identity evidence. |
| `allow_reviewed_high_impact_action` | A high-impact action has approval, risk acceptance, identity, policy, authorization, and receipt evidence. |
| `hold_for_catastrophic_risk_review` | Required runtime evidence is missing or the action needs explicit risk review. |
| `deny_unbounded_autonomy` | High-impact autonomy lacks risk acceptance or tries irreversible authority without approval. |
| `kill_session_on_catastrophic_signal` | Runtime behavior indicates a severe safety or security violation. |

High-impact action classes include production deployments, production
writes, identity administration, secret access, schema migrations, mass
deletion, public releases, critical-infrastructure control, funds
movement, and connector scope escalation.

## Buyer diligence questions

| Buyer view | Question |
| --- | --- |
| Board and executive risk | Can the organization say yes to agentic AI without losing control of irreversible or large-scale consequences? |
| AI platform security | Can high-impact tool calls be stopped before they cross MCP, identity, data, memory, or inter-agent boundaries? |
| Acquisition diligence | Does SecurityRecipes have a credible future enterprise assurance surface beyond open prompts and docs? |

## Product strategy

This annex pushes SecurityRecipes toward the "Secure Context Layer for
Agentic AI" thesis:

| Layer | Value |
| --- | --- |
| Open foundation | Severe-risk scenarios, default decisions, source packs, runtime evaluator, and MCP tools are public and forkable. |
| Production MCP server | Hosted high-impact action inventory, approval receipt validation, customer-specific risk acceptance, and runtime kill policy. |
| Enterprise expansion | Board reporting, insurer evidence, procurement exports, red-team replay, and customer-specific severe-risk test suites. |
| Strategic acquisition fit | Frontier labs, coding-agent platforms, cloud providers, and security vendors need a credible action-governance layer for enterprise agents. |

## MCP examples

Get the annex summary:

```json
{}
```

Get one severe scenario:

```json
{
  "scenario_id": "private-context-exfiltration"
}
```

Evaluate a high-impact action:

```json
{
  "workflow_id": "base-image-remediation",
  "action_class": "production_deployment",
  "run_id": "run-123",
  "identity_id": "sr-agent::base-image-remediation::codex",
  "policy_pack_hash": "policy-hash",
  "authorization_decision": "allow_authorized_mcp_request",
  "affects_prod": true
}
```

## Source anchors

- [CSA announces STAR for AI Catastrophic Risk Annex](https://cloudsecurityalliance.org/press-releases/2026/04/29/csai-foundation-announces-key-milestones-to-secure-the-agentic-control-plane)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)

## See also

- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [Agent Capability Risk Register]({{< relref "/security-remediation/agent-capability-risk-register" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Agent Handoff Boundary]({{< relref "/security-remediation/agent-handoff-boundary" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
