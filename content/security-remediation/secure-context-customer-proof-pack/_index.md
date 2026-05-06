---
title: Secure Context Customer Proof Pack
linkTitle: Customer Proof Pack
weight: 15
sidebar:
  open: true
description: >
  A generated customer-proof contract that tells design partners,
  buyers, and acquirers exactly which runtime events, metrics, receipts,
  and renewal gates must exist before SecurityRecipes can claim
  acquisition-grade value.
---

{{< callout type="info" >}}
**Why this page exists.** SecurityRecipes now has strong reference
evidence. The next credibility gap is customer proof: runtime events,
receipts, MCP decisions, redacted telemetry, ROI metrics, and renewal
signals that prove the secure context layer works in a real pilot.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. The open project already shows the control model: secure context,
MCP authorization, protocol conformance, source freshness, telemetry,
run receipts, evals, buyer diligence, and value modeling. That is enough
to start serious conversations, but it is not enough to claim recurring
revenue or a $10-20M acquisition outcome.

The **Secure Context Customer Proof Pack** closes that gap honestly. It
defines what a design partner must measure before customer evidence can
replace assumptions.

## What was added

- `data/assurance/secure-context-customer-proof-profile.json` - source
  profile for proof claims, runtime event classes, metrics, renewal
  gates, acquirer readout, and proof risks.
- `scripts/generate_secure_context_customer_proof_pack.py` -
  deterministic generator and `--check` validator.
- `data/evidence/secure-context-customer-proof-pack.json` - generated
  pack with source-pack hashes, 7 proof claims, 9 metrics, 9 runtime
  event classes, 5 renewal gates, and 6 proof risks.
- `recipes_secure_context_customer_proof_pack` - MCP tool for the full
  pack, one proof claim, event class, metric, renewal gate, risk, or
  status-filtered view.

Run it from the repo root:

```bash
python3 scripts/generate_secure_context_customer_proof_pack.py
python3 scripts/generate_secure_context_customer_proof_pack.py --check
```

## What the pack contains

| Section | Purpose |
| --- | --- |
| `customer_proof_summary` | Contract status, source-pack readiness, proof-claim count, metric count, renewal-gate count, and failure count. |
| `proof_claims` | Buyer claims that require customer runtime proof, including context retrieval, MCP authorization, safe holds, redacted telemetry, ROI replacement, source freshness, and paid-wedge evidence. |
| `runtime_event_classes` | Metadata-first events a design partner should emit, such as `context.package.returned`, `mcp.authorization.decided`, `approval.receipt.validated`, and `reviewer.outcome.recorded`. |
| `metric_definitions` | Renewal metrics such as receipt completeness, context hash coverage, MCP pre-execution decisions, safe hold behavior, sensitive telemetry escape count, reviewer minutes, and paid-wedge confirmation. |
| `renewal_gates` | Hold conditions that block renewal, expansion, buyer export, or acquisition claims until customer evidence passes. |
| `acquirer_readout` | What is ready, what is not ready, and the next 90 days of proof collection. |
| `risk_register` | How the project avoids overclaiming from synthetic demos, leaky telemetry, unproven MCP auth, weak ROI proof, source drift, or vague paid wedges. |

The generated artifact currently reports `customer_proof_contract_ready`
with 10/10 source packs ready. It still marks the actual proof state as
`customer_runtime_evidence_required`, which is intentional.

## Why it is acquisition-grade

This pack gives the project a more serious posture in buyer and acquirer
conversations:

- It turns a design-partner pilot into a measurable evidence contract.
- It treats holds, denials, and kill decisions as product value when
  they prevent unsafe agent action.
- It requires metadata-first telemetry and zero counted secret capture.
- It blocks ROI and renewal claims until customer runtime evidence
  replaces default assumptions.
- It names the next commercial proof: paid wedge, budget owner,
  expansion trigger, support burden, and renewal signal.

That makes the path to a valuable project clearer: open evidence creates
trust, customer proof validates the wedge, and hosted MCP controls become
the sellable enterprise layer.

## MCP examples

Inspect the full customer proof pack:

```text
recipes_secure_context_customer_proof_pack()
```

Inspect one proof claim:

```text
recipes_secure_context_customer_proof_pack(claim_id="mcp-calls-are-authorized-before-execution")
```

Inspect one runtime event class:

```text
recipes_secure_context_customer_proof_pack(event_id="mcp.authorization.decided")
```

Inspect one renewal gate:

```text
recipes_secure_context_customer_proof_pack(gate_id="roi-replaces-assumptions")
```

Find contract areas that still require customer evidence:

```text
recipes_secure_context_customer_proof_pack(status="customer_metric_required")
```

## Industry alignment

The profile is grounded in current primary sources:

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
  for agent behavior hijacking, tool misuse, and identity abuse.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) for
  MCP-specific token, scope, tool, command, telemetry, shadow-server,
  and context risks.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, token audience validation, PKCE, token
  handling, and scope minimization.
- [OpenTelemetry MCP semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/)
  for MCP sessions, methods, transports, tool calls, errors, and
  duration evidence.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  and [NIST AI RMF critical infrastructure concept note](https://www.nist.gov/itl/ai-risk-management-framework)
  for AI governance, monitoring, provenance, incident response, and
  high-assurance operating expectations.
- [CISA AI Data Security](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
  and [CISA Deploying AI Systems Securely](https://www.cisa.gov/news-events/alerts/2024/04/15/joint-guidance-deploying-ai-systems-securely)
  for data security, integrity, detection, response, and secure
  deployment controls.

## See also

- [Secure Context Buyer Diligence Brief]({{< relref "/security-remediation/secure-context-buyer-diligence-brief" >}})
- [Design Partner Pilot Pack]({{< relref "/security-remediation/design-partner-pilot-pack" >}})
- [Secure Context Value Model]({{< relref "/security-remediation/secure-context-value-model" >}})
- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [Agentic Telemetry Contract]({{< relref "/security-remediation/agentic-telemetry-contract" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Production MCP Server]({{< relref "/mcp-servers" >}})
