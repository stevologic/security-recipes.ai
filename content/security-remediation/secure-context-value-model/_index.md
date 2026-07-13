---
title: Secure Context Value Model
linkTitle: Value Model
weight: 12
sidebar:
  exclude: true
description: >
  A generated trust review- and trust-value model that turns the
  open SecurityRecipes corpus, generated evidence packs, and production
  MCP path into conservative operational-impact scenarios and reviewer diligence answers.
---

{{< callout type="info" >}}
**Why this page exists.** SecurityRecipes should not look like a pile of
interesting artifacts. It should look like a product that can become a
hosted secure context layer. The value model explains the open moat, the
hosted-ready proof paths, the reviewer segments, and the conservative operational-impact assumptions in
one MCP-readable artifact.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. The technical foundation is already in place: secure context
packs, MCP authorization and drift controls, run receipts, telemetry
contracts, evals, incident response, entitlement review, protocol
conformance, and a trust-center export. The next review-ready move
is to make the business case explicit.

The **Secure Context Value Model** does that without pretending the
public repo has already proven hosted adoption proof. It names what is proven
now, what remains assumption-based, which reviewer segments care, which
hosted-ready deployment paths are natural, and what customer telemetry must be
attached before the operational-impact story becomes review-grade.

## What was added

- `data/assurance/secure-context-value-model-profile.json` - source
  profile for reviewer segments, value drivers, adoption scenarios,
  hosted-readiness paths, diligence questions, and source references.
- `data/evidence/secure-context-value-model.json` - generated value
  model with scenario economics, evidence hashes, source-pack status,
  and trust review readiness.
- `recipes_secure_context_value_model` - MCP tool for the full model,
  a value driver, reviewer segment, scenario, hosted-readiness path, or
  diligence question.



{{< playbook-workflow >}}

## What the model contains

| Section | Purpose |
| --- | --- |
| `value_model_summary` | Source-pack readiness, scenario count, value-driver count, assumption status, and annual net value range from the default scenarios. |
| `value_drivers` | Open knowledge distribution, production MCP control plane, trust-center evidence, runtime receipts/evals, and standards drift. |
| `buyer_segments` | Frontier model lab, AI platform vendor, security platform vendor, and regulated enterprise reviewer views. |
| `adoption_scenarios` | Conservative pilot, platform rollout, and hosted MCP control-plane economics. |
| `hosted_readiness_gates` | Hosted MCP policy, private secure-context registry, run-receipt vault, trust-center API, and continuous agentic evals. |
| `diligence_questions` | Answers to why this is not docs-only, what is open, what is hosted-ready, what proves operational impact, and what remains unproven. |
| `acquisition_readiness` | Current signal, missing proof points, and the conditions needed before a trusted-source outcome is credible. |

The Operational-impact model is intentionally conservative and explicit. It uses
assumptions such as runs per month, avoided remediation hours, reviewer
time, loaded hourly cost, platform cost, and implementation cost. The
generated pack labels those numbers as assumptions until customer run
receipts and telemetry replace them.

## Product implications

This feature pushes the site toward the right shape for a serious
enterprise or reviewer review:

- The open corpus remains the distribution engine.
- The generated evidence packs become the product proof.
- The MCP server becomes the inspectable access layer.
- Hosted MCP policy, private context, drift monitoring, receipts, eval
  replay, and trust-center APIs become the hosted-ready surface.
- Customer telemetry becomes the proof point for ROI and renewal.

That is a more credible path than selling prompts. A reviewer can inspect
the technical artifacts, understand the economic assumptions, and see
exactly what still needs to be built for hosted trust value.

## MCP examples

Inspect the full model:

```text
recipes_secure_context_value_model()
```

Inspect one value driver:

```text
recipes_secure_context_value_model(driver_id="production-mcp-control-plane")
```

Inspect the hosted MCP scenario:

```text
recipes_secure_context_value_model(scenario_id="hosted-mcp-control-plane")
```

Answer a diligence question:

```text
recipes_secure_context_value_model(question_id="what-is-acquirable")
```

## Industry alignment

The profile is source-backed by current primary guidance:

- [MCP 2025-11-25 key changes](https://modelcontextprotocol.io/specification/2025-11-25/changelog)
  for protocol drift, incremental scope consent, URL elicitation, and
  task support.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, audience validation, PKCE, and
  token-passthrough denial.
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  for interoperable protocols, agent identity, and security evaluations.
- [CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for indirect prompt injection, data poisoning, misaligned actions, and
  deployment access controls.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for agent behavior, tool, identity, context, inter-agent, and rogue
  agent risks.
- [CISA Secure by Design](https://www.cisa.gov/securebydesign) for
  secure defaults, executive ownership, transparency, and measurable
  customer outcomes.

## See also

- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [Design Partner Pilot Pack]({{< relref "/security-remediation/design-partner-pilot-pack" >}})
- [Secure Context Customer Proof Pack]({{< relref "/security-remediation/secure-context-customer-proof-pack" >}})
- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
- [Agentic Standards Crosswalk]({{< relref "/security-remediation/agentic-standards-crosswalk" >}})
- [MCP Integration]({{< relref "/mcp-servers" >}})
