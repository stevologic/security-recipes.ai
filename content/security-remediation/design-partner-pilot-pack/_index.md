---
title: Design Partner Pilot Pack
linkTitle: Design Partner Pilot
weight: 13
sidebar:
  open: true
description: >
  A generated design-partner pilot motion that turns secure-context,
  MCP, telemetry, eval, receipt, and value-model evidence into a
  buyer-ready path from open knowledge to hosted product proof.
---

{{< callout type="info" >}}
**Why this page exists.** SecurityRecipes already has the artifacts a
serious buyer wants to inspect. The next step is proving that those
artifacts can run inside a customer pilot, produce telemetry, validate a
paid wedge, and support a credible hosted MCP business.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. That claim becomes materially more valuable when a design partner
can answer four questions quickly:

- Which agent workflow are we piloting?
- Which private context and MCP controls are in scope?
- Which telemetry proves security and ROI?
- Which paid product wedge is this pilot validating?

The **Design Partner Pilot Pack** turns those questions into a generated
artifact. It does not claim recurring revenue exists yet. It defines the
motion required to prove it.

## What was added

- `data/assurance/design-partner-pilot-profile.json` - source-backed
  pilot profile for buyer segments, phases, telemetry, success metrics,
  paid wedges, pricing guardrails, diligence questions, and risk gates.
- `scripts/generate_design_partner_pilot_pack.py` - deterministic
  generator and `--check` validator for CI drift detection.
- `data/evidence/design-partner-pilot-pack.json` - generated pack with
  source-pack hashes, readiness score, phase gates, wedge proof states,
  telemetry requirements, and diligence answers.
- `recipes_design_partner_pilot_pack` - MCP tool for the full pack, a
  buyer segment, pilot phase, monetization wedge, metric, diligence
  question, or pilot risk.

Run it from the repo root:

```bash
python3 scripts/generate_design_partner_pilot_pack.py
python3 scripts/generate_design_partner_pilot_pack.py --check
```

## What the pack contains

| Section | Purpose |
| --- | --- |
| `pilot_summary` | Readiness score, decision, source-pack readiness, phase count, wedge count, metric count, and failure count. |
| `buyer_segments` | Frontier model lab, AI platform vendor, security platform vendor, and regulated enterprise views. |
| `pilot_phases` | Qualify, bind private context, run read-only MCP, govern controlled actions, and prove the renewal case. |
| `success_metrics` | Receipt completeness, context hash coverage, MCP decision coverage, reviewer time saved, automation success, safe holds, replay, private context, and renewal intent. |
| `monetization_wedges` | Hosted MCP policy, private context registry, connector drift, run-receipt vault, trust-center API, and continuous eval replay. |
| `telemetry_requirements` | Metadata-first telemetry events and prohibited data classes. |
| `risk_register` | Pilot risks with hold, deny, or kill decisions. |

## Why this is acquisition-grade

The site already has open knowledge, generated evidence, and a
production-oriented read-only MCP server. The missing enterprise proof is
customer pull.

This pack makes that proof testable:

- The open layer stays useful and forkable.
- The pilot binds private context, telemetry, and customer evidence.
- The paid wedge is explicit before implementation expands.
- Synthetic ROI is labeled as assumption-based until customer telemetry
  replaces it.
- The pilot can stop safely on token passthrough, approval bypass,
  unsafe model routing, raw secret capture, or connector drift.

That is the right path toward a credible $10-20M outcome: design
partners first, hosted MCP controls second, renewal evidence third.

## MCP examples

Inspect the full pilot pack:

```text
recipes_design_partner_pilot_pack()
```

Inspect the regulated-enterprise buyer view:

```text
recipes_design_partner_pilot_pack(segment_id="regulated-enterprise")
```

Inspect the hosted MCP policy wedge:

```text
recipes_design_partner_pilot_pack(wedge_id="hosted-mcp-policy-plane")
```

Inspect the controlled-action phase:

```text
recipes_design_partner_pilot_pack(phase_id="govern-controlled-actions")
```

## Industry alignment

The profile is grounded in current primary sources:

- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected-resource metadata, resource indicators, audience
  validation, PKCE, scope handling, and token-passthrough denial.
- [MCP 2025-11-25 key changes](https://modelcontextprotocol.io/specification/2025-11-25/changelog)
  for protocol drift, incremental scope consent, URL elicitation, task
  support, and metadata surfaces.
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  for interoperable agent protocols, agent identity infrastructure, and
  security evaluations.
- [NIST CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for indirect prompt injection, data poisoning, harmful actions,
  measurement, and deployment interventions.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for tool misuse, identity abuse, context poisoning, inter-agent
  communication, cascading failure, and rogue-agent risk.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for AI lifecycle governance, measurement, monitoring, data
  provenance, third-party risk, and incident response.
- [CISA Deploying AI Systems Securely](https://www.cisa.gov/news-events/alerts/2024/04/15/joint-guidance-deploying-ai-systems-securely)
  and [CISA Secure by Design](https://www.cisa.gov/resources-tools/resources/secure-by-design)
  for secure deployment, transparency, secure defaults, and customer
  outcome ownership.

## See also

- [Secure Context Value Model]({{< relref "/security-remediation/secure-context-value-model" >}})
- [Secure Context Customer Proof Pack]({{< relref "/security-remediation/secure-context-customer-proof-pack" >}})
- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [Agentic App Intake Gate]({{< relref "/security-remediation/agentic-app-intake-gate" >}})
- [Agentic Telemetry Contract]({{< relref "/security-remediation/agentic-telemetry-contract" >}})
- [Production MCP Server]({{< relref "/mcp-servers" >}})
