---
title: Agentic Standards Crosswalk
linkTitle: Standards Crosswalk
weight: 19
date: 2026-05-04
lastmod: 2026-11-12
toc: true
description: >
  Generate a standards-to-evidence map linking OWASP Agentic Top 10, CSA AI
  Controls Matrix, NIST AI guidance, MCP authorization, and infrastructure
  readiness.
sidebar:
  exclude: true
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**What this is.** The standards crosswalk is the reviewer-facing evidence
map for SecurityRecipes. It answers which current agentic AI standards
and guidance are tracked, which SecurityRecipes capability covers each
control, and which generated JSON or MCP tool proves it.
{{< /callout >}}

Rechecked source anchors on November 12, 2026 against the public MCP specification [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28), the current [security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices), NIST's [August 27, 2026 agent identity guidance](https://www.nist.gov/blogs/cybersecurity-insights/back-future-why-agentic-ai-needs-strong-identity-foundation), and NIST's [October 27, 2026 design tenets for agent identity management systems](https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems). MCP `latest` still redirects to 2026-07-28. NIST's ten design tenets add attenuated sub-agent delegation, zero standing privilege, signed mandate statements, architectural separation of policy from reasoning, deterministic access decisions, consent-fatigue-aware HITL thresholds, and independent append-only evidence. In our reading, unique short-lived credentials alone are not sufficient. The 2025-06-18 security-best-practices page is kept as a historical source ID at the versioned `/docs/2025-06-18/` path. This editorial pass does not claim human review of the pack.

SecurityRecipes is positioned as **the secure context layer for
agentic AI**. That claim needs more than a strong homepage. Enterprise
reviewers and AI platform teams will ask whether the project
tracks the current external control language: OWASP Agentic Top 10,
CSA AI Controls Matrix, NIST agent standards work, MCP authorization,
critical-infrastructure AI review expectations, prompt-injection
defenses, evals, context provenance, telemetry, and runtime evidence.

The **Agentic Standards Crosswalk** turns those references into a
generated artifact:

- Standards and source anchors from OWASP, NIST, CSA, MCP, OpenAI, and
  Anthropic.
- Control mappings for goal hijack, tool misuse, identity abuse,
  supply-chain risk, unexpected code execution, memory/context
  poisoning, inter-agent communication, cascading failures, human-agent
  trust exploitation, rogue agents, MCP token safety, scope
  minimization, sandboxing, AI governance, shared responsibility,
  telemetry/SOC readiness, critical-infrastructure readiness, and secure
  prompt-injection defenses.
- Capability mappings to the Secure Context Trust Pack, Context
  Poisoning Guard, MCP Gateway Policy, MCP Authorization Conformance,
  Agent Identity Ledger, Run Receipts, Red-Team Drills, Measurement
  Probes, Readiness Scorecard, Agentic System BOM, and related packs.
- MCP tool exposure through `recipes_agentic_standards_crosswalk`.
  This is an interpretation map, not a certification that SecurityRecipes
  implements those standards. Rechecked against MCP
  [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
  on August 21, 2026.

## Generated artifact

- Source model:
  `data/assurance/agentic-standards-crosswalk.json`
- Generator: `scripts/generate_agentic_standards_crosswalk.py`
- Evidence pack:
  `data/evidence/agentic-standards-crosswalk.json`
- MCP tool:
  `recipes_agentic_standards_crosswalk`

Regenerate and validate the pack:

```bash
python3 scripts/generate_agentic_standards_crosswalk.py
python3 scripts/generate_agentic_standards_crosswalk.py --check
```

{{< playbook-workflow >}}

## Why this matters

The most valuable version of SecurityRecipes is not a static prompt
library. It is a standards-aware secure context control plane that can
answer a reviewer's first hard questions:

| reviewer question | Crosswalk answer |
| --- | --- |
| Which agentic risks are covered? | OWASP Agentic Top 10 controls map to generated capabilities and MCP tools. |
| Which MCP authorization requirements matter? | Resource binding, audience validation, token-passthrough denial, PKCE, scope minimization, and local-server sandboxing map to concrete packs. |
| How does this map to enterprise AI control frameworks? | CSA AI Controls Matrix-style governance, data lifecycle, access, monitoring, supply-chain, and resilience controls map to generated evidence. |
| How does this track NIST agent and GenAI guidance? | Distinct agent identity, attenuated delegation, zero standing privilege, signed mandates, policy/reasoning separation, deterministic access, risk-threshold HITL, independent evidence, protocols, evaluations, governance, access constraints, monitoring, data provenance, and lifecycle risk map to evidence artifacts. |
| How are prompt-injection defenses made operational? | Context poisoning scans, egress decisions, handoff boundaries, sandboxed tool use, red-team replay, and readiness checks are linked to frontier-lab guidance. |
| What changes for high-impact deployments? | Critical-infrastructure readiness maps fail-safe action boundaries, operational monitoring, incident response, and lifecycle change control to MCP-readable evidence. |
| What should a diligence team inspect first? | The generated crosswalk returns standards, controls, sources, evidence paths, MCP tools, and vendorization hooks in one packet. |

## Core mappings

| Standard area | SecurityRecipes evidence |
| --- | --- |
| OWASP Agentic Top 10 | Context Poisoning Guard, Secure Context Evals, MCP Gateway Policy, Authorization Conformance, Identity Ledger, Skill Supply Chain, Handoff Boundary, Readiness Scorecard |
| MCP Authorization and Security | MCP Authorization Conformance, MCP Gateway Policy, Connector Intake, Connector Trust, STDIO Launch Boundary, Context Egress Boundary |
| CSA AI Controls Matrix | Agentic Assurance Pack, Enterprise Trust Center Export, Secure Context Trust Pack, Entitlement Review, Telemetry Contract, SOC Detection Pack |
| NIST agent and GenAI risk guidance | Agent Identity Ledger, Agent Trust Fabric, Entitlement Review, Approval Receipts, Run Receipts, Agentic System BOM, Measurement Probes, Red-Team Drills, Enterprise Trust Center Export |
| NIST critical-infrastructure AI readiness | Catastrophic Risk Annex, Action Runtime Pack, Approval Receipts, Telemetry Contract, SOC Detection Pack, Incident Response Pack |
| Frontier-lab prompt-injection defenses | Context Poisoning Guard, Context Egress Boundary, Run Receipts, Handoff Boundary, Action Runtime Pack, Telemetry Contract, Red-Team Drills, Readiness Scorecard |

## MCP examples

Get the crosswalk summary:

```json
{}
```

Get one standard:

```json
{
  "standard_id": "owasp-agentic-top-10-2026"
}
```

Get one control:

```json
{
  "control_id": "ASI06"
}
```

Get every standard control mapped to a capability:

```json
{
  "capability_id": "context-poisoning-guard-pack"
}
```

Get a source anchor:

```json
{
  "source_id": "mcp-authorization-2025-11-25"
}
```

## Source anchors

Review and regenerate the crosswalk when these sources change:

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP Securing Agentic Applications V2](https://genai.owasp.org/resource/securing-agentic-applications-v2/)
- [OWASP GenAI and Agentic AI Exploit Roundup Q3 2026](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/)
- [NIST SI Agent Standards Initiative](https://www.nist.gov/super-intelligence/si-agent-standards-initiative)
- [NIST CAISI RFI on Securing AI Agent Systems](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [NIST design tenets for agent identity management systems](https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems)
- [CSA AI Controls Matrix v1.1](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [OWASP GenAI Security Industry Framework Crosswalk](https://genai.owasp.org/resource/genai-security-industry-framework-crosswalk/)
- [MCP Authorization Security Considerations (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Careful Adoption of Agentic AI Services](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-si-services)
- [OpenAI prompt-injection guidance](https://openai.com/index/prompt-injections)
- [OpenAI guidance on designing agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
- [OpenAI Agents SDK guardrails](https://openai.github.io/openai-agents-js/guides/guardrails/)
- [Anthropic prompt-injection defenses for browser use](https://www.anthropic.com/news/prompt-injection-defenses)

## See also

- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
