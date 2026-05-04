---
title: Agentic Standards Crosswalk
linkTitle: Standards Crosswalk
weight: 19
toc: true
description: >
  Generated standards-to-evidence map that ties OWASP Agentic Top 10,
  NIST AI agent guidance, MCP authorization, and frontier-lab
  prompt-injection defenses to SecurityRecipes controls and MCP tools.
---

{{< callout type="info" >}}
**What this is.** The standards crosswalk is the buyer-facing evidence
map for SecurityRecipes. It answers which current agentic AI standards
and guidance are tracked, which SecurityRecipes capability covers each
control, and which generated JSON or MCP tool proves it.
{{< /callout >}}

SecurityRecipes is positioned as **the secure context layer for
agentic AI**. That claim needs more than a strong homepage. Enterprise
buyers, AI platform teams, and acquirers will ask whether the project
tracks the current external control language: OWASP Agentic Top 10,
NIST agent standards work, MCP authorization, prompt-injection
defenses, evals, context provenance, and runtime evidence.

The **Agentic Standards Crosswalk** turns those references into a
generated artifact:

- Standards and source anchors from OWASP, NIST, MCP, OpenAI, and
  Anthropic.
- Control mappings for goal hijack, tool misuse, identity abuse,
  supply-chain risk, unexpected code execution, memory/context
  poisoning, inter-agent communication, cascading failures, human-agent
  trust exploitation, rogue agents, MCP token safety, scope
  minimization, sandboxing, and secure prompt-injection defenses.
- Capability mappings to the Secure Context Trust Pack, Context
  Poisoning Guard, MCP Gateway Policy, MCP Authorization Conformance,
  Agent Identity Ledger, Run Receipts, Red-Team Drills, Measurement
  Probes, Readiness Scorecard, Agentic System BOM, and related packs.
- MCP tool exposure through `recipes_agentic_standards_crosswalk`.

## Generated artifact

- Source model:
  `data/assurance/agentic-standards-crosswalk.json`
- Generator:
  `scripts/generate_agentic_standards_crosswalk.py`
- Evidence pack:
  `data/evidence/agentic-standards-crosswalk.json`
- MCP tool:
  `recipes_agentic_standards_crosswalk`

Regenerate and validate the pack:

```bash
python3 scripts/generate_agentic_standards_crosswalk.py
python3 scripts/generate_agentic_standards_crosswalk.py --check
```

## Why this matters

The most valuable version of SecurityRecipes is not a static prompt
library. It is a standards-aware secure context control plane that can
answer a buyer's first hard questions:

| Buyer question | Crosswalk answer |
| --- | --- |
| Which agentic risks are covered? | OWASP Agentic Top 10 controls map to generated capabilities and MCP tools. |
| Which MCP authorization requirements matter? | Resource binding, audience validation, token-passthrough denial, PKCE, scope minimization, and local-server sandboxing map to concrete packs. |
| How does this track NIST agent and GenAI guidance? | Identity, protocols, security evaluations, governance, access constraints, monitoring, data provenance, and lifecycle risk map to evidence artifacts. |
| How are prompt-injection defenses made operational? | Context poisoning scans, egress decisions, handoff boundaries, sandboxed tool use, red-team replay, and readiness checks are linked to frontier-lab guidance. |
| What should a diligence team inspect first? | The generated crosswalk returns standards, controls, sources, evidence paths, MCP tools, and commercialization hooks in one packet. |

## Core mappings

| Standard area | SecurityRecipes evidence |
| --- | --- |
| OWASP Agentic Top 10 | Context Poisoning Guard, Secure Context Evals, MCP Gateway Policy, Authorization Conformance, Identity Ledger, Skill Supply Chain, Handoff Boundary, Readiness Scorecard |
| MCP Authorization and Security | MCP Authorization Conformance, MCP Gateway Policy, Connector Intake, Connector Trust, STDIO Launch Boundary, Context Egress Boundary |
| NIST agent and GenAI risk guidance | Agent Identity Ledger, Agentic System BOM, Agentic Assurance Pack, Measurement Probes, Red-Team Drills, Enterprise Trust Center Export |
| Frontier-lab prompt-injection defenses | Context Poisoning Guard, Context Egress Boundary, Run Receipts, Handoff Boundary, Red-Team Drills, Readiness Scorecard |

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
- [OWASP Securing Agentic Applications Guide 1.0](https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/)
- [OWASP GenAI Exploit Round-up Report Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [NIST CAISI RFI on Securing AI Agent Systems](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [OpenAI prompt-injection guidance](https://openai.com/index/prompt-injections)
- [OpenAI guidance on designing agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
- [Anthropic prompt-injection defenses for browser use](https://www.anthropic.com/news/prompt-injection-defenses)

## See also

- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
