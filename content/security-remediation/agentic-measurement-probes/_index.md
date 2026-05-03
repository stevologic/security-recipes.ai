---
title: Agentic Measurement Probes
linkTitle: Measurement Probes
weight: 6
sidebar:
  open: true
description: >
  Generated measurement probes that verify agentic workflow traceability,
  context integrity, MCP authorization, memory, egress, red-team replay,
  readiness, and run receipt evidence before scale.
---

{{< callout type="info" >}}
**Why this matters.** Credible agentic AI security needs measurement,
not only guidance. This pack turns SecurityRecipes controls into
repeatable probes that can be consumed by AI platform reviews, MCP
gateways, procurement security, and acquisition diligence.
{{< /callout >}}

SecurityRecipes is positioned as **the secure context layer for
agentic AI**. The Agentic Measurement Probe Pack makes that position
more concrete: it asks whether a workflow can reconstruct the context,
tools, identities, policy decisions, memory, egress, approvals,
verifiers, and threat signals behind an agent run.

This is the forward-looking product surface suggested by current
industry direction. NIST's April 2026 agentic measurement probe work
focuses on traceability, reconstructing tool usage and evidence, and
using judges or verifiers grounded in knowledge bases. OWASP and MCP
guidance point to the same need from the security side: agentic systems
must prove scope, authorization, context boundaries, telemetry, and
failure handling before they operate in high-stakes environments.

## Generated artifact

- Profile:
  `data/assurance/agentic-measurement-probe-profile.json`
- Generator:
  `scripts/generate_agentic_measurement_probe_pack.py`
- Evidence pack:
  `data/evidence/agentic-measurement-probe-pack.json`
- MCP tool:
  `recipes_agentic_measurement_probe_pack`

Regenerate and validate the pack:

```bash
python3 scripts/generate_agentic_measurement_probe_pack.py
python3 scripts/generate_agentic_measurement_probe_pack.py --check
```

## Probe classes

| Probe class | What it proves |
| --- | --- |
| Context integrity | Retrieved context is registered, owned, hash-bound, cited, and scanned before it influences an agent. |
| Tool authorization | MCP namespaces are default-deny, resource-bound, audience-bound, and scoped before tool execution. |
| Identity delegation | Agents act through scoped non-human identities with explicit denies and revocation evidence. |
| Context egress | Context cannot leave tenant, model, telemetry, MCP, or public-corpus boundaries without data-class and destination checks. |
| Memory boundary | Persistent memory, vector indexes, replay, and prohibited memory are gated before reuse. |
| Red-team replay | Workflows can replay prompt injection, goal hijack, approval bypass, exfiltration, drift, loop, and evidence-integrity probes. |
| Run receipt integrity | A run can reconstruct context, tools, policy decisions, approvals, verifier output, closure, and identity revocation. |
| Readiness decision | Current evidence supports scale, guarded pilot, manual gate, or block decisions. |
| Threat radar alignment | Probe coverage maps back to current source-backed agentic and MCP threat signals. |

## How to use it

**AI platform promotion.** Call the MCP tool with
`decision="measurement_ready"` to list workflows whose probes pass the
minimum score. Treat failed probes as promotion blockers until the
source evidence is regenerated or remediated.

**MCP connector intake.** Filter by `class_id="tool_authorization"` or
`class_id="egress_boundary"` when approving new remote MCP servers,
OAuth-backed connectors, or data-moving tool surfaces.

**Quarterly red-team replay.** Filter by `class_id="red_team_replay"`
and run the named scenarios against the current model, prompt, tool,
context, memory, and policy stack.

**Procurement and diligence.** Attach the generated pack with the
Agentic Assurance Pack, Readiness Scorecard, Agentic System BOM, Run
Receipt Pack, and Threat Radar. The probe pack turns those artifacts
into a single inspectable measurement story.

## MCP examples

List workflows ready for measurement-based promotion:

```json
{
  "decision": "measurement_ready",
  "minimum_score": 90
}
```

Inspect one workflow:

```json
{
  "workflow_id": "vulnerable-dependency-remediation"
}
```

Find failed or held probes:

```json
{
  "status": "fail"
}
```

Inspect egress probes:

```json
{
  "class_id": "egress_boundary"
}
```

## Source anchors

- [NIST agentic measurement probes event](https://www.nist.gov/news-events/events/2026/04/nist-information-technology-laboratory-ai-webinar-series-building)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [CSA Capabilities-Based Risk Assessment](https://cloudsecurityalliance.org/press-releases/2025/11/13/cloud-security-alliance-introduces-new-tool-for-assessing-agentic-risk)

## See also

- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Agentic Readiness Scorecard]({{< relref "/security-remediation/agentic-readiness-scorecard" >}})
- [Agent Capability Risk Register]({{< relref "/security-remediation/agent-capability-risk-register" >}})
- [Agent Memory Boundary]({{< relref "/security-remediation/agent-memory-boundary" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
