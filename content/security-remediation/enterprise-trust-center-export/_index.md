---
title: Enterprise Trust Center Export
linkTitle: Trust Center Export
weight: 13
sidebar:
  open: true
description: >
  A generated buyer-diligence packet that bundles SecurityRecipes
  secure-context, MCP, identity, eval, readiness, runtime evidence, and
  commercialization artifacts into one MCP-readable trust-center export.
---

{{< callout type="info" >}}
**What this is.** SecurityRecipes should be easy for an enterprise buyer
to approve. This export is the compact trust-center packet: one JSON
artifact that says which controls exist, which evidence packs prove them,
which MCP tools expose them, and which diligence questions they answer.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. The open site already has recipes, policy packs, runtime
evaluators, an MCP server, attestation seeds, evals, identity contracts,
handoff controls, and a control-plane blueprint. The missing buyer
surface was the packaging: a single artifact a platform team, CISO staff,
GRC reviewer, procurement team, VC, or acquirer can inspect first.

The **Enterprise Trust Center Export** packages the generated evidence
into a diligence-ready contract:

- what context agents may receive,
- which MCP tools and connectors are governed,
- which non-human identities may act,
- how A2A and provider-native handoffs are bounded,
- how high-impact autonomous actions are held, denied, or killed,
- how agentic incidents are classified, contained, preserved, replayed,
  and disclosed,
- which telemetry fields reconstruct agent, model, MCP, policy, egress,
  approval, verifier, and incident evidence without raw secret capture,
- which evals and red-team drills prove behavior,
- which standards controls map to generated evidence,
- which runtime evidence fields must exist,
- which open artifacts support the paid enterprise control plane.

This makes AI easier because reviewers do not need to read the whole
site to understand the security model. They can ask the MCP server for
one export, then drill into the exact pack, section, or diligence
question that matters.

## What was added

- `data/assurance/enterprise-trust-center-profile.json` - source
  contract for standards alignment, required packs, trust-center
  sections, diligence questions, runtime evidence, and commercial path.
- `scripts/generate_enterprise_trust_center_export.py` - deterministic
  generator and `--check` validator.
- `data/evidence/enterprise-trust-center-export.json` - generated export
  for buyer diligence, MCP clients, and CI drift detection.
- `recipes_enterprise_trust_center_export` - MCP tool for the full
  export, a section, an evidence pack, a diligence question, or filtered
  category/status views.

Run it from the repo root:

```bash
python3 scripts/generate_enterprise_trust_center_export.py
python3 scripts/generate_enterprise_trust_center_export.py --check
```

## What is inside

| Section | Purpose |
| --- | --- |
| `export_summary` | Trust-center readiness, pack counts, section counts, failure counts, MCP tool count, readiness summary, threat radar summary, BOM summary, and acquisition-readiness snapshot. |
| `pack_index` | Required evidence packs with paths, hashes, schemas, categories, failure counts, summaries, status, and MCP tools. |
| `trust_center_sections` | Buyer-readable control areas such as secure context, MCP control plane, agent identity, handoffs, assurance/evals, and market strategy. |
| `catastrophic-risk-governance` | Severe-risk section for high-impact action classes, approval and risk acceptance, runtime kill signals, and replayable catastrophic-risk scenarios. |
| `agentic-incident-response` | Incident-response section for secure-context and MCP failures: classification, containment, forensic evidence, replay gates, recertification, and disclosure. |
| `runtime-telemetry-evidence` | Telemetry section for OpenTelemetry-shaped agent, model, MCP, context, policy, egress, approval, verifier, and incident traces with redaction controls. |
| `diligence_questions` | Specific buyer questions with answers, evidence paths, and MCP tools to inspect next. |
| `crosswalk_summary` | Standards coverage for OWASP Agentic Top 10, NIST AI agent and GenAI guidance, MCP authorization, and frontier-lab prompt-injection defenses. |
| `runtime_evidence_contract` | Fields a production run must capture: workflow, run, identity, source hashes, MCP decisions, auth, egress, handoff, approvals, evals, and receipt IDs. |
| `commercialization_path` | Open, team, enterprise, and acquirer value paths without closing the public knowledge base. |

## MCP examples

Get the executive summary and section index:

```json
{}
```

Inspect secure-context diligence:

```json
{
  "section_id": "secure-context-layer"
}
```

Inspect one evidence pack:

```json
{
  "pack_id": "agentic-catastrophic-risk-annex"
}
```

Answer a buyer question directly:

```json
{
  "question_id": "mcp-auth"
}
```

Find anything not trust-center-ready:

```json
{
  "status": "needs_attention"
}
```

## Why it is acquisition-grade

This is the sales and diligence wrapper a $10-20M project needs. The
open corpus creates distribution. The generated packs create machine
readable trust. The MCP server turns those packs into a product surface.
The trust-center export ties the pieces together so a buyer can quickly
see the category claim, evidence coverage, runtime control points, and
hosted enterprise path.

The paid product path becomes straightforward:

- hosted MCP policy enforcement,
- customer-private context registries,
- signed context releases,
- connector discovery and schema-drift alerts,
- OpenTelemetry collector policy and redaction verification,
- agent run-receipt retention,
- incident evidence vaulting and SIEM/SOAR export,
- approval receipt exports,
- continuous eval replay,
- procurement and trust-center API exports.

## Industry alignment

The export is anchored in current primary guidance:

- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  for agent standards, open protocols, agent identity, and security
  evaluations.
- [CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for constraining and monitoring agent access under indirect prompt
  injection, data poisoning, and misaligned-action risk.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
  for behavior hijacking, tool misuse, identity abuse, supply chain,
  insecure inter-agent communication, memory/context poisoning, and rogue
  behavior.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, token audience validation, PKCE, protected
  resource metadata, and token-passthrough denial.
- [A2A Protocol](https://a2a-protocol.org/latest/specification/)
  for agent discovery, task exchange, HTTP-layer authentication,
  server-identity verification, and skill-based authorization.
- [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final)
  for secure development expectations that apply to AI producers,
  integrators, and acquirers.

## See also

- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
- [Agentic Standards Crosswalk]({{< relref "/security-remediation/agentic-standards-crosswalk" >}})
- [Agentic System BOM]({{< relref "/security-remediation/agentic-system-bom" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Secure Context Attestation]({{< relref "/security-remediation/secure-context-attestation" >}})
- [Agent Handoff Boundary]({{< relref "/security-remediation/agent-handoff-boundary" >}})
- [A2A Agent Card Trust]({{< relref "/security-remediation/a2a-agent-card-trust" >}})
- [Production MCP Server]({{< relref "/mcp-servers" >}})
