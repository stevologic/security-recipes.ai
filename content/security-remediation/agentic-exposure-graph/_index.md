---
title: Agentic Exposure Graph
linkTitle: Exposure Graph
weight: 18
toc: true
description: >
  Generated relationship graph that ranks exposure paths across secure
  context, agent identities, MCP namespaces, authorization, egress,
  readiness, capability risk, and run receipts.
---

{{< callout type="info" >}}
**What this is.** The exposure graph is the due-diligence view for
agentic AI: it shows how context, identity, tools, authorization, data
boundaries, and evidence combine into action paths before agents act.
{{< /callout >}}

SecurityRecipes is positioned as **the secure context layer for
agentic AI**, but secure context becomes valuable only when a buyer can
see where that context can travel. The **Agentic Exposure Graph** turns
the existing evidence packs into a single inspectable graph:

- Which workflow is active?
- Which non-human identity can act for it?
- Which MCP namespace can that identity call?
- Which context package and source hashes are attached?
- Which authorization and egress decisions govern the path?
- Which run receipt reconstructs the path after an incident?
- Which paths deserve architecture review before scale?

That is a stronger enterprise artifact than another checklist. It gives
AI platform, security architecture, IAM, GRC, and acquisition reviewers
an exposure-management surface for agentic AI.

## Generated artifact

- Source profile:
  `data/assurance/agentic-exposure-graph-profile.json`
- Generator:
  `scripts/generate_agentic_exposure_graph.py`
- Evidence pack:
  `data/evidence/agentic-exposure-graph.json`
- MCP tool:
  `recipes_agentic_exposure_graph`

Regenerate and validate the graph:

```bash
python3 scripts/generate_agentic_exposure_graph.py
python3 scripts/generate_agentic_exposure_graph.py --check
```

## Why this matters now

The market is converging on the same conclusion: agent security is an
action-layer problem, not only a prompt-safety problem. NIST's 2026 AI
Agent Standards Initiative calls out industry-led standards,
community-led protocols, agent authentication, identity infrastructure,
and security evaluations. OWASP's Agentic Top 10 focuses on tool misuse,
identity abuse, supply-chain compromise, context poisoning, insecure
inter-agent communication, and cascading failures. The current MCP
authorization specification requires resource binding, audience-aware
tokens, PKCE, HTTPS, and secure token handling. The OWASP MCP Top 10
adds token exposure, scope creep, tool poisoning, shadow servers, audit
gaps, and context over-sharing. CSA's agentic control-plane framing
centers visibility, identity, authorization, orchestration, runtime
behavior, and trust.

The exposure graph gives SecurityRecipes a concrete answer to those
themes: make the agent action graph visible, risk-ranked, and tied to
evidence.

## Graph model

| Node | What it represents |
| --- | --- |
| Workflow | A governed remediation workflow with owner, stage, readiness, and residual risk. |
| Agent identity | A scoped non-human identity for one workflow and agent class. |
| MCP namespace | A connector namespace with access mode, trust tier, transport, and production state. |
| Context source | A registered source of prompt, policy, guidance, or evidence context. |
| Evidence pack | A generated JSON artifact used to reconstruct or govern the path. |

Edges connect workflows to identities, context sources, MCP namespaces,
and evidence packs. Exposure paths join those relationships into a
reviewable route from **context** to **identity** to **tool access** to
**runtime evidence**.

## Path classes

| Path class | Review focus |
| --- | --- |
| Context to Read Tool | Stale context, tool-result poisoning, over-retrieval, and audit evidence. |
| Context to Write Tool | Tool misuse, scope creep, identity abuse, and review bypass. |
| Approval-Required Tool Path | Approval bypass, irreversible operation, blast-radius ambiguity, and missing approval receipts. |
| Tenant-Sensitive Context Path | Secret egress, unredacted customer data, wrong tenant, DPA, and residency gaps. |
| High-Impact Authority Path | Loss of human oversight, funds or asset movement, production mutation, and cascading failure. |

## MCP examples

Get the graph summary:

```json
{}
```

Find paths for one workflow:

```json
{
  "workflow_id": "vulnerable-dependency-remediation"
}
```

Find high-score paths:

```json
{
  "minimum_score": 70
}
```

Find approval-required paths:

```json
{
  "path_class_id": "approval_required_tool_path"
}
```

Find paths for one MCP namespace:

```json
{
  "namespace": "repo.contents"
}
```

## Buyer diligence questions

- Which agent identities create the highest-risk exposure paths?
- Which workflows combine high residual risk with write or
  approval-required MCP namespaces?
- Which MCP namespaces remain pilot-grade and should block scale?
- Which context sources and hashes are attached to each path?
- Which run receipt proves the path can be reconstructed after an
  incident?
- Which paths should move into security architecture review before
  production expansion?

## Source anchors

- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [CSA Securing the Agentic Control Plane](https://cloudsecurityalliance.org/blog/2026/03/20/2026-securing-the-agentic-control-plane)
- [Agent2Agent Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)

## See also

- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
- [Agentic Standards Crosswalk]({{< relref "/security-remediation/agentic-standards-crosswalk" >}})
- [Agentic Measurement Probes]({{< relref "/security-remediation/agentic-measurement-probes" >}})
- [Agent Capability Risk Register]({{< relref "/security-remediation/agent-capability-risk-register" >}})
- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
