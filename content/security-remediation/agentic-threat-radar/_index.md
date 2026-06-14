---
title: Agentic Threat Radar
linkTitle: Agentic Threat Radar
weight: 18
toc: true
description: >
  Source-backed radar that maps current agentic AI and MCP security
  guidance to SecurityRecipes controls, MCP tools, reviewer triggers, and
  source roadmap priorities.
sidebar:
  exclude: true
---

{{< callout type="info" >}}
**What this is.** The threat radar is the strategy and diligence layer
for SecurityRecipes. It answers: what changed in agentic AI security,
which source says so, which SecurityRecipes control covers it, and what
product capability should be built next.
{{< /callout >}}

SecurityRecipes is positioned as **the secure context layer for
agentic AI**. That claim is stronger when the site can prove that its
controls track the current threat landscape, not only a static set of
prompts. The Agentic Threat Radar does that by turning external
guidance into a generated evidence pack:

- Source-backed threat signals from OWASP, MCP, NIST, CISA, Microsoft,
  OpenAI, and CSA.
- Mapped SecurityRecipes capabilities such as the Secure Context Trust
  Pack, Context Poisoning Guard, MCP Gateway Policy, Agent Identity
  Ledger, Red-Team Drill Pack, Readiness Scorecard, Agentic System BOM,
  and this radar.
- reviewer triggers that explain when an enterprise should care.
- Source roadmap actions that keep the open knowledge base aligned
  with a future hosted MCP/server business.

## Generated artifact

- Source registry:
  `data/intelligence/agentic-threat-radar-sources.json`
- Generator:
- Evidence pack:
  `data/evidence/agentic-threat-radar.json`
- MCP tool:
  `recipes_agentic_threat_radar`

Regenerate and validate the pack:


## Current source-backed signals

| Signal | Priority | Why it matters |
| --- | --- | --- |
| Indirect prompt injection as social engineering | Critical | Agents now process hostile emails, websites, documents, tickets, and tool results; string filters are not enough. |
| MCP token passthrough and scope creep | Critical | Remote MCP servers need audience-bound tokens, resource indicators, precise scopes, and default-deny gateway policy. |
| Agent identity explosion | Critical | Agents are becoming their own non-human identity class, with ownership, delegation, token lifetime, and revocation needs. |
| Tool poisoning and shadow MCP | High | Tool descriptions, schemas, local servers, and connector updates are now part of the attack surface. |
| Context over-sharing and memory poisoning | High | Retrieval and egress policy need provenance, freshness, data-class gates, tenant isolation, and destination controls before context reaches or leaves agents. |
| Audit telemetry and evidence chain | High | Enterprises need correlated records for context retrieval, tool calls, policy decisions, reviews, and scanner proof. |
| Human approval and tool safeguards | High | Approval must become a typed, policy-enforced control for high-risk or irreversible actions. |
| AI data security and provenance | High | Guidance is converging on data integrity, monitoring, lifecycle governance, and provenance for AI operations. |
| Continuous red-team replay and evals | High | Model, prompt, connector, and context drift can invalidate a previously safe workflow. |
| Secure-by-design agentic products | Medium | Procurement and diligence will reject products that rely on careful prompting instead of safe defaults. |

## How to use it

**AI platform review.** Use the radar to decide which agentic workflows
can move from pilot to production. Critical or high signals should map
to enforced policy, identity, context, evidence, or red-team coverage
before scale.

**MCP server intake.** Ask for signals tied to `mcp-gateway-policy`,
`mcp-connector-trust-pack`, or `agent-identity-ledger` before approving
new MCP servers or connector namespaces.

**Quarterly threat model.** Treat the radar as the agenda for a
quarterly agentic security review. If a source changes, regenerate the
pack and review affected capabilities.

**trust review diligence.** Use the generated pack to show that
SecurityRecipes is not only content. It is a machine-readable control
story: sources, mapped risks, product surfaces, MCP tools, and roadmap
actions.

## MCP examples

Get critical signals:

```json
{
  "priority": "critical"
}
```

Get signals that support the secure context layer:

```json
{
  "capability_id": "secure-context-trust-pack",
  "minimum_score": 85
}
```

Get signals tied to outbound context movement:

```json
{
  "capability_id": "context-egress-boundary"
}
```

Get one signal with sources and mapped capabilities:

```json
{
  "signal_id": "indirect-prompt-injection-social-engineering"
}
```

## Source anchors

The source registry should be updated when major guidance changes.
The current anchors include:

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [Microsoft guidance on indirect prompt injection](https://learn.microsoft.com/en-us/security/zero-trust/sfi/defend-indirect-prompt-injection)
- [OpenAI guidance on prompt injections](https://openai.com/index/prompt-injections)
- [OpenAI Agent Builder safety guidance](https://platform.openai.com/docs/guides/agent-builder-safety)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [CISA AI Data Security guidance](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
- [CISA Secure by Design for AI](https://www.cisa.gov/news-events/news/software-must-be-secure-design-and-artificial-intelligence-no-exception)
- [CSA MCP Security Resource Center announcement](https://cloudsecurityalliance.org/articles/securing-the-agentic-ai-control-plane-announcing-the-mcp-security-resource-center)
- [CSA agentic AI and MCP identity guidance](https://cloudsecurityalliance.org/blog/2025/07/10/agentic-ai-mcp-and-the-identity-explosion-you-can-t-ignore)
