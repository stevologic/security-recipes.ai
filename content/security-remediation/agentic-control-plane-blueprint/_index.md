---
title: Agentic Control Plane Blueprint
linkTitle: Control Plane Blueprint
weight: 17
toc: true
description: >
  Generated architecture and buyer-diligence artifact that positions
  SecurityRecipes as the secure context and control plane for agentic AI,
  MCP authorization, connector trust, identity, egress, receipts, and
  measurement.
---

{{< callout type="info" >}}
**What this is.** The blueprint is the executive and architecture layer
above the generated packs. It explains how SecurityRecipes becomes a
credible secure context layer for agentic AI, not just a documentation
site or prompt library.
{{< /callout >}}

SecurityRecipes already has the hard parts of an enterprise agentic
program: secure context trust, MCP gateway policy, authorization
conformance, connector trust, non-human identity, entitlement review,
memory boundaries,
skill supply-chain checks, agent handoff boundaries, egress decisions,
run receipts, red-team drills, readiness scoring, catastrophic-risk
gates, measurement probes, and an enterprise trust-center export.

The **Agentic Control Plane Blueprint** turns those individual artifacts
into one product story a buyer, AI platform owner, security architect,
GRC reviewer, or acquirer can evaluate quickly:

- What is the reference architecture?
- Which generated packs prove each layer?
- Which MCP tools expose the evidence to agents and review portals?
- Which current industry references does the architecture track?
- Which standards controls map to generated evidence instead of prose?
- What is the path from open knowledge to production MCP revenue?

## Generated artifact

- Source model:
  `data/assurance/agentic-control-plane-blueprint.json`
- Generator:
  `scripts/generate_agentic_control_plane_blueprint.py`
- Evidence pack:
  `data/evidence/agentic-control-plane-blueprint.json`
- MCP tool:
  `recipes_agentic_control_plane_blueprint`

Regenerate and validate the pack:

```bash
python3 scripts/generate_agentic_control_plane_blueprint.py
python3 scripts/generate_agentic_control_plane_blueprint.py --check
```

## Why this matters

Agentic security is moving from "can we prompt the model safely?" to
"can we govern the action layer?" NIST's 2026 AI Agent Standards
Initiative emphasizes interoperable standards, community protocols,
agent authentication and identity, and security evaluations. OWASP's
Agentic Top 10 frames the new risk surface around goal hijack, tool
misuse, identity abuse, agentic supply chain, memory and context
poisoning, cascading failures, and rogue-agent behavior. The current MCP
authorization specification adds concrete requirements around resource
indicators, token audience validation, PKCE, HTTPS, client metadata, and
forbidden token passthrough.

That is exactly where SecurityRecipes should sit: between agents and the
systems they want to use, making context and authority understandable,
queryable, and enforceable.

## Blueprint layers

| Layer | What it proves | Core evidence |
| --- | --- | --- |
| Workflow scope and default-deny control | Agents only run declared workflows and undeclared tool calls fail closed. | Workflow manifest, MCP gateway policy, assurance pack, readiness scorecard |
| Secure context provenance | Returned context has owner, trust tier, source hash, citation rule, poisoning scan, workflow package hash, and source-to-run lineage. | Secure Context Trust Pack, Secure Context Lineage Ledger, Context Poisoning Guard, Agentic System BOM, Measurement Probes |
| MCP authorization and connector trust | Remote MCP servers are reviewed for token audience, resource binding, PKCE, scope drift, and connector trust. | Connector Trust Pack, Connector Intake Pack, Authorization Conformance, Gateway Policy |
| Agent handoff and protocol boundaries | A2A Agent Cards, MCP, provider-native, and approval-bridge handoffs carry only approved metadata, cited evidence, and explicit authority state. | A2A Agent Card Trust Profile, Agent Handoff Boundary Pack, Secure Context Trust Pack, Context Egress Boundary, Agent Identity Ledger |
| Agent identity, delegation, and entitlements | Every agent run has owner, delegated scope, explicit denies, expiring permission lease, review linkage, and revocation expectations. | Agent Identity Ledger, Agentic Entitlement Review Pack, Gateway Policy, Run Receipt Pack, Capability Risk Register |
| Memory, skill, and runtime boundaries | Skills, rules files, hooks, vector memory, and persistent memory cannot silently inherit authority. | Memory Boundary Pack, Skill Supply-Chain Pack, Poisoning Guard, Red-Team Drills |
| Context egress and data boundaries | Context does not leave tenant, model, telemetry, MCP, or public-corpus boundaries without policy. | Context Egress Boundary, Secure Context Trust Pack, Run Receipts, Assurance Pack |
| Evidence receipts and Agentic System BOM | Runs can be reconstructed from context, tools, policy decisions, approvals, verifiers, closure, and revocation. | Run Receipt Pack, Agentic System BOM, Assurance Pack, Measurement Probes |
| Measurement, red-team replay, and threat alignment | Current threat signals become probes, drills, readiness decisions, and roadmap actions. | Threat Radar, Measurement Probe Pack, Red-Team Drill Pack, Readiness Scorecard |
| Standards crosswalk and diligence | OWASP, NIST, MCP, and frontier-lab guidance map to generated evidence and MCP tools. | Agentic Standards Crosswalk, Threat Radar, Control Plane Blueprint |
| Catastrophic risk and high-impact autonomy | High-impact agent actions are held, denied, or killed when approval, identity, policy, risk acceptance, or receipt evidence is missing. | Catastrophic Risk Annex, Capability Risk Register, Run Receipts, Readiness Scorecard |
| Enterprise trust-center export | Buyer and acquisition diligence can start from one compact packet with evidence paths, hashes, MCP tools, runtime fields, and diligence answers. | Enterprise Trust Center Export, Threat Radar, Control Plane Blueprint |

## Buyer diligence questions

Use the generated `buyer_due_diligence_matrix` when a customer or
acquirer asks for evidence:

| Question | Evidence path |
| --- | --- |
| Which context sources are allowed into an agent run, and how is source drift detected? | `recipes_secure_context_trust_pack`, `recipes_context_poisoning_guard_pack` |
| How does the product prevent token passthrough, wrong-audience tokens, scope creep, and unreviewed MCP tools? | `recipes_mcp_authorization_conformance_pack`, `recipes_mcp_connector_trust_pack` |
| How does the product evaluate A2A Agent Cards and prevent hidden prompts, internal memory, raw traces, credentials, or high-impact authority from crossing an agent-to-agent boundary? | `recipes_a2a_agent_card_trust_profile`, `recipes_evaluate_a2a_agent_card_trust_decision`, `recipes_agent_handoff_boundary_pack`, `recipes_evaluate_agent_handoff_decision` |
| Who owns an agent identity, what can it do, which permission lease proves current authority, and how is one unsafe run revoked? | `recipes_agent_identity_ledger`, `recipes_agentic_entitlement_review_pack`, `recipes_evaluate_agentic_entitlement_decision`, `recipes_agentic_run_receipt_pack` |
| Can the team reconstruct the exact policy, context, tool, approval, verifier, and egress path after an incident? | `recipes_agentic_run_receipt_pack`, `recipes_agentic_system_bom` |
| Which workflows are ready to scale, which stay in a guarded pilot, and which are blocked? | `recipes_agentic_readiness_scorecard`, `recipes_agentic_measurement_probe_pack` |
| Which current agentic AI, MCP, NIST, and prompt-injection references map to generated evidence? | `recipes_agentic_standards_crosswalk` |
| Which high-impact agent actions are held, denied, or killed before severe consequences? | `recipes_agentic_catastrophic_risk_annex`, `recipes_evaluate_agentic_catastrophic_risk_decision` |
| What should a buyer inspect first during procurement, platform review, or acquisition diligence? | `recipes_enterprise_trust_center_export`, `recipes_agentic_control_plane_blueprint` |

## Product strategy

The open project should stay useful and forkable. That is the adoption
engine. The commercial value sits above it:

| Stage | Product surface |
| --- | --- |
| Open foundation | MIT-licensed recipes, generated evidence packs, read-only MCP server, deterministic policy evaluators. |
| Production MCP server | Hosted secure-context retrieval, context signing, MCP authorization conformance, connector trust monitoring, and run receipt storage. |
| Enterprise expansion | Tenant evidence ingestion, identity-provider adapters, hosted red-team replay, measurement probes, and trust-center exports. |
| Strategic acquisition fit | Frontier labs, AI coding platforms, cloud platforms, and security vendors need a credible control layer for agentic tool use and context. |

## MCP examples

Get the full architecture summary:

```json
{}
```

Get one blueprint layer:

```json
{
  "layer_id": "mcp_authorization_and_connector_trust"
}
```

Get buyer evidence for a diligence question:

```json
{
  "question_id": "runtime-evidence"
}
```

Get only layers that need evidence attention:

```json
{
  "status": "needs_attention"
}
```

## Source anchors

The source model should be reviewed when these references change:

- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [NIST AI 800-2 automated benchmark evaluation draft](https://www.nist.gov/news-events/news/2026/01/towards-best-practices-automated-benchmark-evaluations)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [CSA Securing the Agentic Control Plane](https://labs.cloudsecurityalliance.org/agentic/)
- [CSA STAR for AI Catastrophic Risk Annex](https://cloudsecurityalliance.org/press-releases/2026/04/29/csai-foundation-announces-key-milestones-to-secure-the-agentic-control-plane)
- [CSA AI Agent Governance Gap](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/)
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)

## See also

- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
- [Agentic Standards Crosswalk]({{< relref "/security-remediation/agentic-standards-crosswalk" >}})
- [Agentic Catastrophic Risk Annex]({{< relref "/security-remediation/agentic-catastrophic-risk-annex" >}})
- [Agentic Measurement Probes]({{< relref "/security-remediation/agentic-measurement-probes" >}})
- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
- [Secure Context Lineage Ledger]({{< relref "/security-remediation/secure-context-lineage-ledger" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Agent Handoff Boundary]({{< relref "/security-remediation/agent-handoff-boundary" >}})
- [A2A Agent Card Trust]({{< relref "/security-remediation/a2a-agent-card-trust" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Agentic Entitlement Review]({{< relref "/security-remediation/agentic-entitlement-review" >}})
