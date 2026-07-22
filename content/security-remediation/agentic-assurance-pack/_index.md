---
title: Agentic Assurance Pack
linkTitle: Assurance Pack
weight: 6
date: 2026-05-02
lastmod: 2026-07-13
sidebar:
  exclude: true
description: >
  A generated reviewer-, auditor-, and AI-platform-ready evidence bundle
  for agentic remediation controls, workflow scope, MCP gateway policy,
  AI/Agent BOM readiness, and residual risk.
---

{{< callout type="info" >}}
**Why this page exists.** Enterprise teams do not buy "a good prompt."
They buy an operating model they can approve. The assurance pack turns
SecurityRecipes into a portable trust artifact: controls, framework
mapping, workflow coverage, MCP policy, evidence sources, and residual
risk in one machine-readable export.
{{< /callout >}}

## The product bet

SecurityRecipes is strongest when it is the secure context layer between
agents and enterprise remediation work. The
[Workflow Control Plane]({{< relref "/security-remediation/control-plane" >}})
declares what a workflow may do. The
[MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
turns that declaration into runtime decisions. The assurance pack is the
next layer: it explains the control story in a format GRC teams, AI
platform teams, procurement, and reviewers can consume directly.

That matters because the market has moved from generic LLM governance to
agentic AI systems that plan, call tools, persist context, and connect to
MCP servers. A serious reviewer will ask four questions:

- What workflows are approved to run?
- What prevents tool misuse, scope creep, or privileged action?
- What evidence proves the agent stayed inside the approved path?
- How does this map to current AI security and assurance frameworks?

The assurance pack answers those questions without asking a reviewer to
stitch together prose pages by hand.

{{< playbook-workflow >}}

## What was added

The assurance layer lives in source-controlled and generated artifacts:

- `data/assurance/agentic-assurance-control-map.json` - the control map
  for SecurityRecipes assurance objectives, evidence sources, reviewer
  value, and framework mappings.
- `data/evidence/agentic-assurance-pack.json` - the generated trust pack
  that joins the control map, workflow manifest, gateway policy, and
  workflow validation report.
- `data/evidence/agentic-red-team-drill-pack.json` - the generated
  adversarial eval artifact referenced by the assurance controls.

Run it locally from the repo root:

```bash
python3 scripts/generate_agentic_assurance_pack.py
python3 scripts/generate_agentic_assurance_pack.py --check
```

The local MCP server exposes the same generated bundle through
`recipes_agentic_assurance_pack`, so agent hosts and internal control
portals can retrieve it as structured context.

## What is inside the pack

The generated pack includes:

| Section | Purpose |
| --- | --- |
| `assurance_summary` | Workflow, control, standard, evidence, and default-deny coverage counts. |
| `control_objectives` | SecurityRecipes assurance controls (`SR-AI-01` through `SR-AI-09`) with evidence sources and framework mappings. |
| `workflow_assurance` | Per-workflow owner, maturity, gate, evidence, KPI, MCP namespace, and gateway decision coverage. |
| `agent_bom_seed` | A starter inventory for AI/Agent BOM work: agent classes, MCP namespaces, prompt roots, and policy decisions. |
| `enterprise_adoption_packet` | The board-level claim, reviewer questions answered, and first-use guidance. |
| `residual_risks` | What the pack does not solve by itself and what operators must supply. |
| `source_artifacts` | Hashes for the source manifest, policy pack, validation report, and control map. |

This is intentionally not a legal attestation. It is a structured
evidence bundle that reduces the work needed to complete a design
review, AI platform intake, procurement security questionnaire, or audit
evidence request.

## Assurance controls

The initial control set is scoped to the parts of agentic remediation
that create enterprise risk:

| ID | Control | Why it matters |
| --- | --- | --- |
| `SR-AI-01` | Workflow Inventory and Ownership | Every workflow has a status, owner, scope, and escalation path. |
| `SR-AI-02` | Default-Deny Tool Access | MCP and repo actions are denied unless declared by the gateway policy. |
| `SR-AI-03` | Human Review and Separation of Duties | Agents propose; humans approve; source-host records carry the control evidence. |
| `SR-AI-04` | Prompt, Skill, and MCP Supply Chain Governance | Prompt and tool context is treated as reviewed supply-chain surface. |
| `SR-AI-05` | Evidence Chain of Custody | Finding, run, tool, reviewer, scanner, and KPI records are named up front. |
| `SR-AI-06` | Runtime Kill Signals and Session Disablement | Unsafe sessions stop on scope creep, credential access, release attempts, or missing verifiers. |
| `SR-AI-07` | Model and Data Handling Boundaries | Data classes, provider contracts, retention, and runtime access are explicit. |
| `SR-AI-08` | AI and Agent Bill of Materials Readiness | Workflows, agents, prompts, MCP namespaces, and policies can seed an AI/Agent BOM. |
| `SR-AI-09` | Adversarial Evaluation and Red-Team Replay | Agentic workflows have repeatable drills for hostile instructions, tool misuse, approval bypass, connector drift, and evidence failure. |

## Industry alignment

The pack is mapped to current primary references:

- [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework)
  and the
  [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for governed, measured, and managed AI risk.
- [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) and
  [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for prompt injection, tool misuse, excessive agency, agentic supply
  chain, memory poisoning, cascading failures, and rogue-agent risk.
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
  for vendor-neutral cloud AI control objectives.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  for scoped MCP authorization, confused-deputy risk, token-passthrough
  avoidance, and session safety.
- [CISA Secure by Design](https://www.cisa.gov/securebydesign) for
  executive ownership, transparency, secure defaults, and measurable
  customer security outcomes.
- [OWASP AIBOM](https://owaspaibom.org/) for AI system transparency and
  component inventory readiness.

## How to use it

For an internal rollout, attach the pack to the AI platform design
review before the first pilot. Use the `workflow_assurance` entries to
decide which workflows are safe to run and which must remain in `crawl`.

For a procurement or customer security review, attach the pack with the
MCP gateway policy and control-plane report. The pack gives reviewers
the control narrative; the policy and report give them the evidence.

For an audit, treat the generated pack as the index. The external
evidence still comes from the deploying organization: source-host review
events, runtime MCP gateway logs, model-provider contracts, and scanner
before/after records.

For AI/Agent BOM work, start with `agent_bom_seed`. It inventories the
agent classes, MCP namespaces, prompt roots, policy decisions, and
workflow count that an enterprise BOM process will ask for.

## CI contract

The generator fails if:

- A control references an unknown standard or evidence artifact.
- A source-controlled evidence artifact path is missing.
- The gateway policy hash no longer matches the workflow manifest.
- The gateway policy workflow IDs drift from the manifest workflow IDs.
- A workflow is missing required gate phases, evidence records, KPIs, or
  kill signals.
- A generated red-team drill pack path referenced by the control map is
  missing.
- The generated pack is stale in `--check` mode.

That is the useful bar: control language, policy, workflow manifests,
and evidence exports drift together or the build fails.

## See also

- [Workflow Control Plane]({{< relref "/security-remediation/control-plane" >}})
  - the workflow source of truth.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - the runtime enforcement contract.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - the trust-tier, evidence, and promotion contract for MCP namespaces.
- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
  - the non-human identity and delegation contract.
- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}})
  - the adversarial eval layer for approved workflows.
- [Agentic Readiness Scorecard]({{< relref "/security-remediation/agentic-readiness-scorecard" >}})
  - the generated scale, pilot, gate, and block decision layer.
- [Agentic System BOM]({{< relref "/security-remediation/agentic-system-bom" >}})
  - the generated inspectability inventory for agents, identities, MCP
    connectors, evidence, evals, and drift triggers.
- [Compliance & Audit]({{< relref "/security-remediation/compliance" >}})
  - the human-facing compliance narrative.
- [Runtime Controls]({{< relref "/security-remediation/runtime-controls" >}})
  - the session disablement and inline enforcement layer.
