---
title: Agentic System BOM
linkTitle: System BOM
weight: 8
sidebar:
  exclude: true
description: >
  A generated Agent/AI Bill of Materials for the agentic remediation
  system: workflows, agent classes, identities, MCP connectors,
  policy components, evidence artifacts, knowledge sources, eval drills,
  source hashes, and drift triggers.
---

{{< callout type="info" >}}
**Why this page exists.** Enterprise reviewers can approve agentic
remediation faster when they can inspect the system like a supply chain:
which agents exist, what they can touch, which MCP connectors they use,
which policies constrain them, and which evidence proves current state.
{{< /callout >}}

## The product bet

SecurityRecipes is strongest as the secure context layer between agents
and enterprise remediation work. The existing control plane tells an
agent what it may do. The gateway policy enforces that scope. The
identity ledger binds action to non-human principals. The readiness
scorecard decides what can scale.

The Agentic System BOM makes that system inspectable. It turns the
control artifacts into a single generated inventory that an AI platform
team, GRC reviewer, procurement security team, or reviewer can load
without reading the whole site.

That matters because agentic systems are not one binary. They are a
changing composition of models, prompts, skills, workflows, tools, MCP
servers, policies, identities, evidence, and evals. A serious reviewer will
ask:

- Which agents and identities are part of the system?
- Which MCP namespaces and connectors can they reach?
- Which workflows are scale-ready or pilot-guarded?
- Which source artifacts prove the current state?
- Which changes force review before the system can keep running?

The BOM answers those questions in one machine-readable file.

## What was added

The BOM layer lives in three artifacts:

- `data/assurance/agentic-system-bom-profile.json` - the source profile
  for positioning, standards alignment, required component types, and
  drift triggers.
- `data/evidence/agentic-system-bom.json` - the generated BOM that joins
  workflow, policy, identity, connector trust, assurance, red-team, and
  readiness evidence.

Run it locally from the repo root:


The local MCP server exposes the same bundle through
`recipes_agentic_system_bom`.

## What is inside the BOM

| Section | Purpose |
| --- | --- |
| `bom_summary` | Counts for workflows, agent classes, identities, MCP namespaces, connectors, evidence, evals, drift triggers, and readiness decisions. |
| `components.workflows` | Per-workflow BOM rows with agents, identities, MCP namespaces, policy decisions, readiness score, red-team coverage, and evidence counts. |
| `components.agent_classes` | Agent-host inventory with workflow coverage and model-change controls. |
| `components.agent_identities` | Non-human identity contracts, delegated scopes, explicit denies, runtime contracts, and owners. |
| `components.mcp_connectors` | MCP namespaces, trust tiers, transports, access modes, data classes, required controls, evidence counts, and owners. |
| `components.policy_components` | Control-plane, gateway, identity, and readiness policy surfaces. |
| `components.evidence_artifacts` | Source-controlled and generated artifacts with canonical SHA-256 hashes. |
| `components.knowledge_sources` | Prompt, remediation, control-plane, and assurance roots used by agents and generators. |
| `components.evaluation_drills` | Workflow-specific red-team drills tied to attack families and expected policy decisions. |
| `update_triggers` | The changes that force BOM regeneration or manual review before scale. |

## Drift triggers

The BOM treats these changes as first-class inventory events:

| Trigger | Why it matters |
| --- | --- |
| `agent_changed` | Agent hosts, tool authority, or runtime sandboxes can change behavior without workflow text changing. |
| `model_changed` | Model family, context window, reasoning mode, budget controls, and provider contracts affect safety and cost. |
| `mcp_server_changed` | MCP endpoints, transports, auth models, and capabilities are production control surfaces. |
| `tool_changed` | Tool descriptions and schemas are prompt-layer input and supply-chain surface. |
| `policy_changed` | Gateway defaults, gate phases, approvals, branch scope, and kill signals define enforcement. |
| `identity_contract_changed` | Delegated authority, explicit denies, token rules, and reviewer pools define blast radius. |
| `red_team_scenario_changed` | Eval coverage is part of the promotion decision, not a one-time test. |
| `readiness_model_changed` | Score weights and thresholds decide what can scale. |

## Industry alignment

The BOM is mapped to current primary references:

- [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework)
  and the
  [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for lifecycle governance, measurement, monitoring, third-party, and
  data-boundary risk.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for tool misuse, identity abuse, agentic supply chain, context
  poisoning, cascading failures, and rogue-agent risk.
- [OWASP AI Bill of Materials](https://owaspaibom.org/) and the
  [Agent Observability Standard AgBOM](https://aos.owasp.org/spec/inspect/)
  for AI and agent system transparency, inspectability, tool inventory,
  model inventory, and dynamic update triggers.
- [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/) for
  interoperable BOM thinking across software, services, ML, operations,
  vulnerabilities, and attestations.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  for scope minimization, confused-deputy prevention, token-passthrough
  avoidance, SSRF controls, session safety, and auditability.
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
  for vendor-neutral cloud AI controls, ownership, implementation, and
  audit guidance.

## How to use it

For AI platform intake, start with `bom_summary` and
`components.workflows`. They show which workflows are scale-ready,
pilot-guarded, or blocked, plus the agents and MCP namespaces involved.

For access recertification, filter by `agent_class` or `namespace`
through MCP:

```text
recipes_agentic_system_bom(agent_class="codex")
recipes_agentic_system_bom(namespace="repo.contents")
recipes_agentic_system_bom(workflow_id="vulnerable-dependency-remediation")
```

For procurement or diligence, attach the BOM with the assurance pack,
gateway policy, connector trust pack, identity ledger, red-team drill
pack, and readiness scorecard. The BOM is the inventory; the other packs
are the proof behind each row.

For CI, run the generator in `--check` mode after every workflow,
policy, connector, identity, red-team, readiness, or assurance change.
If the BOM is stale, the build should fail before the site publishes.

## CI contract

The generator fails if:

- Source artifact hashes drift from generated evidence.
- Required component lists are missing or empty.
- A workflow references an MCP namespace without connector trust.
- A workflow namespace lacks a gateway policy decision.
- A default agent lacks an identity contract.
- An active workflow has too few red-team drills.
- Required drift triggers are missing.
- The checked-in BOM is stale in `--check` mode.

That is the enterprise-ready bar: the inventory changes when the system
changes, and the site cannot claim inspectability with stale evidence.

## See also

- [Workflow Control Plane]({{< relref "/security-remediation/control-plane" >}})
  - the workflow source of truth.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - the runtime enforcement contract.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - connector trust tiers and promotion criteria.
- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  - context provenance, retrieval policy, source hashes, and workflow context packages.
- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
  - non-human identity and delegated authority.
- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}})
  - adversarial eval coverage.
- [Agentic Readiness Scorecard]({{< relref "/security-remediation/agentic-readiness-scorecard" >}})
  - the scale, pilot, gate, or block decision layer.
