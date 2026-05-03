---
title: Agent Capability Risk Register
linkTitle: Capability Risk Register
weight: 8
sidebar:
  open: true
description: >
  A generated capability-based risk register that scores each agentic
  remediation workflow by system criticality, autonomy, MCP permissions,
  impact radius, compensating controls, and residual risk tier.
---

{{< callout type="info" >}}
**Why this page exists.** Enterprise AI approval cannot stop at
"the workflow is ready." It also needs to know how powerful the agent
capability is, how far a mistake can spread, and which controls reduce
the residual risk before MCP access scales.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the secure context layer for
agentic AI**, but credible enterprise adoption also needs a capability
risk view. A buyer approving an MCP-backed agent has to answer four
questions before the first rollout cohort:

- How critical is the system or workflow domain?
- How autonomous is the agent before the next human review point?
- What is the most powerful MCP permission the workflow can request?
- How far can a bad decision spread across repos, tenants, supply
  chain assets, or irreversible financial systems?

The Agent Capability Risk Register turns those questions into a
generated artifact. It gives security architecture, AI platform, GRC,
procurement, and diligence reviewers a simple residual risk tier:
`low`, `medium`, or `high`.

## What was added

The capability-risk layer has three artifacts and one MCP surface:

- `data/assurance/agent-capability-risk-model.json` - the
  source-controlled factor model, risk tiers, control credits, and
  standards mapping.
- `scripts/generate_agent_capability_risk_register.py` - a
  dependency-free generator with `--check` mode for CI drift detection.
- `data/evidence/agent-capability-risk-register.json` - the generated
  workflow-by-workflow risk register.
- `recipes_agent_capability_risk_register` - the MCP tool that exposes
  risk tiers, residual scores, and next actions to agents, AI platform
  portals, and internal control dashboards.

Run it locally from the repo root:

```bash
python3 scripts/generate_agent_capability_risk_register.py
python3 scripts/generate_agent_capability_risk_register.py --check
```

## What is inside the register

| Section | Purpose |
| --- | --- |
| `capability_risk_summary` | Workflow counts, average raw capability score, average residual score, tier counts, decision counts, and top-risk workflows. |
| `workflow_capability_risks` | Per-workflow dimensions, raw score, control credits, residual score, risk tier, guardrails, and next actions. |
| `factor_model` | The four capability dimensions: system criticality, AI autonomy, access permissions, and impact radius. |
| `control_credit_model` | Credits for readiness, default-deny gateway policy, connector coverage, red-team coverage, and runtime kill signals. |
| `risk_tiers` | Low, medium, and high residual-risk thresholds with operating decisions. |
| `source_artifacts` | Hashes for every artifact used to generate the decision. |

The register separates inherent capability risk from residual risk.
That distinction matters: a workflow can be inherently powerful, but
acceptable to pilot when default-deny MCP policy, production connector
coverage, red-team drills, human review, and runtime kill signals are
current.

## Industry alignment

This feature follows current primary guidance:

- [Cloud Security Alliance Capabilities-Based Risk Assessment](https://cloudsecurityalliance.org/press-releases/2025/11/13/cloud-security-alliance-introduces-new-tool-for-assessing-agentic-risk)
  for scoring autonomous systems by system criticality, AI autonomy,
  access permissions, and impact radius.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
  for agent behavior hijacking, tool misuse, identity and privilege
  abuse, and agentic supply-chain risk.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) for
  token exposure, scope creep, tool poisoning, command execution,
  insufficient authorization, audit gaps, shadow MCP servers, and
  context over-sharing.
- [Model Context Protocol Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
  for resource-bound tokens, audience validation, protected resource
  metadata, token handling, and PKCE expectations.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for lifecycle governance, measurement, provenance, monitoring,
  third-party, and incident-response risk.

## How to use it

For an AI platform review, start with high residual risk:

```text
recipes_agent_capability_risk_register(risk_tier="high")
```

For a workflow owner, inspect the workflow directly:

```text
recipes_agent_capability_risk_register(workflow_id="defi-blockchain-security")
```

For architecture review, ask for workflows above a residual threshold:

```text
recipes_agent_capability_risk_register(minimum_residual_score=35)
```

The output names the factors driving the score and the compensating
controls currently reducing it. That keeps the review focused on
concrete decisions instead of broad fear about agents.

## CI contract

The generator fails if:

- The factor model is missing any of the four capability dimensions.
- Risk tiers do not include low, medium, and high.
- Gateway policy, connector trust, red-team, or readiness evidence
  drifts from the workflow manifest.
- The gateway policy no longer defaults to deny.
- A checked-in register is stale in `--check` mode.

That is the enterprise bar for agentic capability risk: reviewers can
see the raw capability, the compensating controls, the residual tier,
the hashes behind the decision, and the next action before expanding
MCP access.

## See also

- [Agentic Readiness Scorecard]({{< relref "/security-remediation/agentic-readiness-scorecard" >}})
  - the generated workflow promotion gate.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - the runtime enforcement contract.
- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}})
  - the adversarial eval layer.
- [Agentic System BOM]({{< relref "/security-remediation/agentic-system-bom" >}})
  - the inspectable inventory behind capability review.
- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  - the source provenance and retrieval trust layer.
