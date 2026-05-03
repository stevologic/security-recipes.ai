---
title: Agentic Readiness Scorecard
linkTitle: Readiness Scorecard
weight: 7
sidebar:
  open: true
description: >
  A generated enterprise promotion gate that turns workflow, MCP policy,
  connector trust, identity, assurance, and red-team evidence into
  scale, pilot, gate, or block decisions.
---

{{< callout type="info" >}}
**Why this page exists.** Enterprise buyers do not need another static
maturity label. They need a decision surface: which agentic remediation
workflows can scale now, which remain pilot-only, which require manual
approval, and which are blocked by missing evidence.
{{< /callout >}}

## The product bet

SecurityRecipes is strongest when it is the secure context layer that
makes agentic remediation easy to approve. The
[Workflow Control Plane]({{< relref "/security-remediation/control-plane" >}})
declares what a workflow may do. The
[MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
turns that scope into runtime decisions. The
[Agentic Assurance Pack]({{< relref "/security-remediation/agentic-assurance-pack" >}})
explains the control story. The readiness scorecard turns all of that
evidence into an adoption decision.

That matters for an enterprise or acquirer because agentic AI programs
are moving from pilots to platform rollout. The hard question is no
longer "can an agent fix this?" It is "which agentic workflows can we
scale without inventing new governance every time?"

## What was added

The readiness layer lives in source-controlled and generated artifacts:

- `data/assurance/agentic-readiness-model.json` - the scoring model,
  weights, scale gates, blockers, and industry references.
- `scripts/generate_agentic_readiness_scorecard.py` - a deterministic
  generator with `--check` mode for CI drift detection.
- `data/evidence/agentic-readiness-scorecard.json` - the generated
  scale, pilot, gate, or block decision artifact.
- `recipes_agentic_readiness_scorecard` - the MCP tool that exposes
  readiness decisions to agents, AI platform portals, and internal
  control dashboards.

Run it locally from the repo root:

```bash
python3 scripts/generate_agentic_readiness_scorecard.py
python3 scripts/generate_agentic_readiness_scorecard.py --check
```

## What is inside the scorecard

The generated scorecard includes:

| Section | Purpose |
| --- | --- |
| `readiness_summary` | Workflow counts, average score, decision counts, pilot connector dependencies, and failure count. |
| `workflow_readiness` | Per-workflow decision, score, dimension scores, blockers, connector status, identity count, drill count, and next actions. |
| `score_dimensions` | The weighted model used to score control plane, gateway policy, identity, connector trust, adversarial eval, evidence chain, and maturity. |
| `decision_contract` | The thresholds for `scale_ready`, `pilot_guarded`, `manual_gate`, and `blocked`. |
| `scale_plan` | 30- and 90-day operating recommendations for enterprise rollout. |
| `source_artifacts` | Hashes for every artifact used to produce the decision. |

The current generated pack produces four useful expansion lanes:

| Decision | Meaning |
| --- | --- |
| `scale_ready` | Ready for controlled enterprise expansion with standard change controls. |
| `pilot_guarded` | Approved for bounded use, but broad rollout waits on maturity, pilot connector promotion, or exit metrics. |
| `manual_gate` | Human program owner must approve before use. |
| `blocked` | Do not run until blockers are remediated. |

## Why this is industry aligned

The scorecard is mapped to current primary references:

- [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework),
  including the 2026 direction toward trustworthy AI in critical
  infrastructure, for governed, measured, and managed AI risk.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for generative AI lifecycle, third-party, and data-boundary risk.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for autonomous systems that plan, act, and make decisions across
  complex workflows.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  for confused-deputy, token-passthrough, SSRF, session, local-server,
  and scope-minimization risks.
- [CISA Secure by Design](https://www.cisa.gov/securebydesign) for
  secure defaults, transparency, executive ownership, and measurable
  security outcomes.
- [OWASP AIBOM](https://owaspaibom.org/) for AI system inventory and
  transparency readiness.

## How to use it

For an AI platform review, start with `readiness_summary`. It tells the
platform which workflows can scale and which remain pilot guarded.

For a workflow owner, inspect `workflow_readiness[*].next_actions`. It
turns a high-level score into the concrete promotion work: graduate pilot
connectors, keep crawl-stage workflows inside a pilot cohort, or resolve
blockers.

For a procurement or diligence review, attach the scorecard with the
assurance pack, gateway policy, identity ledger, and red-team drill pack.
The scorecard gives reviewers the adoption decision; the source artifact
hashes show where the decision came from.

For MCP consumers, call:

```text
recipes_agentic_readiness_scorecard(decision="scale_ready")
recipes_agentic_readiness_scorecard(workflow_id="vulnerable-dependency-remediation")
recipes_agentic_readiness_scorecard(minimum_score=95)
```

## CI contract

The generator fails if:

- The readiness model weights do not sum to 100.
- Generated source hashes drift from the workflow manifest.
- Gateway policy no longer defaults to deny.
- Any generated evidence pack reports validation failures.
- A checked-in scorecard is stale in `--check` mode.

That is the enterprise-ready bar: scale decisions cannot drift from the
evidence that justifies them.

## See also

- [Agentic Assurance Pack]({{< relref "/security-remediation/agentic-assurance-pack" >}})
  - the buyer and auditor control narrative.
- [Agent Capability Risk Register]({{< relref "/security-remediation/agent-capability-risk-register" >}})
  - the capability and residual-risk view before MCP access expands.
- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}})
  - the adversarial eval layer.
- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
  - the non-human identity contract.
- [Agentic System BOM]({{< relref "/security-remediation/agentic-system-bom" >}})
  - the inspectable inventory behind promotion and recertification decisions.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - the connector trust and promotion contract.
- [Rollout & Maturity Model]({{< relref "/security-remediation/maturity" >}})
  - the human operating model behind scale decisions.
