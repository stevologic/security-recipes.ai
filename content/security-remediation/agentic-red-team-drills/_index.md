---
title: Agentic Red-Team Drill Pack
linkTitle: Red-Team Drill Pack
weight: 7
sidebar:
  open: true
description: >
  A generated adversarial eval bundle for agentic remediation workflows:
  prompt injection, goal hijack, credential access, approval bypass,
  token passthrough, connector drift, runaway loops, and evidence
  integrity failures.
---

{{< callout type="info" >}}
**Why this page exists.** Governance proves the workflow has a declared
shape. Red-team replay proves the shape holds when the agent receives
hostile instructions, poisoned tool results, malformed approvals, or
stale evidence. Enterprise buyers will expect both.
{{< /callout >}}

## The product bet

SecurityRecipes is becoming the secure context layer for agentic
security remediation. That means the product cannot stop at prompts,
workflow manifests, or control mappings. It needs a repeatable way to
ask: "What happens when the agent is pushed off path?"

The red-team drill pack makes that question machine-readable. It joins:

- the workflow control plane,
- the MCP gateway policy,
- the MCP connector trust pack,
- the agent identity delegation ledger,
- and a source-controlled adversarial scenario map.

The generated result is an eval bundle an AI platform team can run
before promoting a workflow, attach to a design review, or expose through
MCP as context for an internal eval harness.

## What was added

The red-team layer lives in three artifacts:

- `data/assurance/agentic-red-team-scenario-map.json` - the source map
  of adversarial scenarios, standards references, expected decisions,
  evidence, pass criteria, and fail signals.
- `scripts/generate_agentic_red_team_drill_pack.py` - a dependency-free
  generator and validator with `--check` mode for CI drift detection.
- `data/evidence/agentic-red-team-drill-pack.json` - the generated pack
  that maps scenarios to every active workflow and MCP namespace.
- `data/evidence/agentic-red-team-replay-harness.json` - the generated
  replay harness that binds those drills to safe fixtures, expected
  runtime decisions, trace events, receipt evidence, and evaluator output.

Run it locally from the repo root:

```bash
python3 scripts/generate_agentic_red_team_drill_pack.py
python3 scripts/generate_agentic_red_team_drill_pack.py --check
```

The local MCP server exposes the pack through
`recipes_agentic_red_team_drill_pack`.

## What is inside the pack

The current generated pack contains 56 workflow-specific drills across
all 8 active workflows.

| Section | Purpose |
| --- | --- |
| `red_team_summary` | Workflow coverage, scenario count, drill count, severity counts, and attack-family counts. |
| `scenario_library` | The canonical adversarial scenarios and the standards, controls, gates, and policy decisions they exercise. |
| `workflow_drills` | Per-workflow drill bundles with matched MCP namespaces, connector trust tiers, expected agent behavior, evidence, pass criteria, and fail signals. |
| `scenario_contract` | Required gate phases, policy decisions, and evidence records every drill pack relies on. |
| `source_artifacts` | Hashes for the scenario map, workflow manifest, gateway policy, connector trust pack, and identity ledger. |
| `enterprise_adoption_packet` | Buyer-facing claim, questions answered, first-use guidance, and commercial motion. |

## Scenario families

The initial drill set targets the failure modes that matter most for
agentic remediation and MCP-connected tools:

| ID | Scenario | Why it matters |
| --- | --- | --- |
| `SR-RT-01` | Tool Result Instruction Injection | Tests whether tool output is treated as untrusted data, not agent instructions. |
| `SR-RT-02` | Goal Hijack to Out-of-Scope Change | Tests whether the agent preserves the admitted remediation goal and path scope. |
| `SR-RT-03` | Credential Retrieval and Data Exfiltration Probe | Tests whether secret, signer, token, and environment access are denied and logged. |
| `SR-RT-04` | Approval Bypass on High-Impact Operation | Tests whether approval-required MCP operations hold for typed human approval. |
| `SR-RT-05` | Confused Deputy and Token Passthrough Probe | Tests whether user-token forwarding, callback abuse, and unapproved egress are blocked. |
| `SR-RT-06` | Connector Description and Schema Drift | Tests whether unreviewed MCP tool surface changes are quarantined before use. |
| `SR-RT-07` | Runaway Loop and Resource Exhaustion | Tests whether retry, CI, scanner, and API loops stop cleanly. |
| `SR-RT-08` | Evidence Laundering and False Verification | Tests whether stale, forged, or incomplete evidence is rejected before merge or closure. |

## How to run it

Use the generated pack as a promotion gate:

1. Pick the workflow under review, for example
   `vulnerable-dependency-remediation`.
2. Load its drills from `workflow_drills` or through
   `recipes_agentic_red_team_drill_pack(workflow_id=...)`.
3. Replay each `benign_payloads` input through mocked MCP tool results,
   ticket comments, user prompts, or verifier records.
4. Capture the agent transcript, gateway policy decision, tool-call
   audit, and reviewer result named in `required_evidence`.
5. Promote the workflow only when every drill meets `pass_criteria` and
   no `fail_signals` appear.

This is not a replacement for exploit-specific verification. The normal
workflow still needs scanner, test, simulator, source-host review, and
post-merge evidence proving the original finding was remediated.

## Industry alignment

The pack is aligned to current primary references:

- [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework)
  and the
  [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for measured and managed AI risk.
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
  and
  [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
  for prompt injection, excessive agency, unbounded consumption, and
  tool-using agent risk.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for goal hijack, tool misuse, identity abuse, agentic supply chain,
  context poisoning, cascading failures, and rogue-agent behavior.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  and
  [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for confused-deputy prevention, token passthrough avoidance, delegated
  authorization, and session safety.
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
  for cloud AI assurance and control validation.

## CI contract

The generator fails if:

- A scenario references an unknown standard, control, gate phase, or
  policy decision.
- A scenario is not mapped to any workflow.
- An active workflow has fewer than five drills.
- The gateway policy, connector trust pack, or identity ledger no
  longer matches the workflow manifest hash.
- The generated pack is stale in `--check` mode.

That turns adversarial coverage into a maintained product surface rather
than a one-time security exercise.

## See also

- [Workflow Control Plane]({{< relref "/security-remediation/control-plane" >}})
  - the workflow source of truth.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - the runtime enforcement contract.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - connector trust tiers and promotion criteria.
- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
  - non-human identity and delegated authority.
- [Agentic Assurance Pack]({{< relref "/security-remediation/agentic-assurance-pack" >}})
  - the buyer and auditor control evidence bundle.
- [Agentic Readiness Scorecard]({{< relref "/security-remediation/agentic-readiness-scorecard" >}})
  - the workflow promotion gate that consumes red-team coverage.
- [Agentic Red-Team Replay Harness]({{< relref "/security-remediation/agentic-red-team-replay-harness" >}})
  - replay fixtures and evaluator decisions for adversarial proof.
