---
title: Agentic AIVSS Risk Scoring
linkTitle: Agentic AIVSS Risk Scoring
weight: 13
toc: true
description: >
  Generated AIVSS-aligned severity, SLA, remediation-priority, and
  deterministic runtime decisions for agentic AI, MCP, A2A, skill,
  identity, context, and approval-bypass risks.
---

{{< callout type="info" >}}
**Positioning.** SecurityRecipes already produces posture, exposure,
control, and trust evidence. The missing buyer surface was quantitative
severity: which agentic risks are critical, who owns them, what SLA
applies, and what a runtime gate should do. This pack turns current
agentic AI security guidance into generated scoring evidence.
{{< /callout >}}

## What this adds

The **Agentic AIVSS Risk Scoring Pack** is the prioritization layer for
the Secure Context Layer. It maps emerging agentic risks into:

- A reproducible 0-10 AIVSS-aligned risk score.
- Severity bands: `critical`, `high`, `medium`, and `low`.
- Runtime default decisions: monitor, guarded receipt, human review,
  deny pending remediation, or kill-session.
- Remediation SLA and owner guidance.
- Evidence keys linking each risk to generated SecurityRecipes packs.
- Hosted MCP wedges that describe the production product surface.

The pack is intentionally conservative: it is **AIVSS-aligned**, not an
official OWASP calculator. The scoring vector is source-controlled so
teams can inspect and fork the assumptions.

## Generated artifacts

```text
data/assurance/agentic-aivss-risk-scoring-profile.json
data/evidence/agentic-aivss-risk-scoring-pack.json
scripts/generate_agentic_aivss_risk_scoring_pack.py
scripts/evaluate_agentic_aivss_risk_decision.py
```

Run the generator after posture, exposure, MCP, skill, approval, action,
or incident evidence changes:

```bash
python3 scripts/generate_agentic_aivss_risk_scoring_pack.py
python3 scripts/generate_agentic_aivss_risk_scoring_pack.py --check
```

Evaluate a runtime event:

```bash
python3 scripts/evaluate_agentic_aivss_risk_decision.py \
  --scenario-id mcp_tool_misuse_lethal_session \
  --expect-decision hold_for_human_security_review
```

Kill an unsafe high-autonomy event:

```bash
python3 scripts/evaluate_agentic_aivss_risk_decision.py \
  --scenario-id agent_goal_hijack_context_poisoning \
  --autonomy-level autonomous \
  --untrusted-context \
  --external-write \
  --exfiltration-capable-tool \
  --expect-decision kill_session_on_agentic_aivss_signal
```

## Risk scenarios

The profile scores nine high-value enterprise scenarios:

- Agent goal hijack through poisoned context.
- MCP tool misuse in a lethal session combination.
- Identity and privilege abuse by an agent.
- Agentic supply chain or skill compromise.
- Unexpected code execution through tool or skill paths.
- Insecure inter-agent handoff or remote agent trust.
- Cascading failure or runaway agent operation.
- Human-agent trust exploitation or approval bypass.
- Rogue agent or shadow MCP server.

Each score includes recommended controls, evidence keys, owner, SLA, and
a hosted MCP wedge that makes the open evidence commercially useful.

## Current industry alignment

This pack tracks the strongest current source signals:

- [OWASP AIVSS v0.8](https://aivss.owasp.org/) for AI-specific risk
  scoring.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
  for goal hijack, tool misuse, identity abuse, supply chain,
  unexpected execution, context poisoning, inter-agent failure,
  cascading failure, trust exploitation, and rogue agents.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) for
  protocol-layer token, scope, tool, command, authorization, telemetry,
  shadow-server, and context-sharing risks.
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
  for the behavior and execution layer that sits between model intent
  and real tool authority.
- [NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for govern, map, measure, and manage expectations.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, audience binding, token handling, and scope
  minimization.

## MCP surface

The MCP server exposes:

- `recipes_agentic_aivss_risk_scoring_pack`
- `recipes_evaluate_agentic_aivss_risk_decision`

Use the pack tool for buyer, platform, and remediation-priority review.
Use the evaluator before a gateway or agent host allows high-autonomy
execution, external writes, untrusted context, shadow MCP servers,
unregistered agents, or unpinned skills.

## What to look at first

For enterprise or acquisition diligence, start with:

1. `severity_summary` - critical/high counts and runtime decision mix.
2. `risk_scores` - the scored risk scenarios and owners.
3. `remediation_queue` - the prioritized critical/high worklist.
4. `source_artifacts` - hashes for the evidence used in scoring.
5. `hosted_mcp_wedges` - the productizable path from open evidence to
   production MCP enforcement.
