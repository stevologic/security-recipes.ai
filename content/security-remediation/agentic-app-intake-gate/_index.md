---
title: Agentic App Intake Gate
linkTitle: Agentic App Intake
weight: 5
toc: true
description: >
  A generated launch-review gate for agentic applications, agent hosts,
  and production MCP rollouts across autonomy, data, tools, memory,
  handoffs, guardrails, telemetry, and approval evidence.
---

{{< callout type="info" >}}
**What this adds.** SecurityRecipes now has an enterprise intake gate
for new agentic apps. It turns "can this AI launch?" into generated
evidence instead of a meeting full of vague claims about prompts.
{{< /callout >}}

## Product bet

SecurityRecipes is positioned as **the Secure Context Layer for Agentic
AI**. The next enterprise buying motion is not only "give my agent safe
context." It is "tell me whether this agentic app should exist, what it
can reach, and what proof is missing before production."

The Agentic App Intake Gate is the launch-review primitive for that
motion. It scores applications by:

- autonomy level and coordinator behavior;
- private, regulated, secret, or signer data exposure;
- MCP read, write, approval-required, and remote tool authority;
- indirect prompt injection exposure from web, tickets, logs, scanners,
  documents, advisories, and user content;
- persistent memory and A2A or remote-agent handoffs;
- guardrail evals, telemetry, run receipts, egress boundaries,
  authorization conformance, skill governance, and incident response;
- human approval and two-key review evidence for high-impact actions.

The result is a simple launch decision that AI platform, product
security, GRC, procurement, and acquisition reviewers can understand.

## Generated artifact

- Source profile:
  `data/assurance/agentic-app-intake-profile.json`
- Generator:
  `scripts/generate_agentic_app_intake_pack.py`
- Runtime evaluator:
  `scripts/evaluate_agentic_app_intake_decision.py`
- Evidence pack:
  `data/evidence/agentic-app-intake-pack.json`
- MCP tools:
  `recipes_agentic_app_intake_pack` and
  `recipes_evaluate_agentic_app_intake_decision`

Regenerate and validate:

```bash
python3 scripts/generate_agentic_app_intake_pack.py
python3 scripts/generate_agentic_app_intake_pack.py --check
```

Evaluate a guarded remediation agent host:

```bash
python3 scripts/evaluate_agentic_app_intake_decision.py \
  --app-id repository-remediation-agent-host \
  --deployment-environment enterprise_pilot \
  --egress-decision allow_internal_boundary \
  --authorization-decision allow_authorized_mcp_request \
  --telemetry-decision telemetry_ready \
  --human-approval-id approval-ci \
  --approver product-security \
  --approver service-owner \
  --two-key-review \
  --expect-decision approve_guarded_pilot
```

Block high-impact signer or production authority:

```bash
python3 scripts/evaluate_agentic_app_intake_decision.py \
  --app-id financial-operations-agent \
  --data-class live_signing_material \
  --external-write \
  --production-write \
  --expect-decision kill_session_on_launch_signal
```

## Decision model

| Decision | Meaning |
| --- | --- |
| `approve_reference_launch` | Read-only or open-reference agentic app can launch with normal evidence refresh. |
| `approve_guarded_pilot` | App can run only as a guarded pilot with approval, telemetry, egress, and run receipts. |
| `hold_for_agentic_app_security_review` | Architecture or security review is required before launch or expansion. |
| `deny_until_controls_exist` | High-risk app lacks required controls or must be redesigned before launch. |
| `kill_session_on_launch_signal` | Runtime launch request includes a hard-stop signal such as signer access, token passthrough, private-network egress, approval bypass, or autonomous high-impact action. |

## Why this is acquisition-relevant

This page gives the project an obvious enterprise product surface:

- hosted private app inventory;
- launch review APIs for AI platform teams;
- MCP gateway evidence ingestion;
- app-level posture diffs when tools, skills, prompts, memory, or Agent
  Cards change;
- procurement exports that show why an app is reference-safe, pilot-ready,
  review-only, or blocked;
- production policy packs a model provider or security vendor can embed
  into agent platforms.

That is the credible open-core path: open launch-review knowledge first,
then production MCP-backed intake, posture, policy, and trust-center APIs.

## Industry alignment

The gate is aligned with current 2026 agentic security direction:

- OWASP treats autonomous planning, tool misuse, identity abuse,
  memory/context poisoning, insecure inter-agent communication, cascading
  failures, and rogue-agent containment as first-class agentic risks.
- OWASP Agentic Skills guidance makes behavior packages part of the
  execution supply chain.
- MCP authorization now emphasizes protected-resource metadata,
  resource indicators, audience-bound tokens, PKCE, and token-passthrough
  prevention.
- OpenAI's Agents SDK guardrail model separates input, output, and tool
  guardrails, with tool guardrails needed around function-tool calls.
- Anthropic's Claude Code security guidance emphasizes read-only
  defaults, explicit approval, trust verification, sandboxing, and MCP
  server trust.
- CISA and NIST guidance keep the enterprise focus on data provenance,
  integrity, access control, monitoring, incident evidence, secure
  defaults, and governed AI risk management.

## See also

- [Agentic Posture Snapshot]({{< relref "/security-remediation/agentic-posture-snapshot" >}})
- [MCP Tool Risk Contract]({{< relref "/security-remediation/mcp-tool-risk-contract" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Agent Skill Supply Chain]({{< relref "/security-remediation/agent-skill-supply-chain" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
- [Agentic Action Runtime Pack]({{< relref "/security-remediation/agentic-action-runtime" >}})
