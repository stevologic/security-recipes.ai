---
title: Agentic Posture Snapshot
linkTitle: Agentic Posture Snapshot
weight: 12
toc: true
description: >
  Generated enterprise posture evidence for agentic AI systems across secure
  context, MCP tools, A2A handoffs, identity, skills, telemetry, exposure
  paths, readiness, standards, and buyer diligence.
---

{{< callout type="info" >}}
**Positioning.** Agentic security has become a posture-management problem:
which agents exist, what they can reach, how they are identified, which
context they consume, where high-autonomy and XPIA exposure meet, and
which evidence proves the current state. This pack turns the open
SecurityRecipes corpus into a posture snapshot a buyer can inspect.
{{< /callout >}}

## What this adds

The **Agentic Posture Snapshot** is the executive and platform-team rollup
for the Secure Context Layer. It does not replace the lower-level packs.
It joins them into one generated artifact:

- Agent and component inventory from the Agentic System BOM.
- Non-human identity, delegation, and authorization evidence.
- MCP connector trust, tool-risk, and session-combination risk.
- Secure-context provenance, poisoning findings, and egress policy.
- A2A Agent Card, handoff, and skill supply-chain controls.
- Runtime telemetry, run receipts, readiness, and exposure paths.
- Standards and buyer-diligence mapping for procurement and acquisition.

The result is a generated posture decision, workflow-level posture rows,
risk-factor summary, buyer views, and source hashes for every source pack.

## Why this is valuable

Enterprise buyers are no longer asking only whether an agent has a good
prompt. They are asking whether the agentic system has posture:

1. Which agents and identities exist?
2. Which MCP namespaces can those identities reach?
3. Which context sources are trusted, fresh, and non-secret?
4. Which paths combine untrusted input with high-impact actions?
5. Which human approvals, telemetry, and run receipts prove control?
6. Which standards and guidance does the control surface map to?

SecurityRecipes can now answer those questions with generated JSON instead
of product claims.

## Generated artifacts

```text
data/assurance/agentic-posture-model.json
data/evidence/agentic-posture-snapshot.json
scripts/generate_agentic_posture_snapshot.py
scripts/evaluate_agentic_posture_decision.py
```

Run the generator after changing any evidence pack that participates in
the posture view:

```bash
python3 scripts/generate_agentic_posture_snapshot.py
python3 scripts/generate_agentic_posture_snapshot.py --check
```

Evaluate a runtime posture event:

```bash
python3 scripts/evaluate_agentic_posture_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --namespace repo.contents \
  --expect-decision allow_with_posture_monitoring
```

Hold high-autonomy XPIA-sensitive execution until a human approval exists:

```bash
python3 scripts/evaluate_agentic_posture_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --namespace repo.contents \
  --autonomy-level autonomous \
  --indirect-prompt-injection-risk high \
  --expect-decision hold_for_xpia_human_review
```

## Decision model

The snapshot scores eight posture dimensions:

- **Agent and Component Inventory** - workflows, agents, identities, MCP
  connectors, evidence artifacts, and context sources.
- **Identity and Delegated Authority** - non-human identities, explicit
  denies, token rules, MCP authorization, and revocation.
- **MCP Tool Surface Control** - connector trust, tool-risk, session
  combination, annotation trust, and exfiltration paths.
- **Context Integrity and Egress** - provenance, hashes, poisoning
  findings, freshness, data classes, and egress controls.
- **Inter-Agent and Skill Boundary** - handoffs, A2A Agent Cards, and
  agent skills as untrusted supply-chain inputs.
- **Runtime Guardrails and Telemetry** - tool-call traces, run receipts,
  redaction, incident linkage, and replay evidence.
- **Exposure Path Management** - risk-ranked paths across context,
  identities, MCP namespaces, and workflow maturity.
- **Standards and Buyer Diligence** - current OWASP, NIST, MCP, OpenAI,
  A2A, and posture-management guidance mapped to SecurityRecipes evidence.

Global posture decisions are:

- `enterprise_foundation_ready`
- `guarded_enterprise_pilot`
- `hold_for_posture_review`
- `kill_session_on_posture_signal`

Workflow posture decisions are:

- `scale_with_posture_monitoring`
- `guarded_pilot`
- `architecture_review`

## MCP surface

The MCP server exposes:

- `recipes_agentic_posture_snapshot`
- `recipes_evaluate_agentic_posture_decision`

Use the snapshot tool for board, platform, procurement, and acquirer
questions. Use the evaluator before a runtime event crosses a posture
boundary, especially when high-autonomy agents touch untrusted content,
pilot MCP connectors, A2A Agent Cards, or approval-required namespaces.

## Current industry alignment

This feature is intentionally aligned with current industry movement:

- OWASP Agentic AI work makes agent goal hijack, tool misuse, identity
  abuse, supply chain, memory/context poisoning, insecure inter-agent
  communication, cascading failures, human-agent trust exploitation, and
  rogue agents first-class risks.
- OWASP Agentic Skills guidance treats skills as the execution layer and
  calls for inventory, publisher verification, scanning, isolation,
  network controls, and audit logging.
- MCP authorization guidance treats HTTP MCP servers as protected resource
  servers and pushes OAuth resource/audience binding, token handling, and
  confused-deputy controls.
- OpenAI Agents SDK guardrails distinguish input, output, and tool
  guardrails, with tool guardrails applied around function-tool calls.
- A2A formalizes Agent Cards, remote agent discovery, interoperability,
  authentication, and observability as multi-agent systems mature.
- Microsoft has framed agent posture around XPIA risk, high autonomy,
  coordinator agents, risk factors, and attack-path visibility.

## What to look at first

For a buyer or acquirer, start with:

1. `posture_summary` - the single posture score and decision.
2. `risk_factor_summary` - XPIA, high-exposure, pilot connector, skill,
   and context-poisoning signals.
3. `workflow_posture` - which workflows can scale, stay guarded, or need
   architecture review.
4. `source_artifacts` - hashes proving which generated packs produced the
   answer.
5. `commercialization_path` - how the open evidence becomes hosted MCP,
   private evidence overlays, and trust-center APIs.

