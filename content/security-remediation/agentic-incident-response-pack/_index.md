---
title: Agentic Incident Response Pack
linkTitle: Incident Response Pack
weight: 14
date: 2026-05-04
lastmod: 2026-11-12
sidebar:
  exclude: true
description: >
  A generated incident response, containment, forensics, replay, and
  disclosure pack for secure-context and MCP-backed agentic AI failures.
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**What this is.** SecurityRecipes should not stop at prevention. This
pack gives an enterprise team a deterministic way to classify an
agentic incident, correlate run receipts and context hashes, contain MCP
authority, preserve evidence, replay the failure, and produce a
trust-center-ready readout.
{{< /callout >}}

Rechecked source anchors on November 12, 2026 against the public MCP specification [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28), the current [security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices), NIST's [August 27, 2026 agent identity guidance](https://www.nist.gov/blogs/cybersecurity-insights/back-future-why-agentic-ai-needs-strong-identity-foundation), NIST's [October 27, 2026 design tenets for agent identity management systems](https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems), and NIST CAISSI, NSA SISC, and CISA's [October 16, 2026 key practices for incident readiness and response in super intelligence training and evaluation](https://www.nist.gov/news-events/news/2026/10/key-practices-incident-readiness-and-response-super-intelligence-training) (PP-26-4396 Ver 1.0). MCP `latest` still redirects to 2026-07-28. The practices distinguish SI control incidents (significant uninstructed actions that compromise operator-imposed policies, controls, or human oversight) from instructed or injection-driven events. Practice 3.3 requires that agents cannot access or interfere with monitoring processes and logs. Practice 6.1 requires shutdown policies for unintended activity, control failures, and monitor outages or tampering. Practice 5.1 requires preserving rejected actions and tool calls. Practice 7.3 requires verifying monitors, logging, egress allowlists, and shutdown mechanisms before resuming agent activity. The audience is SI training and evaluation; the practices may also apply to deployers. This editorial pass does not claim human review of the pack.

## The product bet

SecurityRecipes is positioned as **The Secure Context Layer for
Agentic AI**. A credible secure context layer must answer two questions:

- Can the platform prevent unsafe context, authority, and tool use
  before an agent acts?
- When prevention fails, can the platform prove what happened, contain
  authority, and replay the failure before the workflow scales again?

The **Agentic Incident Response Pack** fills that second gap. It turns
the generated control-plane evidence into a response model for
context-poisoning, MCP tool misuse, authorization confused-deputy
events, token passthrough, agent handoff leakage, memory or skill
compromise, high-impact autonomy near misses, uninstructed
control-compromise, and receipt integrity gaps.

This makes AI easier for enterprises because SOC, AI platform, security
engineering, GRC, and procurement teams can inspect one machine-readable
artifact instead of reverse-engineering a failure from chat transcripts.

{{< playbook-workflow >}}

## What was added

- `data/assurance/agentic-incident-response-profile.json` - source
  contract for incident classes, response phases, required evidence,
  severity thresholds, standards alignment, and operational packaging.
- `data/evidence/agentic-incident-response-pack.json` - generated
  incident response pack for MCP clients, CI drift checks, and reviewer
  diligence.
- `recipes_agentic_incident_response_pack` - MCP lookup by incident
  class, workflow, severity, or response decision.



Evaluate a token passthrough incident:

```bash
python3 scripts/evaluate_agentic_incident_response_decision.py \
  --incident-id inc-ci-token \
  --workflow-id vulnerable-dependency-remediation \
  --run-id run-ci-token \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --tenant-id tenant-demo \
  --correlation-id corr-ci-token \
  --incident-class-id mcp-authorization-confused-deputy \
  --severity-signal sev1 \
  --source-event-id event-authz-1 \
  --receipt-id receipt-ci-token \
  --context-source-id workflow-manifest \
  --context-source-hash hash-ci \
  --mcp-namespace repo.contents \
  --authorization-decision allow_authorized_mcp_request \
  --containment-action-id freeze_mcp_namespace_or_scope \
  --indicator raw_token_passthrough \
  --token-passthrough \
  --expect-decision kill_session_and_escalate_board
```

Evaluate uninstructed control-compromise when an agent can reach monitors:

```bash
python3 scripts/evaluate_agentic_incident_response_decision.py \
  --incident-id inc-ci-monitors \
  --workflow-id vulnerable-dependency-remediation \
  --run-id run-ci-monitors \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --tenant-id tenant-demo \
  --correlation-id corr-ci-monitors \
  --incident-class-id uninstructed-control-compromise \
  --severity-signal sev1 \
  --source-event-id event-monitor-1 \
  --receipt-id receipt-ci-monitors \
  --context-source-id workflow-manifest \
  --context-source-hash hash-ci \
  --mcp-namespace repo.contents \
  --authorization-decision allow_authorized_mcp_request \
  --containment-action-id isolate_monitors_from_agent_access \
  --agent-can-access-monitors \
  --expect-decision kill_session_and_escalate_board
```

Hold resume until monitors, logging, egress allowlists, and shutdown mechanisms are verified. Context-poisoning at sev3 monitors without the flag and holds when resume is requested before containment is verified:

```bash
python3 scripts/evaluate_agentic_incident_response_decision.py \
  --incident-id inc-ci-resume \
  --workflow-id vulnerable-dependency-remediation \
  --run-id run-ci-resume \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --tenant-id tenant-demo \
  --correlation-id corr-ci-resume \
  --incident-class-id context-poisoning \
  --severity-signal sev3 \
  --source-event-id event-resume-1 \
  --receipt-id receipt-ci-resume \
  --context-source-id workflow-manifest \
  --context-source-hash hash-ci \
  --mcp-namespace repo.contents \
  --authorization-decision allow_authorized_mcp_request \
  --containment-action-id pause_agent_run \
  --replay-case-id replay-ci-resume \
  --resume-without-verified-containment \
  --expect-decision hold_for_forensics
```

## What is inside

| Section | Purpose |
| --- | --- |
| `incident_response_summary` | Class counts, response phase counts, workflow coverage, decision distribution, severe incident coverage, required evidence count, and source failure count. |
| `incident_contract` | Default fail-closed state, required runtime fields, required evidence sources, and severity thresholds for SEV0 through SEV3. |
| `incident_classes` | Response models for context poisoning, MCP tool misuse, identity abuse, token passthrough, handoff leakage, memory or skill compromise, high-impact autonomy, uninstructed control-compromise, and evidence gaps. |
| `response_phases` | Detect, contain, preserve, eradicate, replay, recertify, disclose, and learn phases mapped to minimum evidence and MCP tools. |
| `workflow_response_matrix` | Per-workflow incident classes, severity floor, containment actions, readiness state, risk tier, MCP namespaces, and replay requirements. |
| `tabletop_cases` | Ready-made tabletop cases for poisoned context, token forwarding, production writes without approval, uninstructed control-compromise, and missing receipts after drift. |
| `source_artifacts` | Hashes and paths for the source evidence packs used to build the incident response model. |

## MCP examples

Get the executive summary and workflow matrix:

```json
{}
```

Inspect a specific incident class:

```json
{
  "incident_class_id": "mcp-authorization-confused-deputy"
}
```

Inspect incident response coverage for a workflow:

```json
{
  "workflow_id": "artifact-cache-quarantine"
}
```

Find SEV0-class response surfaces:

```json
{
  "severity": "sev0"
}
```

Evaluate one runtime incident signal:

```json
{
  "incident_id": "inc-2026-ctx-001",
  "workflow_id": "sensitive-data-remediation",
  "run_id": "run-ctx-001",
  "agent_id": "sr-agent::sensitive-data-remediation::codex",
  "identity_id": "sr-agent::sensitive-data-remediation::codex",
  "tenant_id": "tenant-a",
  "correlation_id": "corr-ctx-001",
  "incident_class_id": "context-poisoning",
  "severity_signal": "sev1",
  "source_event_ids": ["poisoning-finding-1"],
  "receipt_id": "receipt-ctx-001",
  "context_source_hashes": ["sha256:example"],
  "mcp_namespaces": ["findings.sde", "repo.contents"],
  "authorization_decisions": ["allow_authorized_mcp_request"],
  "containment_action_ids": ["hold_context_source_promotion"],
  "indicators": ["critical_poisoning_finding"]
}
```

## Why it is review-ready

The prevention layer creates trust. The incident layer creates
operational confidence.

The site should not be only a documentation archive or recipe catalog.
It needs a control-plane story that a security team can inspect, run,
and improve. Agentic incident response becomes useful when the open
evidence can support:

- hosted run-receipt vault,
- SIEM and SOAR exports,
- signed incident evidence bundles,
- MCP kill-switch automation,
- customer trust-center incident readouts,
- continuous replay of incident-derived eval cases,
- workflow recertification gates after context, connector, model, or
  policy drift.

That is a credible trusted-source layer around the open knowledge base:
public guidance creates distribution, generated evidence creates trust,
and hosted response automation remains a later deployment concern.

## Industry alignment

The pack is anchored in current primary guidance:

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
  for incident response integrated with CSF 2.0 risk management.
- [NIST SI Agent Standards Initiative](https://www.nist.gov/super-intelligence/si-agent-standards-initiative)
  for agent identity, open protocols, secure multi-agent interactions,
  and security evaluations.
- [CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for prompt injection, data poisoning, misaligned action, measurement,
  and deployment interventions that constrain and monitor agent access.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for operational risks in agents that plan, act, make decisions, and
  execute across complex workflows.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  for protected resource metadata, OAuth 2.1, audience binding, token
  handling, confused-deputy prevention, and scope restriction.
- [CISA Joint Guidance on Deploying AI Systems Securely](https://www.cisa.gov/news-events/alerts/2024/04/15/joint-guidance-deploying-ai-systems-securely)
  for controls to protect, detect, and respond to malicious activity
  against AI systems and related data and services.
- [NIST CAISSI, NSA SISC, and CISA key practices for SI incident readiness](https://www.nist.gov/news-events/news/2026/10/key-practices-incident-readiness-and-response-super-intelligence-training)
  for uninstructed control-compromise, monitor isolation, shutdown on
  monitor tampering or outage, preservation of rejected actions, and
  verified containment before resume.
- [Careful Adoption of Agentic AI Services](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-si-services)
  for privilege creep, behavioral misalignment, obscure event records,
  and starting with low-risk non-sensitive use cases.
- [MCP Authorization Security Considerations (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
  for normative token-audience, PKCE, token-theft, mix-up, and
  confused-deputy requirements used in MCP token-misuse triage.
- [Design Tenets for Agent Identity Management Systems](https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems)
  for identity-incident and evidence-integrity signals around attenuated
  delegation, zero standing privilege, and independent append-only evidence.

## See also

- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Agentic Catastrophic Risk Annex]({{< relref "/security-remediation/agentic-catastrophic-risk-annex" >}})
- [Agentic Exposure Graph]({{< relref "/security-remediation/agentic-exposure-graph" >}})
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Agent Handoff Boundary]({{< relref "/security-remediation/agent-handoff-boundary" >}})
