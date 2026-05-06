---
title: Critical Infrastructure Secure Context Profile
linkTitle: Critical Infrastructure Profile
weight: 19
toc: true
description: >
  Generated critical-infrastructure readiness profile for agentic AI and
  MCP: sector hazard mapping, secure-context evidence, operator approval,
  safety-case gates, telemetry, incident response, and deterministic
  runtime decisions.
---

{{< callout type="info" >}}
**What this is.** A critical-infrastructure readiness layer for the
Secure Context Layer thesis. It turns current NIST, OWASP, CISA, and MCP
guidance into generated evidence and a runtime evaluator before agents
retrieve context or act near high-stakes systems.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. That position is more credible if the project can answer the
hardest enterprise question: "Can this help us pilot agents in critical
infrastructure without weakening safety, availability, privacy,
oversight, or incident response?"

The **Critical Infrastructure Secure Context Profile** is the answer. It
does not claim compliance with a future NIST profile. It creates an
enterprise-ready scaffold now: sector profiles, hazard flags, required
evidence, rollout lanes, buyer views, and deterministic allow, hold,
deny, or kill decisions.

## Generated artifact

- Source model:
  `data/assurance/critical-infrastructure-secure-context-profile.json`
- Generator:
  `scripts/generate_critical_infrastructure_secure_context_pack.py`
- Evidence pack:
  `data/evidence/critical-infrastructure-secure-context-pack.json`
- Runtime evaluator:
  `scripts/evaluate_critical_infrastructure_context_decision.py`
- MCP tools:
  `recipes_critical_infrastructure_secure_context_pack`,
  `recipes_evaluate_critical_infrastructure_context_decision`

Regenerate and validate the pack:

```bash
python3 scripts/generate_critical_infrastructure_secure_context_pack.py
python3 scripts/generate_critical_infrastructure_secure_context_pack.py --check
```

Evaluate a read-only pilot decision:

```bash
python3 scripts/evaluate_critical_infrastructure_context_decision.py \
  --sector-id energy-ot-ics \
  --workflow-id vulnerable-dependency-remediation \
  --action-class read_only_context \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --run-id ci-readonly \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --tenant-id ci-tenant \
  --context-package-hash sha256:context \
  --authorization-decision allow_authorized_mcp_request \
  --egress-decision allow_internal_context \
  --expect-decision allow_ci_read_only_context
```

Evaluate a held high-impact action:

```bash
python3 scripts/evaluate_critical_infrastructure_context_decision.py \
  --sector-id energy-ot-ics \
  --workflow-id base-image-remediation \
  --action-class critical_infrastructure_control \
  --agent-id sr-agent::base-image-remediation::codex \
  --run-id ci-hold \
  --identity-id sr-agent::base-image-remediation::codex \
  --tenant-id ci-tenant \
  --context-package-hash sha256:context \
  --authorization-decision allow_authorized_mcp_request \
  --egress-decision allow_internal_context \
  --flag affects_ot_or_ics=true \
  --expect-decision hold_for_ci_safety_case
```

## Why this matters now

NIST's April 2026 concept note says critical infrastructure will
increasingly rely on AI across IT, OT, and ICS, and that the profile will
help operators communicate trustworthiness requirements across AI and CI
lifecycles and supply chains. That is exactly where SecurityRecipes can
be useful: not by claiming agents are safe, but by forcing context,
authorization, operator approval, telemetry, and incident evidence to
exist before agents act.

This profile also reflects current MCP security guidance:

- protected MCP calls need authorization, resource metadata, and scope
  minimization;
- token passthrough, shadow MCP servers, unsafe local launches, and raw
  secret access are kill signals;
- read-only context pilots are the default starting lane;
- high-impact action classes require operator approval, a safety-case id,
  risk acceptance, receipt evidence, and severe-risk clearance.

## Sector profiles

| Sector | Default decision | Why it is high stakes |
| --- | --- | --- |
| Energy, OT, and ICS | `hold_for_ci_safety_case` | Process control, grid reliability, safety interlocks, vendor remote access, and maintenance windows. |
| Healthcare and public health | `hold_for_ci_safety_case` | Regulated health data, care operations, clinical workflow availability, and emergency coordination. |
| Financial services | `hold_for_ci_safety_case` | Funds movement, market impact, model-route risk, fraud monitoring, and regulated-data leakage. |
| Water and wastewater | `hold_for_ci_safety_case` | Treatment operations, remote access, field response, and public-service continuity. |
| Transportation systems | `hold_for_ci_safety_case` | Passenger safety, logistics availability, signaling support, maintenance, and continuity. |
| Communications, cloud, and DNS | `hold_for_ci_safety_case` | Cross-sector dependencies, routing, identity, DNS, metadata services, and tenant isolation. |

## Runtime decisions

| Decision | Meaning |
| --- | --- |
| `allow_ci_read_only_context` | Read-only or evidence-only context has identity, authorization, egress, and context hash evidence. |
| `allow_ci_supervised_action` | A supervised action has sector safety-case evidence, operator approval, risk acceptance, receipt, authorization, egress, and severe-risk clearance. |
| `hold_for_ci_safety_case` | Sector, run, approval, safety-case, risk, receipt, or policy evidence is missing. |
| `deny_untrusted_ci_context` | Context is untrusted or lacks a context package hash. |
| `kill_session_on_ci_hazard_signal` | Token passthrough, shadow MCP, unsafe local launch, raw secret access, or another runtime hazard appeared. |

## Product strategy

This is a stronger enterprise story than another static checklist.

| Layer | Value |
| --- | --- |
| Open foundation | Public profile, generator, evidence pack, evaluator, docs, and MCP tools. |
| Production MCP server | Hosted sector profiles, authorization checks, safety-case lookup, receipts, and policy evaluation. |
| Design-partner wedge | Regulated teams can start with read-only context and prove whether agent evidence lowers review friction. |
| Acquisition fit | Frontier labs, cloud providers, and security platforms need a credible way to sell agents into high-stakes sectors. |

## MCP examples

Get the summary:

```json
{}
```

Get the energy profile:

```json
{
  "sector_id": "energy-ot-ics"
}
```

Evaluate a critical-infrastructure read-only context request:

```json
{
  "sector_id": "energy-ot-ics",
  "workflow_id": "vulnerable-dependency-remediation",
  "action_class": "read_only_context",
  "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
  "run_id": "ci-readonly",
  "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
  "tenant_id": "ci-tenant",
  "context_package_hash": "sha256:context",
  "authorization_decision": "allow_authorized_mcp_request",
  "egress_decision": "allow_internal_context"
}
```

## Source anchors

- [NIST AI RMF Profile on Trustworthy AI in Critical Infrastructure](https://www.nist.gov/programs-projects/concept-note-ai-rmf-profile-trustworthy-ai-critical-infrastructure)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [CISA Secure by Design](https://www.cisa.gov/securebydesign)

## See also

- [Agentic Catastrophic Risk Annex]({{< relref "/security-remediation/agentic-catastrophic-risk-annex" >}})
- [Agentic Action Runtime Pack]({{< relref "/security-remediation/agentic-action-runtime" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [MCP STDIO Launch Boundary]({{< relref "/security-remediation/mcp-stdio-launch-boundary" >}})
- [Agentic SOC Detection Pack]({{< relref "/security-remediation/agentic-soc-detection-pack" >}})
- [Agentic Incident Response Pack]({{< relref "/security-remediation/agentic-incident-response-pack" >}})
- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
