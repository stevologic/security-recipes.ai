---
title: Agentic Approval Receipt Pack
linkTitle: Approval Receipts
weight: 16
toc: true
description: >
  Scope-bound approval receipts for agentic AI control planes, MCP tools,
  high-impact actions, and enterprise audit evidence.
---

{{< callout type="info" >}}
**Control primitive.** An approval receipt turns "a human said yes" into
machine-checkable evidence before an agent performs a privileged action.
The receipt is bound to scope, workflow, run, identity, approver role,
expiry, policy hash, and run evidence.
{{< /callout >}}

SecurityRecipes already has action envelopes, entitlement leases,
run receipts, telemetry contracts, secure context lineage, MCP
authorization gates, and incident response evidence. The missing enterprise
primitive was the approval itself: a durable, replayable object that proves
the approval was specific enough to trust.

The Agentic Approval Receipt Pack closes that gap. It defines approval
profiles for normal remediation, privileged tool use, identity changes,
production releases, secret/data boundaries, irreversible actions, and
incident containment. It also ships a deterministic evaluator that returns
allow, hold, deny, or kill decisions before a separate orchestrator lets the
agent proceed.

## Why This Matters

Agentic systems are crossing a new risk boundary: they can chain model
reasoning, MCP tools, browser sessions, memory, remote agents, and non-human
identities into workflows that create real side effects. Enterprise buyers
will not trust that surface with comment-thread approvals, Slack reactions,
or ambiguous ticket links.

Approval receipts are a product-grade answer:

- **Security teams** get a standard record for privileged agent actions.
- **AI platform teams** get a narrow runtime API for approval checks.
- **IAM teams** get separation-of-duties and role evidence.
- **GRC teams** get repeatable audit artifacts instead of screenshots.
- **Acquirers** get a differentiated control surface for an MCP-native
  secure context layer.

## What Ships

| Artifact | Purpose |
| --- | --- |
| `data/assurance/agentic-approval-receipt-profile.json` | Source profile with standards alignment, receipt contract, approval profiles, runtime policy, buyer views, and commercialization path. |
| `data/evidence/agentic-approval-receipt-pack.json` | Generated pack joining approval profiles to action runtime, run receipts, telemetry, entitlement, identity, MCP gateway, elicitation, and catastrophic-risk evidence. |
| `scripts/generate_agentic_approval_receipt_pack.py` | Dependency-free generator with `--check` support for CI freshness validation. |
| `scripts/evaluate_agentic_approval_receipt_decision.py` | Deterministic evaluator for one runtime approval request. |
| `recipes_agentic_approval_receipt_pack` | MCP tool for receipt profiles, workflow requirements, buyer views, and evidence. |
| `recipes_evaluate_agentic_approval_receipt_decision` | MCP tool for runtime allow / hold / deny / kill decisions. |

## Approval Profiles

| Profile | Default posture | Use case |
| --- | --- | --- |
| Bounded remediation review | Allow when one qualified reviewer approves the scoped run | Dependency, SAST, base-image, and data-remediation PR work. |
| Privileged tool step-up | Hold until a privileged reviewer approves | Skill installs, persistent memory writes, and remote agent delegation. |
| Identity and scope change | Hold until IAM and security both approve | Agent identity lease changes and MCP scope expansion. |
| Production or release | Hold until production owner and security approve | Deployment, release publication, registry quarantine, or artifact changes. |
| Secret and data boundary | Hold until data-owner evidence is attached | Sensitive context, external egress, secrets, regulated data, and customer data. |
| Irreversible or funds | Deny by default without explicit risk acceptance | Funds movement, signing authority, destructive production writes, and on-chain actions. |
| Quarantine and incident | Allow only with incident-command evidence | Emergency containment, connector isolation, cache purge, and evidence preservation. |

## Decision Model

| Decision | Meaning |
| --- | --- |
| `allow_scope_bound_approval` | The receipt is registered, scope-bound, unexpired, role-complete, separated from the requester, and linked to run evidence. |
| `hold_for_second_approver` | The approval is plausible but lacks required approver count or required role mix. |
| `hold_for_risk_acceptance` | The profile requires explicit risk acceptance before execution. |
| `deny_scope_mismatch` | The approved scope hash does not match the requested action scope. |
| `deny_expired_or_untrusted_approval` | The approval is missing, pending, expired, malformed, or issued by an untrusted source. |
| `deny_unregistered_approval_profile` | The workflow and action class do not map to a registered approval profile. |
| `kill_session_on_approval_bypass_signal` | The runtime observed bypass, post-execution approval, self-approval, secret transit, token passthrough, cross-tenant reuse, or another kill signal. |

## Runtime Example

```bash
python3 scripts/generate_agentic_approval_receipt_pack.py
python3 scripts/generate_agentic_approval_receipt_pack.py --check
```

```bash
python3 scripts/evaluate_agentic_approval_receipt_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --action-class repo_branch_write \
  --run-id run-123 \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --identity-id sr-agent::vulnerable-dependency-remediation::codex \
  --tenant-id tenant-123 \
  --correlation-id corr-123 \
  --approval-id approval-123 \
  --approval-type pull_request_review \
  --approval-status approved \
  --approver-id reviewer-123 \
  --approver-role security_reviewer \
  --requester-id sr-agent::vulnerable-dependency-remediation::codex \
  --requested-scope-hash sha256:scope-123 \
  --approved-scope-hash sha256:scope-123 \
  --issued-at 2099-01-01T00:00:00Z \
  --expires-at 2099-01-02T00:00:00Z \
  --now 2099-01-01T01:00:00Z \
  --receipt-id receipt-123 \
  --policy-pack-hash sha256:policy-123 \
  --authorization-decision allow_authorized_mcp_request \
  --expect-decision allow_scope_bound_approval
```

## MCP Usage

Use `recipes_agentic_approval_receipt_pack` when an agent host needs the
receipt contract, all approval profiles, or one workflow's approval matrix.

```json
{
  "workflow_id": "artifact-cache-quarantine"
}
```

Use `recipes_evaluate_agentic_approval_receipt_decision` before a high-impact
agent action executes.

```json
{
  "workflow_id": "artifact-cache-quarantine",
  "action_class": "artifact_or_registry_quarantine",
  "run_id": "run-123",
  "agent_id": "sr-agent::artifact-cache-quarantine::codex",
  "identity_id": "sr-agent::artifact-cache-quarantine::codex",
  "tenant_id": "tenant-123",
  "correlation_id": "corr-123",
  "approval_id": "approval-123",
  "approval_type": "incident_command_review",
  "approval_status": "approved",
  "approver_ids": ["incident-commander", "security-reviewer"],
  "approver_roles": ["incident_commander", "security_reviewer"],
  "requested_scope_hash": "sha256:scope-123",
  "approved_scope_hash": "sha256:scope-123",
  "issued_at": "2099-01-01T00:00:00Z",
  "expires_at": "2099-01-02T00:00:00Z",
  "receipt_id": "receipt-123",
  "policy_pack_hash": "sha256:policy-123"
}
```

## Standards Alignment

This pack is intentionally mapped to current agentic AI and MCP security
work:

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
- [Model Context Protocol Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Model Context Protocol Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [Model Context Protocol Elicitation Specification](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
- [OpenAI Agents SDK Guardrails](https://openai.github.io/openai-agents-js/guides/guardrails/)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)

## Acquisition Logic

Approval receipts push SecurityRecipes beyond documentation. They create a
repeatable enterprise control surface around MCP-backed agent actions:

- **Open corpus:** publish the profile, pack, evaluator, and examples so
  teams can adopt the vocabulary quickly.
- **Hosted MCP server:** validate signed approval receipts, cache workflow
  matrices, expose policy decisions, and export trust-center evidence.
- **Enterprise integrations:** connect approval sources from GitHub, Jira,
  Slack, ServiceNow, IAM, incident tools, and deployment gates.
- **Diligence packet:** show acquirers a coherent path from open knowledge
  to revenue-grade runtime infrastructure.

## See Also

- [Agentic Action Runtime]({{< relref "/security-remediation/agentic-action-runtime" >}})
- [Agentic Entitlement Review]({{< relref "/security-remediation/agentic-entitlement-review" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [MCP Elicitation Boundary]({{< relref "/security-remediation/mcp-elicitation-boundary" >}})
- [Agentic Catastrophic Risk Annex]({{< relref "/security-remediation/agentic-catastrophic-risk-annex" >}})
- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
