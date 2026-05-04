---
title: MCP Tool Risk Contract
linkTitle: MCP Tool Risk
weight: 7
sidebar:
  open: true
description: >
  A generated MCP tool-risk contract that turns tool annotations,
  connector trust, authorization conformance, workflow scope, and
  session-combination risk into deterministic pre-call decisions.
---

{{< callout type="info" >}}
**What this adds.** SecurityRecipes now treats MCP tool metadata as
risk vocabulary, not enforcement. The contract lets an agent host or MCP
gateway use annotations safely while still relying on deterministic
scope, authorization, sandbox, network, approval, and output controls.
{{< /callout >}}

MCP tools can now declare behavior with annotations such as
`readOnlyHint`, `destructiveHint`, `idempotentHint`, and
`openWorldHint`. That is valuable, but the MCP specification is clear:
clients must treat annotations as untrusted unless they come from a
trusted server. The MCP Tool Risk Contract turns that reality into a
buyer-ready control surface.

The core policy is simple: before a tool call runs, decide whether the
session has private data, untrusted content, and an external or
state-changing capability in the same execution path. If it does, the
call is denied unless there is an explicit approval/control path. This
makes tool risk easy for enterprise teams to reason about without
pretending the model can reliably separate user instructions from
attacker-controlled content.

## Generated artifact

- Profile:
  `data/assurance/mcp-tool-risk-contract-profile.json`
- Generator:
  `scripts/generate_mcp_tool_risk_contract.py`
- Runtime evaluator:
  `scripts/evaluate_mcp_tool_risk_decision.py`
- Evidence pack:
  `data/evidence/mcp-tool-risk-contract.json`
- MCP tools:
  `recipes_mcp_tool_risk_contract` and
  `recipes_evaluate_mcp_tool_risk_decision`

Regenerate and validate:

```bash
python3 scripts/generate_mcp_tool_risk_contract.py
python3 scripts/generate_mcp_tool_risk_contract.py --check
```

Evaluate one proposed tool call:

```bash
python3 scripts/evaluate_mcp_tool_risk_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --namespace repo.contents \
  --tool-name repo.contents.patch \
  --requested-access-mode write_branch \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --run-id run-ci \
  --session-id session-ci \
  --correlation-id corr-ci \
  --server-trusted \
  --read-only-hint false \
  --destructive-hint false \
  --idempotent-hint false \
  --open-world-hint true \
  --human-approval-id approval-ci \
  --expect-decision allow_with_confirmation
```

## Decision model

| Decision | Meaning |
| --- | --- |
| `allow_tool_call` | The call fits workflow scope, trusted annotations, and session-combination policy. |
| `allow_with_confirmation` | The call can proceed only with a durable human approval or confirmation record. |
| `hold_for_tool_risk_review` | Evidence is missing, annotations are untrusted for the risk level, or the tool is sensitive. |
| `deny_annotation_contradiction` | Runtime request contradicts the tool annotations, such as read-only metadata on a write call. |
| `deny_session_exfiltration_path` | The session combines private data, untrusted content, and external or state-changing capability without approval. |
| `deny_scope_drift` | Namespace, connector, access mode, or workflow is outside the generated contract. |
| `kill_session_on_tool_risk_signal` | A kill signal appeared: secret-bearing arguments/results, tool-list drift after approval, private-network destination, or approval bypass. |

## What gets scored

The generator reads the MCP connector trust pack, authorization
conformance pack, workflow manifest, and gateway policy. It produces a
profile for every MCP namespace with:

- trusted vs untrusted annotation source
- suggested standard annotations
- risk tier
- private-data, untrusted-content, exfiltration, state-change, and
  approval-required factors
- authorization conformance state
- workflow-level combination risk

The pack is intentionally conservative. Open-world tools taint the
session; untrusted annotations never reduce friction for sensitive
tools; write and non-idempotent calls need approval; tool-list changes
after approval are kill signals.

## Source anchors

- [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP Tool Annotations as Risk Vocabulary](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)
- [MCP Authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [MCP Elicitation specification](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)

## See also

- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [MCP Tool Surface Drift Sentinel]({{< relref "/security-remediation/mcp-tool-surface-drift-sentinel" >}})
- [MCP Gateway Policy]({{< relref "/security-remediation/mcp-gateway-policy" >}})
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
- [Agentic Action Runtime Pack]({{< relref "/security-remediation/agentic-action-runtime" >}})
