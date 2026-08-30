---
title: MCP Tool Surface Drift Sentinel
linkTitle: Tool Surface Drift
weight: 8
date: 2026-05-04
lastmod: 2026-08-30
sidebar:
  exclude: true
description: >
  A generated MCP tool-surface drift pack that fingerprints approved
  tool descriptions, schemas, x-mcp-header maps, annotations, and
  capability metadata, then makes deterministic allow, hold, deny, or
  kill decisions when a live MCP server changes after approval.
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**What this adds.** SecurityRecipes now treats the MCP tool list as a
runtime supply-chain surface. Tool descriptions, schemas, annotations,
and capability flags are pinned, hashed, and review-gated before a
changed tool can influence an agent run.
{{< /callout >}}

Rechecked August 30, 2026: MCP
[2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
is still current and **stateless**. There is no negotiation handshake.
Each request carries protocol version and capabilities. Servers
**MUST** implement
[`server/discover`](https://modelcontextprotocol.io/specification/2026-07-28/server/discover).
Tool `inputSchema` properties **MAY** include
[`x-mcp-header`](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#x-mcp-header)
so Streamable HTTP clients mirror arguments into `Mcp-Param-*`
headers. Clients **MUST** exclude a tool from `tools/list` when any
`x-mcp-header` value is invalid. Servers **SHOULD NOT** mark
passwords, tokens, API keys, or PII as headers. `--session-id` and
`kill_session` here are local run identifiers and host-session kill
switches, not `Mcp-Session-Id`. Streamable HTTP revisions through
[2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
could assign that header; 2026-07-28 ignores it and does not mint
session IDs.

## The product bet

The next enterprise MCP problem is not only connector intake. It is
what happens after intake.

A connector can be approved on Monday and become materially different on
Thursday because a vendor changes a tool description, adds a schema
field, changes annotations, expands network reachability, or ships a new
tool inside an already-approved namespace. For an agent, those changes
are not just metadata. They alter prompt-layer instructions, approval
UI, input affordances, output validation, and session risk.

The MCP Tool Surface Drift Sentinel gives the secure context layer a
continuous control: fingerprint the approved surface, compare the live
surface, then decide before the agent trusts it.

{{< playbook-workflow >}}

## What was added

- Profile:
  `data/assurance/mcp-tool-surface-drift-profile.json`
- Generator: `scripts/generate_mcp_tool_surface_drift_pack.py`
- Runtime evaluator: `scripts/evaluate_mcp_tool_surface_drift_decision.py`
- Evidence pack:
  `data/evidence/mcp-tool-surface-drift-pack.json`
- MCP tools:
  `recipes_mcp_tool_surface_drift_pack`, paired with `recipes_playbook_plan` using playbook id `mcp-tool-surface-drift-sentinel`.

Regenerate and validate:

```bash
python3 scripts/generate_mcp_tool_surface_drift_pack.py
python3 scripts/generate_mcp_tool_surface_drift_pack.py --check
```

Evaluate a pinned live surface:

```bash
python3 scripts/evaluate_mcp_tool_surface_drift_decision.py \
  --namespace repo.contents \
  --tool-name repo.contents.patch_scoped_branch \
  --workflow-id vulnerable-dependency-remediation \
  --requested-access-mode write_branch \
  --use-baseline-hashes \
  --expect-decision allow_pinned_tool_surface
```

Evaluate capability expansion:

```bash
python3 scripts/evaluate_mcp_tool_surface_drift_decision.py \
  --namespace registries.quarantine \
  --tool-name registries.quarantine.stage_plan \
  --workflow-id artifact-cache-quarantine \
  --requested-access-mode approval_required \
  --capability-expansion \
  --added-capability-flag delete \
  --added-capability-flag production_credential \
  --expect-decision kill_session_on_tool_surface_signal
```

Refuse a tool that adds `x-mcp-header` mirroring after approval:

```bash
python3 scripts/evaluate_mcp_tool_surface_drift_decision.py \
  --namespace repo.contents \
  --tool-name repo.contents.patch_scoped_branch \
  --workflow-id vulnerable-dependency-remediation \
  --requested-access-mode write_branch \
  --input-schema-json '{"type":"object","properties":{"repository":{"type":"string","x-mcp-header":"Repository"}}}' \
  --expect-decision kill_session_on_tool_surface_signal
```

## Decision model

| Decision | Meaning |
| --- | --- |
| `allow_pinned_tool_surface` | The live description, schemas, annotations, and surface hash match the pinned baseline. |
| `allow_reviewed_tool_surface` | Drift exists, but it is tied to an explicit human review record. |
| `hold_for_tool_surface_review` | A description, schema, annotation, tool-list, source-kind, or trust signal needs review. |
| `deny_tool_surface_regression` | The live request drifts outside workflow, access-mode, or annotation boundaries. |
| `deny_unregistered_tool_surface` | The namespace/tool pair is not in the generated baseline. |
| `kill_session_on_tool_surface_signal` | A high-impact expansion or runtime signal appeared: secrets, private network, delete, publish, deploy, signer, token, `x-mcp-header` mirroring, approval bypass, or hidden instruction. |

## What gets pinned

Each baseline records:

- tool name and namespace
- connector ID and source kind
- allowed workflow IDs
- access mode and risk tier
- description hash
- input schema hash
- `x-mcp-header` parameter-to-header map
- output schema hash
- annotation hash
- aggregate surface hash
- data classes, external systems, and capability flags
- source artifacts used to build the pack

That lets a hosted MCP gateway answer a hard reviewer question: "Can you
prove this production tool list is the one we reviewed?"

## Industry alignment

This follows current primary guidance and emerging agentic security
practice:

- [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
  defines tool descriptions, schemas, annotations, structured output,
  tool-list change notifications, and `x-mcp-header` constraints.
  Invalid header annotations **MUST** be excluded from `tools/list`.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)
  emphasizes confused-deputy, token-passthrough, SSRF, session, local
  server, and scope controls.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  anchors protected calls in resource binding, consent, and strict
  bearer-token handling.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
  calls out token exposure, scope creep, tool poisoning, supply-chain
  tampering, command execution, and intent-flow subversion.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  elevates tool misuse, identity abuse, agentic supply-chain risk, and
  cascading failures.
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
  reinforces the same update-drift and behavior-package governance
  problem at the skill layer.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  and the
  [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  frame this as governed, measured, and managed lifecycle risk.

## Enterprise use

An MCP gateway should evaluate this pack when:

1. A server emits a tool-list changed notification.
2. A vendor-hosted MCP server upgrades.
3. A local STDIO server package changes.
4. A tool description, schema, `x-mcp-header` map, annotation, data
   class, or external system changes.
5. A workflow starts with a cached tool baseline.
6. A high-impact action is about to execute.

The open pack is the readiness gate. The hosted-ready surface is hosted live
tool-list monitoring, signed baselines, tenant-specific policy, approval
workflows, and fleet drift alerts.

## See also

- [MCP Connector Intake Scanner]({{< relref "/security-remediation/mcp-connector-intake-scanner" >}})
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
- [MCP Tool Risk Contract]({{< relref "/security-remediation/mcp-tool-risk-contract" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
