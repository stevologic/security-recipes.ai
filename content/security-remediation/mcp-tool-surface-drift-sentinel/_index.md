---
title: MCP Tool Surface Drift Sentinel
linkTitle: Tool Surface Drift
weight: 8
sidebar:
  open: true
description: >
  A generated MCP tool-surface drift pack that fingerprints approved
  tool descriptions, schemas, annotations, and capability metadata, then
  makes deterministic allow, hold, deny, or kill decisions when a live
  MCP server changes after approval.
---

{{< callout type="info" >}}
**What this adds.** SecurityRecipes now treats the MCP tool list as a
runtime supply-chain surface. Tool descriptions, schemas, annotations,
and capability flags are pinned, hashed, and review-gated before a
changed tool can influence an agent run.
{{< /callout >}}

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

## What was added

- Profile:
  `data/assurance/mcp-tool-surface-drift-profile.json`
- Generator:
  `scripts/generate_mcp_tool_surface_drift_pack.py`
- Runtime evaluator:
  `scripts/evaluate_mcp_tool_surface_drift_decision.py`
- Evidence pack:
  `data/evidence/mcp-tool-surface-drift-pack.json`
- MCP tools:
  `recipes_mcp_tool_surface_drift_pack` and
  `recipes_evaluate_mcp_tool_surface_drift_decision`

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

## Decision model

| Decision | Meaning |
| --- | --- |
| `allow_pinned_tool_surface` | The live description, schemas, annotations, and surface hash match the pinned baseline. |
| `allow_reviewed_tool_surface` | Drift exists, but it is tied to an explicit human review record. |
| `hold_for_tool_surface_review` | A description, schema, annotation, tool-list, source-kind, or trust signal needs review. |
| `deny_tool_surface_regression` | The live request drifts outside workflow, access-mode, or annotation boundaries. |
| `deny_unregistered_tool_surface` | The namespace/tool pair is not in the generated baseline. |
| `kill_session_on_tool_surface_signal` | A high-impact expansion or runtime signal appeared: secrets, private network, delete, publish, deploy, signer, token, approval bypass, or hidden instruction. |

## What gets pinned

Each baseline records:

- tool name and namespace
- connector ID and source kind
- allowed workflow IDs
- access mode and risk tier
- description hash
- input schema hash
- output schema hash
- annotation hash
- aggregate surface hash
- data classes, external systems, and capability flags
- source artifacts used to build the pack

That lets a hosted MCP gateway answer a hard buyer question: "Can you
prove this production tool list is the one we reviewed?"

## Industry alignment

This follows current primary guidance and emerging agentic security
practice:

- [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
  defines tool descriptions, schemas, annotations, structured output,
  and tool-list change notifications.
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  emphasizes confused-deputy, token-passthrough, SSRF, session, local
  server, and scope controls.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
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
4. A tool description, schema, annotation, data class, or external
   system changes.
5. A workflow starts with a cached tool baseline.
6. A high-impact action is about to execute.

The open pack is the product wedge. The paid surface is hosted live
tool-list monitoring, signed baselines, tenant-specific policy, approval
workflows, and fleet drift alerts.

## See also

- [MCP Connector Intake Scanner]({{< relref "/security-remediation/mcp-connector-intake-scanner" >}})
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
- [MCP Tool Risk Contract]({{< relref "/security-remediation/mcp-tool-risk-contract" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
