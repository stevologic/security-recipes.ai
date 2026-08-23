---
title: MCP Gateway Policy Pack
linkTitle: Gateway Policy
weight: 5
date: 2026-05-02
lastmod: 2026-08-21
sidebar:
  exclude: true
description: >
  Convert agentic workflow manifests into enforceable MCP gateway decisions
  for tools, identities, approvals, arguments, evidence, and denials.
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**Why this page exists.** The control plane says what a workflow is
allowed to do. The gateway policy pack turns that into a portable
enforcement contract an MCP gateway, agent host, CI admission check, or
policy sidecar can load directly.
{{< /callout >}}

Rechecked August 23, 2026: MCP
[2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
is still current and **stateless**. There is no negotiation handshake.
Each request carries protocol version and capabilities. Servers
**MUST** implement
[`server/discover`](https://modelcontextprotocol.io/specification/2026-07-28/server/discover).
`kill_session` here is a host-session kill switch, not `Mcp-Session-Id`.
Streamable HTTP revisions through
[2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
could assign that header; 2026-07-28 ignores it and does not mint
session IDs.

## The product bet

Agentic remediation cannot scale on prompt discipline alone. Enterprise
reviewers need a boring answer to a hard question: "What prevents this
agent from using the wrong tool, touching the wrong file, or continuing
after its scope has changed?"

The policy pack is that answer. It makes the site more than a library of
instructions by creating a machine-readable layer that can sit between
AI agents and enterprise systems:

- Agents get a simple decision contract instead of paragraphs of policy.
- Gateways get explicit scopes, path limits, labels, and runtime kill
  signals.
- Reviewers get evidence requirements that are consistent across tools.
- Platform teams get one artifact they can pin, diff, and promote.

This is the shape a reviewer can underwrite: recipes for adoption,
manifests for governance, policy for enforcement, and evidence for
audit.

{{< playbook-workflow >}}

## What was added

The policy pack is generated from the workflow control-plane manifest:

- `data/policy/mcp-gateway-policy.json` - the generated policy bundle.
- `scripts/generate_mcp_gateway_policy.py` - the deterministic compiler
  from workflow manifests to gateway policy.
- `scripts/evaluate_mcp_gateway_decision.py` - the runtime pre-call and
  mid-run policy evaluator.
- `recipes_mcp_gateway_policy` - an MCP tool that exposes the pack to
  connected agents and gateways.

Regenerate the policy and fail CI on drift:

```bash
python3 scripts/generate_mcp_gateway_policy.py
python3 scripts/generate_mcp_gateway_policy.py --check
```

Evaluate a declared read-only tool call:

```bash
python3 scripts/evaluate_mcp_gateway_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --agent-class codex \
  --run-id run-ci \
  --tool-namespace advisories.vulnerability \
  --tool-access-mode read \
  --gate-phase tool_call \
  --expect-decision allow
```

The manifest cannot change without updating the generated enforcement
contract.

## Policy decisions

Every workflow policy defaults to `deny`. A gateway should allow only
the declared decisions:

| Decision | Meaning |
| --- | --- |
| `allow` | Read-only context access inside the declared MCP namespace. |
| `allow_scoped_branch` | Write only to the workflow branch prefix and declared file scope. |
| `allow_scoped_ticket` | Write workflow evidence or triage notes only to declared ticket systems. |
| `hold_for_approval` | Pause and require a typed human approval record before continuing. |
| `deny` | Fail closed for undeclared workflows, tools, paths, hosts, or gates. |
| `kill_session` | Disable the active agent session when a runtime kill signal fires. |

The generated pack also carries the runtime attributes an enforcer needs
to make those decisions: workflow ID, agent ID, run ID, tool namespace,
access mode, branch name, changed paths, diff size, gate phase, and
human approval record.

## How gateways use it

An MCP gateway or agent runtime should apply the pack as a pre-call and
mid-run control:

1. Load the policy pack at startup and pin its `source_manifest.sha256`.
2. Match the incoming run to `workflow_id`.
3. Reject the run if the workflow is missing, paused, retired, or outside
   its declared maturity posture.
4. For each tool call, match `tool_namespace` and requested access mode
   against `allowed_mcp_scopes`.
5. For each proposed file write, enforce `allowed_paths`,
   `forbidden_paths`, `max_changed_files`, and `max_diff_lines`.
6. For each gate transition, require the phase rules and evidence
   records declared by the workflow.
7. Kill the session when any runtime kill signal fires.

The policy pack is intentionally vendor-neutral. It can be converted into
OPA/Rego, Cedar, a gateway-native rule format, or a simple in-process
decision table. The important part is that the source of truth is the
same artifact agents can retrieve and auditors can review.

## Industry alignment

This feature is aligned with the controls serious AI security programs
are already converging on:

- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)
  calls out MCP-specific attack paths such as confused deputy and token
  passthrough risk. A gateway policy pack keeps tool access scoped and
  auditable.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  requires token audience validation and explicit authorization handling
  for HTTP transports. The pack gives operators the workflow-level
  authorization context those checks need.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
  highlights goal hijacking, tool misuse, and identity or privilege abuse
  as core agentic risks. The pack narrows tool use and fails closed on
  undeclared actions.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  frames trustworthy AI around govern, map, measure, and manage
  functions. This pack operationalizes those functions for remediation
  workflows.
- [CISA Secure by Design](https://www.cisa.gov/securebydesign) pushes
  measurable security outcomes and executive ownership. Generated,
  versioned policy is a measurable control, not a slide.
- [Open Policy Agent](https://www.openpolicyagent.org/docs/latest)
  popularized decoupling policy decisions from application logic. The
  pack follows that model while staying neutral about the final policy
  engine.

## Enterprise checklist

Before promoting a workflow to broad rollout, require:

- The workflow manifest validates cleanly.
- The gateway policy pack is regenerated and `--check` passes in CI.
- The MCP gateway denies undeclared namespaces by default.
- The gateway records every hold, denial, and kill-session decision with
  run ID attribution.
- Human approvals are typed records, not chat messages.
- The policy pack hash is attached to PR evidence or the run log.

That is the difference between "the prompt said no" and "the platform
could not do it."

## See also

- [Workflow Control Plane]({{< relref "/security-remediation/control-plane" >}})
  - the source manifest this pack is generated from.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - the connector inventory and trust-tier contract for every MCP namespace.
- [MCP Runtime Decision Evaluator]({{< relref "/security-remediation/mcp-runtime-decision-evaluator" >}})
  - how to execute the policy pack before an agent tool call runs.
- [Runtime Controls]({{< relref "/security-remediation/runtime-controls" >}})
  - how inline proxies and session disablement enforce the pack.
- [Agentic Assurance Pack]({{< relref "/security-remediation/agentic-assurance-pack" >}})
  - how generated policy becomes part of the enterprise trust export.
- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
  - how gateway scopes become non-human identity delegation contracts.
- [Gatekeeping Patterns]({{< relref "/security-remediation/gatekeeping" >}})
  - where admission, tool-call, pre-merge, post-merge, and runtime gates fit.
- [Compliance & Audit]({{< relref "/security-remediation/compliance" >}})
  - how generated policy becomes auditor-ready evidence.
