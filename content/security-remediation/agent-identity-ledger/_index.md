---
title: Agent Identity & Delegation Ledger
linkTitle: Identity Ledger
weight: 7
date: 2026-05-02
lastmod: 2026-09-18
sidebar:
  exclude: true
description: >
  Record every human, agent, service, delegation, credential boundary, and
  approval chain involved in an agentic remediation workflow.
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**Why this page exists.** Agentic remediation is not just an AI
workflow. It is a non-human identity acting through tools, source hosts,
ticket systems, scanners, registries, and MCP servers. Enterprises need
a ledger that says which agent may act, on whose authority, with what
scope, and how that authority is revoked.
{{< /callout >}}

Rechecked September 18, 2026: NIST
[IR 8587](https://csrc.nist.gov/pubs/ir/8587/final)
(*Protecting Tokens and Assertions from Forgery, Theft, and Misuse*,
final September 15, 2026) says organizations **should** apply these
token-protection guidelines when AI agents use signed tokens to access
systems, data, tools, or APIs. Workload and non-person identities
**MUST** use tightly scoped, short-lived tokens issued through approved
identity platforms and **SHOULD** use sender-constrained mechanisms
such as
[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) or
[mTLS-bound tokens](https://datatracker.ietf.org/doc/html/rfc8705)
whenever feasible. Access and identity tokens **MUST** have defined
short lifetimes, **SHOULD** be valid for no more than one hour, and
expired tokens **MUST** be rejected. Tokens must never be written to
logs, console output, cache directories, or artifact stores. IR 8587 is
not a comprehensive agent-IAM guide; it still applies to agent runtime
tokens. MCP
[2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
remains the current public revision.

## The product bet

SecurityRecipes already has a
[Workflow Control Plane]({{< relref "/security-remediation/control-plane" >}})
and an
[MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}}).
The missing enterprise surface is identity: IAM, AI Platform, GRC, and
trust review diligence teams will ask whether agent permissions are
unique, scoped, auditable, and revocable.

The Agent Identity & Delegation Ledger is the answer. It turns each
approved workflow plus each approved agent class into a machine-readable
identity contract:

- who delegates authority to the agent,
- which MCP namespaces and access modes the agent may use,
- which repository paths and branch prefixes it may write,
- which actions are explicitly denied,
- which reviewers must approve the output,
- which runtime attributes and evidence records must exist,
- which kill signals revoke the run.

This makes AI easier for adopters because the model does not have to
remember identity policy. The host, gateway, or orchestrator can load
one JSON artifact and make a default-deny decision.

{{< playbook-workflow >}}

## What was added

The identity layer lives in two generated artifacts and one MCP tool:

- `data/evidence/agent-identity-delegation-ledger.json` - the generated
  ledger that joins workflow manifests, MCP gateway policy, and the
  workflow validation report.
- `recipes_agent_identity_ledger` - the MCP server tool that exposes the
  ledger to agent hosts, policy engines, and internal control portals.

Run it locally from the repo root:

```bash
python3 scripts/generate_agent_identity_ledger.py
python3 scripts/generate_agent_identity_ledger.py --check
```

CI runs the same `--check` command after the workflow control plane,
gateway policy pack, and assurance pack checks.

## What is inside the ledger

| Section | Purpose |
| --- | --- |
| `identity_summary` | Identity count, workflow count, agent classes, MCP namespace count, default decision, and approval-required workflows. |
| `agent_identities` | One identity contract per workflow and agent class, such as `sr-agent::sast-finding-remediation::codex`. |
| `delegated_authority` | Allowed actions, MCP scopes, eligible findings, repository scope, branch prefix, and approval-required namespaces. |
| `explicit_denies` | Actions an agent cannot perform: merge, deploy, release, publish, secret-store access, default-branch push, and policy edits without review. |
| `identity_controls` | Credential model, no shared tokens, no model-visible secrets, sender-constrained short-lived token rules, and required delegation-chain fields. |
| `runtime_contract` | Required runtime attributes, egress default, session disablement, and kill signals. |
| `enterprise_iam_contract` | The portable IAM checklist for issuing, auditing, and revoking agent identities. |
| `delegation_graph` | A compact graph from accountable team to agent identity to MCP namespaces and reviewer pools. |

## Enterprise IAM contract

Treat every ledger identity as a non-human identity class. A production
agent host should issue runtime credentials only when all of these are
true:

- The request names a known `identity_id`, `workflow_id`, `agent_class`,
  and `run_id`.
- The workflow is active or explicitly approved for pilot execution.
- The requested tool namespace exists in `delegated_authority.mcp_scopes`.
- Branch writes use the declared remediation branch prefix and PR label.
- Ticket writes are limited to the declared security or incident workspace.
- Approval-required namespaces carry a typed human approval record.
- Runtime tokens are tightly scoped, audience-restricted, and
  sender-constrained whenever feasible.
- Access and identity tokens expire within one hour or at run
  completion, whichever is sooner; expired tokens are rejected.
- Tokens are never written to logs, console output, cache directories,
  or artifact stores.
- Runtime tokens are revoked when a kill signal fires or token
  exposure is detected.
- No user token is passed through to downstream tools.

The ledger intentionally separates delegation from execution. It tells
the platform what may be issued. The MCP gateway and IAM layer still
enforce the decision.

## Industry alignment

This feature is aligned to primary industry direction:

- [NIST IR 8587](https://csrc.nist.gov/pubs/ir/8587/final)
  says workload identities MUST use tightly scoped, short-lived tokens,
  SHOULD use sender-constrained presentation, MUST reject expired
  tokens, and should apply those controls when agents use signed tokens.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  calls out tool misuse, identity and privilege abuse, agentic supply
  chain risk, and rogue-agent behavior.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  defines the authorization flow for restricted MCP servers over HTTP
  transports, including token audience validation.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)
  emphasizes scoped authorization, confused-deputy prevention,
  token-passthrough avoidance, and session safety.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  frames AI systems as governed, mapped, measured, and managed assets.
- [CISA Secure by Design](https://www.cisa.gov/securebydesign)
  anchors the product in secure defaults, transparency, accountability,
  and measurable security outcomes.

The forward-looking move is not another prompt. It is turning agent
authority into an inspectable, enforceable, revocable artifact.

## How agents use it

An agent or orchestrator should load the identity ledger before the
first tool call:

1. Match the finding to a workflow.
2. Select the agent class and derive `identity_id`.
3. Confirm the identity exists and the workflow status allows execution.
4. Bind the run token to `workflow_id`, `agent_class`, `run_id`, and
   intended audience; prefer sender-constrained presentation.
5. Evaluate every tool call against `delegated_authority.mcp_scopes`
   and reject expired or unbound tokens.
6. Block every action in `explicit_denies`.
7. Attach the required evidence records before the PR is reviewable.
8. Revoke the identity when a runtime kill signal fires or token
   exposure is detected.

The local MCP server exposes this flow through
`recipes_agent_identity_ledger`. Query it with:

- no arguments for the full summary and identity previews,
- `workflow_id` for every identity allowed on a workflow,
- `agent_class` for every workflow a given agent class may run,
- `identity_id` for the full delegated-authority contract.

## CI contract

The generator fails if:

- Workflow IDs drift between the manifest and gateway policy.
- Gateway policy is not default-deny.
- Manifest defaults stop requiring human review.
- An agent identity lacks reviewer pools, evidence records, or kill signals.
- MCP namespaces use wildcards.
- Branch-writing identities lack branch prefix or PR label controls.
- Approval-required namespaces lack human approval metadata.
- Identity token rules omit sender constraint, one-hour lifetime,
  audience binding, expired-token rejection, or no-raw-token logging.
- The generated ledger is stale in `--check` mode.

That is the review-ready bar: AI identities are not implied by
tool access. They are declared, checked, versioned, exposed over MCP,
and ready to enforce.

## See also

- [Workflow Control Plane]({{< relref "/security-remediation/control-plane" >}})
  - the workflow source of truth.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - the runtime enforcement contract.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - connector trust tiers and controls for the namespaces delegated to agents.
- [Agentic Assurance Pack]({{< relref "/security-remediation/agentic-assurance-pack" >}})
  - the reviewer- and auditor-ready control narrative.
- [Runtime Controls]({{< relref "/security-remediation/runtime-controls" >}})
  - session disablement and inline enforcement.
