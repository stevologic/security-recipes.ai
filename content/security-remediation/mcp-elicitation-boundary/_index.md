---
title: MCP Elicitation Boundary
linkTitle: MCP Elicitation Boundary
weight: 11
date: 2026-05-04
lastmod: 2026-08-31
toc: true
description: >
  Enforce MCP multi-round-trip and tasks-extension form-mode and URL-mode
  elicitation boundaries with state binding, allowlists, approval gates,
  and deterministic decisions.
sidebar:
  exclude: true
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**Why this page exists.** MCP now lets servers ask users for information
through clients. That is powerful, but it creates a new enterprise
boundary: a server must not collect secrets through form prompts, send a
user to a phishing URL, or confuse external OAuth with MCP authorization.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the secure context layer for agentic
AI**. Secure context is not only retrieval and tool policy; it also
includes the moment an MCP server asks a human for data.

The new MCP elicitation surface makes AI easier for users because a
server can ask for missing information inside a workflow. The enterprise
version needs a default-deny policy:

- clients advertise elicitation modes in capabilities metadata on every
  parent request, and servers only ask for modes declared on that request;
- servers return elicitation inside `InputRequiredResult.inputRequests`,
  never as a standalone server-initiated JSON-RPC request;
- long-running `tools/call` work MAY instead return
  `CreateTaskResult`; later `tasks/get` snapshots MAY carry the same
  elicitation `inputRequests`, which clients fulfill with `tasks/update`,
  not by retrying the original method;
- hosts **MUST** apply the same form, URL, consent, and secret-collection
  controls to task-bound `inputRequests`. A task is not a higher-trust
  channel;
- clients **MUST** declare `io.modelcontextprotocol/tasks` on that parent
  request. Servers **MUST NOT** return a task handle otherwise;
- task IDs **MAY** be bearer tokens: they **MUST** be unguessable, and
  every `tasks/get`, `tasks/update`, and `tasks/cancel` **MUST** be
  authenticated and authorized. Do not treat a task ID as `Mcp-Session-Id`;
- clients correlate each response by its `inputRequests` map key, echo
  opaque `requestState` exactly, and retry the original operation with a
  new JSON-RPC ID when the elicitation used `InputRequiredResult`;
- servers treat `requestState` as attacker-controlled, verify its integrity,
  bind it to the principal and original request, enforce a short expiry, and
  add single-use enforcement where replay would have side effects;
- low-risk form prompts can collect display names, preferences, and
  approval rationale;
- passwords, API keys, payment credentials, access tokens, private keys,
  seed phrases, and session cookies are never allowed through form mode;
- sensitive third-party authorization and credential setup uses URL mode;
- URL mode requires HTTPS, explicit consent, full URL display, domain
  review, no prefetch, no pre-authenticated URLs, and no sensitive data
  embedded in the URL;
- external OAuth via URL mode is separate from MCP authorization and must
  not become token passthrough;
- every request creates receipt evidence tied to workflow, agent, run,
  server, user, session, and correlation ID.

{{< playbook-workflow >}}

## What was added

- Source profile:
  `data/assurance/mcp-elicitation-boundary-profile.json`
- Generator: `scripts/generate_mcp_elicitation_boundary_pack.py`
- Evidence pack:
  `data/evidence/mcp-elicitation-boundary-pack.json`
- Runtime evaluator: `scripts/evaluate_mcp_elicitation_boundary_decision.py`
- MCP tools:
  `recipes_mcp_elicitation_boundary_pack`, paired with `recipes_playbook_plan` using playbook id `mcp-elicitation-boundary`.

Regenerate and validate the pack:

```bash
python3 scripts/generate_mcp_elicitation_boundary_pack.py
python3 scripts/generate_mcp_elicitation_boundary_pack.py --check
```

Evaluate a safe URL-mode OAuth request:

```bash
python3 scripts/evaluate_mcp_elicitation_boundary_decision.py \
  --workflow-id mcp-connector-intake-scanner \
  --agent-id sr-agent::mcp-connector-intake::codex \
  --run-id run-123 \
  --connector-id github \
  --namespace github.oauth \
  --server-id mcp-server::github \
  --elicitation-profile-id profile-third-party-oauth-url \
  --input-request-id github_oauth \
  --request-state opaque-aead-state \
  --mode url \
  --url https://github.com/login/oauth/authorize \
  --url-domain github.com \
  --user-id user-123 \
  --session-id session-123 \
  --correlation-id corr-123 \
  --authorization-pack-hash auth-pack-sha256 \
  --client-supports-mode \
  --server-identity-displayed \
  --user-can-decline \
  --user-consent-recorded \
  --request-state-echoed-exactly \
  --request-state-integrity-validated \
  --retry-request-bound \
  --https-url \
  --url-allowlisted \
  --expect-decision allow_elicitation_with_receipt
```

Evaluate the same URL-mode OAuth request when it arrives on a task handle:

```bash
python3 scripts/evaluate_mcp_elicitation_boundary_decision.py \
  --workflow-id mcp-connector-intake-scanner \
  --agent-id sr-agent::mcp-connector-intake::codex \
  --run-id run-125 \
  --connector-id github \
  --namespace github.oauth \
  --server-id mcp-server::github \
  --elicitation-profile-id profile-third-party-oauth-url \
  --input-request-id github_oauth \
  --request-state opaque-aead-state \
  --mode url \
  --url https://github.com/login/oauth/authorize \
  --url-domain github.com \
  --user-id user-125 \
  --session-id session-125 \
  --correlation-id corr-125 \
  --authorization-pack-hash auth-pack-sha256 \
  --delivery tasks_get \
  --task-id 8f3c9e2a1b4d80c65e4a3210abcdef12 \
  --task-status input_required \
  --result-type task \
  --tasks-extension-declared \
  --task-id-unguessable \
  --task-request-authorized \
  --tasks-update-used \
  --client-supports-mode \
  --server-identity-displayed \
  --user-can-decline \
  --user-consent-recorded \
  --request-state-echoed-exactly \
  --request-state-integrity-validated \
  --https-url \
  --url-allowlisted \
  --expect-decision allow_elicitation_with_receipt
```

Evaluate a blocked secret-form request:

```bash
python3 scripts/evaluate_mcp_elicitation_boundary_decision.py \
  --workflow-id mcp-gateway-policy \
  --agent-id sr-agent::gateway::codex \
  --run-id run-124 \
  --server-id mcp-server::unknown \
  --elicitation-profile-id profile-credential-form-prohibited \
  --input-request-id api_key_form \
  --request-state opaque-aead-state \
  --mode form \
  --data-class api_key \
  --schema-field api_key \
  --session-id session-124 \
  --correlation-id corr-124 \
  --client-supports-mode \
  --server-identity-displayed \
  --user-can-decline \
  --user-can-review \
  --expect-decision deny_sensitive_form_elicitation
```

Kill a task handle that was returned without the tasks extension:

```bash
python3 scripts/evaluate_mcp_elicitation_boundary_decision.py \
  --workflow-id mcp-connector-intake-scanner \
  --agent-id sr-agent::mcp-connector-intake::codex \
  --run-id run-126 \
  --server-id mcp-server::github \
  --elicitation-profile-id profile-third-party-oauth-url \
  --input-request-id github_oauth \
  --mode url \
  --url https://github.com/login/oauth/authorize \
  --session-id session-126 \
  --correlation-id corr-126 \
  --delivery tasks_get \
  --task-id 1 \
  --client-supports-mode \
  --expect-decision kill_session_on_elicitation_abuse
```

## Decision model

| Decision | Meaning |
| --- | --- |
| `allow_elicitation_with_receipt` | The request satisfies mode, data-class, URL, consent, identity, receipt, and (when present) task-handle controls. |
| `hold_for_elicitation_evidence` | The request is missing profile, client capability, identity, consent, review, completion, workflow, task-ID entropy, auth-binding, or `tasks/update` evidence. |
| `deny_sensitive_form_elicitation` | Form mode is asking for a secret, token, payment credential, private key, seed phrase, or secret-like field, including when that form arrived on a task. |
| `deny_untrusted_elicitation_url` | URL mode failed HTTPS, allowlist, phishing, open-redirect, prefetch, pre-authenticated URL, or sensitive-URL checks. |
| `deny_token_or_secret_transit` | Credentials or tokens would transit the MCP client, LLM context, or intermediate MCP server. |
| `kill_session_on_elicitation_abuse` | A runtime kill signal fired, a URL was opened without consent, a task handle was returned without `io.modelcontextprotocol/tasks`, a task ID is guessable, or the host treated the task as a higher-trust channel. |

## What the pack proves

The generated pack joins:

- the MCP authorization conformance pack,
- the context egress boundary pack,
- the MCP tool-risk contract,
- the agentic run receipt pack,
- the workflow control plane,
- and the MCP gateway policy pack.

That gives reviewers a single answer for a subtle production question:
when an MCP server asks a user for more information, is the request safe,
auditable, and separate from tool authorization?

For MCP 2026-07-28, the answer also covers the breaking multi-round-trip
transport change: supported parent request, per-request client capability,
unique input-request correlation, exact opaque-state echo, a distinct retry
request ID, state integrity and replay protection, and binding to the
authenticated principal and original operation. Rechecked August 31, 2026:
2026-07-28 is still current and **stateless**. There is no negotiation
handshake. Servers **MUST** implement
[`server/discover`](https://modelcontextprotocol.io/specification/2026-07-28/server/discover).
Experimental tasks moved into the
[`io.modelcontextprotocol/tasks`](https://modelcontextprotocol.io/extensions/tasks/overview)
extension. Task-bound elicitation uses `tasks/get` `inputRequests` and
`tasks/update`, not a retry of the original method. `--session-id` and
`kill_session` here are local run identifiers and host-session kill
switches, not `Mcp-Session-Id` and not a task ID. Streamable HTTP
revisions through
[2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
could assign that header; 2026-07-28 ignores it and does not mint
session IDs.

## Industry alignment

This feature follows current primary guidance:

- [MCP Elicitation 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
  for form mode, URL mode, per-request capabilities, `InputRequiredResult`,
  sensitive data handling, URL safety, identity binding, and phishing controls.
- [MCP Multi Round-Trip Requests 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)
  for the breaking replacement of server-initiated requests, opaque
  `requestState`, retry correlation, integrity checks, and replay protection.
- [MCP Tasks Extension 2026-07-28](https://modelcontextprotocol.io/extensions/tasks/overview)
  for `CreateTaskResult` handles, `tasks/get` polling, `tasks/update`
  input, unguessable task IDs, auth binding, and the rule that task
  `inputRequests` use the same elicitation trust model.
- [MCP Authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  for protected-resource metadata, resource indicators, audience-bound
  tokens, client identity metadata, and scope challenges.
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  for token passthrough, confused deputy prevention, session safety,
  consent, and auditability.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for tool misuse, identity abuse, human-agent trust exploitation,
  insecure communication, and rogue-agent containment.
- [OpenAI prompt-injection guidance](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
  for treating prompt injection as social engineering and controlling
  sensitive transmissions to third parties.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for governed, measured, and managed GenAI lifecycle risk.

## Trusted-source path

The open pack is the reference model. The reviewed production opportunity
is hosted elicitation safety for MCP:

- customer-specific URL allowlists and domain reputation checks,
- consent receipt storage and replay,
- connector setup flows for external OAuth and API-key rotation,
- phishing and open-redirect telemetry,
- separation checks between external authorization and MCP
  authorization,
- trust-center exports proving which MCP servers can ask users for what.

That is a concrete path from open knowledge to a production MCP safety
layer a model provider, developer platform, security platform, or AI
gateway vendor can acquire.

## MCP examples

Inspect the overall pack:

```text
recipes_mcp_elicitation_boundary_pack()
```

Review URL-mode profiles:

```text
recipes_mcp_elicitation_boundary_pack(mode="url")
```

Plan one runtime request:

```text
recipes_playbook_plan(
  playbook_id="mcp-elicitation-boundary",
  finding="GitHub OAuth URL elicitation request needs consent and domain validation."
)
```

## See also

- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
  for protected-resource and token-boundary proof.
- [MCP Tool Risk Contract]({{< relref "/security-remediation/mcp-tool-risk-contract" >}})
  for pre-call annotation and session-combination risk.
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  for sensitive data movement controls.
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
  for portable run-level proof.
