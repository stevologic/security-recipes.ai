---
title: MCP Elicitation Boundary
linkTitle: MCP Elicitation Boundary
weight: 11
toc: true
description: >
  Generated MCP form-mode and URL-mode elicitation controls with
  deterministic runtime decisions for sensitive data, external auth,
  payment, URL safety, consent, and receipt evidence.
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

## What was added

- Source profile:
  `data/assurance/mcp-elicitation-boundary-profile.json`
- Generator:
  `scripts/generate_mcp_elicitation_boundary_pack.py`
- Evidence pack:
  `data/evidence/mcp-elicitation-boundary-pack.json`
- Runtime evaluator:
  `scripts/evaluate_mcp_elicitation_boundary_decision.py`
- MCP tools:
  `recipes_mcp_elicitation_boundary_pack` and
  `recipes_evaluate_mcp_elicitation_boundary_decision`

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
  --elicitation-id elicit-123 \
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
  --completion-notification-bound \
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
  --elicitation-id elicit-124 \
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

## Decision model

| Decision | Meaning |
| --- | --- |
| `allow_elicitation_with_receipt` | The request satisfies mode, data-class, URL, consent, identity, and receipt controls. |
| `hold_for_elicitation_evidence` | The request is missing profile, client capability, identity, consent, review, completion, or workflow evidence. |
| `deny_sensitive_form_elicitation` | Form mode is asking for a secret, token, payment credential, private key, seed phrase, or secret-like field. |
| `deny_untrusted_elicitation_url` | URL mode failed HTTPS, allowlist, phishing, open-redirect, prefetch, pre-authenticated URL, or sensitive-URL checks. |
| `deny_token_or_secret_transit` | Credentials or tokens would transit the MCP client, LLM context, or intermediate MCP server. |
| `kill_session_on_elicitation_abuse` | A runtime kill signal fired or a URL was opened without explicit consent. |

## What the pack proves

The generated pack joins:

- the MCP authorization conformance pack,
- the context egress boundary pack,
- the MCP tool-risk contract,
- the agentic run receipt pack,
- the workflow control plane,
- and the MCP gateway policy pack.

That gives buyers a single answer for a subtle production question:
when an MCP server asks a user for more information, is the request safe,
auditable, and separate from tool authorization?

## Industry alignment

This feature follows current primary guidance:

- [MCP Elicitation 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
  for form mode, URL mode, sensitive data handling, URL safe handling,
  user identity binding, completion notifications, and phishing controls.
- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
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

## Commercial path

The open pack is the reference model. The premium production opportunity
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

Evaluate one runtime request:

```text
recipes_evaluate_mcp_elicitation_boundary_decision(
  workflow_id="mcp-connector-intake-scanner",
  agent_id="sr-agent::mcp-connector-intake::codex",
  run_id="run-123",
  connector_id="github",
  namespace="github.oauth",
  server_id="mcp-server::github",
  elicitation_profile_id="profile-third-party-oauth-url",
  elicitation_id="elicit-123",
  mode="url",
  url="https://github.com/login/oauth/authorize",
  url_domain="github.com",
  user_id="user-123",
  session_id="session-123",
  correlation_id="corr-123",
  authorization_pack_hash="auth-pack-sha256",
  client_supports_mode=true,
  server_identity_displayed=true,
  user_can_decline=true,
  user_consent_recorded=true,
  completion_notification_bound=true,
  https_url=true,
  url_allowlisted=true
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
