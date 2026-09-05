---
title: MCP Authorization Conformance
linkTitle: MCP Authorization Conformance
weight: 10
date: 2026-05-02
lastmod: 2026-09-05
toc: true
description: >
  Generate an MCP authorization conformance pack for resource-bound tokens,
  audience validation, PKCE, RFC 9207 issuer mix-up checks, http(s)-only
  authorization URLs, client metadata, scope challenges, and step-up
  authorization.
sidebar:
  exclude: true
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**Why this page exists.** MCP makes tool connection easy. Enterprises
need the missing authorization proof: which agent was delegated, which
resource the token was minted for, which scopes were granted, and whether
the tool call stayed inside the workflow.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the secure context layer for
agentic AI**. Context trust, egress controls, and run receipts are not
enough if MCP authorization is loose. A production reviewer will ask:

- Is the token bound to the MCP resource, not a generic upstream API?
- Does the MCP server validate audience, issuer, expiry, and scope?
- Are raw user tokens ever passed through to downstream tools?
- Is the scope tied to workflow, namespace, access mode, agent, and run?
- Was the OAuth client ID metadata document validated for this client?
- Was the authorization-response `iss` checked against the recorded
  authorization-server issuer before the code was redeemed?
- Are client credentials keyed to that same issuer, not reused across
  authorization servers?
- Is the authorization endpoint URL http or https, not `javascript:`,
  `data:`, `file:`, or `vbscript:`?
- Did the client satisfy an authoritative `WWW-Authenticate` scope challenge?
- Is a typed step-up authorization receipt present for approval-required access?
- Can the gateway prove consent, session binding, and audit correlation?
- Which new MCP servers fail before promotion?

The MCP Authorization Conformance pack answers those questions in a
machine-readable artifact and exposes a runtime evaluator for pre-call
authorization decisions. Rechecked September 5, 2026: MCP
[2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
is still current and **stateless**. There is no negotiation handshake.
Each request carries protocol version and capabilities. Servers
**MUST** implement
[`server/discover`](https://modelcontextprotocol.io/specification/2026-07-28/server/discover).
Authorization servers **SHOULD** include RFC 9207 `iss` on
authorization responses; clients **MUST** record the issuer from
validated authorization-server metadata and apply
[RFC 9207 Section 2.4](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4)
with simple string comparison before redeeming a code. Clients
**MUST** open only `http://` or `https://` authorization URLs and
**MUST** reject `javascript:`, `data:`, `file:`, and `vbscript:`
schemes. `http://` is acceptable only for loopback addresses during
local development; production authorization servers **MUST** use
`https://`. Dynamic Client Registration is **deprecated**; Client ID
Metadata Documents remain the preferred registration method.
`--session-id` and `kill_session` here are local run identifiers and
host-session kill switches, not `Mcp-Session-Id`. Session binding in
this pack means OAuth and token-to-run binding. Streamable HTTP
revisions through
[2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
could assign that header; 2026-07-28 ignores it and does not mint
session IDs. Unspecified authorization-endpoint evidence stays on the
prior allow path so existing issuer, audience, and scope checks remain
valid.

{{< playbook-workflow >}}

## What was added

- Source profile:
  `data/assurance/mcp-authorization-conformance-profile.json`
- Generator: `scripts/generate_mcp_authorization_conformance_pack.py`
- Evidence pack:
  `data/evidence/mcp-authorization-conformance-pack.json`
- Runtime evaluator: `scripts/evaluate_mcp_authorization_decision.py`
- MCP tools:
  `recipes_mcp_authorization_conformance_pack`, paired with `recipes_playbook_plan` using playbook id `mcp-authorization-conformance`.

Regenerate and validate the pack:

```bash
python3 scripts/generate_mcp_authorization_conformance_pack.py
python3 scripts/generate_mcp_authorization_conformance_pack.py --check
```

Evaluate a runtime authorization request:

```bash
python3 scripts/evaluate_mcp_authorization_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --connector-id repository-contents \
  --namespace repo.contents \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --run-id ci-allow \
  --client-id https://agent.security-recipes.ai/client-metadata/codex.json \
  --client-metadata-document-url https://agent.security-recipes.ai/client-metadata/codex.json \
  --client-metadata-document-validated \
  --authorization-server-discovery-method www_authenticate \
  --protected-resource-metadata-url https://mcp.security-recipes.ai/.well-known/oauth-protected-resource \
  --requested-access-mode write_branch \
  --resource-indicator https://mcp.security-recipes.ai/mcp \
  --token-audience https://mcp.security-recipes.ai/mcp \
  --token-issuer https://auth.security-recipes.ai \
  --expected-authorization-issuer https://auth.security-recipes.ai \
  --authorization-response-iss https://auth.security-recipes.ai \
  --authorization-response-iss-parameter-supported \
  --token-expires-at 2099-01-01T00:15:00Z \
  --token-scope repo.contents:write_branch \
  --scope-challenge repo.contents:write_branch \
  --consent-record-id consent-ci \
  --session-id session-ci \
  --correlation-id corr-ci \
  --gateway-policy-hash sha256:ci-policy \
  --expect-decision allow_authorized_mcp_request
```

Reject a mix-up grant whose authorization-response `iss` does not match
the recorded authorization-server issuer:

```bash
python3 scripts/evaluate_mcp_authorization_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --connector-id repository-contents \
  --namespace repo.contents \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --run-id ci-mixup \
  --client-id https://agent.security-recipes.ai/client-metadata/codex.json \
  --client-metadata-document-url https://agent.security-recipes.ai/client-metadata/codex.json \
  --client-metadata-document-validated \
  --authorization-server-discovery-method www_authenticate \
  --protected-resource-metadata-url https://mcp.security-recipes.ai/.well-known/oauth-protected-resource \
  --requested-access-mode write_branch \
  --resource-indicator https://mcp.security-recipes.ai/mcp \
  --token-audience https://mcp.security-recipes.ai/mcp \
  --token-issuer https://auth.security-recipes.ai \
  --expected-authorization-issuer https://auth.security-recipes.ai \
  --authorization-response-iss https://attacker.example/as \
  --authorization-response-iss-parameter-supported \
  --token-expires-at 2099-01-01T00:15:00Z \
  --token-scope repo.contents:write_branch \
  --scope-challenge repo.contents:write_branch \
  --consent-record-id consent-ci \
  --session-id session-ci \
  --correlation-id corr-ci \
  --gateway-policy-hash sha256:ci-policy \
  --expect-decision deny_authorization_issuer_mismatch
```

Reject a grant whose authorization endpoint uses a `javascript:` URL:

```bash
python3 scripts/evaluate_mcp_authorization_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --connector-id repository-contents \
  --namespace repo.contents \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --run-id ci-js-url \
  --client-id https://agent.security-recipes.ai/client-metadata/codex.json \
  --client-metadata-document-url https://agent.security-recipes.ai/client-metadata/codex.json \
  --client-metadata-document-validated \
  --authorization-server-discovery-method www_authenticate \
  --protected-resource-metadata-url https://mcp.security-recipes.ai/.well-known/oauth-protected-resource \
  --authorization-endpoint-url 'javascript:alert(1)' \
  --requested-access-mode write_branch \
  --resource-indicator https://mcp.security-recipes.ai/mcp \
  --token-audience https://mcp.security-recipes.ai/mcp \
  --token-issuer https://auth.security-recipes.ai \
  --expected-authorization-issuer https://auth.security-recipes.ai \
  --authorization-response-iss https://auth.security-recipes.ai \
  --authorization-response-iss-parameter-supported \
  --token-expires-at 2099-01-01T00:15:00Z \
  --token-scope repo.contents:write_branch \
  --scope-challenge repo.contents:write_branch \
  --consent-record-id consent-ci \
  --session-id session-ci \
  --correlation-id corr-ci \
  --gateway-policy-hash sha256:ci-policy \
  --expect-decision deny_insecure_authorization_url
```

## Decision model

| Decision | Meaning |
| --- | --- |
| `allow_authorized_mcp_request` | The request is bound to the expected MCP resource and stays inside the connector and workflow scope. |
| `hold_for_authorization_evidence` | The connector or candidate server still needs authorization metadata, gateway evidence, or conformance controls. |
| `hold_for_client_metadata_evidence` | The remote MCP request lacks a validated HTTPS OAuth client ID metadata document that matches `client_id`. |
| `hold_for_step_up_authorization` | Approval-required MCP access lacks a typed step-up authorization receipt. |
| `deny_token_passthrough` | The request would pass raw user or upstream tokens through the agent/tool path. |
| `deny_unbound_token` | The token is missing the expected resource indicator or audience binding. |
| `deny_authorization_issuer_mismatch` | The authorization-response `iss` or token issuer does not match the recorded authorization-server issuer. |
| `deny_insecure_authorization_url` | The authorization endpoint uses a prohibited scheme or non-loopback `http://` URL. |
| `deny_scope_challenge_mismatch` | The token scopes do not satisfy the authoritative MCP scope challenge for the resource. |
| `deny_scope_drift` | The workflow, namespace, connector, or access mode is outside the approved authorization scope. |
| `kill_session_on_secret_or_signer_scope` | The request includes credential, signer, deploy, publish, or live-funds authority. |

## What the pack proves

The generated pack joins:

- the MCP connector trust pack,
- the MCP connector intake pack,
- the workflow control plane,
- the gateway policy pack,
- and the authorization conformance profile.

For production connector namespaces, it records the gateway attestation
controls that must exist: per-client consent, short-lived workload
identity, token-passthrough denial, audit, session binding, and write or
approval controls where applicable.

For the latest MCP authorization revision, it also records the metadata
evidence a production gateway should retain: protected-resource metadata
discovery, authorization-server discovery, client ID metadata document
validation, the recorded authorization-server issuer, RFC 9207 `iss`
support, authorization endpoint URL, resource indicator and audience
values, JWKS or introspection validation, redirect policy, scope
challenge policy, and step-up authorization policy.

For candidate MCP servers, it evaluates the detailed intake profile for
resource indicators, audience validation, PKCE, short-lived tokens,
client ID metadata documents, scope challenge handling, step-up
authorization, private-network exposure, token passthrough, session
binding, and audit evidence before promotion.

## Industry alignment

This feature follows current primary guidance:

- [Model Context Protocol Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  for protected-resource metadata discovery, OAuth client ID metadata
  documents, resource indicators, audience-bound bearer tokens, HTTPS,
  PKCE, RFC 9207 authorization-response issuer validation, issuer-bound
  client credentials, scope challenges, step-up authorization, and token
  validation. Dynamic Client Registration remains available only as a
  deprecated compatibility path.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)
  for confused-deputy prevention, token-passthrough avoidance, SSRF,
  OAuth authorization URL scheme validation, session safety, scope
  minimization, and audit trails.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for tool misuse, identity abuse, agentic supply-chain risk, context
  poisoning, cascading failures, and rogue-agent containment.
- [CISA AI Data Security](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
  for provenance, integrity, access control, monitoring, third-party data
  handling, and incident evidence.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  and the
  [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for governed, mapped, measured, and managed AI risk.

## Trusted-source path

The open pack is the proof model. The reviewed production opportunity is
a hosted MCP authorization scanner:

- discover live protected-resource and authorization-server metadata,
- validate OAuth client ID metadata documents,
- diff resource indicators, audiences, scopes, and redirect policy,
- alert on scope challenge drift and token-passthrough regressions,
- enforce step-up authorization receipts for approval-required calls,
- replay confused-deputy, issuer mix-up, unsafe authorization-URL, and unbound-token tests,
- attach signed authorization receipts to agent run receipts,
- export fleet-wide evidence for AI platform review and procurement.

That is the path from open knowledge to a production MCP security
platform that a model provider, AI platform vendor, or security company
would understand.

## MCP examples

Inspect the overall pack:

```text
recipes_mcp_authorization_conformance_pack()
```

Review one connector:

```text
recipes_mcp_authorization_conformance_pack(
  connector_id="repository-contents"
)
```

Plan one runtime request:

```text
recipes_playbook_plan(
  playbook_id="mcp-authorization-conformance",
  finding="Repository-write MCP request needs OAuth and authorization conformance review."
)
```

## See also

- [MCP Connector Intake Scanner]({{< relref "/security-remediation/mcp-connector-intake-scanner" >}})
  for pre-promotion MCP server review.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  for namespace tiers and connector evidence.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  for default-deny tool access decisions.
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
  for run-level proof objects that can carry authorization evidence.
