---
title: MCP Authorization Conformance
linkTitle: MCP Authorization Conformance
weight: 10
toc: true
description: >
  A generated MCP authorization conformance pack for resource-bound
  tokens, audience validation, PKCE, client ID metadata documents,
  scope challenges, step-up authorization, token-passthrough denial,
  workflow-scoped authorization, session binding, and scope drift.
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
enough if MCP authorization is loose. A production buyer will ask:

- Is the token bound to the MCP resource, not a generic upstream API?
- Does the MCP server validate audience, issuer, expiry, and scope?
- Are raw user tokens ever passed through to downstream tools?
- Is the scope tied to workflow, namespace, access mode, agent, and run?
- Was the OAuth client ID metadata document validated for this client?
- Did the client satisfy an authoritative `WWW-Authenticate` scope challenge?
- Is a typed step-up authorization receipt present for approval-required access?
- Can the gateway prove consent, session binding, and audit correlation?
- Which new MCP servers fail before promotion?

The MCP Authorization Conformance pack answers those questions in a
machine-readable artifact and exposes a runtime evaluator for pre-call
authorization decisions.

## What was added

- Source profile:
  `data/assurance/mcp-authorization-conformance-profile.json`
- Generator:
  `scripts/generate_mcp_authorization_conformance_pack.py`
- Evidence pack:
  `data/evidence/mcp-authorization-conformance-pack.json`
- Runtime evaluator:
  `scripts/evaluate_mcp_authorization_decision.py`
- MCP tools:
  `recipes_mcp_authorization_conformance_pack` and
  `recipes_evaluate_mcp_authorization_decision`

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
  --token-expires-at 2099-01-01T00:15:00Z \
  --token-scope repo.contents:write_branch \
  --scope-challenge repo.contents:write_branch \
  --consent-record-id consent-ci \
  --session-id session-ci \
  --correlation-id corr-ci \
  --gateway-policy-hash sha256:ci-policy \
  --expect-decision allow_authorized_mcp_request
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
validation, resource indicator and audience values, JWKS or introspection
validation, redirect policy, scope challenge policy, and step-up
authorization policy.

For candidate MCP servers, it evaluates the detailed intake profile for
resource indicators, audience validation, PKCE, short-lived tokens,
client ID metadata documents, scope challenge handling, step-up
authorization, private-network exposure, token passthrough, session
binding, and audit evidence before promotion.

## Industry alignment

This feature follows current primary guidance:

- [Model Context Protocol Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected-resource metadata discovery, OAuth client ID metadata
  documents, resource indicators, audience-bound bearer tokens, HTTPS,
  PKCE, scope challenges, step-up authorization, and token validation.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  for confused-deputy prevention, token-passthrough avoidance, SSRF,
  session safety, scope minimization, and audit trails.
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

## Commercial path

The open pack is the proof model. The premium production opportunity is
a hosted MCP authorization scanner:

- discover live protected-resource and authorization-server metadata,
- validate OAuth client ID metadata documents,
- diff resource indicators, audiences, scopes, and redirect policy,
- alert on scope challenge drift and token-passthrough regressions,
- enforce step-up authorization receipts for approval-required calls,
- replay confused-deputy and unbound-token tests,
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

Evaluate one runtime request:

```text
recipes_evaluate_mcp_authorization_decision(
  workflow_id="vulnerable-dependency-remediation",
  connector_id="repository-contents",
  namespace="repo.contents",
  agent_id="sr-agent::vulnerable-dependency-remediation::codex",
  run_id="run-123",
  client_id="https://agent.security-recipes.ai/client-metadata/codex.json",
  client_metadata_document_url="https://agent.security-recipes.ai/client-metadata/codex.json",
  client_metadata_document_validated=true,
  authorization_server_discovery_method="www_authenticate",
  protected_resource_metadata_url="https://mcp.security-recipes.ai/.well-known/oauth-protected-resource",
  requested_access_mode="write_branch",
  resource_indicator="https://mcp.security-recipes.ai/mcp",
  token_audience="https://mcp.security-recipes.ai/mcp",
  token_issuer="https://auth.security-recipes.ai",
  token_expires_at="2099-01-01T00:15:00Z",
  token_scopes=["repo.contents:write_branch"],
  scope_challenge=["repo.contents:write_branch"],
  consent_record_id="consent-123",
  session_id="session-123",
  correlation_id="corr-123",
  gateway_policy_hash="sha256:policy"
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
