---
title: Context Egress Boundary
linkTitle: Context Egress Boundary
weight: 11
toc: true
description: >
  A generated data-boundary and runtime evaluator for secure-context
  egress: allow, hold, deny, or kill-session decisions before context
  leaves a tenant, model provider, MCP server, telemetry sink, or public
  corpus boundary.
sidebar:
  exclude: true
---

{{< callout type="info" >}}
**Why this page exists.** A secure context layer is incomplete if it
only controls retrieval. Enterprise reviewers also need to know where
context is allowed to go after retrieval.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the secure context layer for
agentic AI**. That creates two control planes:

- **Ingress:** which context can an agent retrieve?
- **Egress:** where can that context go next?

The existing [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
and [Secure Context Firewall]({{< relref "/security-remediation/secure-context-firewall" >}})
cover ingress. The Context Egress Boundary covers outbound movement to
model providers, remote MCP servers, tenant gateways, telemetry sinks,
public docs, and external URLs.

That matters because agentic systems routinely mix public guidance,
generated evidence, customer findings, source code, logs, tickets,
pipeline output, and connector responses in one workflow. A high-trust
product needs to make the safe path obvious and the unsafe path boringly
blocked.

{{< playbook-workflow >}}

## What was added

- Source model:
  `data/assurance/context-egress-boundary-model.json`
- Generator: `scripts/generate_context_egress_boundary_pack.py`
- Evidence pack:
  `data/evidence/context-egress-boundary-pack.json`
- Runtime evaluator: `scripts/evaluate_context_egress_decision.py`
- MCP tools:
  `recipes_context_egress_boundary_pack`, paired with `recipes_playbook_plan` using playbook id `context-egress-boundary`.

Regenerate and validate the pack:

```bash
python3 scripts/generate_context_egress_boundary_pack.py
python3 scripts/generate_context_egress_boundary_pack.py --check
```

## Decision model

The pack is default-deny. Runtime decisions are:

| Decision | Meaning |
| --- | --- |
| `allow_public_egress_with_citation` | Public or open SecurityRecipes context may leave when source ID, path, hash, and citation metadata are preserved. |
| `allow_tenant_bound_egress` | Tenant-sensitive context may move inside an approved tenant boundary with redaction, audit, retention, and residency controls satisfied. |
| `hold_for_redaction_or_dpa` | The request may be legitimate, but is missing redaction, tenant ID, approval, DPA, zero-data-retention, or residency evidence. |
| `deny_unapproved_workflow_egress` | The workflow or MCP namespace is not approved for this egress path. |
| `deny_untrusted_destination` | The destination is unknown, untrusted, or disallowed for the data class. |
| `deny_unclassified_egress` | The data class or source is missing, unknown, or unmapped. |
| `kill_session_on_secret_egress` | Secrets, tokens, private keys, signing material, seed phrases, or production credentials attempted to leave the boundary. |

## Data classes

The model separates context into classes such as:

- public references,
- curated SecurityRecipes guidance,
- generated policy evidence,
- public vulnerability intelligence,
- customer asset metadata,
- customer source code,
- customer finding metadata,
- customer pipeline metadata,
- customer case context,
- customer runtime logs,
- regulated personal data,
- secrets and signing material.

That makes the agent-side behavior simple: classify the context, name
the destination, attach the workflow and namespace, then ask for a
decision before the data moves.

## Destination classes

The generated pack declares destination classes for:

- `securityrecipes_public_corpus`,
- `tenant_mcp_gateway`,
- `approved_model_provider`,
- `approved_remote_mcp_server`,
- `observability_sink`,
- `untrusted_remote_mcp_server`,
- `external_url_or_webhook`.

Each destination records whether it is trusted, whether it is an
external processor, and whether it requires DPA, zero-data-retention,
residency match, connector trust, schema pinning, token-audience
validation, or tool-result inspection.

## CLI examples

Allow public guidance to an approved model provider:

```bash
python3 scripts/evaluate_context_egress_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --destination-class approved_model_provider \
  --source-id recipes \
  --data-class curated_security_guidance \
  --dpa-in-place \
  --zero-data-retention \
  --residency-region us \
  --required-region us \
  --expect-decision allow_public_egress_with_citation
```

Hold customer source code that lacks required human approval:

```bash
python3 scripts/evaluate_context_egress_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --destination-class approved_model_provider \
  --data-class customer_source_code \
  --mcp-namespace repo.contents \
  --tenant-id tenant-123 \
  --dpa-in-place \
  --zero-data-retention \
  --residency-region us \
  --required-region us \
  --expect-decision hold_for_redaction_or_dpa
```

Kill a secret-egress attempt:

```bash
python3 scripts/evaluate_context_egress_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --destination-class approved_model_provider \
  --data-class customer_source_code \
  --contains-secret \
  --expect-decision kill_session_on_secret_egress
```

## MCP examples

Inspect the boundary:

```text
recipes_context_egress_boundary_pack()
```

Review one data class:

```text
recipes_context_egress_boundary_pack(data_class="customer_source_code")
```

Plan one outbound context movement:

```text
recipes_playbook_plan(
  playbook_id="context-egress-boundary",
  finding="Tenant-sensitive remediation context is proposed for an approved US-region model provider."
)
```

## Why this is enterprise-grade

This moves SecurityRecipes closer to a product an AI platform team can
approve and a reviewer can diligence:

- It separates public context from tenant runtime context.
- It makes model providers and remote MCP servers explicit external
  processors.
- It records DPA, zero-data-retention, residency, approval, redaction,
  and trust-tier requirements as policy inputs.
- It gives privacy, security, and platform teams a shared vocabulary for
  data movement.
- It creates a hosted-ready path for tenant-side egress enforcement,
  DLP integrations, provider adapters, residency alerts, and customer
  trust-center exports.

## Industry alignment

This feature follows current guidance:

- [OpenAI Connectors and MCP servers](https://platform.openai.com/docs/guides/tools-remote-mcp)
  for connector, remote MCP, sensitive-data, retention, and residency
  risk.
- [OpenAI Safety in building agents](https://platform.openai.com/docs/guides/agent-builder-safety)
  for structured outputs, tool approvals, guardrails, trace graders, and
  careful MCP tool calling.
- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, audience-bound tokens, HTTPS, PKCE, token
  validation, and no token passthrough.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  for confused-deputy prevention, token safety, scope minimization,
  SSRF controls, session safety, and auditability.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
  for token mismanagement, scope creep, tool poisoning, command
  execution, missing telemetry, shadow MCP servers, and context
  over-sharing.
- [CISA AI Data Security](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
  and [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for data security, integrity, provenance, monitoring, third-party, and
  lifecycle risk.

## See also

- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  for approved context roots and hashes.
- [Secure Context Firewall]({{< relref "/security-remediation/secure-context-firewall" >}})
  for retrieval decisions before context enters the model window.
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
  for pre-retrieval scanning of registered context roots.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  for remote MCP trust tiers and promotion criteria.
- [Agentic System BOM]({{< relref "/security-remediation/agentic-system-bom" >}})
  for inspectable agentic-system inventory.
