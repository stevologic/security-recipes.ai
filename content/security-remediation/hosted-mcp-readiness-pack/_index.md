---
title: Hosted MCP Readiness Pack
linkTitle: Hosted MCP Readiness
weight: 14
sidebar:
  open: true
description: >
  A generated hosted-MCP readiness plan that turns the open
  SecurityRecipes corpus into a tenant-safe enterprise product roadmap:
  protected-resource authorization, private context ingestion, connector
  isolation, telemetry, signed receipts, metering, and buyer rollout
  gates.
---

{{< callout type="info" >}}
**Why this page exists.** SecurityRecipes already ships a credible open
corpus and local read-only MCP server. The next enterprise gap is hosted
MCP: tenant isolation, private evidence ingestion, protected-resource
authorization, receipt integrity, SOC evidence, metering, and operational
readiness.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. The long-term product is not just documentation. It is a hosted
secure context and MCP control plane that lets agent hosts ask safer
questions, call tools with bounded authority, and produce evidence that
security, GRC, and buyers can inspect.

The **Hosted MCP Readiness Pack** makes that path concrete. It names the
controls that are already reference-ready, the controls that need
design-partner runtime evidence, and the controls that block production
hosted claims until a tenant-safe service exists.

## What was added

- `data/assurance/hosted-mcp-readiness-profile.json` - source profile
  for hosted MCP positioning, current source references, source-pack
  dependencies, stages, controls, rollout gates, buyer evidence,
  commercialization, risks, and next 90 days.
- `scripts/generate_hosted_mcp_readiness_pack.py` - deterministic
  generator and `--check` validator.
- `data/evidence/hosted-mcp-readiness-pack.json` - generated pack with
  14 source packs, 5 rollout stages, 21 readiness controls, 7 gates, 5
  buyer evidence items, and 7 hosted-product risks.
- `recipes_hosted_mcp_readiness_pack` - MCP tool for the full pack, one
  readiness stage, control, rollout gate, buyer evidence item, risk, or
  implementation-status view.

Run it from the repo root:

```bash
python3 scripts/generate_hosted_mcp_readiness_pack.py
python3 scripts/generate_hosted_mcp_readiness_pack.py --check
```

## Product decision

The generated artifact currently reports:

| Field | Value |
| --- | --- |
| `contract_status` | `hosted_mcp_readiness_contract_ready` |
| `product_readiness_decision` | `hold_for_hosted_runtime_implementation` |
| `production_ready` | `false` |
| `source_pack_ready_count` | `14` |
| `control_count` | `21` |
| `hosted_runtime_required_count` | `18` |

That is intentional. The open reference layer is credible, but a
production hosted MCP service must still prove tenant isolation, private
evidence ingestion, protected-resource authorization, receipt integrity,
operational controls, metering, and customer proof.

## Readiness stages

| Stage | Meaning |
| --- | --- |
| Open reference MCP server | Public read-only site and generated packs are ready for reference use. |
| Design partner private context pilot | One scoped tenant binds private context, redacted telemetry, proof metrics, and reviewer outcomes. |
| Protected hosted MCP gateway | Hosted MCP enforces resource indicators, audience validation, scope challenge, no token passthrough, connector isolation, and tool-surface drift controls. |
| Assurance and operations | Receipts, SOC detection, incident containment, retention/deletion, SLO, and recovery controls become inspectable. |
| Commercial packaging and acquisition readiness | Metering, plan boundaries, renewal metrics, support model, and paid-wedge proof become explicit. |

## Controls that matter most

The pack intentionally focuses on high-leverage enterprise controls:

- **Tenant-bound context index** - private context cannot cross tenant,
  package, egress, retention, or receipt boundaries.
- **Protected-resource authorization** - hosted MCP calls require
  resource indicators, token audience validation, issuer checks, session
  binding, scope state, and explicit pre-execution decisions.
- **No token passthrough** - the service kills sessions on token
  reuse, wrong audience, secret capture, or cross-tenant credential
  signals.
- **Connector runtime isolation** - hosted connectors need namespace,
  sandbox, egress, promotion, and rollback boundaries.
- **Tool-surface drift monitoring** - tool descriptions, schemas,
  annotations, and capability flags cannot silently expand authority.
- **Metadata-first telemetry** - customer proof uses traces, hashes,
  decisions, and redacted summaries instead of raw prompts, secrets, or
  private code.
- **Signed or verifiable run receipts** - every governed run needs
  tamper-evident proof linking identity, context, MCP authorization,
  egress, approvals, verifier output, and closure.
- **Metering and entitlement** - the paid wedge is usage of tenant-bound
  context packages, governed MCP decisions, connector namespaces,
  trust-center exports, and proof retention.

## Rollout gates

| Gate | Decision |
| --- | --- |
| Tenant isolation gate | Deny private context until tenant, egress, retention, and deletion controls pass. |
| Protected-resource authorization gate | Hold hosted MCP until resource, audience, issuer, session, scope, and token checks pass. |
| Connector promotion gate | Hold connector promotion until isolation, tool-surface drift, and elicitation checks pass. |
| Telemetry redaction gate | Hold customer proof until telemetry is useful without leaking sensitive data. |
| Receipt integrity gate | Hold acquisition claims until receipts are tamper-evident or externally verifiable. |
| Operations gate | Hold enterprise rollout until incident, support, SLO, recovery, and disablement paths are tested. |
| Commercial gate | Hold the revenue story until usage meters, renewal metrics, and a budget-owned paid wedge exist. |

## Why it is acquisition-grade

This pack turns the $10-20M vision into diligence artifacts an acquirer
can inspect:

- It separates the open reference moat from the paid hosted product.
- It names the runtime controls that must exist before private customer
  context is allowed.
- It maps MCP authorization, connector drift, source freshness,
  telemetry, SOC detection, receipts, and trust-center exports into one
  hosted roadmap.
- It treats no-token-passthrough, step-up authorization, egress holds,
  and kill decisions as premium product value.
- It defines usage meters and plan boundaries before revenue is claimed.

The resulting story is more credible: open knowledge creates
distribution and trust; hosted MCP turns that knowledge into enforceable
context; customer proof and metering create the enterprise value.

## MCP examples

Inspect the full hosted MCP readiness pack:

```text
recipes_hosted_mcp_readiness_pack()
```

Inspect one readiness control:

```text
recipes_hosted_mcp_readiness_pack(control_id="protected-resource-authorization")
```

Inspect one rollout gate:

```text
recipes_hosted_mcp_readiness_pack(gate_id="receipt-integrity-gate")
```

Find all controls that still need hosted runtime implementation:

```text
recipes_hosted_mcp_readiness_pack(status="hosted_runtime_required")
```

Find buyer evidence for the acquirer revenue story:

```text
recipes_hosted_mcp_readiness_pack(buyer_evidence_id="acquirer-revenue-proof")
```

## Industry alignment

The profile is grounded in current primary sources:

- [MCP basic specification](https://modelcontextprotocol.io/specification/2025-11-25/basic)
  for protocol layers, lifecycle, resources, prompts, tools, client
  features, and utilities.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected-resource metadata, resource indicators, token audience
  binding, scope minimization, step-up authorization, PKCE, and no token
  passthrough.
- [MCP Elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
  for form-mode and URL-mode interaction boundaries.
- [OpenTelemetry MCP semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/)
  for MCP spans, sessions, methods, transports, errors, and duration
  metrics.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
  and [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
  for agentic and MCP-specific threat classes.
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
  and [CSA capabilities-based risk assessment](https://cloudsecurityalliance.org/press-releases/2025/11/13/cloud-security-alliance-introduces-new-tool-for-assessing-agentic-risk)
  for enterprise AI assurance and consequence-driven agentic risk.
- [NIST AI Agent Standards Initiative](https://www.nist.gov/node/1906621)
  and [NIST CAISI agent security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for secure, interoperable agent infrastructure and deployment
  measurement.
- [CISA AI Data Security](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
  and [CISA Deploying AI Systems Securely](https://www.cisa.gov/news-events/alerts/2024/04/15/joint-guidance-deploying-ai-systems-securely)
  for data security, integrity, monitoring, detection, response, and
  secure AI deployment.

## See also

- [Production MCP Server]({{< relref "/mcp-servers" >}})
- [Secure Context Customer Proof Pack]({{< relref "/security-remediation/secure-context-customer-proof-pack" >}})
- [Design Partner Pilot Pack]({{< relref "/security-remediation/design-partner-pilot-pack" >}})
- [Secure Context Buyer Diligence Brief]({{< relref "/security-remediation/secure-context-buyer-diligence-brief" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [MCP Tool Surface Drift Sentinel]({{< relref "/security-remediation/mcp-tool-surface-drift-sentinel" >}})
- [Agentic Telemetry Contract]({{< relref "/security-remediation/agentic-telemetry-contract" >}})
- [Agentic SOC Detection Pack]({{< relref "/security-remediation/agentic-soc-detection-pack" >}})
