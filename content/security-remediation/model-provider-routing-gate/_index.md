---
title: Model Provider Routing Gate
linkTitle: Model Provider Routing
weight: 16
toc: true
description: >
  A generated model-provider routing gate for deciding which model
  provider and model route may receive secure context for an agentic
  workflow, with proof for data retention, residency, guardrails,
  telemetry, receipts, and approval before the model call starts.
---

{{< callout type="info" >}}
**Why this page exists.** The secure context layer is not complete until
it can answer one operational question: which model/provider is allowed
to receive this context for this workflow, right now?
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the Secure Context Layer for Agentic
AI**. That means context is not just retrieved, cited, signed, and
egress-checked. It also needs a provider route decision before the next
model call starts.

The enterprise version of agentic AI will be multi-provider. Teams will
want OpenAI, Anthropic, xAI, private-cloud models, local models, and
specialized guardrail models in the same estate. The problem is not
choosing a favorite model. The problem is proving that the selected
model route matches:

- the workflow,
- the data class,
- the autonomy level,
- the provider contract,
- the tenant region,
- the retention/training posture,
- the MCP and tool guardrails,
- the telemetry contract,
- the run receipt,
- and any human approval required for sensitive context.

The Model Provider Routing Gate makes that decision inspectable. It is a
provider-neutral policy pack that enterprises can fork into their own
model registry while keeping the open evidence shape stable.

## What was added

- Source profile:
  `data/assurance/model-provider-routing-profile.json`
- Generator:
  `scripts/generate_model_provider_routing_pack.py`
- Runtime evaluator:
  `scripts/evaluate_model_provider_routing_decision.py`
- Evidence pack:
  `data/evidence/model-provider-routing-pack.json`
- MCP tools:
  `recipes_model_provider_routing_pack` and
  `recipes_evaluate_model_provider_routing_decision`

Regenerate and validate the pack:

```bash
python3 scripts/generate_model_provider_routing_pack.py
python3 scripts/generate_model_provider_routing_pack.py --check
```

Evaluate a tenant-sensitive route before a model call starts:

```bash
python3 scripts/evaluate_model_provider_routing_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --provider-id frontier-enterprise-provider \
  --model-id frontier-code-and-security-reasoning \
  --route-class tenant_sensitive_remediation \
  --data-class customer_source_code \
  --data-class customer_finding_metadata \
  --autonomy-level bounded_agent \
  --tenant-id tenant-123 \
  --tenant-region us \
  --provider-region us \
  --enterprise-contract \
  --dpa-in-place \
  --zero-data-retention \
  --training-opt-out \
  --mcp-gateway-enforced \
  --tool-guardrails-enforced \
  --output-guardrails-enforced \
  --telemetry-redacted \
  --run-receipt-attached \
  --egress-decision allow_tenant_bound_egress \
  --human-approval-id approval-123
```

## Routing contract

The default state is `hold_for_model_provider_review`. A route is not
trusted just because a model is capable. The decision contract requires:

| Proof | What it prevents |
| --- | --- |
| Approved provider profile | Shadow AI, personal accounts, unmanaged agents, and revoked contracts. |
| Approved model route | Model misbinding and ad hoc provider/model selection. |
| Data-class allowlist | Customer code, regulated data, secrets, and browser context crossing the wrong boundary. |
| Autonomy ceiling | High-impact autonomy using a route intended only for assisted or bounded work. |
| ZDR / private runtime | Sensitive context being retained, trained on, or reused outside the tenant boundary. |
| DPA and residency evidence | External processor and regional-policy drift. |
| MCP gateway enforcement | Tool-backed context bypassing resource, audience, scope, and session controls. |
| Tool/output guardrails | Model calls starting before tool or output tripwires can block side effects. |
| Redacted telemetry | Prompts, tool arguments, outputs, and retrieved context becoming a new data sink. |
| Run receipt binding | Provider decisions that cannot be reconstructed during review or incident response. |
| Egress decision | Model routing bypassing the context egress boundary. |

## Route classes

The generated pack ships with five reference routes:

| Route | Default decision | Intended use |
| --- | --- | --- |
| `public-context-frontier-route` | `allow_approved_route` | Public SecurityRecipes context, generated open evidence, and vulnerability intelligence. |
| `tenant-remediation-frontier-route` | `allow_guarded_route` | Tenant remediation work through an approved frontier provider under enterprise controls. |
| `private-runtime-restricted-route` | `allow_guarded_route` | Private runtime for tenant source, regulated data, and restricted support context. |
| `browser-and-untrusted-content-guardrail-route` | `allow_guarded_route` | Blocking guardrail classification before browser or untrusted-content work proceeds. |
| `shadow-ai-deny-route` | `deny_unapproved_route` | Personal accounts, unmanaged providers, and unsanctioned model hosts. |

Forks should replace abstract model IDs such as
`frontier-code-and-security-reasoning` with their approved OpenAI,
Anthropic, xAI, private-cloud, or local model SKUs.

## Runtime decisions

The evaluator returns:

- `allow_approved_route` when a low-risk route has all required evidence.
- `allow_guarded_route` when a sensitive route is acceptable with
  guardrails, receipts, telemetry, egress approval, and human approval.
- `hold_for_model_provider_review` when the route is plausible but proof
  is missing.
- `deny_unapproved_route` when the provider, route, workflow, data class,
  or autonomy request is not approved.
- `kill_session_on_provider_signal` when the request includes secrets,
  cross-tenant context, non-HTTPS endpoints, denied egress, or another
  route-level kill signal.

## Why this matters

The acquisition-grade story is simple: SecurityRecipes can become the
neutral policy layer that makes multi-model agentic AI safe to approve.
Open knowledge gets teams started. The paid surface is the hosted
provider-routing PDP, tenant-specific model registry, contract-state
checks, route telemetry, procurement exports, and trust-center evidence.

That is valuable to a frontier lab, an AI coding platform, a cloud
platform, or a security vendor because it reduces the buyer friction
around letting agents use powerful models on real enterprise context.

## MCP examples

Inspect all provider routes:

```text
recipes_model_provider_routing_pack()
```

Review one workflow's preferred routes:

```text
recipes_model_provider_routing_pack(
  workflow_id="sast-finding-remediation"
)
```

Evaluate a route:

```text
recipes_evaluate_model_provider_routing_decision(
  workflow_id="vulnerable-dependency-remediation",
  provider_id="frontier-enterprise-provider",
  model_id="frontier-code-and-security-reasoning",
  route_class="tenant_sensitive_remediation",
  data_classes=["customer_source_code", "customer_finding_metadata"],
  autonomy_level="bounded_agent",
  tenant_id="tenant-123",
  tenant_region="us",
  provider_region="us",
  zero_data_retention=true,
  training_opt_out=true,
  dpa_in_place=true,
  enterprise_contract=true,
  mcp_gateway_enforced=true,
  tool_guardrails_enforced=true,
  output_guardrails_enforced=true,
  telemetry_redacted=true,
  run_receipt_attached=true,
  egress_decision="allow_tenant_bound_egress",
  human_approval_record={"approval_id": "approval-123"}
)
```

## Industry alignment

This feature follows current guidance:

- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, audience-bound tokens, HTTPS, PKCE, scope
  challenges, and token validation.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  for confused-deputy prevention, token-passthrough denial, scope
  minimization, SSRF controls, session safety, and audit trails.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for agent goal hijacking, tool misuse, privilege abuse, context
  poisoning, insecure inter-agent communication, cascading failures, and
  rogue-agent containment.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) for
  model misbinding, context spoofing, prompt-state manipulation,
  insecure memory references, and covert-channel concerns in MCP-shaped
  systems.
- [OpenAI prompt-injection guidance](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
  for source-sink reasoning, constrained impact, and user confirmation
  before sensitive transmissions.
- [OpenAI Agents SDK Guardrails](https://openai.github.io/openai-agents-python/guardrails/)
  and [Tracing](https://openai.github.io/openai-agents-python/tracing/)
  for input, output, and tool guardrails plus trace evidence.
- [Anthropic Claude Code Security](https://code.claude.com/docs/en/security)
  for read-only defaults, explicit approvals, trusted MCP server
  configuration, isolated execution, and command review.
- [CISA AI Data Security](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
  for AI lifecycle data provenance, integrity, access control,
  monitoring, third-party handling, and incident evidence.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  and [NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for govern/map/measure/manage practices and generative-AI risk
  management.

## See also

- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  for data-class and destination decisions before context leaves a
  boundary.
- [Agentic Telemetry Contract]({{< relref "/security-remediation/agentic-telemetry-contract" >}})
  for model-call and tool-call trace evidence.
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
  for proof that a run stayed inside delegated authority.
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
  for OAuth resource, audience, PKCE, session, and scope-drift checks.
- [Agentic App Intake Gate]({{< relref "/security-remediation/agentic-app-intake-gate" >}})
  for app-level launch review before autonomy expands.
