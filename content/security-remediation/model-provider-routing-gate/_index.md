---
title: Model Provider Routing Gate
linkTitle: Model Provider Routing
weight: 16
date: 2026-05-04
lastmod: 2026-11-14
toc: true
description: >
  A generated model-provider routing gate for deciding which model
  provider and model route may receive secure context for an agentic
  workflow, with proof for data retention, residency, guardrails,
  consumption halt conditions, telemetry, receipts, and approval
  before the model call starts.
sidebar:
  exclude: true
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**Why this page exists.** The secure context layer is not complete until
it can answer one operational question: which model/provider is allowed
to receive this context for this workflow, right now?
{{< /callout >}}

Rechecked source anchors against the public MCP specification [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) on November 14, 2026. MCP `latest` still redirects to 2026-07-28. Rechecked the same day against [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) and the canonical [LLM06:2026 Unbounded Consumption](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM06_UnboundedConsumption.md) entry: traditional request-rate limits are not enough. Token-aware rate limits, hard spending caps that halt inference rather than only alert, and agentic circuit breakers with step, recursion, time, and per-run cost limits are required before a route is allowed. An already-detected recursive tool-calling or reasoning loop is a kill. Unspecified consumption evidence stays on the prior hold path. This change does not claim human review of the pack; `lastmod` and the source `last_reviewed` date record this editorial pass.

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
- token-aware rate limits, hard spending caps that halt inference, and agentic circuit breakers,
- the telemetry contract,
- the run receipt,
- and any human approval required for sensitive context.

The Model Provider Routing Gate makes that decision inspectable. It is a
provider-neutral policy pack that enterprises can fork into their own
model registry while keeping the open evidence shape stable.

{{< playbook-workflow >}}

## What was added

- Source profile:
  `data/assurance/model-provider-routing-profile.json`
- Generator: `scripts/generate_model_provider_routing_pack.py`
- Runtime evaluator: `scripts/evaluate_model_provider_routing_decision.py`
- Evidence pack:
  `data/evidence/model-provider-routing-pack.json`
- MCP tools:
  `recipes_model_provider_routing_pack`, paired with `recipes_playbook_plan` using playbook id `model-provider-routing-gate`.

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
  --human-approval-id approval-123 \
  --token-aware-rate-limit \
  --spending-cap-halts-inference \
  --agentic-circuit-breaker \
  --expect-decision allow_guarded_route
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
| Token-aware rate limit | Request-per-second limits that miss token, reasoning, multimodal, or MCP tool-fan-out cost. |
| Hard spending cap that halts inference | Alert-only budgets that Denial of Wallet and recursive loops can outpace. |
| Agentic circuit breaker | Unbounded tool-calling or reasoning loops with no step, recursion, time, or per-run cost limit. |
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
  cross-tenant context, non-HTTPS endpoints, denied egress, an already
  detected unbounded consumption loop, or another route-level kill
  signal.

## Why this matters

The review-ready story is simple: SecurityRecipes can become the
neutral policy layer that makes multi-model agentic AI safe to approve.
Open knowledge gets teams started. The hosted-ready surface is the hosted
provider-routing PDP, tenant-specific model registry, contract-state
checks, route telemetry, procurement exports, and trust-center evidence.

That is valuable to a frontier lab, an AI coding platform, a cloud
platform, or a security vendor because it reduces the reviewer friction
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

Plan a route:

```text
recipes_playbook_plan(
  playbook_id="model-provider-routing-gate",
  finding="Tenant-sensitive remediation data needs an approved US-region model route."
)
```

## Industry alignment

This feature follows current guidance:

- [MCP Authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  for resource indicators, audience-bound tokens, HTTPS, PKCE, scope
  challenges, and token validation.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)
  for confused-deputy prevention, token-passthrough denial, scope
  minimization, SSRF controls, session safety, and audit trails.
- [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
  and [LLM06:2026 Unbounded Consumption](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM06_UnboundedConsumption.md)
  for token-aware cost controls, hard spending caps that halt inference,
  agentic circuit breakers, and Denial of Wallet / recursive tool-loop
  failure modes.
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
