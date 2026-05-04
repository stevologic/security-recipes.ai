---
title: Secure Context Lineage Ledger
linkTitle: Secure Context Lineage
weight: 10
sidebar:
  open: true
description: >
  A generated context-lineage ledger for agentic AI: source hashes,
  attestations, poisoning scan state, retrieval decisions, model routes,
  egress, handoffs, telemetry, run receipts, and reuse policy.
---

{{< callout type="info" >}}
**Why this page exists.** A secure context layer is only credible if it
can explain where context came from, which controls governed it, and
whether that context can be reused after an agent has transformed,
summarized, routed, handed off, or persisted it.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the Secure Context Layer for Agentic
AI**. The next enterprise question is not just "which context was
retrieved?" It is:

- Which source hash entered the run?
- Was the source attested and still fresh?
- Did a poisoning scan find hidden instructions or exfiltration markers?
- Which model route, egress boundary, handoff boundary, telemetry event,
  and run receipt explain how the context moved?
- Can the resulting context be reused in another run, workflow, model,
  tenant, memory store, A2A handoff, or public corpus?

The Secure Context Lineage Ledger answers those questions as a generated
JSON artifact and a runtime MCP decision tool.

## What was added

The lineage layer has four artifacts:

- `data/assurance/secure-context-lineage-profile.json` - the source
  profile for context lineage stages, reuse policy, runtime fields,
  standards alignment, buyer views, and commercialization path.
- `scripts/generate_secure_context_lineage_ledger.py` - a dependency-free
  generator and validator with `--check` mode for CI drift detection.
- `scripts/evaluate_secure_context_lineage_decision.py` - a dependency-free
  runtime evaluator that returns allow, hold, deny, or kill decisions for
  context lineage and reuse.
- `data/evidence/secure-context-lineage-ledger.json` - the generated
  ledger joining the trust pack, attestation pack, poisoning guard,
  egress boundary, handoff boundary, telemetry contract, run receipts,
  and model-provider routing pack.

Run it locally from the repo root:

```bash
python3 scripts/generate_secure_context_lineage_ledger.py
python3 scripts/generate_secure_context_lineage_ledger.py --check
```

The local MCP server exposes the ledger through
`recipes_secure_context_lineage_ledger` and exposes runtime lineage
decisions through `recipes_evaluate_secure_context_lineage_decision`.

## Lineage stages

| Stage | What it proves |
| --- | --- |
| `source_registration` | Source owner, trust tier, source hash, allowed files, and retrieval modes are known. |
| `source_attestation` | The context source or workflow package has an attestation-shaped subject and digest. |
| `retrieval_policy` | The source, path, retrieval mode, data class, and workflow package were approved before context returned. |
| `poisoning_screen` | Prompt-injection, hidden instruction, approval-bypass, exfiltration, and secret markers were scanned. |
| `model_route` | Context used an approved model/provider route with data-class, contract, DPA, and training controls. |
| `egress_boundary` | Context movement across tenant, model, MCP, telemetry, webhook, or public-corpus boundaries was classified. |
| `handoff_boundary` | A2A, MCP, provider-native, and approval-bridge handoffs carried only approved fields. |
| `telemetry_binding` | Trace, span, redaction, retention, and required runtime attributes were recorded. |
| `run_receipt` | The run sealed evidence, verifier output, closure, and identity revocation into a receipt. |

## Runtime decisions

The evaluator is intentionally simple for agents:

- `allow_lineage_bound_context` - context is registered, hash-bound,
  attested, scanned, routed, egress-gated, telemetry-bound, and
  receipt-backed.
- `hold_for_lineage_evidence` - the workflow is known, but runtime
  evidence is absent, stale, or mismatched.
- `hold_for_poisoning_review` - the source or runtime scan reports
  actionable context-poisoning risk.
- `hold_for_reuse_review` - context is valid for the original run, but
  reuse crosses a workflow, model, memory, handoff, or persistence
  boundary.
- `deny_unbound_context_lineage` - the request references unknown
  workflow, source, hash, package, or lineage stage.
- `deny_cross_tenant_lineage_reuse` - tenant-bound context is being
  reused across tenant, account, workspace, or public-corpus boundaries.
- `kill_session_on_lineage_break` - a secret, token passthrough,
  prohibited data class, forged hash, poisoned context, forbidden
  egress, or runtime kill signal appeared.

## Use it through MCP

Inspect a workflow lineage envelope:

```text
recipes_secure_context_lineage_ledger(
  workflow_id="vulnerable-dependency-remediation"
)
```

Inspect a source that is causing a hold:

```text
recipes_secure_context_lineage_ledger(
  decision="hold_for_poisoning_review"
)
```

Evaluate runtime context reuse before an agent uses it:

```text
recipes_evaluate_secure_context_lineage_decision(
  workflow_id="vulnerable-dependency-remediation",
  run_id="run-123",
  agent_id="sr-agent::vulnerable-dependency-remediation::codex",
  tenant_id="tenant-1",
  correlation_id="corr-123",
  trace_id="trace-123",
  source_ids=["prompt-library-recipes", "workflow-control-plane"],
  source_hashes=["..."],
  context_package_hash="...",
  context_retrieval_decision="allow_public_context",
  attestation_decision="allow_attested_workflow_context",
  poisoning_scan_state="clean",
  model_route_id="tenant-remediation-frontier-route",
  model_route_decision="allow_guarded_route",
  egress_decision="allow_public_egress_with_citation",
  handoff_decision="allow_metadata_handoff",
  telemetry_event_id="otel-123",
  telemetry_decision="telemetry_ready",
  receipt_id="sr-run-receipt::vulnerable-dependency-remediation"
)
```

## Industry alignment

This feature follows current primary guidance:

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
  for memory and context poisoning, insecure inter-agent communication,
  cascading failures, goal hijack, tool misuse, and rogue-agent risk.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) for
  context injection, over-sharing, tool poisoning, telemetry gaps,
  shadow MCP servers, and insufficient authorization.
- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, token audience validation, PKCE, protected
  resource metadata, and token-passthrough denial.
- [MCP Elicitation 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
  for consent and sensitive URL-mode flows that should not expose
  credentials or third-party authorization secrets to the client.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  and the
  [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for AI lifecycle governance, provenance, monitoring, measurement, and
  incident response.

## Buyer value

This is the enterprise-ready version of "make AI easy": the agent does
not need to debate whether context is safe. It asks the MCP tool for the
lineage decision, gets a structured answer, and either proceeds, asks for
missing evidence, routes to review, denies reuse, or kills the session.

For a future commercial product, the same shape becomes a hosted lineage
API for MCP gateways, private context registries, SIEM/SOAR exports,
signed run receipt verification, trust-center exports, and incident
forensics.

## See also

- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  - registered sources, owners, trust tiers, source hashes, and
    retrieval decisions.
- [Secure Context Attestation]({{< relref "/security-remediation/secure-context-attestation" >}})
  - attestation-shaped context subjects and signature-readiness policy.
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
  - pre-retrieval scanning for hidden instructions and exfiltration
    markers.
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  - data-class and destination decisions before context crosses a
    boundary.
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
  - proof templates for governed agent runs.
