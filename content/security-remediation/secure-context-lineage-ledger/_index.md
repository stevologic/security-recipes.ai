---
title: Secure Context Lineage Ledger
linkTitle: Secure Context Lineage
weight: 10
date: 2026-05-04
lastmod: 2026-08-21
sidebar:
  exclude: true
description: >
  Generate a context-lineage ledger for agentic AI: source hashes,
  attestations, poisoning scans, retrieval, model routes, egress, handoffs,
  telemetry, and receipts.
breadcrumb_parent: /agentic-security/
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

{{< playbook-workflow >}}

## What was added

The lineage layer has four artifacts:

- `data/assurance/secure-context-lineage-profile.json` - the source
  profile for context lineage stages, reuse policy, runtime fields,
  standards alignment, reviewer views, and trusted-source path.
- `data/evidence/secure-context-lineage-ledger.json` - the generated
  ledger joining the trust pack, attestation pack, poisoning guard,
  egress boundary, handoff boundary, telemetry contract, run receipts,
  and model-provider routing pack.
- `scripts/evaluate_secure_context_lineage_decision.py` - the runtime
  source/hash/evidence binding decision before context is reused.

Run it locally from the repo root:

```bash
python3 scripts/generate_secure_context_lineage_ledger.py
python3 scripts/generate_secure_context_lineage_ledger.py --check
```

Evaluate a fully bound remediation run:

```bash
python3 scripts/evaluate_secure_context_lineage_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --source-id recipes \
  --use-ledger-evidence \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --run-id run-ci \
  --tenant-id tenant-ci \
  --correlation-id corr-ci \
  --trace-id trace-ci \
  --context-retrieval-decision allow_public_context \
  --attestation-decision allow_attested_workflow_context \
  --poisoning-scan-state clean \
  --model-route-id tenant-remediation-frontier-route \
  --model-route-decision allow_guarded_route \
  --egress-decision allow_tenant_bound_egress \
  --handoff-decision allow_metadata_handoff \
  --telemetry-event-id telemetry-ci \
  --telemetry-decision telemetry_ready \
  --receipt-id sr-run-receipt::vulnerable-dependency-remediation \
  --expect-decision allow_lineage_bound_context
```

The local MCP server exposes the ledger through
`recipes_secure_context_lineage_ledger`. Runtime lineage decisions stay
with `scripts/evaluate_secure_context_lineage_decision.py`. The MCP tool
returns the hashed ledger; it does not approve reuse by itself.

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

Plan runtime context reuse before an agent uses it:

```text
recipes_playbook_plan(
  playbook_id="secure-context-lineage-ledger",
  finding="Context from recipe and workflow-control-plane sources is proposed for reuse by a remediation agent."
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
- [MCP Authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  for resource indicators, token audience validation, PKCE, protected
  resource metadata, and token-passthrough denial.
- [MCP Elicitation 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
  for consent and sensitive URL-mode flows that should not expose
  credentials or third-party authorization secrets to the client.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  and the
  [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for AI lifecycle governance, provenance, monitoring, measurement, and
  incident response.

## reviewer value

This is the enterprise-ready version of "make AI easy": the agent does
not need to debate whether context is safe. It asks the MCP tool for the
lineage decision, gets a structured answer, and either proceeds, asks for
missing evidence, routes to review, denies reuse, or kills the session.

For a future vendor product, the same shape becomes a hosted lineage
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
