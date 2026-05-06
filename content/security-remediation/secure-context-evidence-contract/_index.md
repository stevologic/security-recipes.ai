---
title: Secure Context Evidence Contract
linkTitle: Secure Context Evidence Contract
weight: 12
toc: true
description: >
  Generated evidence object, hosted API, release-channel, redaction,
  signature, and runtime decision contract for secure context exports.
---

{{< callout type="info" >}}
**Why this page exists.** SecurityRecipes already has many generated
evidence packs. The next product step is a stable contract for exposing
that evidence safely through a hosted MCP/API surface without leaking raw
prompts, customer code, secrets, tokens, or private runtime data.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the Secure Context Layer for Agentic
AI**. That only becomes enterprise-grade when buyers can answer:

- What evidence objects are safe to expose?
- Which source packs back each claim?
- Which channels can publish public, design-partner, trust-center,
  hosted API, or acquirer evidence?
- Which controls block an export that contains raw prompts, source code,
  customer data, secrets, tokens, or unsigned evidence?
- What would the hosted API look like before the product is built?

The Secure Context Evidence Contract turns those questions into a
generated artifact and deterministic release evaluator. It is a product
foundation, not a marketing page.

## What was added

- Source profile:
  `data/assurance/secure-context-evidence-contract-profile.json`
- Generator:
  `scripts/generate_secure_context_evidence_contract.py`
- Evidence contract:
  `data/evidence/secure-context-evidence-contract.json`
- Runtime evaluator:
  `scripts/evaluate_secure_context_evidence_release.py`
- MCP tools:
  `recipes_secure_context_evidence_contract` and
  `recipes_evaluate_secure_context_evidence_release`

Regenerate and validate the contract:

```bash
python3 scripts/generate_secure_context_evidence_contract.py
python3 scripts/generate_secure_context_evidence_contract.py --check
```

Evaluate a safe trust-center release:

```bash
python3 scripts/evaluate_secure_context_evidence_release.py \
  --release-id trust-center-ci \
  --release-channel trust_center_external \
  --artifact-id enterprise_trust_center_export \
  --artifact-id secure_context_customer_proof_pack \
  --artifact-id agentic_run_receipt_pack \
  --source-hashes-present \
  --redaction-verified \
  --signature-present \
  --approval-receipt-id approval-ci \
  --retention-policy-id retention-ci \
  --dpa-state not_required \
  --expect-decision allow_publish_evidence_release
```

Evaluate a blocked secret release:

```bash
python3 scripts/evaluate_secure_context_evidence_release.py \
  --release-id secret-ci \
  --release-channel trust_center_external \
  --artifact-id enterprise_trust_center_export \
  --source-hashes-present \
  --redaction-verified \
  --signature-present \
  --approval-receipt-id approval-ci \
  --retention-policy-id retention-ci \
  --contains-token \
  --expect-decision kill_session_on_secret_or_token_release
```

## Decision model

| Decision | Meaning |
| --- | --- |
| `allow_publish_evidence_release` | The release satisfies channel, redaction, source-hash, artifact, tenant, approval, retention, DPA, ZDR, and signature requirements. |
| `hold_for_redaction_or_signature` | The release is missing redaction, source hashes, tenant binding, approval, retention, DPA/ZDR state, signature evidence, or registered artifact references. |
| `hold_for_customer_runtime_evidence` | The selected channel requires customer runtime proof, receipts, telemetry, or customer proof metrics. |
| `deny_sensitive_payload_release` | The release contains raw prompts, source code, or customer data without an allowed and verified redaction boundary. |
| `kill_session_on_secret_or_token_release` | The release contains or declares secrets, tokens, keys, cookies, seed phrases, signing material, or other prohibited payload classes. |

## Evidence object catalog

The generated contract defines stable object types for the evidence a
hosted product will need:

- evidence releases and source-pack references;
- secure context source references, lineage, and attestations;
- MCP policy decisions and tool-surface baselines;
- run receipt and approval receipt references;
- metadata-only telemetry references;
- trust-center claims and customer proof metrics;
- incident signals, redaction manifests, and release signatures.

Each object type has required fields, a redaction rule, linked source
packs, and a contract hash. That makes the output reviewable by agents,
humans, procurement systems, and future hosted APIs.

## Release channels

The contract separates evidence by audience and risk:

| Channel | Purpose |
| --- | --- |
| `open_reference` | Public evidence for forks, search, and open adopters. |
| `design_partner_private` | Tenant-bound customer pilot proof with runtime evidence. |
| `trust_center_external` | Signed or signable procurement and governance packet. |
| `acquirer_diligence` | Redacted runtime proof for strategic buyer review. |
| `hosted_mcp_api` | Paid API path for evidence release checks, MCP decisions, receipt lookup, and trust-center export. |

The important design choice is fail-closed publication. A channel that
needs customer runtime proof, tenant binding, DPA state, ZDR state, or a
signature cannot silently downgrade itself to a public export.

## Hosted API surface

The generated artifact sketches the hosted `v1` API before the product
exists:

- `GET /v1/evidence/contract`
- `POST /v1/evidence/releases/evaluate`
- `POST /v1/evidence/releases`
- `GET /v1/evidence/releases/{release_id}`
- `GET /v1/trust-center/export`
- `GET /v1/mcp/decisions/{correlation_id}`
- `GET /v1/run-receipts/{receipt_id}`
- `GET /v1/customer-proof/metrics`

This is intentionally narrow. It gives a design partner or acquirer a
concrete integration shape while preserving the open repo's read-only
boundary.

## Industry alignment

This feature follows current primary guidance:

- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected-resource metadata, resource indicators, audience-bound
  tokens, client metadata, scope challenges, and token-passthrough
  boundaries.
- [MCP Elicitation 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
  for form-mode limits, URL-mode sensitive flows, consent, identity
  binding, completion notifications, and phishing controls.
- [MCP Tools 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
  for tool schemas, output schemas, annotations, and trusted-server
  treatment.
- [NIST AI Agent Standards Initiative](https://www.nist.gov/caisi/ai-agent-standards-initiative)
  for secure, interoperable agent standards, agent authentication,
  identity infrastructure, and security evaluations.
- [OpenAI prompt-injection guidance](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
  for source-to-sink controls and constraining sensitive transmissions.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and
  [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
  for agentic and MCP risk vocabulary.
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
  for procurement-friendly AI control mapping.

## Commercial path

The open repo now proves the object model and evaluator. The paid wedge
is a hosted evidence API:

- tenant-private evidence release checks;
- signed trust-center exports;
- MCP decision lookup by correlation ID;
- run-receipt and approval-receipt lookup;
- customer-proof metric aggregation;
- DPA, ZDR, retention, and signature state enforcement;
- acquirer-ready redacted evidence packets.

That is a credible bridge from open knowledge to a production secure
context layer that an AI platform, frontier lab, security vendor, or
regulated enterprise could buy.

## MCP examples

Inspect the contract:

```text
recipes_secure_context_evidence_contract()
```

Inspect one release channel:

```text
recipes_secure_context_evidence_contract(channel_id="trust_center_external")
```

Evaluate a hosted API release:

```text
recipes_evaluate_secure_context_evidence_release(
  release_id="hosted-api-release-1",
  release_channel="hosted_mcp_api",
  artifact_ids=[
    "secure_context_customer_proof_pack",
    "agentic_run_receipt_pack",
    "agentic_telemetry_contract"
  ],
  tenant_id="tenant-123",
  correlation_id="corr-123",
  source_hashes_present=true,
  redaction_verified=true,
  tenant_bound=true,
  signature_present=true,
  retention_policy_id="retention-123",
  zero_data_retention_state="committed"
)
```

## See also

- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
  for the buyer packet this contract can expose.
- [Secure Context Customer Proof Pack]({{< relref "/security-remediation/secure-context-customer-proof-pack" >}})
  for design-partner runtime proof.
- [Hosted MCP Readiness Pack]({{< relref "/security-remediation/hosted-mcp-readiness-pack" >}})
  for tenant isolation, metering, SLO, and rollout gates.
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  for data movement policy behind release decisions.
