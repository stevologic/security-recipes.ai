---
title: Agentic Run Receipts
linkTitle: Agentic Run Receipts
weight: 12
toc: true
description: >
  A generated receipt template pack for enterprise agent runs: identity,
  context retrieval, poisoning scan, MCP tool decisions, egress decisions,
  approvals, verifier results, evidence retention, and revocation in one
  portable proof object.
---

{{< callout type="info" >}}
**Why this page exists.** Enterprises do not only need safe agent
behavior. They need portable proof that a specific run stayed inside its
delegated authority.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the secure context layer for
agentic AI**. The strongest product shape is not another prompt catalog;
it is a control plane that can tell a buyer:

- which context an agent was allowed to retrieve,
- which context was inspected before use,
- which tools were allowed, held, denied, or killed,
- where context was allowed to move,
- who approved risky steps,
- which verifier proved the result,
- and when the agent's delegated identity was revoked.

Agentic Run Receipts make that story inspectable. A receipt is the
auditable envelope for one governed agent run. It is designed to be
signed by a tenant KMS, Sigstore, or equivalent workload attestation
system after the run closes.

## What was added

- Source profile:
  `data/assurance/agentic-run-receipt-profile.json`
- Generator:
  `scripts/generate_agentic_run_receipt_pack.py`
- Evidence pack:
  `data/evidence/agentic-run-receipt-pack.json`
- MCP tool:
  `recipes_agentic_run_receipt_pack`

Regenerate and validate the pack:

```bash
python3 scripts/generate_agentic_run_receipt_pack.py
python3 scripts/generate_agentic_run_receipt_pack.py --check
```

## Receipt chain

Every workflow receipt template requires these event classes:

| Event | What it proves |
| --- | --- |
| `identity_issued` | The agent used a scoped non-human identity, not a shared human token. |
| `context_retrieval_decision` | Retrieved context was registered, hash-bound, owned, and cited. |
| `context_poisoning_scan` | Prompt-like content was inspected and treated as untrusted data. |
| `mcp_tool_decision` | Every tool call passed through the default-deny MCP gateway policy. |
| `context_egress_decision` | Context movement was classified before crossing a model, tenant, telemetry, MCP, or public boundary. |
| `human_approval` | Approval-required namespaces were authorized before execution or merge. |
| `verifier_result` | Scanner, CI, simulation, resolver, or policy evidence proved the outcome. |
| `evidence_attached` | Required evidence was retained with owner, hash, and retention metadata. |
| `run_closed` | The run reached a terminal state and the receipt envelope was sealed. |
| `identity_revoked` | Short-lived credentials ended with the run or kill signal. |

The default state is `untrusted_until_complete`. A run is not trusted
until the receipt contains every required event and the hashes match the
current SecurityRecipes control artifacts.

## Why this matters

This is the difference between "the agent said it followed the rules"
and "the platform can prove the run followed the rules." That is the
shape procurement, GRC, security operations, incident response, and
acquisition diligence teams will expect before agentic remediation is
allowed to touch real enterprise systems.

It also creates a realistic commercial path:

- open receipt schemas and templates in the public project,
- hosted receipt signing and verification,
- cross-tool log ingestion from MCP gateways, source hosts, CI, and IAM,
- SIEM and trust-center exports,
- buyer diligence workspaces for enterprise and M&A review.

## MCP examples

Inspect the receipt pack:

```text
recipes_agentic_run_receipt_pack()
```

Review one workflow:

```text
recipes_agentic_run_receipt_pack(
  workflow_id="vulnerable-dependency-remediation"
)
```

List only workflows above a readiness score:

```text
recipes_agentic_run_receipt_pack(minimum_score=95)
```

## Industry alignment

This feature follows current guidance:

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for agent goal hijack, tool misuse, identity abuse, context poisoning,
  cascading failures, and rogue-agent containment.
- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, audience-bound tokens, HTTPS, PKCE, and token
  validation.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  for confused-deputy prevention, token passthrough denial, SSRF, session
  safety, local server compromise controls, scope minimization, and audit
  trails.
- [CISA AI Data Security](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
  for provenance, integrity, access control, monitoring, third-party data
  handling, and incident evidence.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  for governed, mapped, measured, and managed AI risk, including the 2026
  critical-infrastructure profile concept.

## See also

- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
  for scoped non-human identity contracts.
- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  for approved context roots and package hashes.
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
  for pre-retrieval scan evidence.
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  for outbound context decisions.
- [MCP Runtime Decision Evaluator]({{< relref "/security-remediation/mcp-runtime-decision-evaluator" >}})
  for per-tool allow, hold, deny, and kill-session decisions.
