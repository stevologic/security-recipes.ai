---
title: Agent Memory Boundary
linkTitle: Agent Memory Boundary
weight: 13
toc: true
description: >
  A generated policy and runtime evaluator for agent memory: ephemeral
  scratchpads, append-only receipts, read-only policy memory, tenant
  runtime memory, vector memory, TTLs, provenance, rollback, and
  prohibited persistence.
---

{{< callout type="info" >}}
**Why this page exists.** Agent memory is secure context that persists.
If an agent can remember something across runs, that memory needs the
same ownership, provenance, poisoning, egress, and deletion controls as
any other context source.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the secure context layer for
agentic AI**. Context is not only what an MCP server retrieves on demand.
It also includes what an agent writes into scratchpads, project memory,
run receipts, vector stores, workflow summaries, user preferences, and
tenant-side operational state.

The Agent Memory Boundary turns that surface into a policy artifact:

- what an agent may remember only for the current run,
- what may become append-only evidence,
- what policy memory is read-only,
- what customer memory must stay tenant-side,
- what vector or embedding memory needs admission review,
- what memory classes require approval, provenance, TTLs, rollback, or
  deletion,
- and what attempted persistence should kill the session.

That is an enterprise-grade control because it converts "the agent
remembered it" into an auditable decision.

## What was added

- Source model:
  `data/assurance/agent-memory-boundary-model.json`
- Generator:
  `scripts/generate_agent_memory_boundary_pack.py`
- Runtime evaluator:
  `scripts/evaluate_agent_memory_boundary_decision.py`
- Evidence pack:
  `data/evidence/agent-memory-boundary-pack.json`
- MCP tools:
  `recipes_agent_memory_boundary_pack` and
  `recipes_evaluate_agent_memory_decision`

Regenerate and validate the pack:

```bash
python3 scripts/generate_agent_memory_boundary_pack.py
python3 scripts/generate_agent_memory_boundary_pack.py --check
```

Evaluate one memory operation:

```bash
python3 scripts/evaluate_agent_memory_boundary_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --memory-class-id run-receipt-evidence \
  --operation write \
  --tenant-id tenant-123 \
  --provenance-hash example-source-hash \
  --expect-decision allow_append_only_evidence_memory
```

## Memory classes

| Class | Default decision | Purpose |
| --- | --- | --- |
| `ephemeral-scratchpad` | `allow_ephemeral_memory` | Short-lived run-local state that is deleted at run closure. |
| `run-receipt-evidence` | `allow_append_only_evidence_memory` | Append-only, non-secret audit evidence for governed runs. |
| `workflow-policy-memory` | `allow_readonly_policy_memory` | Source-controlled policy and evidence the agent can read but not mutate at runtime. |
| `user-preference-memory` | `hold_for_tenant_memory_boundary` | Tenant-visible preferences that need consent, deletion, and approval for sensitive writes. |
| `customer-runtime-memory` | `hold_for_tenant_memory_boundary` | Findings, tickets, repository summaries, scanner summaries, and redacted logs that stay tenant-side. |
| `vector-embedding-memory` | `hold_for_memory_admission_review` | Retrieval indexes that require source hashes, poisoning scans, redaction, and reindex rules. |
| `prohibited-memory` | `kill_session_on_prohibited_memory` | Secrets, raw tokens, signing material, unrestricted PII, approval-bypass instructions, and scope-escalation instructions. |

The default is deliberately conservative: any unknown memory class holds
for review, and prohibited memory kills the session.

## Runtime decisions

The evaluator returns one of these decisions:

| Decision | Meaning |
| --- | --- |
| `allow_ephemeral_memory` | The agent may use run-local scratchpad state that is not replayed across runs. |
| `allow_append_only_evidence_memory` | The agent may append non-secret evidence with tenant, source, and provenance metadata. |
| `allow_readonly_policy_memory` | The agent may read policy memory, but runtime mutation is denied. |
| `hold_for_tenant_memory_boundary` | Tenant-side controls, redaction, and approval are required before persistence. |
| `hold_for_memory_admission_review` | The memory class, TTL, provenance, or data class needs review. |
| `deny_runtime_memory_write` | The operation is not allowed for that memory class. |
| `deny_cross_tenant_memory` | The request lacks tenant isolation or would cross a tenant boundary. |
| `kill_session_on_prohibited_memory` | The agent attempted to persist or replay prohibited material. |

## MCP examples

Inspect the portfolio-level memory boundary:

```text
recipes_agent_memory_boundary_pack()
```

Review one workflow memory profile:

```text
recipes_agent_memory_boundary_pack(
  workflow_id="vulnerable-dependency-remediation"
)
```

Filter classes that hold for tenant-side controls:

```text
recipes_agent_memory_boundary_pack(
  decision="hold_for_tenant_memory_boundary"
)
```

Evaluate a policy-memory mutation attempt:

```text
recipes_evaluate_agent_memory_decision(
  workflow_id="vulnerable-dependency-remediation",
  memory_class_id="workflow-policy-memory",
  operation="write",
  provenance_hash="example-source-hash"
)
```

That returns `deny_runtime_memory_write` because workflow policy memory
is source-controlled and read-only at runtime.

## Industry alignment

This feature follows current guidance:

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for autonomous agent risks across planning, tools, identity, memory,
  cascading failures, trust exploitation, and rogue-agent behavior.
- [OWASP Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/)
  for memory poisoning, cryptographic baselines, declarative memory
  policies, snapshots, and rollback.
- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, token audience validation, PKCE, HTTPS, and
  token-passthrough denial.
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  for confused-deputy prevention, session safety, local server controls,
  and scope minimization.
- [NIST AI RMF Critical Infrastructure concept note](https://www.nist.gov/programs-projects/concept-note-ai-rmf-profile-trustworthy-ai-critical-infrastructure)
  for trustworthy AI agents, tested guardrails, auditability, and
  lifecycle communication in high-stakes environments.

## See also

- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  for approved context roots and source hashes.
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
  for pre-retrieval scan evidence.
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  for outbound data-boundary decisions.
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
  for append-only run evidence.
- [Agentic System BOM]({{< relref "/security-remediation/agentic-system-bom" >}})
  for the inventory of workflows, agents, identities, MCP connectors,
  policies, evidence, and drift triggers.
