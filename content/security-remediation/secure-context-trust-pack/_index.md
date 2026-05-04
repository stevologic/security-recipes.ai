---
title: Secure Context Trust Pack
linkTitle: Secure Context Trust
weight: 9
sidebar:
  open: true
description: >
  A generated provenance and retrieval trust pack for the SecurityRecipes
  secure context layer: approved context roots, owners, trust tiers,
  source hashes, poisoning controls, and workflow context packages.
---

{{< callout type="info" >}}
**Why this page exists.** Agents are only as safe as the context they
are allowed to consume. This pack turns SecurityRecipes from a useful
docs corpus into an inspectable context supply chain for MCP-backed
agentic remediation.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the secure context layer for agentic
AI**. That means the product has to answer more than "what prompt should
I use?" It has to answer:

- Which context roots can an agent retrieve?
- Who owns each root?
- Which hash proves the current version?
- Is retrieved text policy, guidance, evidence, runtime code, or
  prohibited data?
- How is prompt injection in retrieved content handled?
- Which context package is approved for a workflow?

The Secure Context Trust Pack answers those questions in one generated
artifact. It is designed for AI platform intake, MCP server approval,
retrieval-augmented-agent design review, procurement security, and
acquisition diligence.

## What was added

The secure context layer has three artifacts:

- `data/context/secure-context-registry.json` - the source registry for
  context roots, owners, trust tiers, retrieval decisions, freshness
  expectations, poisoning controls, and prohibited context classes.
- `scripts/generate_secure_context_trust_pack.py` - a dependency-free
  generator and validator with `--check` mode for CI drift detection.
- `scripts/evaluate_secure_context_retrieval.py` - a dependency-free
  runtime evaluator that turns the pack into an allow, hold, deny, or
  kill-session retrieval decision.
- `data/evidence/secure-context-trust-pack.json` - the generated pack
  with source hashes, registered file counts, retrieval contracts, and
  per-workflow context package hashes.

Run it locally from the repo root:

```bash
python3 scripts/generate_secure_context_trust_pack.py
python3 scripts/generate_secure_context_trust_pack.py --check
```

The local MCP server exposes the same bundle through
`recipes_secure_context_trust_pack`, and exposes runtime retrieval
decisions through `recipes_evaluate_context_retrieval_decision`.

## What is inside the pack

| Section | Purpose |
| --- | --- |
| `context_trust_summary` | Counts for registered sources, files, bytes, trust tiers, source kinds, decisions, risk families, and workflow context packages. |
| `context_sources` | Approved context roots with owner, kind, trust tier, retrieval modes, source hash, registered files, risk families, and instruction-handling rules. |
| `retrieval_decision_contract` | The default-deny decision model for public context, policy context, customer runtime context, unregistered context, and prohibited context. |
| `workflow_context_map` | Per-workflow context package hashes and approved source IDs for MCP-backed agent runs. |
| `source_artifacts` | Canonical hashes for the secure context registry and workflow manifest. |
| `trust_tiers` | Public reference, curated guidance, policy context, customer runtime context, and prohibited context tiers. |

## Retrieval rules

The pack makes five rules explicit:

1. Retrieved context is evidence, not instruction.
2. System, developer, gateway, and human-review policy outrank retrieved
   text.
3. Every returned context bundle carries source ID, path, hash, trust
   tier, freshness state, and citation requirement.
4. Customer runtime context stays tenant-side.
5. Secrets, private keys, signing material, raw tokens, and unrestricted
   personal data are prohibited retrieval targets.

That keeps the product easy for agents: ask the MCP tool for the context
package, cite the source hash, and do not guess whether unregistered
context is safe.

## Industry alignment

This feature follows current primary guidance:

- [Model Context Protocol Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, audience validation, HTTPS, PKCE, and token
  handling.
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  for confused-deputy prevention, token-passthrough avoidance, SSRF,
  session safety, local MCP server controls, and scope minimization.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for agent goal hijack, memory and context poisoning, identity abuse,
  cascading failures, human-agent trust exploitation, and rogue-agent
  containment.
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
  for prompt injection, supply chain, poisoning, improper output
  handling, excessive agency, vector weakness, and over-retrieval risk.
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
  for autonomous-agent threat modeling and mitigations.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  and the
  [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for AI lifecycle governance, measurement, monitoring, third-party, and
  data-boundary risk.

## How to use it

For workflow approval, query the context package:

```text
recipes_secure_context_trust_pack(workflow_id="vulnerable-dependency-remediation")
```

For source review, query a source:

```text
recipes_secure_context_trust_pack(source_id="workflow-control-plane")
recipes_secure_context_trust_pack(trust_tier="tier_2_policy_context")
```

For gateway design, start with `retrieval_decision_contract`. The
default is `deny_unregistered_context`; customer runtime context holds
for tenant-side controls; prohibited context kills the session.

For runtime enforcement, evaluate the specific context request before
retrieval:

```text
recipes_evaluate_context_retrieval_decision(
  workflow_id="vulnerable-dependency-remediation",
  source_id="prompt-library-recipes",
  retrieval_mode="workflow_prompt_context",
  requested_path="content/prompt-library/general/base-image-bump.md"
)
```

## CI contract

The generator fails if:

- A registered context root does not exist.
- A root has no matching files.
- A source misses its trust-tier controls.
- Default workflow context sources are not registered.
- Registered sources fail to cover the required risk families.
- The workflow manifest has no MCP context to package.
- The checked-in pack is stale in `--check` mode.

That is the enterprise bar for a secure context layer: context is
registered, hashed, owned, tiered, cited, and validated before agents use
it.

## See also

- [Workflow Control Plane]({{< relref "/security-remediation/control-plane" >}})
  - the workflow source of truth.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - the runtime enforcement contract.
- [Secure Context Firewall]({{< relref "/security-remediation/secure-context-firewall" >}})
  - the runtime retrieval gate for context requests.
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  - data-class and destination decisions before retrieved context leaves
    a tenant, model, MCP, telemetry, or public-corpus boundary.
- [Secure Context Attestation]({{< relref "/security-remediation/secure-context-attestation" >}})
  - in-toto-shaped attestation seed, recertification queue, and
    signature-readiness policy for trusted context.
- [Secure Context Lineage Ledger]({{< relref "/security-remediation/secure-context-lineage-ledger" >}})
  - source-to-run lineage for context hashes, attestations, poisoning
    scans, model routes, egress, handoffs, telemetry, receipts, and
    reuse decisions.
- [Secure Context Evals]({{< relref "/security-remediation/secure-context-evals" >}})
  - scenario-backed evals for retrieval correctness, attestation holds,
    poisoning resilience, egress safety, answer contracts, and handoffs.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - connector trust tiers and promotion criteria.
- [Agentic System BOM]({{< relref "/security-remediation/agentic-system-bom" >}})
  - inspectable inventory for the agentic system.
- [Agent Capability Risk Register]({{< relref "/security-remediation/agent-capability-risk-register" >}})
  - the residual-risk view for workflows before MCP access expands.
- [Agent Memory Boundary]({{< relref "/security-remediation/agent-memory-boundary" >}})
  - persistent-memory classes, TTLs, provenance, rollback, and runtime
    decisions before agent state is stored or replayed.
- [Agent Skill Supply Chain]({{< relref "/security-remediation/agent-skill-supply-chain" >}})
  - provenance, permission, isolation, package-hash, signature, and
    runtime decisions for skills, rules files, hooks, and extensions.
