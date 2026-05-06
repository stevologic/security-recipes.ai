---
title: Secure Context Firewall
linkTitle: Secure Context Firewall
weight: 10
sidebar:
  open: true
description: >
  A deterministic runtime evaluator for secure-context retrieval:
  allow, hold, deny, or kill-session decisions before MCP-backed
  context is returned to an agent.
---

{{< callout type="info" >}}
**Why this page exists.** A trust pack proves which context is approved.
A firewall decides whether this specific agent run may retrieve this
specific context right now.
{{< /callout >}}

## The product bet

SecurityRecipes should make AI easy without making agent context loose.
The [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
declares approved context roots, owners, trust tiers, source hashes,
retrieval modes, poisoning controls, and per-workflow context packages.
The Secure Context Firewall turns that declaration into a runtime
decision function an MCP gateway can enforce before retrieved text enters
the model window.

That is the enterprise shape acquirers and platform teams expect:

- **Registered context only.** Unknown source IDs fail closed.
- **Workflow-bound packages.** A source must be approved for the
  workflow context package, not merely present somewhere in the corpus.
- **Retrieval-mode checks.** A runtime request must use a mode the source
  owner declared, such as `workflow_prompt_context` or
  `runtime_policy_context`.
- **Path boundaries.** Requested files must stay inside the source root
  and match allowed globs.
- **Hash recertification.** A supplied hash mismatch pauses retrieval
  until the context owner recertifies the source.
- **Prohibited data kills.** Secrets, private keys, live tokens,
  signing material, and unrestricted customer logs disable the session.

## What was added

The firewall has two runtime surfaces:

- `scripts/evaluate_secure_context_retrieval.py` - a dependency-free CLI
  evaluator for CI, gateway sidecars, and audit replay.
- `recipes_evaluate_context_retrieval_decision` - the MCP tool that
  exposes the same decision function to agent hosts.

Run it locally from the repo root:

```bash
python3 scripts/evaluate_secure_context_retrieval.py \
  --workflow-id vulnerable-dependency-remediation \
  --source-id prompt-library-recipes \
  --retrieval-mode workflow_prompt_context \
  --requested-path content/prompt-library/general/base-image-bump.md \
  --expect-decision allow_public_context
```

The output is a structured decision record with:

| Field | Purpose |
| --- | --- |
| `decision` | One of `allow_public_context`, `allow_policy_context_with_citation`, `hold_for_customer_context`, `hold_for_context_recertification`, `deny_unapproved_workflow_context`, `deny_unregistered_context`, or `kill_session_on_prohibited_context`. |
| `allowed` | Boolean shortcut for gateway enforcement. |
| `matched_source` | Source ID, trust tier, source hash, retrieval modes, citation requirement, and freshness state. |
| `matched_workflow` | Workflow ID, status, approved source IDs, and context package hash. |
| `violations` | The exact failed boundary checks for audit logs and triage. |
| `evidence` | Source hash, context package hash, instruction-handling rule, trust-pack source artifacts, and observed runtime attributes. |

## Runtime decisions

Use the evaluator before any retrieved context is returned to an agent:

```text
agent request -> MCP gateway -> secure context firewall -> retrieval
```

For an allowed public prompt context request:

```bash
python3 scripts/evaluate_secure_context_retrieval.py \
  --workflow-id vulnerable-dependency-remediation \
  --source-id prompt-library-recipes \
  --retrieval-mode workflow_prompt_context \
  --requested-path content/prompt-library/general/base-image-bump.md
```

For a policy-context request:

```bash
python3 scripts/evaluate_secure_context_retrieval.py \
  --workflow-id sensitive-data-remediation \
  --source-id workflow-control-plane \
  --retrieval-mode policy_context \
  --requested-path data/control-plane/workflow-manifests.json
```

For a prohibited retrieval attempt:

```bash
python3 scripts/evaluate_secure_context_retrieval.py \
  --workflow-id vulnerable-dependency-remediation \
  --source-id prompt-library-recipes \
  --retrieval-mode workflow_prompt_context \
  --data-class production_credential
```

That last request returns `kill_session_on_prohibited_context`. The
gateway should stop the agent session and preserve the decision record as
incident evidence.

## Industry alignment

This feature is intentionally boring and enforceable:

- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  emphasizes scoped authorization, secure transport, PKCE, and token
  handling. The firewall narrows context retrieval to declared source,
  workflow, and mode attributes.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  calls out confused-deputy, token-passthrough, scope, audit, and local
  server risks. The firewall gives each context request a logged
  default-deny decision before the model consumes retrieved text.
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
  and [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
  cover prompt injection, poisoning, excessive agency, tool misuse, and
  delegated authority. The firewall treats retrieved content as evidence,
  not instruction.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  pushes teams toward governed, measured, monitored AI systems. The
  firewall creates a small, replayable control point for context
  governance.

## MCP tool

Agent hosts can call the runtime tool directly:

```text
recipes_evaluate_context_retrieval_decision(
  workflow_id="vulnerable-dependency-remediation",
  source_id="prompt-library-recipes",
  retrieval_mode="workflow_prompt_context",
  requested_path="content/prompt-library/general/base-image-bump.md"
)
```

The tool does not retrieve the context. It only answers whether the
retrieval may proceed and what evidence must be attached to the run log.

## CI contract

CI should replay at least four cases:

- allowed public context,
- allowed policy context with citation,
- denied unregistered or workflow-unapproved context,
- kill-session on prohibited data class.

That gives buyers a testable story: SecurityRecipes is not just a docs
site that agents read. It is a secure context layer with deterministic
runtime context gates.

## See also

- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  - source registry, trust tiers, hashes, and workflow context packages.
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  - data-boundary decisions after context retrieval.
- [MCP Runtime Decision Evaluator]({{< relref "/security-remediation/mcp-runtime-decision-evaluator" >}})
  - tool-call authorization for MCP actions.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - scoped MCP tool-access policy.
- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}})
  - adversarial evals for hostile context and tool misuse.
