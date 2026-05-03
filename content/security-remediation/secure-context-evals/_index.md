---
title: Secure Context Evals
linkTitle: Secure Context Evals
weight: 11
sidebar:
  open: true
description: >
  Scenario-backed evals for the SecurityRecipes secure context layer:
  retrieval correctness, attestation, poisoning resilience, egress
  safety, answer contracts, and agent-to-agent handoff boundaries.
---

{{< callout type="info" >}}
**Why this page exists.** A credible secure context layer needs more
than provenance. It needs repeatable evals that prove context is
registered, cited, attested, poisoning-scanned, and safe to hand to an
agent before the agent relies on it.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. The Secure Context Eval Pack turns that positioning into a
CI-ready product surface: a buyer can inspect scenario results, source
hashes, expected runtime decisions, citation requirements, and
agent-to-agent handoff limits through the repo and MCP server.

This is the next high-value layer after the Secure Context Trust Pack
and Secure Context Attestation. The trust pack proves what context is
registered. Attestation proves the context package can be certified.
The eval pack proves the runtime behavior a buyer actually cares about:
will the system return the right context, hold when signatures are
missing, terminate on prohibited data classes, preserve citations, and
keep remote-agent handoffs metadata-only?

## What was added

- `data/assurance/secure-context-eval-scenarios.json` - the source
  scenario profile.
- `scripts/generate_secure_context_eval_pack.py` - deterministic pack
  generator with `--check` and `--update-if-stale` support.
- `scripts/evaluate_secure_context_eval_case.py` - runtime evaluator for
  observed answers, citations, decisions, and handoff payloads.
- `data/evidence/secure-context-eval-pack.json` - generated evidence
  pack for CI, MCP, diligence, and trust-center review.
- MCP tools:
  `recipes_secure_context_eval_pack` and
  `recipes_evaluate_secure_context_eval_case`.

Regenerate and validate:

```bash
python3 scripts/generate_secure_context_eval_pack.py
python3 scripts/generate_secure_context_eval_pack.py --check
```

Evaluate one runtime answer:

```bash
python3 scripts/evaluate_secure_context_eval_case.py \
  --scenario-id ctx-eval-prohibited-data-kill \
  --answer-text "kill_session" \
  --expect-decision eval_ready
```

## Eval scenario classes

| Scenario class | What it proves |
| --- | --- |
| Retrieval correctness | The requested workflow, source, path, and retrieval mode produce the expected allow, hold, deny, or kill decision. |
| Source attestation | Production MCP and trust-center use hold unless the context package has the required attestation evidence. |
| Context poisoning resilience | Registered sources are checked against the poisoning guard before they influence an agent. |
| Egress safety | Context cannot move to a model, MCP server, telemetry sink, public corpus, or external destination without data-class and destination controls. |
| Answer contract | Runtime answers preserve source IDs, hashes, and citations instead of turning retrieved text into hidden authority. |
| Agent-to-agent handoff boundary | Remote-agent handoffs carry task summaries, workflow IDs, source hashes, and approval state, not internal memory or tenant runtime context. |

## Why it is acquisition-grade

Enterprise buyers and likely acquirers will not value another prompt
library by itself. They will value a control surface that makes agentic
AI easier to approve, monitor, and defend. This eval layer is designed
to answer diligence questions directly:

- Can SecurityRecipes prove that secure context retrieval is tested?
- Can it show negative controls, not only happy paths?
- Can it produce machine-readable evidence for MCP clients and gateways?
- Can it support customer-specific eval packs without exposing tenant
  data in the open corpus?
- Can it extend from MCP tool use into agent-to-agent protocols where
  remote agents are opaque applications?

The open artifact creates trust and distribution. The commercial path is
hosted eval replay, customer corpus eval ingestion, model/provider
regression tracking, signed eval results, and trust-center exports.

## Industry alignment

This layer follows current primary guidance and market movement:

- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for resource indicators, audience validation, OAuth 2.1 security
  expectations, PKCE, HTTPS, and bounded token use.
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  for confused-deputy prevention, connector scope minimization, SSRF
  controls, session safety, and auditable mediation.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for goal hijack, tool misuse, identity abuse, unexpected code
  execution, memory and context poisoning, inter-agent communication,
  cascading failure, and containment.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
  for model misbinding, context spoofing, prompt-state manipulation,
  insecure memory references, and covert channels.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  and the
  [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for AI governance, measurement, monitoring, provenance, and data
  boundary management.
- [A2A Enterprise-Ready Features](https://google-a2a.github.io/A2A/latest/topics/enterprise-ready/)
  for treating remote agents as opaque enterprise applications with
  transport security, identity, authorization, and monitoring.

## MCP examples

List eval-ready scenarios:

```json
{
  "decision": "eval_ready",
  "minimum_score": 100
}
```

Inspect one scenario:

```json
{
  "scenario_id": "ctx-eval-production-attestation-hold"
}
```

Evaluate an observed answer:

```json
{
  "scenario_id": "ctx-eval-vuln-dep-prompt-context",
  "answer_text": "Use vulnerable-dependency-remediation context and preserve the source hash.",
  "citations": [
    {
      "source_id": "prompt-library-recipes",
      "source_hash": "<hash from the eval pack>",
      "path": "content/prompt-library/codex/vulnerable-dep-remediation.md"
    }
  ]
}
```

## See also

- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
- [Secure Context Attestation]({{< relref "/security-remediation/secure-context-attestation" >}})
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
- [Agentic Measurement Probes]({{< relref "/security-remediation/agentic-measurement-probes" >}})
- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
