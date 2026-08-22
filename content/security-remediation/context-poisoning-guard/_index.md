---
title: Context Poisoning Guard
linkTitle: Context Poisoning Guard
weight: 10
date: 2026-05-02
lastmod: 2026-08-21
toc: true
description: >
  Scan retrieved context before agent use for prompt injection, provenance
  failures, unsafe instructions, and evidence-backed blocking decisions.
sidebar:
  exclude: true
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**Why this page exists.** A secure context layer cannot only hash
context. It has to inspect context for instruction-like payloads before
that context is returned to an agent through MCP.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the secure context layer for
agentic AI**. The strongest enterprise version of that idea is not a
recipe catalog. It is a controlled context supply chain:

- registered source roots,
- owners and trust tiers,
- retrieval decisions,
- source hashes,
- poisoning controls,
- and deterministic inspection before context reaches an agent.

The Context Poisoning Guard adds that inspection layer. It scans every
registered context root from the Secure Context Registry and produces a
generated evidence pack that says whether a source passes, contains only
documented adversarial examples, should hold for review, or should be
blocked until fixed. Leftover CVE drafts that invent a next version or
copy unrelated floors are untrusted context: cite NVD or GHSA, and do
not treat that text as a retrieval-approved floor.

{{< playbook-workflow >}}

## What was added

- Source profile:
  `data/assurance/context-poisoning-guard-profile.json`
- Generator: `scripts/generate_context_poisoning_guard_pack.py`
- Evidence pack:
  `data/evidence/context-poisoning-guard-pack.json`
- MCP tool:
  `recipes_context_poisoning_guard_pack`

Regenerate and validate the pack:

```bash
python3 scripts/generate_context_poisoning_guard_pack.py
python3 scripts/generate_context_poisoning_guard_pack.py --check
```

## What it scans

| Rule | Severity | Why it matters |
| --- | --- | --- |
| Direct instruction override | Critical | Detects text that asks an agent to ignore or override higher-priority instructions. |
| Secret exfiltration request | Critical | Detects transfer language near secrets, tokens, credentials, private keys, or environment dumps. |
| Approval bypass request | High | Detects requests to skip, bypass, remove, or disable review, approval, policy, CI, or guardrails. |
| Hidden HTML instruction | High | Detects hidden HTML/comment patterns that may evade human review but remain visible to models. |
| External callback instruction | High | Detects send/post/upload/callback language near external URLs. |
| Encoded payload | Medium | Detects long base64-like strings that may hide instructions or data. |
| Zero-width control | Medium | Detects zero-width and bidirectional controls that can hide or reorder text. |

The guard is intentionally conservative. It does not pretend regexes can
solve prompt injection. It creates evidence and routing:

- `pass` when no markers are detected.
- `allow_with_adversarial_examples` when markers appear only in
  documented red-team, threat-model, or defensive examples.
- `hold_for_context_review` when normal guidance contains high-risk
  markers.
- `block_until_removed` when critical actionable findings appear outside
  approved examples.

## Why this is enterprise-grade

This feature makes AI easier for reviewers because it turns a hard question
into a simple artifact:

> Can this context be returned to an agent?

An MCP server, AI platform intake workflow, or procurement reviewer can
ask the guard pack for source-level decisions and findings instead of
reading every page manually. The answer carries source ID, path, line,
rule ID, severity, disposition, and source hash.

The generated pack supports:

- recipe publication review,
- MCP server intake,
- quarterly secure-context recertification,
- red-team replay planning,
- trust review diligence,
- and future hosted context monitoring.

## MCP examples

Get the portfolio-level summary:

```json
{}
```

Get all sources held for context review:

```json
{
  "decision": "hold_for_context_review"
}
```

Get actionable critical findings for one source:

```json
{
  "source_id": "recipes",
  "severity": "critical",
  "actionable_only": true
}
```

Get all direct instruction override matches:

```json
{
  "rule_id": "direct-instruction-override"
}
```

## Industry alignment

The guard follows current agentic AI and MCP security guidance:

- [OpenAI guidance on prompt injection resistance](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
  for treating prompt injection as an impact-limiting problem, not only
  a string-filtering problem.
- [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
  for the risk of hidden or malicious instructions in MCP tool metadata
  and runtime context.
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
  for agent threat models around autonomy, tools, delegation, and
  retrieved context.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)
  for scoped access, token-safety, confused-deputy prevention, and
  auditability.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  and
  [CISA AI Data Security guidance](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
  for AI data provenance, integrity, monitoring, and lifecycle controls.

## See also

- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  for registered context roots and hashes.
- [Secure Context Firewall]({{< relref "/security-remediation/secure-context-firewall" >}})
  for runtime retrieval decisions.
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  for outbound data-boundary decisions after retrieval.
- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}})
  for adversarial examples that should stay labeled as test payloads.
- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
  for source-backed prioritization.
