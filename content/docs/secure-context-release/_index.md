---
title: Secure Context Release Gate
linkTitle: Secure Context Release
weight: 6
toc: true
description: >
  A generated release gate for promoting SecurityRecipes context into
  open-reference, production MCP, and trust-center channels.
---

{{< callout type="info" >}}
**What this adds.** SecurityRecipes already tracks context provenance,
attestation, poisoning scans, evals, and egress policy. The release gate
packages those controls into versioned context releases so agent hosts,
MCP gateways, and buyers know exactly which source hashes are safe to
consume.
{{< /callout >}}

## Why This Matters

The product thesis is **The Secure Context Layer for Agentic AI**. A
credible context layer needs a release step. Enterprise buyers do not
only ask "where did this guidance come from?" They ask:

- Which context bundle is approved for production agents?
- Which source hashes define the bundle?
- Which attestation, poisoning, eval, and egress checks passed?
- Which channels require signatures before use?
- Which drift or incident signals roll the release back?

The Secure Context Release Gate answers those questions with generated
JSON rather than prose-only claims.

## Generated Artifacts

- Profile:
  `data/context/secure-context-release-profile.json`
- Generator:
  `scripts/generate_secure_context_release_pack.py`
- Runtime evaluator:
  `scripts/evaluate_secure_context_release_decision.py`
- Generated release pack:
  `data/context/secure-context-release-pack.json`

Regenerate and validate:

```bash
python3 scripts/generate_secure_context_release_pack.py
python3 scripts/generate_secure_context_release_pack.py --check
```

## Release Channels

| Channel | Use | Default posture |
| --- | --- | --- |
| `open-reference` | Public docs, local MCP, CI, and open-source evaluation. | Unsigned but hash-bound. |
| `production-mcp` | Hosted MCP and enterprise agent hosts. | Held until signature and transparency proof exist. |
| `trust-center` | Procurement, AI platform review, and acquisition diligence. | Held until signed, or held earlier if a source needs review. |

## Runtime Decisions

The evaluator returns:

| Decision | Meaning |
| --- | --- |
| `allow_open_reference_release` | Local or CI use can consume the unsigned release with source hashes and citations. |
| `allow_context_release` | Production or diligence use has the required signature and transparency proof. |
| `hold_for_signature` | The bundle is structurally ready but cannot promote to production or trust-center use yet. |
| `hold_for_recertification` | A source or workflow context package needs fresh attestation. |
| `hold_for_poisoning_review` | A source has actionable poisoning findings. |
| `hold_for_eval_replay` | Required secure-context evals are missing or stale. |
| `deny_unregistered_release_source` | The request references context outside the release manifest. |
| `deny_release_hash_mismatch` | Runtime source hashes do not match the generated release. |
| `deny_release_channel_mismatch` | The caller requested the wrong channel or environment. |
| `kill_session_on_release_violation` | The request includes prohibited context or a runtime kill signal. |

## Example Checks

Open-reference release:

```bash
python3 scripts/evaluate_secure_context_release_decision.py \
  --release-id open-remediation-context-release \
  --channel-id open-reference \
  --environment open_reference \
  --expect-decision allow_open_reference_release
```

Production MCP release without signature:

```bash
python3 scripts/evaluate_secure_context_release_decision.py \
  --release-id production-policy-context-release \
  --channel-id production-mcp \
  --environment production_mcp \
  --expect-decision hold_for_signature
```

Assurance model release with actionable poisoning findings:

```bash
python3 scripts/evaluate_secure_context_release_decision.py \
  --release-id assurance-model-source-release \
  --channel-id trust-center \
  --environment enterprise_trust_center \
  --expect-decision hold_for_poisoning_review
```

## Product Path

The open repo now proves the release model. The enterprise product path
is hosted signed releases:

- customer-private context release channels,
- keyless signing and transparency-log proof,
- release promotion APIs for MCP gateways,
- source drift and rollback alerts,
- trust-center export automation.

That makes the site easier for enterprise teams to approve and gives a
future acquirer a concrete control primitive around agent context
distribution.

## Source Anchors

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP GenAI Exploit Round-up Report Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
- [CISA AI Data Security Best Practices](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
