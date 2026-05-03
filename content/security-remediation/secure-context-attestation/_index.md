---
title: Secure Context Attestation Pack
linkTitle: Secure Context Attestation
weight: 10
sidebar:
  open: true
description: >
  A generated attestation and recertification layer for SecurityRecipes
  context sources and workflow context packages, designed for CI, MCP
  gateways, procurement review, and future production keyless signing.
---

{{< callout type="info" >}}
**Why this page exists.** The Secure Context Trust Pack proves which
context sources exist. This pack answers the next buyer question:
which context was attested, which hash should an MCP gateway verify, and
what has to be signed before production use?
{{< /callout >}}

## The product bet

SecurityRecipes should not look like another prompt library. The
defensible product is a **secure context layer**: context sources are
registered, hashed, scanned, recertified, exposed through typed MCP
tools, and eventually signed for production gateways.

The Secure Context Attestation Pack turns the existing trust pack into
an attestation-shaped artifact. It does not pretend the open repo has
already produced a cryptographic signature. Instead, it creates a stable
attestation seed that can be verified in CI today and signed later with a
keyless signing system such as Sigstore or an enterprise attestation
service.

## What was added

- `data/assurance/secure-context-attestation-profile.json` - the source
  profile for attestation policy, signed environments, recertification
  SLAs, and primary-source standards alignment.
- `scripts/generate_secure_context_attestation_pack.py` - a
  dependency-free generator and `--check` validator.
- `scripts/evaluate_context_attestation_decision.py` - a deterministic
  runtime evaluator for context-source, workflow-package, and source
  artifact attestation decisions.
- `data/evidence/secure-context-attestation-pack.json` - the generated
  pack with in-toto-shaped subjects, verification policy,
  recertification queue, and signature readiness.
- MCP tools:
  `recipes_secure_context_attestation_pack` and
  `recipes_evaluate_context_attestation_decision`.

Run it locally from the repo root:

```bash
python3 scripts/generate_secure_context_attestation_pack.py
python3 scripts/generate_secure_context_attestation_pack.py --check
```

Evaluate an open-reference context source:

```bash
python3 scripts/evaluate_context_attestation_decision.py \
  --subject-type context_source \
  --source-id prompt-library-recipes \
  --environment open_reference \
  --expect-decision allow_attested_context
```

Evaluate the same subject for production MCP use:

```bash
python3 scripts/evaluate_context_attestation_decision.py \
  --subject-type context_source \
  --source-id prompt-library-recipes \
  --environment production_mcp \
  --expect-decision hold_for_signature
```

That second hold is intentional. Production and diligence environments
must present a signature bundle and transparency-log verification before
the subject is treated as production attested.

## What is inside the pack

| Section | Purpose |
| --- | --- |
| `attestation_summary` | Counts for active subjects, source subjects, workflow-package subjects, source-artifact subjects, decisions, statuses, and validation failures. |
| `attestation_manifest` | Attestation subjects for registered context sources, workflow context packages, and trust-pack source artifacts. |
| `in_toto_statement` | An in-toto-shaped statement seed with subject digests and a SecurityRecipes secure-context predicate. |
| `verification_policy` | Allow, hold, deny, and kill-session decisions for open-reference, CI, production MCP, trust-center, and diligence environments. |
| `signature_readiness` | The statement hash and explicit production requirement for a keyless signature bundle, identity-bound certificate, and transparency-log proof. |
| `recertification_queue` | Any source or workflow package that is registered but not active enough for trusted retrieval. |

## Runtime decisions

The evaluator returns:

- `allow_attested_context` for active context sources or source artifacts
  in open-reference and CI environments.
- `allow_attested_workflow_context` for active workflow context packages
  whose source set is covered by context-source attestations.
- `hold_for_signature` when a production, trust-center, or acquisition
  diligence request lacks signature and transparency-log evidence.
- `hold_for_recertification` when a subject is registered but stale,
  inactive, or missing source coverage.
- `deny_attestation_mismatch` when a supplied hash does not match the
  attested digest.
- `deny_unregistered_attestation` for unknown subjects or undeclared
  environments.
- `kill_session_on_forbidden_attestation` for prohibited data classes
  such as raw tokens, private keys, live signing material, or
  unrestricted customer logs.

## Industry alignment

This feature follows current primary guidance:

- [Model Context Protocol Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for audience-bound access tokens, resource indicators, HTTPS, PKCE, and
  per-request authorization.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  for token-passthrough denial, confused-deputy protection, SSRF defense,
  session binding, scope minimization, and local MCP server controls.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and
  [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
  for context injection, over-sharing, tool poisoning, shadow servers,
  skill governance, update drift, and supply-chain risk.
- [AWS Security for Agentic AI](https://docs.aws.amazon.com/prescriptive-guidance/latest/agentic-ai-security/introduction.html)
  for threat modeling, agent scoping, shared memory management, session
  isolation, data governance, and continuous posture management.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for lifecycle governance, measurement, provenance, monitoring, and
  third-party risk.
- [Sigstore](https://docs.sigstore.dev/),
  [SLSA 1.2](https://slsa.dev/spec/latest/), and
  [in-toto attestations](https://github.com/in-toto/attestation) for the
  signing, provenance, and attestation pattern this pack is shaped to
  support.

## Commercial path

The open pack is valuable by itself because teams can inspect the context
surface and fail CI on drift. The enterprise product path is stronger:

- Hosted keyless signing for context packs and workflow context packages.
- Customer-private context recertification for repositories, tickets,
  logs, approvals, and connector metadata.
- Transparency-log monitoring for unexpected signing events.
- MCP gateway verification APIs that hold or deny context before agents
  see it.
- Procurement and trust-center exports that show context provenance,
  signature readiness, and recertification state.

That is the kind of control primitive a frontier AI lab, cloud platform,
or security company can acquire: not only content, but a credible trust
layer for the context agents depend on.

## See also

- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  - the source registry and workflow context package hashes this pack
  attests.
- [Secure Context Evals]({{< relref "/security-remediation/secure-context-evals" >}})
  - scenario-backed checks that prove attestation holds, retrieval
    decisions, citations, egress, and handoff boundaries.
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
  - pre-retrieval inspection before context is trusted.
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
  - data-boundary decisions before retrieved context leaves a tenant,
  model, MCP server, telemetry sink, or public corpus.
- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
  - the broader acquisition-ready control-plane architecture.
