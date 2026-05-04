---
title: Agentic Protocol Conformance Pack
linkTitle: Protocol Conformance
weight: 14
sidebar:
  open: true
description: >
  Generated MCP and A2A protocol conformance evidence with deterministic
  runtime decisions for authorization, tool annotations, tool-surface
  drift, Agent Cards, identity, handoff, and prompt-injection boundaries.
---

{{< callout type="info" >}}
**Why this page exists.** MCP and A2A make agent systems composable.
Enterprise trust depends on proving those protocol boundaries are current,
reviewed, and enforced before context, authority, tools, or remote-agent
delegation crosses them.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. The secure context layer cannot stop at content provenance. It also
needs protocol conformance: the evidence that MCP authorization metadata,
tool annotations, tool-surface drift, A2A Agent Cards, authenticated
extended cards, identity, handoff, egress, and prompt-injection source to
sink controls are current and fail closed.

The **Agentic Protocol Conformance Pack** turns fast-moving protocol and
agent-security guidance into a generated artifact that a platform team,
procurement reviewer, or acquirer can inspect through MCP.

## What was added

- Source profile:
  `data/assurance/agentic-protocol-conformance-profile.json`
- Generator:
  `scripts/generate_agentic_protocol_conformance_pack.py`
- Evidence pack:
  `data/evidence/agentic-protocol-conformance-pack.json`
- Runtime evaluator:
  `scripts/evaluate_agentic_protocol_conformance_decision.py`
- MCP tools:
  `recipes_agentic_protocol_conformance_pack` and
  `recipes_evaluate_agentic_protocol_conformance_decision`

Regenerate and validate:

```bash
python3 scripts/generate_agentic_protocol_conformance_pack.py
python3 scripts/generate_agentic_protocol_conformance_pack.py --check
```

Evaluate an MCP authorization boundary:

```bash
python3 scripts/evaluate_agentic_protocol_conformance_decision.py \
  --protocol-id mcp-authorization-2025-11-25 \
  --workflow-id vulnerable-dependency-remediation \
  --agent-id sec-auto-remediator \
  --run-id run-2026-05-04-001 \
  --session-id sess-001 \
  --correlation-id corr-001 \
  --transport streamable-http \
  --resource-indicator-present \
  --token-audience-bound \
  --pkce-verified \
  --client-metadata-reviewed \
  --expect-decision allow_with_protocol_receipt
```

## Decision model

| Decision | Meaning |
| --- | --- |
| `allow_with_protocol_receipt` | Protocol evidence is current enough to proceed and can be attached to the run receipt. |
| `hold_for_protocol_evidence` | Required metadata, identity, consent, Agent Card, approval, or evidence-pack state is missing. |
| `hold_for_protocol_drift_review` | The observed protocol version, tool surface, annotations, or schema drift requires review. |
| `deny_unbound_protocol_authority` | MCP authority is not bound to the expected protected resource, audience, or PKCE evidence. |
| `deny_untrusted_protocol_surface` | A protocol path combines unsafe trust boundaries such as untrusted content, private data, external egress, or unauthenticated remote-agent delegation. |
| `kill_session_on_protocol_violation` | The request includes token passthrough, secret movement, or an explicit runtime kill signal. |

## What the pack proves

The generated pack joins existing SecurityRecipes evidence into four
protocol profiles:

- **MCP Authorization Conformance** for protected-resource metadata,
  audience and resource binding, PKCE, token-passthrough denial, client
  metadata review, and incremental consent evidence.
- **MCP Tool Annotation, Schema, and Drift Safety** for trusted
  annotations, pinned tool descriptions and schemas, tool-output
  validation, and private-data plus untrusted-content plus external-send
  risk.
- **A2A Agent Discovery and Delegation** for Agent Card completeness,
  authenticated extended cards, HTTPS transport, version headers, signed
  card evidence, skill trust, and handoff minimization.
- **Agent Identity, Protocol Handoff, and Prompt-Injection Boundary** for
  non-human identity, run receipts, egress policy, source-to-sink prompt
  injection defenses, and standards-drift review.

## Industry alignment

This feature tracks current primary guidance:

- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected-resource metadata, resource indicators, audience-bound
  tokens, PKCE, client metadata, and token-passthrough denial.
- [MCP Tool Annotations](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)
  for annotation-driven tool UX and the need to treat annotations as
  policy hints until trust and drift evidence exist.
- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
  for Agent Cards, authenticated extended cards, security schemes,
  version headers, and transport requirements.
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  for interoperable agent standards, authentication, identity
  infrastructure, and security evaluations.
- [NIST CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for indirect prompt injection, poisoning, misaligned actions, and
  deployment access controls.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for tool misuse, identity abuse, context poisoning, insecure
  inter-agent communication, cascading failures, and rogue agents.
- [OpenAI prompt-injection guidance](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
  for source-to-sink reasoning, constrained impact, confirmations, and
  data-transmission safeguards.

## Commercial path

The open pack is the proof model. The premium product surface is hosted
MCP and A2A protocol conformance:

- live MCP protected-resource metadata checks,
- client metadata and redirect-policy review,
- resource, audience, PKCE, consent, and scope-drift monitoring,
- signed tool-surface baselines and annotation drift alerts,
- A2A Agent Card monitoring, signature verification, and skill allowlists,
- source-to-sink prompt-injection policy across protocol boundaries,
- signed protocol receipts attached to agent run receipts,
- procurement and acquisition diligence exports.

That turns SecurityRecipes from a static knowledge base into a protocol
control plane a model lab, AI platform vendor, security company, or VC
can underwrite.

## MCP examples

Inspect the overall pack:

```text
recipes_agentic_protocol_conformance_pack()
```

Review one protocol profile:

```text
recipes_agentic_protocol_conformance_pack(
  protocol_id="mcp-tooling-safety"
)
```

Evaluate one A2A boundary:

```text
recipes_evaluate_agentic_protocol_conformance_decision(
  protocol_id="a2a-agent-discovery",
  workflow_id="agentic-app-intake",
  agent_id="platform-intake-agent",
  run_id="run-001",
  https_transport=true,
  agent_card_present=true,
  provider_identity_verified=true,
  extended_card_authenticated=true,
  a2a_version_header=true
)
```

## See also

- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [MCP Tool Risk Contract]({{< relref "/security-remediation/mcp-tool-risk-contract" >}})
- [MCP Tool Surface Drift Sentinel]({{< relref "/security-remediation/mcp-tool-surface-drift-sentinel" >}})
- [A2A Agent Card Trust]({{< relref "/security-remediation/a2a-agent-card-trust" >}})
- [Agent Handoff Boundary]({{< relref "/security-remediation/agent-handoff-boundary" >}})
- [Agentic Standards Crosswalk]({{< relref "/security-remediation/agentic-standards-crosswalk" >}})
