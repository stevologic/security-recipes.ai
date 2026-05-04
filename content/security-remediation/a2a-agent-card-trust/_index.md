---
title: A2A Agent Card Trust
linkTitle: A2A Agent Card Trust
weight: 13
sidebar:
  open: true
description: >
  Generated trust profile and runtime decisions for A2A Agent Cards
  before remote agents receive secure context or join an agent handoff.
---

{{< callout type="info" >}}
**What this is.** An A2A Agent Card is not just metadata. It is the
front door to a remote opaque agent. This profile turns the card into an
intake decision before context, authority, or evidence crosses the
agent boundary.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. That layer needs a decision point before a newly discovered A2A
agent is trusted. MCP controls tool access; A2A controls agent-to-agent
coordination. The Agent Card is where a buyer first sees the remote
agent's identity, supported interfaces, auth requirements, skills,
signatures, and extended-card behavior.

The **A2A Agent Card Trust Profile** scores that discovery surface as a
security intake artifact. It helps teams decide whether a card is ready
for production handoff, restricted metadata-only pilot use, owner
review, denial, or immediate session termination.

## What was added

- `data/assurance/a2a-agent-card-trust-profile.json` - source model for
  Agent Card fields, trust profiles, decisions, controls, sample cards,
  and industry alignment.
- `scripts/generate_a2a_agent_card_trust_profile.py` - deterministic
  generator and `--check` validator.
- `scripts/evaluate_a2a_agent_card_trust_decision.py` - runtime
  evaluator for one proposed A2A Agent Card.
- `data/evidence/a2a-agent-card-trust-profile.json` - generated
  evidence pack for CI, MCP, architecture review, and diligence.
- MCP tools:
  `recipes_a2a_agent_card_trust_profile` and
  `recipes_evaluate_a2a_agent_card_trust_decision`.

Regenerate and validate:

```bash
python3 scripts/generate_a2a_agent_card_trust_profile.py
python3 scripts/generate_a2a_agent_card_trust_profile.py --check
```

Evaluate a trusted production card:

```bash
python3 scripts/evaluate_a2a_agent_card_trust_decision.py \
  --agent-card /tmp/trusted-agent-card.json \
  --profile-id trusted-production-agent \
  --production \
  --declared-control https_interface \
  --declared-control provider_identity_verified \
  --declared-control server_identity_verified \
  --declared-control agent_card_signature_verified \
  --declared-control standard_http_auth \
  --declared-control scope_minimized_security \
  --declared-control gateway_enforced \
  --declared-control audit_log \
  --declared-control human_approval_for_high_impact \
  --expect-decision allow_trusted_agent_card
```

## Trust profiles

| Profile | Default decision | Use when |
| --- | --- | --- |
| `trusted-production-agent` | `allow_trusted_agent_card` | A remote agent has HTTPS interfaces, provider identity, standard auth, signed-card evidence, scoped skills, gateway enforcement, audit logs, and high-impact approval controls. |
| `restricted-pilot-agent` | `pilot_with_restricted_context` | The card is valid and authenticated but lacks enough evidence for production. Restrict it to metadata-only handoffs. |
| `public-discovery-only` | `hold_for_agent_card_intake` | The card may be indexed or reviewed, but it must not receive tenant context or delegated authority. |
| `blocked-agent-card` | `deny_insecure_agent_card` | The card leaks secrets, advertises insecure interfaces, includes prompt-injection instructions, or requests unsafe skills without controls. |

## Why it matters

A2A makes agents discoverable and composable across vendors. That is
useful, but it also creates a new trust problem: an enterprise cannot
let any discovered opaque agent receive internal context just because it
publishes a card.

This profile answers concrete buyer questions:

- Does the Agent Card use HTTPS interfaces?
- Is provider identity present and reviewable?
- Are standard HTTP-layer security schemes declared?
- Is the card signed before production promotion?
- Are high-impact skills gated by approval and gateway policy?
- Does the card contain credential material or prompt-injection text?
- Which handoff profiles may the agent receive after intake?

The commercial path is hosted Agent Card monitoring, signature
verification, allowlist drift detection, procurement exports, remote
agent trust tiers, and A2A/MCP gateway enforcement.

## Industry alignment

This feature is grounded in current primary guidance:

- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
  for Agent Card fields, supported interfaces, security schemes,
  security requirements, signatures, and `.well-known/agent-card.json`.
- [A2A Enterprise Implementation](https://a2a-protocol.org/latest/topics/enterprise-ready/)
  for HTTPS, server identity verification, HTTP-layer auth,
  authorization, observability, and governance.
- [Google Cloud A2A toolkit announcement](https://cloud.google.com/blog/products/ai-machine-learning/agent2agent-protocol-is-getting-an-upgrade/)
  for enterprise adoption momentum and signed security-card support.
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for the complementary tool-access boundary: resource indicators,
  audience validation, PKCE, and token-passthrough denial.
- [OpenAI prompt-injection guidance](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
  for source-sink reasoning, constrained impact, and confirmation before
  sensitive transmissions or dangerous actions.
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
  for emerging agentic threats and mitigations.
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
  for vendor-neutral AI control evidence and third-party assessment.

## MCP examples

List trust profiles:

```json
{}
```

Inspect production profile:

```json
{
  "profile_id": "trusted-production-agent"
}
```

Evaluate a restricted pilot card:

```json
{
  "profile_id": "restricted-pilot-agent",
  "production": false,
  "declared_controls": [
    "https_interface",
    "standard_http_auth",
    "gateway_enforced",
    "metadata_only_context",
    "audit_log"
  ],
  "agent_card": {
    "name": "Public CVE Research Agent",
    "description": "Reads public vulnerability references and returns citation-only summaries.",
    "provider": {
      "organization": "Example Research Vendor",
      "url": "https://research.example.com"
    },
    "version": "0.9.2",
    "supportedInterfaces": [
      {
        "url": "https://research.example.com/.well-known/a2a",
        "protocolBinding": "https://a2a-protocol.org/specification/transport/http+json",
        "protocolVersion": "1.0"
      }
    ],
    "capabilities": {
      "streaming": false,
      "pushNotifications": false,
      "extendedAgentCard": false
    },
    "securitySchemes": {
      "bearer": {
        "httpAuthSecurityScheme": {
          "scheme": "Bearer",
          "bearerFormat": "JWT"
        }
      }
    },
    "securityRequirements": [
      {
        "bearer": ["research.read"]
      }
    ],
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/markdown"],
    "skills": [
      {
        "id": "public-cve-summary",
        "name": "Public CVE summary",
        "description": "Read public advisories and summarize mitigation options with citations."
      }
    ]
  }
}
```

## See also

- [Agent Handoff Boundary]({{< relref "/security-remediation/agent-handoff-boundary" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
- [Agentic Standards Crosswalk]({{< relref "/security-remediation/agentic-standards-crosswalk" >}})
