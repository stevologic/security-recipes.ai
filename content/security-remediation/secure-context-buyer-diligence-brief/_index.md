---
title: Secure Context Buyer Diligence Brief
linkTitle: Buyer Diligence Brief
weight: 14
sidebar:
  open: true
description: >
  A generated buyer and acquirer diligence brief that compresses the
  SecurityRecipes secure-context, MCP, telemetry, pilot, source-freshness,
  and value evidence into review-ready answers.
---

{{< callout type="info" >}}
**Why this page exists.** SecurityRecipes has enough evidence that the
next problem is not adding more claims. The next problem is making the
first buyer review easy: one brief, exact evidence paths, clear
objection handling, and no overclaiming before customer runtime proof.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. That is a strong category claim, but a serious enterprise buyer,
frontier lab, or acquirer will not start by reading every artifact. They
will ask:

- What is the product in one sentence?
- Why is this timely now?
- Why is it more than docs?
- Which MCP, A2A, telemetry, identity, and context risks are covered?
- What is open, what is paid, and what proof is still missing?

The **Secure Context Buyer Diligence Brief** turns those questions into
a generated MCP-readable packet. It pulls from the trust-center export,
value model, pilot pack, source freshness watch, control-plane
blueprint, standards crosswalk, protocol conformance, MCP authorization,
telemetry contract, run receipts, app intake, and posture snapshot.

## What was added

- `data/assurance/secure-context-buyer-diligence-profile.json` - source
  profile for buyer briefs, enterprise questions, objection handlers,
  industry bets, and deal-room next steps.
- `scripts/generate_secure_context_buyer_diligence_brief.py` -
  deterministic generator and `--check` validator.
- `data/evidence/secure-context-buyer-diligence-brief.json` - generated
  brief with source-pack hashes, 5 buyer briefs, 12 enterprise
  questions, 8 objection handlers, 4 industry bets, and 4 next proof
  steps.
- `recipes_secure_context_buyer_diligence_brief` - MCP tool for the full
  brief, a buyer persona, enterprise question, objection, industry bet,
  source reference, or status-filtered view.

Run it from the repo root:

```bash
python3 scripts/generate_secure_context_buyer_diligence_brief.py
python3 scripts/generate_secure_context_buyer_diligence_brief.py --check
```

## What the brief contains

| Section | Purpose |
| --- | --- |
| `features_assessed` | Records the high-value feature options considered and why this buyer brief was selected for this run. |
| `buyer_briefs` | Frontier lab, AI platform, security platform, regulated enterprise, and VC/acquirer review angles. |
| `enterprise_questions` | RFP-style answers for product shape, urgency, MCP safety, A2A handoffs, telemetry, ROI, secure-by-design, and exit readiness. |
| `objection_handlers` | Crisp answers to docs-only, no-revenue, MCP-risk, prompt-injection, incumbent, private-data, and artifact-sprawl objections. |
| `industry_bets` | Current bets around MCP, A2A, OpenTelemetry, and agentic control planes with monetizable surfaces. |
| `deal_room_next_steps` | The proof points needed next: design partners, hosted MCP auth, private context registry, and trust-center API. |

The generated artifact currently reports `buyer_diligence_brief_ready`
with 12/12 source packs ready, 12/12 enterprise questions backed by
reference evidence, and 8/8 objections tied to generated evidence.

## Why it is acquisition-grade

This is the packet a buyer should see before a broad demo. It makes the
site feel like a company foundation instead of a collection of pages:

- It names the buyer and acquirer personas explicitly.
- It turns the open corpus into a review workflow.
- It separates reference evidence from customer runtime proof.
- It points each claim to generated JSON and MCP tools.
- It keeps the next valuation proof concrete: design partners, hosted
  auth, tenant isolation, private context ingestion, signed receipts,
  metering, and renewal signal.

That is the right posture for a credible $10-20M path. The project does
not need to pretend revenue exists today. It needs to prove that the
open secure-context layer can become a hosted MCP control plane that a
frontier lab, AI platform, or security vendor would rather buy than
rebuild.

## MCP examples

Inspect the full brief:

```text
recipes_secure_context_buyer_diligence_brief()
```

Inspect the acquirer view:

```text
recipes_secure_context_buyer_diligence_brief(buyer_id="vc-or-acquirer")
```

Answer a buyer question:

```text
recipes_secure_context_buyer_diligence_brief(question_id="mcp-authorization")
```

Handle a common objection:

```text
recipes_secure_context_buyer_diligence_brief(objection_id="docs-only")
```

Inspect a market bet:

```text
recipes_secure_context_buyer_diligence_brief(bet_id="mcp-becomes-agent-integration-layer")
```

## Industry alignment

The profile is grounded in current primary and authoritative sources:

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for autonomous agent risk framing.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) for
  MCP-specific token, scope, tool, command, audit, shadow-server, and
  context risks.
- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for OAuth 2.1, protected resource metadata, resource indicators,
  audience validation, PKCE, and token handling.
- [OpenAI MCP guidance](https://developers.openai.com/api/docs/mcp) and
  [ChatGPT MCP developer mode guidance](https://help.openai.com/en/articles/12584461-developer-mode-apps-and-full-mcp-connectors-in-chatgpt-beta)
  for custom MCP safety, prompt injection, write actions, server trust,
  RBAC, risk warnings, and connector vetting.
- [OpenTelemetry MCP semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/)
  for MCP-specific trace and metric evidence.
- [CSA Securing the Agentic Control Plane](https://cloudsecurityalliance.org/blog/2026/04/29/securing-the-agentic-control-plane-key-progress-at-the-csai-foundation)
  for the emerging control-plane category.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence),
  [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final),
  and [CISA Secure by Design](https://www.cisa.gov/resources-tools/resources/secure-by-design)
  for enterprise governance, secure development, and producer
  accountability expectations.

## See also

- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [Secure Context Value Model]({{< relref "/security-remediation/secure-context-value-model" >}})
- [Design Partner Pilot Pack]({{< relref "/security-remediation/design-partner-pilot-pack" >}})
- [Secure Context Customer Proof Pack]({{< relref "/security-remediation/secure-context-customer-proof-pack" >}})
- [Agentic Source Freshness Watch]({{< relref "/security-remediation/agentic-source-freshness-watch" >}})
- [Agentic Control Plane Blueprint]({{< relref "/security-remediation/agentic-control-plane-blueprint" >}})
- [Production MCP Server]({{< relref "/mcp-servers" >}})
