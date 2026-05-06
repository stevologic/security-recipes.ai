---
title: Agentic Source Freshness Watch
linkTitle: Source Freshness Watch
weight: 19
toc: true
description: >
  Generated source-freshness and standards-drift evidence for the secure
  context layer across OWASP, NIST, MCP, A2A, CISA, OpenAI, CSA, and
  related agentic AI security sources.
---

{{< callout type="info" >}}
**What this is.** The Source Freshness Watch makes "up to date" an
inspectable product claim. It tracks the primary sources that drive the
SecurityRecipes evidence packs, checks when dependent packs were last
reviewed, and exposes the result as generated JSON plus an MCP tool.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. That category depends on trust: a buyer needs to know not only
what the site says, but whether its source-backed controls still track
the latest protocol, standards, government, and frontier-lab guidance.

The **Agentic Source Freshness Watch** fills that gap. It treats source
references as maintained dependencies, similar to libraries in a
software supply chain.

## Feature decision

This run considered three high-value product directions:

| Candidate | Value | Decision |
| --- | --- | --- |
| Hosted context signing | Strong paid wedge for production MCP, but the repo already has attestation and release-gate foundations. | Keep as next hosted layer. |
| More protocol conformance | Valuable, but MCP and A2A conformance already exists as a generated pack. | Extend later with live probes. |
| Source freshness and standards drift | Directly strengthens every existing evidence pack and answers the buyer question: "How do we know this is current?" | **Implemented now.** |

## Generated artifact

- Profile:
  `data/assurance/agentic-source-freshness-profile.json`
- Generator:
  `scripts/generate_agentic_source_freshness_watch.py`
- Evidence pack:
  `data/evidence/agentic-source-freshness-watch.json`
- MCP tool:
  `recipes_agentic_source_freshness_watch`

Regenerate and validate:

```bash
python3 scripts/generate_agentic_source_freshness_watch.py
python3 scripts/generate_agentic_source_freshness_watch.py --check
```

## What it watches

The watch currently monitors source references and last-reviewed dates
from the product's most buyer-relevant evidence inputs:

- Agentic Threat Radar sources.
- Agentic Standards Crosswalk profile.
- Agentic Protocol Conformance profile.
- MCP and Agentic Skills Risk Coverage profile.
- MCP Authorization Conformance profile.
- Secure Context Release profile.
- Agentic Catastrophic Risk Annex.
- Agentic Incident Response profile.

Each watched source has a review cadence and a default fail-closed
decision if the pack is missing, has no references, or is past its
review window.

## Primary source anchors

The primary watchlist tracks sources that currently matter most for the
SecurityRecipes category claim:

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [NIST CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
- [OpenAI agent prompt-injection guidance](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
- [CISA AI Data Security](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
- [A2A Enterprise Implementation Guidance](https://a2a-protocol.org/latest/topics/enterprise-ready/)
- [CSA MCP Security Resource Center](https://cloudsecurityalliance.org/articles/securing-the-agentic-ai-control-plane-announcing-the-mcp-security-resource-center)

## Enterprise use cases

**Procurement security.** Return the watched packs, source references,
last-reviewed dates, publisher coverage, and review-due findings before
a buyer relies on the site for an AI platform decision.

**AI platform standards drift.** Use the watch as the quarterly agenda
for MCP, A2A, OWASP, NIST, CISA, OpenAI, and CSA guidance changes.

**Acquisition diligence.** Show that SecurityRecipes is maintained as a
living control plane with generated evidence, not a static prompt
library.

## MCP examples

Inspect the overall freshness watch:

```text
recipes_agentic_source_freshness_watch()
```

Review one watched pack:

```text
recipes_agentic_source_freshness_watch(
  watched_source_id="agentic-protocol-conformance-profile"
)
```

Find source references from one publisher family:

```text
recipes_agentic_source_freshness_watch(
  publisher_family="NIST"
)
```

Find references tied to protocol specifications:

```text
recipes_agentic_source_freshness_watch(
  source_class_family="protocol"
)
```

## Commercial path

The open pack proves the operating model. The hosted product surface is
standards and source-drift monitoring:

- customer-private source maps,
- MCP and A2A protocol update alerts,
- source freshness SLAs,
- generated review tickets,
- trust-center freshness exports,
- source-pack recertification evidence,
- alerts when a source change should regenerate evals, gateway policy,
  conformance checks, or context release manifests.

That is a natural enterprise layer above the open SecurityRecipes
knowledge base and a credible acquisition wedge for a model lab,
security platform, cloud platform, or developer-tool company.

## See also

- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
- [Agentic Standards Crosswalk]({{< relref "/security-remediation/agentic-standards-crosswalk" >}})
- [Agentic Protocol Conformance Pack]({{< relref "/security-remediation/agentic-protocol-conformance" >}})
- [Secure Context Release]({{< relref "/docs/secure-context-release" >}})
