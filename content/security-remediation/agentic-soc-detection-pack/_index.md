---
title: Agentic SOC Detection Pack
linkTitle: SOC Detection Pack
weight: 7
sidebar:
  open: true
description: >
  A generated SIEM-ready detection pack for agentic AI and MCP systems:
  deployable rule logic, trace-field requirements, SOC decisions,
  response playbooks, and runtime evaluation without raw prompt capture.
---

{{< callout type="info" >}}
**What this adds.** SecurityRecipes now turns the secure context layer
into SOC-operable signal. The pack gives detection engineers a starting
set of MCP and agentic AI alerts tied to run receipts, telemetry
contracts, policy decisions, incident response, and replay evidence.
{{< /callout >}}

Enterprise AI security will not be trusted if the only evidence lives in
chat transcripts or one-off audit documents. Agentic systems need the
same operational muscle as cloud and endpoint security: normalized
events, tuned detections, escalation decisions, replay validation, and
alert evidence that a SOC can route into existing workflows.

The Agentic SOC Detection Pack makes that concrete. It packages
metadata-only detection rules for token passthrough, tool-surface drift,
context poisoning, unsafe telemetry, approval bypass, browser-agent
egress, runaway loops, shadow MCP servers, stale standards, and red-team
replay regressions.

## Generated artifact

- Profile:
  `data/assurance/agentic-soc-detection-profile.json`
- Generator:
  `scripts/generate_agentic_soc_detection_pack.py`
- Runtime evaluator:
  `scripts/evaluate_agentic_soc_detection_event.py`
- Evidence pack:
  `data/evidence/agentic-soc-detection-pack.json`
- MCP tools:
  `recipes_agentic_soc_detection_pack` and
  `recipes_evaluate_agentic_soc_detection_event`

Regenerate and validate:

```bash
python3 scripts/generate_agentic_soc_detection_pack.py
python3 scripts/generate_agentic_soc_detection_pack.py --check
```

Evaluate one event:

```bash
python3 scripts/evaluate_agentic_soc_detection_event.py \
  --workflow-id vulnerable-dependency-remediation \
  --event-class mcp.tools.call \
  --attribute service.name=security-recipes-mcp \
  --attribute deployment.environment=production \
  --attribute trace_id=trace-ci \
  --attribute span_id=span-ci \
  --attribute workflow_id=vulnerable-dependency-remediation \
  --attribute run_id=run-ci \
  --attribute agent_id=sr-agent::vuln-deps::codex \
  --attribute identity_id=sr-agent::vuln-deps::codex \
  --attribute tenant_id=tenant-ci \
  --attribute correlation_id=ci-correlation \
  --attribute receipt_id=sr-run-receipt::vulnerable-dependency-remediation \
  --attribute telemetry.redaction_state=metadata_only \
  --attribute authorization.token_passthrough_detected=true \
  --attribute authorization.decision=deny_token_passthrough \
  --expect-decision soc_critical_kill_session
```

## Detection rules

| Rule | SOC decision | Why it matters |
| --- | --- | --- |
| MCP token passthrough or audience mismatch | `soc_critical_kill_session` | Stops confused-deputy and token-forwarding failures before an MCP server becomes an exfiltration proxy. |
| Critical MCP tool surface drift | `soc_high_escalate` | Catches changed tool descriptions, schemas, or fingerprints before agents trust a poisoned capability. |
| Context poisoning reached retrieval | `soc_critical_kill_session` | Treats retrieved prompt injection as an operational incident, not a model-quality issue. |
| Secret or cross-tenant telemetry | `soc_critical_kill_session` | Prevents observability systems from becoming a prompt, token, or tenant-data sink. |
| High-impact action without approval receipt | `soc_high_escalate` | Makes excessive agency visible to the SOC when approval evidence is missing, expired, or bypassed. |
| Browser agent URL or form exfiltration | `soc_high_escalate` | Detects agentic browser flows that send sensitive context through URLs, forms, or external destinations. |
| Unbounded agent loop or cost runaway | `soc_medium_investigate` | Converts denial-of-wallet and runaway planning loops into measurable budget alerts. |
| Shadow MCP server or unknown connector | `soc_high_escalate` | Flags unregistered servers before a local or remote MCP connector gains trust by convenience. |
| Source freshness or standard drift | `soc_medium_investigate` | Keeps rules tied to current MCP, OWASP, NIST, and frontier-lab guidance instead of stale assumptions. |
| Red-team replay regression | `soc_high_escalate` | Blocks releases and connector promotions when known adversarial fixtures start passing unexpectedly. |

## Enterprise default

The default alert path is metadata-first. The pack expects workflow id,
run id, agent id, identity id, tenant id, trace id, span id, correlation
id, receipt id, policy decision, and redaction state. Raw prompts, model
outputs, tool arguments, tool results, HTTP bodies, and retrieved
context snippets are not required for initial SOC detection.

That choice matters for regulated buyers. A detection pack that requires
full transcripts will be blocked by privacy, legal, and customer-data
review. A pack built on hashes, decisions, receipts, and trace links can
ship into production sooner.

## SIEM export shape

The generated pack includes starter query templates for:

- Splunk SPL
- Microsoft Sentinel KQL
- Google Security Operations / Chronicle YARA-L-style predicates

These are intentionally fielded templates, not turnkey customer rules.
Production deployments still map collector fields, severity routing,
suppression windows, ownership, ticket enrichment, and retention to the
tenant environment.

## Source anchors

- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
- [OpenTelemetry MCP semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [MCP Elicitation](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [Google Cloud MCP AI Security and Safety](https://docs.cloud.google.com/mcp/ai-security-safety)
- [OpenAI Cybersecurity in the Intelligence Age](https://openai.com/index/cybersecurity-in-the-intelligence-age/)
- [MITRE ATLAS OpenClaw Investigation](https://www.mitre.org/news-insights/publication/mitre-atlas-openclaw-investigation)

## See also

- [Agentic Telemetry Contract]({{< relref "/security-remediation/agentic-telemetry-contract" >}})
- [Agentic Incident Response Pack]({{< relref "/security-remediation/agentic-incident-response-pack" >}})
- [Agentic Red-Team Replay Harness]({{< relref "/security-remediation/agentic-red-team-replay-harness" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
