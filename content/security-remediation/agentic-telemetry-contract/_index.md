---
title: Agentic Telemetry Contract
linkTitle: Telemetry Contract
weight: 6
sidebar:
  open: true
description: >
  A generated OpenTelemetry-aligned trace contract for agentic AI and MCP
  runs: required fields, redaction tiers, reconstruction links, and
  runtime decisions before trace evidence is trusted.
---

{{< callout type="info" >}}
**What this adds.** SecurityRecipes now treats telemetry as part of the
secure context layer. Agent and MCP traces are useful only when they are
complete enough to reconstruct a run and safe enough not to become a new
secret, prompt, or tenant-data sink.
{{< /callout >}}

Agentic AI security is moving from "did the model answer correctly?" to
"can we prove what context, tool, identity, policy, approval, egress
decision, verifier, and incident signal shaped the run?" The Agentic
Telemetry Contract turns that into a generated artifact that a platform
team can hand to observability, SIEM, MCP gateway, GRC, and acquisition
diligence reviewers.

## Generated artifact

- Profile:
  `data/assurance/agentic-telemetry-contract-profile.json`
- Generator:
  `scripts/generate_agentic_telemetry_contract.py`
- Runtime evaluator:
  `scripts/evaluate_agentic_telemetry_event.py`
- Evidence pack:
  `data/evidence/agentic-telemetry-contract.json`
- MCP tools:
  `recipes_agentic_telemetry_contract` and
  `recipes_evaluate_agentic_telemetry_event`

Regenerate and validate:

```bash
python3 scripts/generate_agentic_telemetry_contract.py
python3 scripts/generate_agentic_telemetry_contract.py --check
```

Evaluate one telemetry event:

```bash
python3 scripts/evaluate_agentic_telemetry_event.py \
  --workflow-id vulnerable-dependency-remediation \
  --event-class mcp.tools.call \
  --attribute service.name=security-recipes-mcp \
  --attribute deployment.environment=production \
  --attribute trace_id=trace-ci \
  --attribute span_id=span-ci \
  --attribute workflow_id=vulnerable-dependency-remediation \
  --attribute run_id=run-ci \
  --attribute agent_id=sr-agent::vulnerable-dependency-remediation::codex \
  --attribute identity_id=sr-agent::vulnerable-dependency-remediation::codex \
  --attribute correlation_id=ci-correlation \
  --attribute receipt_id=sr-run-receipt::vulnerable-dependency-remediation \
  --attribute telemetry.redaction_state=metadata_only \
  --attribute gen_ai.operation.name=execute_tool \
  --attribute gen_ai.tool.name=repo.contents.patch \
  --attribute mcp.protocol.version=2025-11-25 \
  --attribute mcp.session.id=session-ci \
  --attribute mcp.method.name=tools/call \
  --attribute jsonrpc.request.id=req-ci \
  --attribute network.transport=tcp \
  --attribute policy.decision=allow \
  --attribute authorization.decision=allow_authorized_mcp_request \
  --expect-decision telemetry_ready
```

## Signal classes

| Signal | What must be reconstructable |
| --- | --- |
| Agent session | Workflow, run, agent, identity, tenant, correlation, and receipt linkage. |
| Model call | Provider/model operation and redaction state without raw prompt capture by default. |
| MCP tool call | JSON-RPC request id, method, session, protocol, transport, tool, policy, and authorization evidence. |
| Context retrieval | Source ids, source hashes, package hash, poisoning scan state, and retrieval decision. |
| Policy decision | Policy pack hash, rule, gate phase, MCP namespace, access mode, and decision. |
| Egress decision | Destination class, data class, policy hash, tenant, and allow/hold/deny/kill result. |
| Human approval | Approval system, actor, decision, expiry, and risk acceptance linkage. |
| Verifier result | Test, eval, scanner, or red-team result linked to receipt and artifact hash. |
| Incident signal | Incident class, severity, containment, replay case, and correlation evidence. |

## Enterprise default

The default state is
`untrusted_until_required_trace_fields_present`. Raw prompt text, model
outputs, tool arguments, tool results, MCP resource URIs, and HTTP bodies
are opt-in only. Credentials, bearer tokens, private keys, seed phrases,
unredacted PII, customer secrets, and cross-tenant context force a
`kill_session_on_secret_telemetry` decision.

This makes AI easier for enterprises because platform teams do not have
to choose between blind agents and unsafe logging. They get a small
contract: emit metadata, hashes, policy decisions, and receipt links by
default; capture content only with explicit redaction and retention
controls.

## Source anchors

- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
- [OpenTelemetry MCP semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/)
- [MCP Authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Transports specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [CISA AI Data Security Best Practices](https://www.cisa.gov/resources-tools/resources/ai-data-security-best-practices-securing-data-used-train-operate-ai-systems)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)

## See also

- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Agentic Measurement Probes]({{< relref "/security-remediation/agentic-measurement-probes" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
- [Agentic Incident Response Pack]({{< relref "/security-remediation/agentic-incident-response-pack" >}})
