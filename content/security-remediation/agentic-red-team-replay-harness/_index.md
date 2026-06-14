---
title: Agentic Red-Team Replay Harness
linkTitle: Red-Team Replay Harness
weight: 7
sidebar:
  exclude: true
description: >
  A generated replay harness that turns agentic red-team drills into
  safe fixtures, expected runtime decisions, trace requirements, run
  receipt bindings, and reviewer evidence before a drill can be counted.
---

{{< callout type="info" >}}
**What this adds.** SecurityRecipes now has a replay layer between
static red-team drills and customer runtime proof. A drill only counts
when the observed decision, evidence classes, trace events, and fail
signals match the generated harness.
{{< /callout >}}

The existing red-team drill pack defines the scenarios. The replay
harness makes them operational: every workflow/scenario pair gets a
safe fixture, expected policy decision set, required evidence classes,
required trace event classes, reviewer questions, and customer-private
proof bindings.

This is the practical bridge from open knowledge to production MCP. A
design partner can run the fixture in its own agent host, keep raw
prompts and customer data tenant-side, and export only decisions,
hashes, trace metadata, receipt ids, and reviewer outcomes.

## Generated artifact

- Profile:
  `data/assurance/agentic-red-team-replay-harness-profile.json`
- Generator:
- Runtime evaluator:
- Evidence pack:
  `data/evidence/agentic-red-team-replay-harness.json`
- MCP tools:
  `recipes_agentic_red_team_replay_harness` and

Regenerate and validate:


Evaluate a passing replay result:


Evaluate a failing replay result:


## Replay modes

| Mode | Why it matters |
| --- | --- |
| Mocked connector payload | Run fast benign adversarial fixtures without touching customer production systems. |
| Trace-only import | Validate redacted OpenTelemetry or agent traces when the customer cannot export raw transcripts. |
| Agent host replay | Exercise the actual agent host, model, guardrails, and MCP gateway before expansion. |
| Customer-private replay | Export only hashes, decisions, trace metadata, receipt ids, and reviewer outcomes. |

## Required evidence classes

| Evidence class | Minimum proof |
| --- | --- |
| Mocked connector payload | Fixture id, scenario id, workflow id, payload class, payload hash, and source namespace. |
| Agent transcript or structured response | Refusal or continuation state, response hash, agent id, run id, and redaction state. |
| MCP gateway policy decision | Tool namespace, gate phase, decision, policy hash, and correlation id. |
| Authorization or scope decision | Resource, scope, audience, decision, and token boundary state. |
| Telemetry trace event | Trace id, span id, event class, correlation id, workflow id, run id, and redaction state. |
| Run receipt | Receipt id, context hash, policy hash, verifier status, and run closure. |
| Verifier or replay assertion | Expected decisions, observed decision, replay result, and completion time. |
| Reviewer outcome | Reviewer pool, decision, review time, and follow-up. |

## Enterprise default

The default state is
`untrusted_until_replay_result_and_runtime_evidence_match`. A replay is
held when evidence or trace events are missing, fails when observed
policy decisions do not match the fixture, and kills the session when
critical unsafe flags appear, such as secret leakage, unauthorized tool
use, fabricated evidence, or an unbounded loop.

This makes AI easier because a reviewer does not need to read every raw
transcript to know whether the control plane held. The evaluator checks
a small, stable contract: expected decision, evidence classes, trace
events, fail signals, and unsafe runtime flags.

## Source anchors

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [MCP Authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [Agent2Agent Protocol specification](https://a2a-protocol.org/v0.2.0/specification/)
- [OpenAI Agents SDK guardrails](https://openai.github.io/openai-agents-python/guardrails/)
- [OpenAI Agents SDK tracing](https://openai.github.io/openai-agents-python/tracing/)
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)

## See also

- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}})
- [Agentic Telemetry Contract]({{< relref "/security-remediation/agentic-telemetry-contract" >}})
- [Agentic Run Receipts]({{< relref "/security-remediation/agentic-run-receipts" >}})
- [Agentic Action Runtime Pack]({{< relref "/security-remediation/agentic-action-runtime" >}})
- [Secure Context Customer Proof Pack]({{< relref "/security-remediation/secure-context-customer-proof-pack" >}})
