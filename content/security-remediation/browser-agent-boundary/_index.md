---
title: Browser Agent Workspace Boundary
linkTitle: Browser Agent Boundary
weight: 16
sidebar:
  exclude: true
description: >
  A generated browser-agent workspace boundary and deterministic runtime
  evaluator for logged-in sessions, untrusted web content, localhost,
  local storage, downloads, forms, and external browser side effects.
---

{{< callout type="info" >}}
**What this is.** SecurityRecipes is positioned as **The Secure Context
Layer for Agentic AI**. Browser agents are where secure context meets
ambient user authority: logged-in sessions, untrusted pages, local
storage, downloads, forms, localhost, email, documents, and external
delivery routes. This pack decides when that boundary should allow, hold,
deny, or kill a browser-agent session.
{{< /callout >}}

## The product bet

The next enterprise question is not just whether an agent can use MCP
safely. It is:

> Can the agent safely operate inside a browser that sees my logged-in
> apps and adversarial web content?

The **Browser Agent Workspace Boundary** turns that question into a
machine-readable control. It models workspace classes, task profiles,
required controls, prohibited conditions, source-backed standards, and a
runtime evaluator for browser-agent sessions.

The control point is intentionally practical:

- public research can run in a logged-out, isolated browser;
- draft handoffs can proceed only after explicit route selection;
- email and document triage holds because embedded instructions are
  untrusted;
- personal browser profiles are denied by default;
- localhost, downloads, admin consoles, payments, secrets, and raw token
  exposure can kill the session.

That is a high-value trusted-source surface. The open pack helps teams reason
about browser agents today. A hosted product can enforce the same
decisions with browser isolation logs, origin policy, user confirmations,
SIEM export, and signed run receipts.

## What was added

- `data/assurance/browser-agent-boundary-profile.json` - source contract
  for workspace classes, task profiles, browser authority controls,
  runtime fields, kill signals, standards alignment, and trusted-source path.
- `data/evidence/browser-agent-boundary-pack.json` - generated evidence
  pack for MCP clients, CI drift checks, and reviewer diligence.
- `recipes_browser_agent_boundary_pack` - MCP lookup by workspace class,
  task profile, risk tier, or decision.



Evaluate safe public research:


Evaluate a prompt-injected email attempting an external send:


## What is inside

| Section | Purpose |
| --- | --- |
| `browser_agent_boundary_summary` | Workspace count, task count, risk tier counts, decision distribution, source summary count, and readiness state. |
| `boundary_contract` | Fail-closed default state, required runtime attributes, required browser controls, valid decisions, and kill indicators. |
| `workspace_classes` | Browser workspace profiles for public research, SecurityRecipes planner, isolated enterprise workspaces, email/document agents, personal browsers, localhost/devtools, and admin/payment consoles. |
| `task_profiles` | Browser tasks such as public research, draft remediation handoff, email/document triage, internal form fill, localhost review, and admin/payment observation. |
| `runtime_risk_weights` | Runtime signals that increase risk: ambient cookies, personal profile use, untrusted content, external sends, cross-origin egress, visible credentials, localhost access, downloads, code execution, admin writes, and payments. |
| `source_artifacts` | Hashes for this profile plus related SecurityRecipes packs, so browser-agent policy can be tied to secure context, egress, telemetry, action runtime, app intake, incident response, and threat radar evidence. |

## MCP examples

Get the executive summary and workspace index:

```json
{}
```

Inspect one workspace boundary:

```json
{
  "workspace_class_id": "security-recipes-browser-planner"
}
```

Inspect one browser task:

```json
{
  "task_profile_id": "draft-remediation-handoff"
}
```

Find the critical browser workspaces:

```json
{
  "risk_tier": "critical"
}
```

Evaluate one browser-agent run:

```json
{
  "workspace_class_id": "public-research-browser",
  "task_profile_id": "public-security-research",
  "session_id": "browser-run-123",
  "run_id": "run-123",
  "agent_id": "sr-browser-agent",
  "tenant_id": "tenant-a",
  "user_intent": "Collect cited public AI security references.",
  "target_origin": "https://www.nist.gov",
  "content_trust_level": "standards_body",
  "auth_state": "logged_out",
  "isolation_mode": "dedicated_agent_profile",
  "action_classes": ["navigate", "read_page", "summarize", "copy_draft"],
  "data_classes": ["public_security_guidance"],
  "network_egress_policy": "origin_allowlist",
  "browser_storage_policy": "ephemeral_or_scoped_storage",
  "approval_state": "approved",
  "telemetry_event_id": "telemetry-123",
  "receipt_id": "receipt-123",
  "controls": [
    "dedicated_agent_profile",
    "ephemeral_or_scoped_storage",
    "logged_out_by_default",
    "origin_allowlist",
    "metadata_only_telemetry",
    "run_receipt"
  ]
}
```

## Why it is review-ready

Browser agents are a natural reviewer surface for frontier labs, AI
browser vendors, AI coding platforms, and security companies. They need a
way to make agentic browsing safe enough for enterprises without forcing
every customer to invent policy from scratch.

This pack creates that path:

- hosted browser-agent policy API;
- dedicated agent workspace broker;
- origin allowlist and localhost controls;
- browser storage and token exposure checks;
- prompt-injection event ingestion;
- signed browser run receipts;
- SIEM/SOAR export for browser-agent incidents;
- procurement-ready evidence for AI browser adoption.

It also makes AI easier. Teams can start from a clear rule: public
research runs isolated, draft outputs require confirmation, personal
browsers are denied, and dangerous source-to-sink combinations kill the
session.

## Industry alignment

The pack is anchored in current primary guidance:

- [OpenAI: Designing AI agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
  for source-to-sink analysis and constraining the impact of social
  engineering-style prompt injection.
- [OpenAI: Hardening ChatGPT Atlas against prompt injection](https://openai.com/index/hardening-atlas-against-prompt-injection/)
  for browser agents that view pages and take clicks or keystrokes on a
  user's behalf.
- [Anthropic: Mitigating the risk of prompt injections in browser use](https://www.anthropic.com/research/prompt-injection-defenses)
  for browser-specific exposure across webpages, embedded documents,
  dynamic content, forms, clicks, downloads, and email workflows.
- [Microsoft Agent Workspace](https://support.microsoft.com/en-us/windows/experimental-agentic-features-a25ede8a-e4c2-4841-85a8-44839191dfb3)
  for dedicated agent accounts, scoped authorization, isolation,
  visibility, and user control.
- [CAISI AI Agent Security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
  for constraining and monitoring deployment-environment access under
  indirect prompt injection and misaligned-action risk.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for secure token handling, audience binding, resource indicators, PKCE,
  and token-passthrough denial when browser agents hand off to tools.

## See also

- [Agentic App Intake Gate]({{< relref "/security-remediation/agentic-app-intake-gate" >}})
- [Agentic Action Runtime Pack]({{< relref "/security-remediation/agentic-action-runtime" >}})
- [Agentic Incident Response Pack]({{< relref "/security-remediation/agentic-incident-response-pack" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
- [Agentic Telemetry Contract]({{< relref "/security-remediation/agentic-telemetry-contract" >}})
