---
title: Agent Skill Supply Chain
linkTitle: Agent Skill Supply Chain
weight: 18
sidebar:
  exclude: true
description: >
  A generated provenance, permission, isolation, and runtime-decision pack
  for agent skills, rules files, hooks, extensions, and behavior packages.
---

{{< callout type="info" >}}
**Why this page exists.** MCP controls what tools an agent can call.
Skills, rules files, hooks, and extensions control how the agent behaves
before those calls. This pack governs that behavior layer as a software
supply chain.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as **the secure context layer for agentic
AI**. That layer is incomplete if it only validates prompts, context, and
MCP tools. Enterprise agent hosts now load reusable behavior packages:
Claude skills, Cursor and Codex rules, VS Code extensions, Devin
knowledge, hooks, local helper scripts, and marketplace tool bundles.

Those packages can quietly combine three dangerous ingredients:

- access to private data or repository secrets;
- untrusted context that the model may treat as instructions;
- external network egress, shell, memory, or MCP authority.

The Agent Skill Supply Chain Pack makes those risks explicit. It turns
skills into governed inventory with owner, publisher, registry,
permissions, package hash, version pinning, signature status, sandbox
requirements, runtime approval requirements, and deterministic decisions.

{{< playbook-workflow >}}

## What was added

- `data/assurance/agent-skill-supply-chain-model.json` - the source
  model for skill provenance, permission, risk, and control credits.
- `data/evidence/agent-skill-supply-chain-pack.json` - the generated
  evidence pack.
- `scripts/evaluate_agent_skill_supply_chain_decision.py` - the
  deterministic install, enable, update, and runtime decision point.

Run it locally from the repo root:

```bash
python3 scripts/generate_agent_skill_supply_chain_pack.py
python3 scripts/generate_agent_skill_supply_chain_pack.py --check
```

Evaluate a pinned read-only context skill before the agent loads it:

```bash
python3 scripts/evaluate_agent_skill_supply_chain_decision.py \
  --skill-id sr-secure-context-retrieval-skill \
  --operation run \
  --workflow-id vulnerable-dependency-remediation \
  --platform codex \
  --expect-decision allow_pinned_readonly_skill
```

The MCP server exposes the pack through
`recipes_agent_skill_supply_chain_pack` and exposes runtime decisions

## Decision model

| Decision | Meaning |
| --- | --- |
| `allow_pinned_readonly_skill` | Registered low-risk skill may run with read-only or context-only authority. |
| `allow_guarded_skill` | Registered skill may run with sandbox, egress, approval, and evidence controls. |
| `hold_for_skill_security_review` | Security-owner review is required before install, update, enable, or run. |
| `deny_untrusted_skill` | Provenance, permission, version, scan, or isolation controls are insufficient. |
| `deny_unregistered_skill` | Default-deny result for anything not in the supply-chain register. |
| `kill_session_on_malicious_skill_signal` | Private-data-plus-egress, prohibited capability, or runtime kill signal disables the agent session. |

## Why this matters now

The 2026 agent security market is shifting from "prompt injection" to
"behavior package supply chain." A mature reviewer will ask:

- Which skills are installed across agent hosts?
- Which publisher and registry does each skill come from?
- Are versions pinned and package hashes recorded?
- Which skills can write memory, identity files, hooks, or rules?
- Which skills have shell, network, or approval-required MCP access?
- What happens when a skill update changes the hash or permission set?

This pack answers those questions in a form an MCP gateway or agent host
can enforce.

## Industry alignment

This feature follows current primary guidance:

- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
  for malicious skills, supply-chain compromise, over-privileged skills,
  unsafe metadata, weak isolation, update drift, scanning gaps,
  governance gaps, and cross-platform reuse.
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) for tool
  poisoning, command execution, insufficient authorization, audit gaps,
  shadow servers, and context over-sharing.
- [Model Context Protocol Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for OAuth 2.1, client metadata, resource indicators, token audience
  validation, and trust policy expectations.
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
  for threat-model-based agentic security controls.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  for governance, measurement, provenance, third-party dependency, and
  monitoring expectations.

## Runtime examples

Plan a pinned, read-only context skill before running:

```text
recipes_playbook_plan(
  playbook_id="agent-skill-supply-chain",
  finding="Pinned read-only context skill requested for a dependency-remediation workflow."
)
```

Plan a high-consequence quarantine skill with approval:

```text
recipes_playbook_plan(
  playbook_id="agent-skill-supply-chain",
  finding="High-consequence artifact quarantine skill requested with human approval."
)
```

An unregistered marketplace skill, a changed package hash, a wildcard
egress request, or a private-data-plus-egress pattern fails closed.

## CI contract

The generator fails if:

- the model misses current standards references;
- the decision contract does not default-deny unregistered skills;
- a skill references an unknown workflow;
- mapped AST or MCP risk IDs are invalid;
- required source packs are missing or have failures;
- an allowed skill has no package hash;
- the checked-in pack is stale in `--check` mode.

That is the enterprise bar for agentic behavior packages: inventory them,
pin them, hash them, scan them, sandbox them, and deny them by default
until the controls are present.

## See also

- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - connector trust evidence for tool namespaces.
- [Agent Memory Boundary]({{< relref "/security-remediation/agent-memory-boundary" >}})
  - persistent memory classes and runtime memory decisions.
- [Secure Context Trust Pack]({{< relref "/security-remediation/secure-context-trust-pack" >}})
  - provenance and retrieval trust for context returned to agents.
- [Context Poisoning Guard]({{< relref "/security-remediation/context-poisoning-guard" >}})
  - scanner output for hostile instructions in retrieved context.
- [Agentic System BOM]({{< relref "/security-remediation/agentic-system-bom" >}})
  - inventory of agentic workflows, identities, connectors, evidence, and evals.
