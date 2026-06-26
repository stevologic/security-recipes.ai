---
title: Recipes
linkTitle: Recipes
url: /recipes/
aliases:
  - /prompt-library/
weight: 4
description: >
  Browse remediation recipes that humans can inspect, agents can fetch as
  JSON, and MCP clients can select as bounded context packs.
sidebar:
  open: false
cascade:
  - _target:
      kind: page
    sidebar:
      exclude: true
  - _target:
      kind: section
    sidebar:
      open: false
---

Recipes are the working shelf for agent instructions and MCP-ready context
packs. Search across the full library, filter by agent, risk, audit,
compliance, code hygiene, or problem class, open the recipe that matches the
finding, or download a portable JSON copy for downstream review and agent
handoff.

Each recipe should be narrow enough for one source-code finding or evidence
question, but rich enough to carry scope, stop conditions, verification,
review expectations, and the context another agent needs to act safely.

Agents and maintainers can use `recipes_quality_report` over MCP to find
recipes that need stronger inputs, output contracts, verification, guardrails,
or related context before they are treated as world-class context packs.

{{< callout type="info" >}}
**Prompts are guidance, not enforcement.** Pair them with branch protections,
CODEOWNERS, required CI, scoped MCP tokens, and human review.
{{< /callout >}}

{{< recipe-browser >}}

## How to use a prompt

1. Pick the prompt that matches the finding class and agent.
2. Read the scope and stop conditions before copying anything.
3. Put the prompt in the native place your agent reads.
4. Edit build, test, branch, and ownership details for your repository.
5. Run it against one small finding.
6. Keep the PR or triage note only if it satisfies the recipe's output contract.

## What a good prompt includes

- The finding class it handles.
- Inputs the agent needs.
- Files or areas the agent must not touch.
- The recipe or guidance source it should follow.
- MCP context it may read.
- Tests or verification expected.
- Stop conditions.
- PR or triage-note output requirements.

## MCP context in prompts

Prompts should describe MCP access in plain language:

```text
Use approved MCP servers as read-only evidence.
Do not create tickets, push branches, rotate secrets, deploy changes, or alter
cloud resources through MCP unless this task explicitly grants that permission.
```

That language keeps connector access aligned with the recipe instead of giving
the agent a vague instruction to "use tools."

## Contribute a prompt

Good candidates include `copilot-instructions.md`, `CLAUDE.md`,
`.cursor/rules/*.mdc`, `AGENTS.md`, Devin Knowledge entries, Claude skills,
hook scripts, issue templates, PR templates, triage prompts, and named CVE
remediation prompts.

Remove secrets, internal hostnames, customer data, and private vulnerability
details before submitting. See [Contribute]({{< relref "/contribute#contributing-a-prompt" >}})
for the review process.
