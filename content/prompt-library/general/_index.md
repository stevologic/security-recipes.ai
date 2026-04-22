---
title: General
linkTitle: General
weight: 6
sidebar:
  open: true
description: >
  Tool-agnostic prompts, triage frameworks, guardrail patterns,
  and review checklists that apply regardless of which agent
  you're running.
---

Prompts and patterns that are **not tied to a specific agent**.
If a prompt works the same whether you paste it into Claude,
Copilot, Cursor, Codex, or Devin, it belongs here.

## What usually lives here

- **Triage frameworks** — the decision trees and checklists your
  team uses when a new finding lands, independent of which agent
  gets handed the fix.
- **Guardrail patterns** — repeated ideas for keeping automation
  safe (scoped credentials, dry-run gates, review policies) that
  work across tools.
- **Review checklists** — what a human should look at when
  reviewing a machine-generated PR.
- **PR templates** — the body your agent should fill in when it
  opens a PR, agnostic of which agent is writing.
- **Commit-message conventions** — style rules your agent should
  follow when committing.

## When this is the right folder

Put a prompt here if **at least two agents** would use it
unchanged. If you find yourself writing a Claude-only skill, put
it under [`claude/`]({{< relref "/prompt-library/claude" >}})
instead — the whole point of per-tool folders is that agent
specifics stay where their context lives.

## Browse entries

Every entry carries its author, team, and maturity. Click any card
for the full prompt.

{{< prompt-toc >}}

[Contribute a new general prompt →]({{< relref "/contribute#contributing-a-prompt" >}})
