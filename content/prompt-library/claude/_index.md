---
title: Claude
linkTitle: Claude
weight: 1
sidebar:
  open: true
description: >
  CLAUDE.md files, `.claude/skills/*/SKILL.md` entries, hooks, and
  slash-commands contributed by teams using Claude for agentic
  remediation.
---

Prompts and configuration targeted at **Claude** and **Claude Code**.
If it goes into a repo at `CLAUDE.md`, `.claude/skills/`, or
`.claude/hooks/`, this is the right subfolder for it.

## What usually lives here

- **`CLAUDE.md`** — repo-level context Claude reads on every session.
- **Skills** (`.claude/skills/<name>/SKILL.md`) — encoded fix
  procedures. Often paired with helper scripts in the same folder.
- **Hooks** — `PreToolUse` / `PostToolUse` shell scripts that
  enforce guardrails at tool-call time.
- **Slash commands** — reusable inline prompts that get invoked with
  `/<name>`.
- **Triage prompts** — one-shot-style prompts that are worth saving
  because they've been iterated on.

## Browse entries

Every entry carries its author, team, and maturity so you can tell
what's been battle-tested vs. what's still a draft. Click any card
for the full prompt.

{{< prompt-toc >}}

[Contribute a new Claude prompt →]({{< relref "/contribute#contributing-a-prompt" >}})
