---
title: Claude
linkTitle: Claude
weight: 1
lastmod: 2026-08-21
sidebar:
  open: false
noindex: true
noindex_follow: true
description: >
  Claude Code CLAUDE.md files, skills, hooks, and slash-commands that
  keep agentic remediation bounded, reviewable, and safe to fetch as
  JSON or MCP context.
---

Prompts and configuration targeted at **Claude** and **Claude Code**.
If it goes into a repo at `CLAUDE.md`, `.claude/skills/`, or
`.claude/hooks/`, this is the right subfolder for it.

These pages stay `noindex` so leftover drafts cannot rank as
authoritative CVE floors. Humans browse the cards below; agents can
fetch the same bounded files through the recipe JSON feed and MCP
search tools.

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
