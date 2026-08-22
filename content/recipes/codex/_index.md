---
title: Codex
linkTitle: Codex
weight: 4
lastmod: 2026-08-21
sidebar:
  open: false
noindex: true
noindex_follow: true
description: >
  Codex AGENTS.md files and task prompts that turn one finding into a
  reviewed PR, safe for humans to copy and for MCP clients to fetch
  as bounded context.
---

Prompts and configuration targeted at **Codex** (OpenAI's hosted
coding agent).

These pages stay `noindex` so leftover drafts cannot rank as
authoritative CVE floors. Humans browse the cards below; agents can
fetch the same bounded files through the recipe JSON feed and MCP
search tools.

## What usually lives here

- **`AGENTS.md`** — the repo brief Codex reads on every invocation.
  Covers how to build, how to test, style conventions, and what
  files are out-of-bounds.
- **Task prompts** — the narrow description you paste into a Codex
  task that turns a finding into a PR.
- **`PROJECT_GUIDELINES`** snippets that are small enough to share
  but too big to inline in every task prompt.

## Browse entries

Every entry carries its author, team, and maturity. Click any card
for the full prompt.

{{< prompt-toc >}}

[Contribute a new Codex prompt →]({{< relref "/contribute#contributing-a-prompt" >}})
