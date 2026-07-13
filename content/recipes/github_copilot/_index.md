---
title: GitHub Copilot
linkTitle: GitHub Copilot
weight: 2
sidebar:
  open: false
description: >
  copilot-instructions.md files, issue templates, and Copilot Coding
  Agent setups contributed by teams running Copilot for agentic
  remediation.
---

Prompts and configuration targeted at **GitHub Copilot** — both the
in-IDE chat and the **Copilot Coding Agent**.

## What usually lives here

- **`.github/copilot-instructions.md`** — the repo-level file that
  tells Copilot your house rules (style, test runner, DB layer,
  what not to touch).
- **Issue templates** designed for the Coding Agent to pick up:
  narrow scope, acceptance criteria, reproduction steps, links to
  the failing CI run.
- **Path-specific instructions** — Copilot supports
  `instructions/<path>.instructions.md` for file-scoped rules.
- **Prompt snippets** that live in the IDE chat history and got
  enough reuse to be worth sharing.

## Browse entries

Every entry carries its author, team, and maturity. Click any card
for the full prompt.

{{< prompt-toc >}}

[Contribute a new Copilot prompt →]({{< relref "/contribute#contributing-a-prompt" >}})
