---
title: GitHub Copilot
linkTitle: GitHub Copilot
weight: 2
lastmod: 2026-08-21
sidebar:
  open: false
noindex: true
noindex_follow: true
description: >
  copilot-instructions.md files, issue templates, and GitHub Copilot cloud
  agent setups contributed by teams running Copilot for agentic
  remediation.
---

Prompts and configuration targeted at **GitHub Copilot** — both the
in-IDE chat and the **GitHub Copilot cloud agent**.

## What usually lives here

- **`.github/copilot-instructions.md`** — the repo-level file that
  tells Copilot your house rules (style, test runner, DB layer,
  what not to touch).
- **Issue templates** designed as bounded tasks for explicit Copilot
  assignment, API-based assignment, or a repository Copilot automation:
  narrow scope, acceptance criteria, reproduction steps, and links to the
  failing CI run.
- **Path-specific instructions** — Copilot supports
  `.github/instructions/NAME.instructions.md` with `applyTo` frontmatter for
  file-scoped rules.
- **Prompt snippets** that live in the IDE chat history and got
  enough reuse to be worth sharing.

## Browse entries

Every entry carries its author, team, and maturity. Click any card
for the full prompt.

{{< prompt-toc >}}

[Contribute a new Copilot prompt →]({{< relref "/contribute#contributing-a-prompt" >}})
