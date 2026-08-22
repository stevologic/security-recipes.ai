---
title: Cursor
linkTitle: Cursor
weight: 3
lastmod: 2026-08-21
sidebar:
  open: false
noindex: true
noindex_follow: true
description: >
  Cursor rules, Cloud Agent task prompts, and chat macros for
  bounded remediation that humans can inspect and MCP clients can
  fetch as context packs.
---

Prompts and configuration targeted at **Cursor** — both the
interactive Agent and headless **Cloud Agents**.

These pages stay `noindex` so leftover drafts cannot rank as
authoritative CVE floors. Humans browse the cards below; agents can
fetch the same bounded files through the recipe JSON feed and MCP
search tools.

## What usually lives here

- **`.cursor/rules/*.mdc`** — project rules that steer Cursor's
  Agent and Cloud Agents. Scoped with glob patterns so you
  can apply different guidance to different file types.
- **Cloud Agent task prompts** — the canned task description
  you paste into a Cloud Agent when kicking off a run.
- **Cursor chat macros** — long chat prompts that have proven
  themselves worth keeping.

## Browse entries

Every entry carries its author, team, and maturity. Click any card
for the full prompt.

{{< prompt-toc >}}

[Contribute a new Cursor prompt →]({{< relref "/contribute#contributing-a-prompt" >}})
