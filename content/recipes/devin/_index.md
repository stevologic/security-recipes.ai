---
title: Devin
linkTitle: Devin
weight: 5
lastmod: 2026-08-21
sidebar:
  open: false
noindex: true
noindex_follow: true
description: >
  Devin Knowledge entries, playbooks, and task prompts for bounded
  remediation that humans can review and MCP clients can fetch as
  context.
---

Prompts and configuration targeted at **Devin** (Cognition's
autonomous engineering agent).

These pages stay `noindex` so leftover drafts cannot rank as
authoritative CVE floors. Humans browse the cards below; agents can
fetch the same bounded files through the recipe JSON feed and MCP
search tools.

## What usually lives here

- **Devin Knowledge entries** — per-repo runbooks Devin reads on
  every session. Include the commands Devin should run, the
  gotchas it should avoid, and the humans it should ping.
- **Playbooks** — longer, step-by-step descriptions for recurring
  remediation patterns (e.g. "bump a transitive dep behind a
  feature flag").
- **Task prompts** — canned descriptions for the Devin task UI.

## Browse entries

Every entry carries its author, team, and maturity. Click any card
for the full prompt.

{{< prompt-toc >}}

[Contribute a new Devin prompt →]({{< relref "/contribute#contributing-a-prompt" >}})
