---
title: AI Vulnerability Remediation Recipes
linkTitle: Recipes
url: /recipes/
weight: 4
lastmod: 2026-08-21
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

Browse reviewed workflows for common security tasks. Search by intent, filter
by outcome and review quality, share a filtered URL, or retrieve the same
bounded context through JSON and MCP.

{{< recipe-browser >}}

## Use recipes safely

Recipes guide people and agents; they do not enforce policy.

1. Match the recipe to one finding or evidence question.
2. Read its inputs, scope, guardrails, and stop conditions before acting.
3. Adapt repository-specific build, test, branch, and ownership details.
4. Start with a small change, verify the output contract, and require human review.

Back recipes with scoped credentials, branch protections, CODEOWNERS, and
required CI. Never treat generated remediation as proof that a system is safe.

## For agents and integrations

Use the curated JSON feed for workflow discovery. For exact or filtered
vulnerability intelligence, use the separate [CVE Database](/cve-database/)
and its dedicated MCP tools. MCP access should remain read-only unless the task
explicitly authorizes a specific write.

```text
Use approved MCP servers as read-only evidence.
Do not create tickets, push branches, rotate secrets, deploy changes, or alter
cloud resources through MCP unless this task explicitly grants that permission.
```

Maintainers can run `recipes_quality_report` through MCP to find recipes that
need stronger inputs, when-to-use guidance, output contracts, verification, or
guardrails. Those same headings also drive search quality on this site.

## Contribute

Contributions can add workflows, evidence checks, toolsets, templates, or
reviewed CVE overrides. Remove secrets, internal hostnames, customer data, and
private vulnerability details first, then follow the
[contribution process]({{< relref "/contribute#contributing-a-prompt" >}}).
