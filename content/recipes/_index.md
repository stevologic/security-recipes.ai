---
title: Recipes
linkTitle: Recipes
url: /recipes/
weight: 4
description: >
  Search CVE intelligence and move directly into a matched, human-reviewed
  security workflow with evidence, verification, rollback, and stop conditions.
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

Move from a vulnerability signal to a reviewable action path. Exact CVE links
open the matching source record and recommended workflows; broader searches
help people and agents find the right audit, containment, or remediation recipe.

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

Use the curated JSON feed for workflow discovery and the dedicated CVE catalog
tools for exact or filtered vulnerability lookup. MCP access should remain
read-only unless the task explicitly authorizes a specific write.

```text
Use approved MCP servers as read-only evidence.
Do not create tickets, push branches, rotate secrets, deploy changes, or alter
cloud resources through MCP unless this task explicitly grants that permission.
```

Maintainers can run `recipes_quality_report` through MCP to find recipes that
need stronger inputs, output contracts, verification, or guardrails.

## Contribute

Contributions can add workflows, evidence checks, toolsets, templates, or
reviewed CVE overrides. Remove secrets, internal hostnames, customer data, and
private vulnerability details first, then follow the
[contribution process]({{< relref "/contribute#contributing-a-prompt" >}}).
