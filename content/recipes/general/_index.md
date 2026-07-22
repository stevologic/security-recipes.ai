---
title: Tool-Agnostic Security Remediation Recipes
linkTitle: General
weight: 6
sidebar:
  open: false
description: >
  Browse tool-agnostic security remediation prompts, MCP context recipes,
  triage frameworks, guardrails, helper tools, and reviewer checklists.
---

Prompts, toolsets, and patterns that are **not tied to a specific agent** live
here. Treat General as the default shelf: recipes should be usable by any
workflow that can read the prompt, fetch the JSON, or attach the MCP context.

## What usually lives here

- **Triage frameworks** - the decision trees and checklists your team uses
  when a new finding lands.
- **Guardrail patterns** - repeated ideas for keeping automation safe, such as
  scoped credentials, dry-run gates, and review policies.
- **Review checklists** - what a human should look at when reviewing a
  machine-generated PR.
- **PR templates** - the body your workflow should fill in when it opens a PR.
- **Commit-message conventions** - style rules automation should follow when
  committing.
- **Python helper toolsets** - small scripts and checks that prepare evidence,
  normalize scanner output, or validate a recipe result.

## When this is the right folder

Put a recipe here when the finding class, evidence question, or helper toolset
matters more than the product used to run it. Product-specific packaging can be
mentioned inside the recipe, but the reusable guidance belongs in General.

## Browse entries

Every entry carries its author, team, and maturity. Click any card for the full
prompt.

{{< prompt-toc >}}

[Contribute a new general prompt]({{< relref "/contribute#contributing-a-prompt" >}})
