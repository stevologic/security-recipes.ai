---
title: Recipe Routing Evals
linkTitle: Recipe Routing Evals
weight: 6
date: 2026-05-02
lastmod: 2026-08-21
toc: true
sidebar:
  open: true
description: >
  A golden-set evaluation loop for proving that MCP search, CI
  injection, and agent dispatch choose the right security recipe before
  they touch production repositories.
---

{{< callout type="info" >}}
**What this page is.** A lightweight evaluation harness for the
load-bearing question in agentic remediation: when a finding lands,
does the system route the agent to the right recipe?
{{< /callout >}}

## Why this matters

SecurityRecipes is only useful in production if retrieval is reliable.
An MCP server that confidently returns the wrong CVE prompt can produce
the same kind of bad PR as a bad agent. Treat recipe selection as an
evaluated subsystem, not a helper function.

The repo now ships a golden routing set at
`data/evaluations/recipe-routing-golden.json` and an evaluator at
`scripts/evaluate_recipe_routing.py`. Together they let teams test:

- **MCP relevance.** Does `recipes_search` put the right recipe in the
  top result set?
- **CI dispatch.** Does the recipe picker for scheduled remediation
  select the intended prompt?
- **Content changes.** Did a new page accidentally outrank a mature
  production workflow?
- **Model wrappers.** Does the agent's own "choose a recipe" step
  agree with the deterministic baseline?

## Run the baseline

Build the Eleventy site first so `public/recipes-index.json` exists:

```bash
npm run build
python scripts/evaluate_recipe_routing.py \
  --index public/recipes-index.json \
  --golden data/evaluations/recipe-routing-golden.json \
  --enforce-thresholds
```

The report prints `top1_accuracy`, `top3_accuracy`, and each case's
top three matches. `--enforce-thresholds` exits non-zero if the golden
set's minimum accuracy is missed, which makes it suitable for CI.

## Enterprise operating model

Use three rings of evaluation:

1. **Deterministic baseline.** Run the included evaluator against
   `recipes-index.json` on every content PR. This catches accidental
   relevance regressions before deploy.
2. **MCP parity.** Run the same case queries through your deployed MCP
   server and compare top-three paths against the baseline. This catches
   gateway, cache, and tool-description drift.
3. **Agent agreement.** Ask each production agent to choose a recipe
   from the same finding text, then compare its chosen path to the
   golden expected path. This catches prompt-wrapper and model drift.

Promote a recipe or workflow only when all three rings pass. If an
agent disagrees with the deterministic baseline, the agent should stop
and write a triage note instead of guessing.

## Add a golden case

Each case needs a realistic query and one or more expected paths:

```json
{
  "id": "cve-example",
  "query": "CVE-20XX-12345 package ecosystem exploit shape",
  "expected_paths": ["/recipes/cve/cve-20xx-12345-example/"],
  "tags": ["cve", "ecosystem"]
}
```

Good queries sound like scanner output, advisory text, or an engineer's
ticket title. Avoid copying the recipe title verbatim; that inflates
accuracy and hides routing failures.

## See also

- [Integrating an AI Agent]({{< relref "/docs/agent-integration" >}})
- [MCP Servers]({{< relref "/mcp-servers" >}})
- [Program Metrics & KPIs]({{< relref "/security-remediation/metrics" >}})
- [Gatekeeping Patterns]({{< relref "/security-remediation/gatekeeping" >}})
