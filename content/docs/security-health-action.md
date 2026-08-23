---
title: Security Health GitHub Action
linkTitle: GitHub Action
weight: 3
toc: true
date: 2026-07-29
lastmod: 2026-08-21
description: >
  One GitHub Action that grounds an LLM in security-recipes.ai recipe context
  from the hosted MCP server and runs toggleable security health checks as CI.
---

The [Security Recipes Health Check action](https://github.com/stevologic/security-recipes.ai/tree/main/actions/security-health)
turns this site's guidance into a CI gate. It connects to the hosted
[Security Recipes MCP server]({{< relref "/mcp-servers" >}}) for recipe
context, evaluates bounded repository evidence with the model you choose, and
reports every check — including the ones you have not enabled — in the job
summary, so remaining coverage is always visible. Rechecked August 23, 2026:
this repository's workflows pin
`actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (**v7.0.1**).
The example below uses the current major tag `v7`. `v5` is still published
and is not the current major. `check-owasp` still grounds in the current
[OWASP Top 10:2025 audit](/recipes/general/owasp-top-10-2025-audit/). The
hosted MCP endpoint is Streamable HTTP. MCP
[2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) is
stateless.

## Quick start

```yaml
name: Security health
on:
  pull_request:

jobs:
  security-health:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: stevologic/security-recipes.ai/actions/security-health@main
        with:
          provider: openai              # anthropic | openai | xai | ollama
          api-key: ${{ secrets.OPENAI_API_KEY }}
```

Each check is a boolean toggle grounded in a published recipe:

| Toggle | Default | Grounded in |
| --- | --- | --- |
| `check-dependencies` | on | [Vulnerable dependencies]({{< relref "/security-remediation/vulnerable-dependencies" >}}) |
| `check-secrets` | on | [Secrets and data exposure audit](/recipes/general/source-code-secrets-data-exposure-audit/) |
| `check-injection` | on | [Injection sink audit](/recipes/general/source-code-injection-sink-audit/) |
| `check-supply-chain` | on | [Supply chain build integrity audit](/recipes/general/source-code-supply-chain-build-integrity-audit/) |
| `check-authz` | off | [Authorization and tenant boundary audit](/recipes/general/source-code-authz-tenant-boundary-audit/) |
| `check-containers` | off | [Base image hygiene](/recipes/general/base-image-bump/) |
| `check-owasp` | off | [OWASP Top 10 audit](/recipes/general/owasp-top-10-2025-audit/) |
| `check-cve-exposure` | off | [CVE intelligence intake gate](/recipes/general/cve-intelligence-intake-gate/) |
| `check-compliance` | off | [Compliance standards](/recipes/general/compliance-standards/) |

## Models

Select `provider` (Anthropic, OpenAI, Grok/xAI, or an Ollama-served model via
`base-url`) and optionally `model`. **When no model is set, the action queries
the provider's live model list and picks the lowest available model** — for
Ollama, the smallest installed model by size — so the default run stays cheap.

## How verdicts work

- Recipe context is fetched from `https://security-recipes.ai/mcp`
  (streamable-HTTP MCP) with an automatic fallback to the public
  [`api/recipes.json`](/api/recipes.json) feed.
- Evidence is bounded and deterministic: manifests, workflows, container
  files, and source excerpts, capped to a few dozen kilobytes per check.
- The model must answer in strict JSON (`pass` / `warn` / `fail` plus
  findings); malformed replies degrade to `warn`, never to silence.
- `fail-on` decides whether the job fails on `fail` (default), on `warn`, or
  `never` (report-only).

This repository runs the action on itself
([workflow](https://github.com/stevologic/security-recipes.ai/blob/main/.github/workflows/security-health.yml))
in report-only mode: the deterministic build gate stays the required check,
and the LLM verdicts surface loudly in every pull request summary.

An LLM check is a bounded review gate, not a proof of security. Keep the
[evaluation discipline]({{< relref "/agents" >}}#evaluate-an-agent-before-broader-rollout)
and your required human review and CI gates in place.
