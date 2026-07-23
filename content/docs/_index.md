---
title: "Security Recipes Documentation: Playbooks, Agents, and MCP"
linkTitle: Docs
weight: 6
lastmod: 2026-07-23
toc: true
sidebar:
  open: true
cascade:
  - _target:
      kind: page
    sidebar:
      exclude: true
  - _target:
      kind: section
    sidebar:
      open: false
description: >
  Explore Security Recipes documentation for remediation playbooks, AI agent
  setup, read-only MCP integrations, CVE intake, and review workflows.
---

[security-recipes.ai](/) is a recipe library for teams that want AI agents to help
with security remediation without handing those agents broad authority.

Use the site to answer four questions:

1. What kind of security finding am I trying to fix?
2. Which recipe and prompt should the agent use?
3. Which agent configuration file should carry the rules?
4. Which MCP servers or data sources should the agent read before acting?

That is the whole shape. The repository includes helper scripts and an optional
read-only MCP server, but the primary artifact is the content: recipes,
prompts, setup guides, and review patterns.

## Core surfaces

{{< cards >}}
  {{< card link="/quickstart/" title="Quick Start" subtitle="A short path from one finding to one reviewed agent output." >}}
  {{< card link="/security-remediation/" title="AI Vulnerability Remediation" subtitle="Agent playbooks for dependency, SAST, sensitive-data, container, CVE, and default-hardening work." >}}
  {{< card link="/agents/" title="AI Agent Comparison" subtitle="Compare verified operating modes, instruction surfaces, artifacts, limits, and review gates." >}}
  {{< card link="/recipes/" title="Recipes" subtitle="Reusable prompts, instruction files, rules, skills, and review checklists." >}}
  {{< card link="/mcp-servers/" title="MCP Integration" subtitle="How to connect public and internal security context as scoped, read-only agent input." >}}
  {{< card link="/docs/agent-integration/" title="Agent Consumption" subtitle="Patterns for direct fetch, vendored snapshots, MCP connectors, and CI injection." >}}
  {{< card link="/docs/cve-intelligence-intake/" title="CVE Intake" subtitle="Route advisory signals into remediation, containment, suppression, triage, or rejection." >}}
  {{< card link="/docs/control-plane-marketplace/" title="Control Plane Marketplace" subtitle="Review the browser workbench's input channels, output routes, report packs, and workflow templates." >}}
  {{< card link="/docs/ai-adoption-blueprint/" title="AI Adoption Blueprint" subtitle="A staged rollout path for small teams and governed enterprise programs." >}}
  {{< card link="/docs/recipe-routing-evals/" title="Recipe Routing Evals" subtitle="Golden-set tests that verify search and dispatch choose the intended recipe." >}}
{{< /cards >}}

For governed delivery, explore the [Control Plane Marketplace](/docs/control-plane-marketplace/)
to compare input channels and workflow outputs, then use the
[Secure Context Release Gate](/docs/secure-context-release/) to verify evidence
before context reaches production MCP or trust-center channels.

## What the site does

- Provides practical security remediation recipes that an agent can follow.
- Gives teams prompt and rules-file examples they can adapt to their repos.
- Shows how to add security context from MCP servers without turning every
  connector into an action surface.
- Keeps review gates clear: one finding, one bounded change, tests run, human
  approval before merge.
- Makes the optional site index and MCP server available for teams that want
  agents to search the recipes directly.

## What the site does not do

- It is not a replacement for SCA, SAST, secrets scanning, CI, ticketing, SIEM,
  SOAR, or code review.
- It is not a general-purpose automation platform.
- It does not require teams to run a custom scanner before they can use a
  recipe.
- It does not treat prompts as enforcement. Policy still belongs in branch
  protections, CODEOWNERS, CI, approvals, scoped tokens, and audit logs.

## Helper scripts

The scripts in this repository are support tooling. They help maintainers
validate content, generate indexes, import public advisory material, and run
local checks. They are not required runtime tooling for a company using a
recipe.

If a team wants to operationalize a recipe, the recommended path is:

1. Keep the recipe and prompt in the repo or agent configuration.
2. Use existing scanners and ticket systems to provide findings.
3. Use existing CI and branch protections to enforce review.
4. Add MCP connectors only for context the agent must read.
5. Treat any write-capable connector as a separate security review.

## Where to start

Start with the [Quick Start]({{< relref "/quickstart" >}}), then choose the
agent your team already uses under [AI Agent Comparison]({{< relref "/agents" >}}).
When the first loop works, add [MCP context]({{< relref "/mcp-servers" >}})
and stronger prompts from [Recipes]({{< relref "/recipes" >}}).
