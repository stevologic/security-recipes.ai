---
title: Visual Guide
linkTitle: Visual Guide
weight: 3
toc: true
sidebar:
  open: true
description: >
  A visual, user-friendly walkthrough for exploring security-recipes.ai,
  running a first agentic remediation PR, and scaling with MCP-backed
  context and controls.
---

{{< callout type="info" >}}
Use this page when the site feels like a lot to unpack. The docs are
deep on purpose; this page gives you the shortest visual route through
them.
{{< /callout >}}

## The path at a glance

SecurityRecipes is meant to be read as a loop:

1. Find the right entry point.
2. Run one small, reviewer-gated remediation PR.
3. Turn the pattern into a security-operated workflow.
4. Add MCP context, policy, and audit when the workflow needs to scale.

{{< cards >}}
  {{< card link="/quickstart/" title="Quick Start" subtitle="The five-minute path to your first agentic remediation PR." >}}
  {{< card link="/agents/" title="Agents" subtitle="Pick the tool your team already uses and follow its recipe." >}}
  {{< card link="/prompt-library/" title="Prompt Library" subtitle="Fork instruction files, skills, rules, and remediation prompts." >}}
  {{< card link="/mcp-servers/" title="MCP Servers" subtitle="Add controlled context and scoped enterprise tool access." >}}
  {{< card link="/security-remediation/" title="Security Remediation" subtitle="Operate reviewable workflows from intake to evidence." >}}
{{< /cards >}}

## 1. Start with the map

<figure class="visual-guide-figure">
  <img src="../images/how-to-use/visual-site-map.png" alt="Visual map of the security-recipes.ai docs showing Start, Search, Pick, and Read across Quick Start, Agents, Prompt Library, MCP Servers, and Security Remediation." loading="lazy">
  <figcaption>Start with Quick Start, use search when you know the problem, then pick the section that matches your job.</figcaption>
</figure>

If you are brand new, begin with [Quick Start]({{< relref "/quickstart" >}}).
If you already know the task, search directly for an agent, CVE, MCP
connector, prompt, or workflow. The site is intentionally structured so
you do not have to read everything before doing something useful.

## 2. Run one safe agent PR

<figure class="visual-guide-figure">
  <img src="../images/how-to-use/first-agent-pr.png" alt="Workflow showing Pick Agent, Add Rules, Draft PR, and Review for a first reviewer-gated remediation pull request." loading="lazy">
  <figcaption>Pick one agent, add the matching rules file, let it draft a PR, and keep a human reviewer in the merge path.</figcaption>
</figure>

For the first run, choose the AI coding tool your team already has:
GitHub Copilot, Devin, Cursor, Codex, or Claude. Copy the matching
house-rules file from the agent recipe or prompt library, give the
agent one small finding, and review the pull request like any other
change.

## 3. Operate remediation as a workflow

<figure class="visual-guide-figure">
  <img src="../images/how-to-use/security-workflow-ops.png" alt="Security operations workflow showing Intake, Gate, Sandbox, Evidence, and Review." loading="lazy">
  <figcaption>At scale, agentic remediation is a security-operated workflow with gates, sandboxing, evidence, and review.</figcaption>
</figure>

Once one PR works, graduate to the
[Security Remediation]({{< relref "/security-remediation" >}}) section.
The workflows there show how to decide which findings are eligible,
what files the agent may touch, what evidence the run must produce, and
where the agent must stop instead of guessing.

## 4. Use MCP as the context layer

<figure class="visual-guide-figure">
  <img src="../images/how-to-use/mcp-context-layer.png" alt="Architecture view showing Agents, Recipes, MCP Server, Policy, Audit, and Scoped Tools." loading="lazy">
  <figcaption>MCP turns the site from static guidance into controlled, auditable context that agents can use at runtime.</figcaption>
</figure>

The production shape is MCP-backed. Agents retrieve recipe context from
the site or MCP server, policy narrows which tools they may call, scoped
connectors reach enterprise systems, and audit records keep the run
reviewable.

## What to read next

- [Quick Start]({{< relref "/quickstart" >}}) if you want the shortest
  path to a first PR.
- [Agents]({{< relref "/agents" >}}) if you already know which AI tool
  your team uses.
- [Prompt Library]({{< relref "/prompt-library" >}}) if you need rules,
  skills, or prompts to copy into a repo.
- [MCP Servers]({{< relref "/mcp-servers" >}}) if you need controlled
  context and enterprise connectors.
- [Security Remediation]({{< relref "/security-remediation" >}}) if you
  are designing the full security-operated workflow.
