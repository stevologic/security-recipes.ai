---
title: AI Agent Security Context Integration
linkTitle: Integrate an AI Agent
weight: 2
date: 2026-04-25
lastmod: 2026-07-23
toc: true
sidebar:
  open: true
description: >
  Architecture patterns for delivering security recipes, repository policy,
  finding evidence, and read-only MCP context to AI coding agents safely.
---

This architecture guide is for teams that already have an AI coding agent and
need a repeatable way to deliver recipes, repository rules, finding evidence,
and review requirements into each run. If you are still selecting or setting up
a tool, start with the [AI coding agent comparison]({{< relref "/agents" >}}).

An agent should consume a recipe the same way a careful engineer would:
read the relevant guidance, understand the repository rules, inspect only the
needed evidence, make the smallest useful change, and stop when the work no
longer fits the recipe.

The patterns below cover direct task links, vendored snapshots, native agent
configuration, CI injection, and MCP-backed context. The per-agent setup pages
show the exact files and commands for each tool.

## Consumption patterns

### 1. Direct link in the task

The simplest path is to paste the recipe URL into the agent task:

```text
Fix GHSA-xxxx-yyyy in this repository.
Use https://security-recipes.ai/security-remediation/vulnerable-dependencies/
as the remediation recipe.
Make one PR. Stop with a triage note if the fix needs a broad refactor.
```

Use this for one-off work, trials, and teams that do not want extra plumbing.

### 2. Vendored recipe snapshot

Copy the recipe or prompt into the repository as a versioned local file, such
as:

```text
SECURITY_RECIPES.md
.github/copilot-instructions.md
CLAUDE.md
AGENTS.md
.cursor/rules/security-remediation.mdc
```

Use this when the agent must work offline, when review requires pinned
instructions, or when the recipe has been adapted for local build and test
commands.

### 3. MCP knowledge connector

Expose the recipe index through an MCP server so the agent can search and
retrieve guidance at run time. The optional server in this repository is
read-only and suitable for that role.

Use this when a team wants agents to ask questions such as:

- Which recipe matches this finding?
- What prompt should I use for this tool?
- What output contract should the PR body satisfy?
- When should the agent stop and produce a triage note?

### 4. Native agent configuration

Most coding agents have a local instruction format. Put the recipe summary,
guardrails, and output contract into the format your tool already reads:

| Agent | Primary place to put recipe rules |
| --- | --- |
| GitHub Copilot | `.github/copilot-instructions.md` and issue templates |
| Claude | `CLAUDE.md`, skills, and hooks |
| Cursor | `.cursor/rules/*.mdc` |
| Codex | `AGENTS.md` |
| Devin | Knowledge entries and playbooks |
| Shiba Studio | Per-agent instructions, skills, and MCP servers |
| Hermes | Skills and agent-curated memory |
| OpenClaw | Workspace `AGENTS.md` and workspace skills |

Use native configuration for repeated remediation work. It keeps the task
prompt short and makes the agent behavior more consistent.

### 5. CI or ticket injection

If findings already land in GitHub Issues, Jira, Linear, ServiceNow, SARIF, or
another queue, have that system attach the matching recipe link and prompt
block when it dispatches the agent.

Use this for security programs that want the same instructions applied every
time a class of finding appears.

For GitHub repositories, the
[Security Health GitHub Action]({{< relref "/docs/security-health-action" >}})
packages this pattern: it fetches recipe context from the hosted MCP server
and runs toggleable, model-agnostic health checks as CI.

## Add MCP context safely

MCP is useful because it lets agents read structured context instead of asking
humans to paste screenshots or long scanner output into chat. Treat it as
context first.

Good context sources include:

- Public vulnerability and package intelligence such as
  [OSV](https://google.github.io/osv.dev/api/),
  [GitHub Advisories](https://docs.github.com/en/rest/security-advisories),
  [deps.dev](https://docs.deps.dev/api/v3/),
  [package registries](https://github.com/package-url/purl-spec), and
  [NVD-backed mirrors](https://nvd.nist.gov/developers/vulnerabilities).
- Repository context such as
  [GitHub MCP Server](https://docs.github.com/en/copilot/how-tos/provide-context/use-mcp-in-your-ide/use-the-github-mcp-server),
  [GitLab MCP server](https://docs.gitlab.com/user/gitlab_duo/model_context_protocol/mcp_server/),
  [Azure DevOps MCP Server](https://learn.microsoft.com/en-us/azure/devops/mcp-server/remote-mcp-server?view=azure-devops),
  [code scanning](https://docs.github.com/en/rest/code-scanning),
  [Dependabot](https://docs.github.com/en/rest/dependabot),
  [secret scanning](https://docs.github.com/en/rest/secret-scanning),
  [SARIF](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning),
  [SBOMs](https://www.cisa.gov/sbom), and
  [CI results](https://docs.github.com/en/rest/actions/workflow-runs).
- Product security tools such as
  [Semgrep MCP](https://semgrep.dev/docs/mcp),
  [Snyk MCP / Snyk Studio](https://docs.snyk.io/evo-by-snyk/agentic-security-with-snyk-studio/getting-started-with-snyk-studio),
  [CodeQL MCP](https://github.com/advanced-security/codeql-development-mcp-server),
  [Checkmarx MCP](https://docs.checkmarx.com/en/34965-591689-mcp-server---interacting-with-checkmarx-one-via-ai-assistant.html),
  [Veracode API docs for MCP gateway wrapping](https://docs.veracode.com/r/Veracode_APIs),
  [Wiz MCP](https://www.wiz.io/blog/introducing-mcp-server-for-wiz),
  [Tenable Hexa AI MCP](https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm),
  [Rapid7 Bulk Export MCP](https://github.com/rapid7/rapid7-bulk-export-mcp), and other
  approved systems when your organization has reviewed the connector.
- Internal runbooks, ownership maps, service catalogs, and architecture docs
  exposed through read-only documentation connectors.

Start with read-only permissions. A connector that can create tickets, edit
code, rotate secrets, deploy workloads, or change cloud configuration deserves
its own security review.

## Recommended agent run contract

Every recipe-backed agent run should carry this contract:

```text
Scope:
- One finding per run.
- Use the named recipe and repository rules.
- Touch only files needed to remediate or prove the finding.

Context:
- Use MCP servers as read-only evidence unless the task explicitly grants write access.
- Cite the recipe, finding ID, and evidence sources in the output.

Stop conditions:
- Stop if ownership is unclear.
- Stop if the fix needs a schema, API, infrastructure, or broad architecture change.
- Stop if tests cannot be run or the result is ambiguous.

Output:
- PR with tests and residual risk, or a triage note explaining why no safe fix was made.
```

## Guardrails that matter

- Pin or vendor instructions for repeatable workflows.
- Use branch protections, CODEOWNERS, required CI, and review gates for
  enforcement.
- Keep MCP tokens scoped to the repository, organization, and data class the
  agent needs.
- Log agent runs and MCP tool calls when the client supports it.
- Never pass secrets, customer data, or private vulnerability details to a
  public model or public connector unless your policy explicitly allows it.

## See also

- [AI Agent Comparison]({{< relref "/agents" >}})
- [Recipes]({{< relref "/recipes" >}})
- [MCP Integration]({{< relref "/mcp-servers" >}})
- [Recipes]({{< relref "/security-remediation" >}})
