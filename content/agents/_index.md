---
title: Agent Setup
linkTitle: Agent Setup
weight: 3
toc: true
sidebar:
  open: true
description: >
  How to configure common AI coding agents to consume security recipes,
  prompts, and scoped MCP context.
---

Start with the agent your team already uses. The recipe pattern works across
tools as long as the agent gets three things:

- A local rule file or knowledge entry.
- The specific security recipe for the finding.
- Only the context needed to produce a PR or triage note.

{{< callout type="info" >}}
**Do not switch agents just for a recipe.** The best first agent is usually the
one already connected to your repos, approvals, and review habits.
{{< /callout >}}

## Supported agents

{{< cards >}}
  {{< card link="/github_copilot/" title="GitHub Copilot" subtitle="Use repository instructions, narrow GitHub Issues, code scanning context, and the Copilot Coding Agent." >}}
  {{< card link="/claude/" title="Claude" subtitle="Use `CLAUDE.md`, skills, hooks, and read-only MCP context for repeatable remediation." >}}
  {{< card link="/cursor/" title="Cursor" subtitle="Use Cursor Rules and Background Agents for IDE-native remediation runs." >}}
  {{< card link="/codex/" title="Codex" subtitle="Use `AGENTS.md` and focused task prompts for terminal-first remediation." >}}
  {{< card link="/devin/" title="Devin" subtitle="Use Knowledge entries and playbooks for hosted ticket-to-PR workflows." >}}
{{< /cards >}}

## Common setup pattern

Every agent page follows this shape:

1. Create or update the agent's native instruction file.
2. Add the remediation rules and stop conditions.
3. Link or vendor the relevant security-recipes.ai recipe.
4. Add read-only MCP context only when the finding needs it.
5. Run one low-risk finding and inspect the PR or triage note.
6. Promote the pattern only after reviewers trust the output.

## Native instruction files

| Agent | Native context | Best use |
| --- | --- | --- |
| GitHub Copilot | `.github/copilot-instructions.md`, issue body, repository settings | Issue-to-PR flows inside GitHub |
| Claude | `CLAUDE.md`, `.claude/skills/*/SKILL.md`, hooks | Rich repo rules and repeatable procedures |
| Cursor | `.cursor/rules/*.mdc`, chat, Background Agents | IDE-centered remediation with project rules |
| Codex | `AGENTS.md`, task prompt | Terminal and repository-local work |
| Devin | Knowledge, playbooks, task description | Hosted task execution with curated runbooks |

## What to give the agent

Keep the prompt small and specific:

```text
Use the vulnerable dependency recipe from security-recipes.ai.
Fix only <finding ID>.
Use repository instructions before editing.
Read package/advisory context from approved read-only MCP sources.
Run the relevant tests.
Open one PR or stop with a triage note.
```

## What to enforce outside the prompt

Prompts guide behavior; they do not enforce it. Use the systems you already
trust for enforcement:

- Branch protection and required reviews.
- CODEOWNERS for sensitive files.
- Required CI and security checks.
- Scoped tokens and read-only MCP permissions.
- Audit logs for agent runs and connector calls.

## See also

- [Quick Start]({{< relref "/quickstart" >}})
- [Recipes]({{< relref "/recipes" >}})
- [MCP Integration]({{< relref "/mcp-servers" >}})
- [Integrate an AI Agent]({{< relref "/docs/agent-integration" >}})
