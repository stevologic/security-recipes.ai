---
title: AI Vulnerability Remediation Quick Start
linkTitle: Quick Start
weight: 1
date: 2026-04-22
lastmod: 2026-07-23
toc: true
sidebar:
  open: true
description: >
  Remediate one vulnerability with an AI coding agent using a scoped Security
  Recipes playbook, source evidence, tests, rollback, and human review.
---

Use this page when you want to try [security-recipes.ai](/) without adopting new
tooling. Pick one real finding, give the agent one recipe, and keep the output
reviewable.

{{< callout type="info" >}}
**The first win is not full automation.** The first win is a clean PR or a
useful triage note that followed a recipe and respected your repo rules.
{{< /callout >}}

## The loop

1. **Pick one finding.** Use a small dependency, SAST, secret, container, SDE,
   or CVE finding. Avoid a noisy backlog for the first run.
2. **Pick the matching recipe.** Start in
   [AI vulnerability remediation playbooks]({{< relref "/security-remediation" >}}) or search the
   [Recipes]({{< relref "/recipes" >}}).
3. **Choose the agent your team already uses.** GitHub Copilot, Claude, Cursor,
   Codex, and Devin all work with this pattern.
4. **Put the rules where the agent reads them.** Use the native instruction file
   for your agent.
5. **Add only the context needed.** Attach scanner output, advisory details,
   SBOM/SARIF evidence, or an approved read-only MCP connector.
6. **Review the result.** Accept a PR only when tests and reviewer expectations
   are satisfied. Otherwise keep the triage note.

## Minimal agent task

```text
Remediate one security finding using the matching security-recipes.ai recipe.

Finding:
- <finding ID, package, rule ID, CVE, or scanner alert>

Rules:
- Use one recipe and cite it in the output.
- Make the smallest safe change.
- Do not touch unrelated files.
- Use MCP servers as read-only context unless this task explicitly grants write access.
- Run the relevant tests.
- Open one PR, or stop with a triage note if the fix is not bounded.
```

## Where to put recipe rules

| Agent | File or place to start |
| --- | --- |
| GitHub Copilot | `.github/copilot-instructions.md` plus a narrow issue assigned to `@copilot` |
| Claude | `CLAUDE.md`; use a skill for repeatable remediation procedures |
| Cursor | `.cursor/rules/security-remediation.mdc` |
| Codex | `AGENTS.md` |
| Devin | Knowledge entry or playbook attached to the task |

## Starter repo rules

Copy this into the relevant agent instruction file and edit the commands to
match your repo:

```markdown
# Security remediation rules

- Work on one security finding at a time.
- Prefer the matching recipe from security-recipes.ai.
- Make the smallest safe change that remediates or clearly triages the finding.
- Do not edit migrations, production infrastructure, generated files, or release
  automation unless the task explicitly allows it.
- Run the tests for the touched area before proposing a PR.
- Include the finding ID, recipe used, files changed, tests run, and residual
  risk in the output.
- Stop with a triage note if ownership, blast radius, or verification is unclear.
```

## Add MCP context only when it helps

Good first connectors are read-only:

- GitHub or GitLab repository context.
- Code scanning, Dependabot, SARIF, or SBOM data.
- Public advisory/package data such as OSV, GitHub Advisories, deps.dev, package
  registries, or NVD-backed mirrors.
- Product security tools your organization already approves, such as Semgrep or
  Snyk.

Do not start with write-capable tools. Ticket creation, code mutation, cloud
changes, secret rotation, and deployment should remain outside the first run.

## Good first recipes

{{< cards >}}
  {{< card link="/security-remediation/vulnerable-dependencies/" title="Vulnerable Dependencies" subtitle="The cleanest first loop for dependency and package advisory findings." >}}
  {{< card link="/security-remediation/sast-findings/" title="SAST Findings" subtitle="Use the recipe when the fix is local, testable, and tied to one rule." >}}
  {{< card link="/security-remediation/sensitive-data/" title="Sensitive Data" subtitle="Use for bounded cleanup of accidental secrets, PII, or sensitive fields." >}}
  {{< card link="/security-remediation/base-images/" title="Base Images" subtitle="Use when the remediation is an image, Dockerfile, or OS package bump." >}}
{{< /cards >}}

## Next steps

- [Agent Setup]({{< relref "/agents" >}}) for your exact tool.
- [Recipes]({{< relref "/recipes" >}}) for reusable prompts.
- [MCP Integration]({{< relref "/mcp-servers" >}}) when you need richer
  security context.
