---
title: Agent Scheduling
linkTitle: Agent Scheduling
weight: 20
toc: true
description: >
  How the SecurityRecipes beta browser agent queues precise remediation
  actions, gathers bounded context, and prepares reviewed outputs.
---

{{< callout type="info" >}}
The browser agent is a beta planner. It can gather context, ask OpenAI,
Grok, or Claude for a focused remediation plan, and deliver a draft
handoff. It does not silently merge, deploy, rotate secrets, or run a
background scheduler.
{{< /callout >}}

## The simple model

Use the **Agents** tab as a local run queue:

1. **Choose one action.** Dependency fix, SAST triage, sensitive data
   cleanup, MCP guardrail review, base image update, or apply a recipe.
2. **Name the target.** Repository, package, CVE, finding group, file
   path, image, connector, or policy surface.
3. **Choose the cadence and output.** Manual approval, once, daily,
   weekly, or on-new-finding; then draft PR packet, GitHub issue, Slack,
   email, Jira, runbook receipt, or server runbook.

The planner sends that small contract to the selected provider using the
same credential saved in the Chat settings.

## Context sources

Each context source is optional and visible in Settings:

| Source | What It Adds | Auth Required |
|--------|--------------|---------------|
| Page context | The current SecurityRecipes page and nearby headings. | No |
| Recipe index | Matching recipes, CVEs, prompts, and workflow entries from the local site index. | No |
| GitHub repository | README, SECURITY, CONTRIBUTING, license, manifests, open issues, and open PRs. | Public repos: no. Private repos or higher API limits: GitHub token. |
| deps.dev CVEs | GitHub Dependency Graph SBOM packages checked against deps.dev advisory data. | Public dependency graph: no. Private graph: GitHub token. |

GitHub credentials are saved in this browser profile only. A PAT or
OAuth token can read private repository context and can create GitHub
issues when that output route is selected. The token is sent only with
GitHub API requests.

## Output routes

| Route | What Happens | Required Configuration |
|-------|--------------|------------------------|
| Draft PR packet | Copies a branch name, PR body, tests, rollback, and review checklist to the clipboard. | Provider token only |
| GitHub issue | Creates an issue in the configured repository. | GitHub PAT or OAuth token with issue write access |
| Slack message | Posts the handoff to an incoming webhook. | Slack webhook URL |
| Email handoff | Opens a local `mailto:` draft or posts to a CORS-enabled email relay. | Recipient; relay URL optional |
| Jira ticket | Creates a Jira task with the remediation handoff. | Jira URL, project, email, and API token |
| Runbook receipt | Copies a reviewed run receipt to the clipboard. | Provider token only |
| Server runbook | Copies commands, checks, stop conditions, and rollback for a human-run window. | Provider token only |

Browser CORS rules still apply. Slack webhooks, Jira, and email relays
may need a same-origin backend relay in production.

## Browser boundary

The scheduler must pass the
[Browser Agent Workspace Boundary]({{< relref "/security-remediation/browser-agent-boundary" >}})
before it becomes a recurring worker. That boundary denies personal
browser profiles, holds external sends for confirmation, and kills
sessions when prompt-injection signals combine with credential exposure,
localhost access, downloads, admin writes, payments, or cross-origin
secret egress.

## Scheduling

The beta scheduler is intentionally local:

- **Add action to queue** saves an item in browser storage.
- **Generate plan** asks the selected provider for a route-specific
  draft using the selected context.
- **Run selected output** performs the selected browser-safe delivery
  action.
- **Save schedule draft** records status, next run time, approval gate,
  and output route in browser storage.

Unattended schedules need a backend job runner, identity, audit log,
credential vault, retry policy, and revocation path. Until those exist,
saved schedules are drafts for review.

## Production shape

A production scheduler should persist each queued action as a small job
record:

| Field | Purpose |
|-------|---------|
| action type | Keeps the agent on one remediation workflow. |
| target scope | Names the repository, CVE, package, finding, image, or file path. |
| context manifest | Lists which sources the agent may read. |
| cadence | Defines when the job can prepare output for review. |
| approval gate | Names the required human or team review. |
| output route | Draft PR, issue, message, ticket, runbook, or receipt. |
| run receipt | Records context used, decisions, output, skipped steps, and rollback. |

The browser planner is the front-end contract for that future scheduler:
small action, bounded context, explicit output, and human review.
