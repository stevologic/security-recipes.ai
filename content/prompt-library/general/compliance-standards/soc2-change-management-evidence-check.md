---
title: "SOC 2 change-management evidence check"
linkTitle: "SOC 2 change evidence"
description: "Read-only recipe for mapping repository changes, reviews, and agent runs to SOC 2 change-management evidence."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["compliance", "soc-2", "change-management", "audit", "evidence", "review"]
weight: 10
date: 2026-06-25
severity: "medium"
---

A read-only check that gathers change-management evidence for SOC 2 style
review. It does not decide whether the organization is SOC 2 compliant. It
collects the evidence a control owner or auditor needs to decide whether recent
changes are traceable, reviewed, tested, and attributable.

## When to use it

- Before an audit window closes and reviewers need PR-level evidence.
- After introducing coding agents or automated remediation into the SDLC.
- When a service team cannot quickly answer who requested, implemented,
  reviewed, tested, and approved a security change.

Do not use it as the final control mapping. Trust Services Criteria mappings
must be confirmed against the current SOC 2 scope and auditor interpretation.

## Inputs

- Repository path and target time window.
- Optional PR list, ticket IDs, scanner finding IDs, or agent run IDs.
- Branch protection and CODEOWNERS files when available.
- CI test logs or workflow configuration when available.

## The prompt

~~~markdown
You are running a SOC 2 change-management evidence check for this repository.
Run read-only. Do not edit files, open PRs, change settings, or claim that the
organization is SOC 2 compliant.

## Step 0 - Scope and source inventory

Record:

- Repository and service name.
- Evidence window in `YYYY-MM-DD` to `YYYY-MM-DD` format.
- Branches, PRs, tickets, scanner findings, or agent run IDs included.
- Evidence sources available locally: git history, PR metadata, CI workflows,
  CODEOWNERS, branch-protection-as-code, run logs, test artifacts, release
  notes, and scanner output.
- Evidence sources missing or outside this repository.

If the operator did not provide a time window, inspect the most recent 20
merged changes or the last 30 days, whichever is smaller, and state that choice.

## Step 1 - Build the change evidence table

For each in-scope change, collect:

- Change identifier: PR, commit, release, ticket, scanner finding, or run ID.
- Request source: ticket, finding, incident, user request, scheduled job, or
  policy.
- Implementer: human, agent, bot, or unknown.
- Reviewer: named human reviewer or missing.
- Approval evidence: review event, CODEOWNERS match, branch protection, or
  missing.
- Test evidence: CI job names, test commands, scanner reruns, or missing.
- Diff scope: files changed and whether production, security, CI, policy, or
  data-handling code was touched.
- Merge evidence: merge commit, squash commit, release tag, or not merged.

Use exact file paths, PR URLs, commit hashes, and timestamps where available.
Do not include secrets or customer data in the report.

## Step 2 - Check agent-specific attribution

If any change was authored or assisted by an agent, verify that the evidence
names:

- Agent run ID or session ID.
- Prompt, recipe, or workflow used.
- Model/provider if recorded.
- Tools or MCP sources used.
- Human reviewer who accepted the output.
- Stop conditions or guardrails included in the PR body.

Flag missing agent attribution separately from ordinary PR evidence gaps.

## Step 3 - Evaluate evidence gaps

Classify each gap:

- `blocking`: no human review, no approval evidence, or production/security
  change merged without test evidence.
- `material`: request source, run ID, reviewer rationale, or scanner rerun is
  missing.
- `minor`: metadata is present but hard to parse or inconsistently formatted.

For each gap, record the affected change, why it matters, and the smallest
next action for the control owner.

## Step 4 - Write the report

Write `SOC2_CHANGE_EVIDENCE_CHECK.md` at the repo root. If the session is
read-only, print the same content to stdout.

Use this structure:

```markdown
# SOC 2 change-management evidence check - <repo>

Generated on <date>. Evidence window: <window>.
Framework note: candidate mapping only; control owner must confirm current SOC
2 scope and auditor expectations.

## Evidence Sources Reviewed
- ...

## Change Evidence Table
| Change | Request | Implementer | Reviewer | Tests | Merge | Evidence status |
| ... |

## Agent-Assisted Change Evidence
- ...

## Gaps
### <blocking|material|minor> - <short title>
- **Change:** ...
- **Evidence missing:** ...
- **Why it matters:** ...
- **Next action:** ...

## Changes With Complete Evidence
- ...

## Out-of-Scope or Missing Sources
- ...
```

## Stop conditions

Stop and produce a partial report if:

- PR metadata or branch protection data is unavailable and cannot be inferred
  from repository files.
- The check would require administrator access to change repository settings.
- You find live credentials, customer data, private incident details, or
  confidential auditor workpapers.
~~~

## Output contract

- `SOC2_CHANGE_EVIDENCE_CHECK.md` or equivalent stdout report.
- One row per reviewed change.
- No code edits, settings changes, approvals, merges, or ticket updates.
- Clear separation between observed evidence and candidate control mapping.

## Guardrails

- Never mark a control as passing solely because a PR exists.
- Human review evidence must name a human reviewer.
- Agent-generated code requires both agent attribution and human approval.
- Treat missing CI logs as a gap, not as implicit failure or success.

## References

- [AICPA Trust Services Criteria with revised points of focus (2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)
- [Security Remediation - Compliance & Audit]({{< relref "/security-remediation/compliance" >}})

