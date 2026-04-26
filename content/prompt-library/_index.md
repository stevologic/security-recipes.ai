---
title: Prompt Forge
linkTitle: Prompt Forge
weight: 8
description: >
  Prompt Forge: community prompts plus agent-verified premium prompts
  delivered through the SecurityRecipes production MCP server.
sidebar:
  open: true
cascade:
  sidebar:
    open: true
---

{{< callout type="info" >}}
**This is a team effort.** If a prompt is earning its keep on your
team, share it here. Someone else is debugging the exact same
problem right now — browse by tool below, or jump straight to the
[sample prompt]({{< relref "/prompt-library/claude/cve-triage-skill" >}})
to see what a good entry looks like.
{{< /callout >}}

The recipes elsewhere on this site show you **how** to enable
agentic remediation in each tool. Prompt Forge is where we
collect the actual **prompts, rules, skills, and instruction
files** that are shipping fixes in production today — with a clear split between open community prompts and premium agent-verified packs.

Think of this as a shared cookbook for AI coding agents —
community-driven, versioned, and reviewed.

## Prompt Forge: community + premium

Every prompt lives under the folder for the agent it targets. If a
prompt works the same across two or more agents, it belongs in
[**General**]({{< relref "/prompt-library/general" >}}).

{{< cards >}}
  {{< card link="/prompt-library/claude/" title="Claude" subtitle="`CLAUDE.md`, skills, hooks, slash commands, and Agent SDK prompts." >}}
  {{< card link="/prompt-library/github_copilot/" title="GitHub Copilot" subtitle="`copilot-instructions.md`, issue templates, and Coding Agent task prompts." >}}
  {{< card link="/prompt-library/cursor/" title="Cursor" subtitle="`.cursor/rules/*.mdc`, Background Agent prompts, and chat macros." >}}
  {{< card link="/prompt-library/codex/" title="Codex" subtitle="`AGENTS.md`, task prompts, and shared guideline snippets." >}}
  {{< card link="/prompt-library/devin/" title="Devin" subtitle="Knowledge entries, playbooks, and task prompts." >}}
  {{< card link="/prompt-library/general/" title="General" subtitle="Tool-agnostic triage frameworks, guardrails, review checklists, and PR templates." >}}
{{< /cards >}}

## Free vs Premium in Prompt Forge

| Access | Includes |
| --- | --- |
| **Free (on-site)** | Community prompts, public playbooks, and tool-specific examples. |
| **Premium (via production MCP server)** | Agent-verified premium prompts, curated workflow packs, and premium-only context features. |

## Start with the sample

If you're new here, read
[**CVE triage skill**]({{< relref "/prompt-library/claude/cve-triage-skill" >}})
first. It's a real, production-shaped Claude skill that shows the
expected shape: frontmatter with author / team / maturity, a
"what this does" paragraph, the prompt itself in a code block,
explicit guardrails, and a known-limitations section. Every new
submission should look roughly like that.

## How to use a prompt from this library

Every entry is self-contained — a developer should be able to go
from "opened the page" to "ran it in their tool" without any
other docs. The pattern is the same across every entry:

1. **Read the "What this prompt does" paragraph** at the top. If
   it doesn't match your situation, the prompt is not the right
   one — don't force it.
2. **Check the "When to use it / Don't use it for" sections.**
   These prevent the most common misuses.
3. **Copy the prompt block** into the file the entry names
   (`.claude/skills/<name>/SKILL.md`, `.cursor/rules/<name>.mdc`,
   `AGENTS.md`, a Devin Knowledge entry, a `.github/copilot-instructions.md`).
4. **Fill in anything the Inputs section marks as required.** If
   the Inputs section says "infer from context", leave it alone —
   the prompt is designed not to need it.
5. **Run against one small, recent finding first.** Review the PR
   or triage note the agent produces. Then expand.

## How to adapt a prompt for your repo

A prompt written by another team is a starting point, not a
contract. Safe edits:

- **Change the tone to match your team.** The shape of the
  prompt matters; the prose around it is yours.
- **Tighten the allowlist to your repo's layout.** Filenames,
  branch conventions, and CI commands should match what your
  repo actually uses.
- **Add guardrails — don't remove them.** If a prompt says "do
  not touch `db/migrations/`," that's load-bearing. If you
  remove a guardrail, note *why* in your fork's version history.
- **Keep the stop conditions.** The "when to stop and write a
  triage note" section is what keeps the agent reviewer-friendly
  — deleting it is how you end up with mass edits at 3 a.m.

## Anatomy of a good entry

Every prompt on this site follows the same outline so you can
skim one and know what to expect from the next:

- **Frontmatter** — `title`, `tool`, `author`, `team`, `maturity`,
  `model`, `tags`, `date`.
- **What this prompt does** — one or two paragraphs, in plain
  language. No jargon you can't look up on the
  [Fundamentals]({{< relref "/fundamentals" >}}) page.
- **When to use it / Don't use it for** — the hard edges.
- **Inputs** — what the agent needs to run. If inputs can be
  inferred from session context, the prompt says so.
- **The prompt** — in a fenced code block, ready to copy.
- **Output contract** — what the agent produces (PR, triage note,
  audit report).
- **Guardrails** — concrete constraints that carry into every
  run.
- **See also / Related** — links to companion prompts, recipes,
  or MCP connectors.

If you're writing a new entry, match that outline and a reviewer
will have a much easier time accepting the PR.

## Other prompt libraries worth knowing

The library on this site focuses on agentic remediation
specifically. For a curated list of **external prompt
collections** worth borrowing from — OWASP, the major agent
vendors' published examples, awesome-style community lists, and
the framework-vendor reference prompts — see
[Reputable Prompt Sources]({{< relref "/prompt-library/sources" >}}).

{{< cards >}}
  {{< card link="/prompt-library/sources/" title="Reputable Prompt Sources" subtitle="Curated external libraries: OWASP, vendor docs, community awesome-lists, and reference prompts that pair well with the recipes here." >}}
{{< /cards >}}

## MCP Server access

A great prompt is only half the recipe — the other half is the
**context** the agent can reach while it runs. The more of your
risk-relevant signals (findings, ownership, tickets, runbooks,
build status) are exposed through MCP with the right scopes, the
faster an agent can go from "here's a finding" to "here's a
reviewed PR" without stopping to ask a human for context.

Democratizing that data to agentic workflows — safely, with
scoped tokens, typed interfaces, rate limits, and audit logs —
is what moves risk reduction from "as fast as a human can
triage" to "as fast as the reviewer queue can drain." It's also
how Security stays in control while Engineering ships faster:
every tool call is a scoped, logged, reviewable API call
instead of a screen-scrape or a copy-paste into a chat.

The catalog of data sources we've wired up (and the ones on
deck), plus a template for integrating a new one, lives on the
MCP Server Access page.

{{< cards >}}
  {{< card link="/mcp-servers/" title="Click more to find out →" subtitle="Connector catalog, integration template, and per-agent wiring for Claude, Cursor, Devin, Codex, and Copilot." >}}
{{< /cards >}}

## Agentic Security Remediation on engineering's behalf

Separately from the recipes above, a **security team can operate
its own agentic workflows** to drive down risk without asking
every engineering team to stand up their own. The reference
workflows on this site cover **sensitive data element (SDE)
remediation** and **vulnerable dependency remediation**. The PRs
that come out of these carry an auto-remediation label (the site
uses `sec-auto-remediation` as the illustrative example — rename
to your org's convention).

To understand what the workflows do, what's in scope, how
orchestration decides when to hand work to an agent, and what
the guardrails look like, the full writeup (plus mermaid
diagrams of each flow) lives under
[**Agentic Security Remediation**]({{< relref "/security-remediation" >}}).

{{< cards >}}
  {{< card link="/security-remediation/" title="Click to see more →" subtitle="Reference workflows a security team can run on engineering's behalf, with scope, guardrails, and review policy for each." >}}
{{< /cards >}}

## What belongs here

Any prompt or config that is **working in production** for agentic
remediation is welcome. Good candidates: `copilot-instructions.md`,
`CLAUDE.md`, `.cursor/rules/*.mdc`, `AGENTS.md`, Devin Knowledge
entries, Claude skills, `PreToolUse` / `PostToolUse` hook scripts,
and triage prompts that get pasted into chat when a new CVE lands.

## What doesn't belong here

Secrets, API tokens, internal hostnames, or customer data — scrub
everything before you submit. One-shot prompts you used once and
never again. "Clever" jailbreaks: this library is about
trustworthy, reviewable automation, so if a prompt only works by
evading a guardrail, it doesn't belong.

## Contribute a prompt

The full fork-and-PR workflow, including the frontmatter template
and review expectations, lives on the
[**Contribute**]({{< relref "/contribute#contributing-a-prompt" >}})
page. The short version: fork, add a file under
`content/prompt-library/<tool>/<your-prompt>.md`, open a PR against
`main`, and ping a reviewer from Security plus a reviewer from the
team that will own the prompt.

## See also

- [Docs]({{< relref "/docs" >}}) — what this site is for
- [Agents]({{< relref "/agents" >}}) — per-tool remediation recipes
- [Reputable Prompt Sources]({{< relref "/prompt-library/sources" >}}) — external prompt libraries to mine for ideas
- [Contribute]({{< relref "/contribute" >}}) — how to submit a prompt
