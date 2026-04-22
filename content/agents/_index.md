---
title: Agents
linkTitle: Agents
weight: 2
toc: true
sidebar:
  open: true
description: >
  The five AI coding agents this site supports — GitHub Copilot, Devin,
  Cursor, Codex, and Claude — and how to decide which one to start with.
---

This site treats each AI coding agent as a **separate product with its
own recipe**. The configuration shape, the rules files, the guardrails,
and the failure modes are different enough that one-size-fits-all
guidance is misleading. Pick the agent your team already uses and
follow its page.

{{< callout type="info" >}}
**Already have a licensed tool on your team?** Use that. Migrating
agents for the sake of "the better recipe" is almost always a bad
trade — pick the agent with the shortest path to rolled-out
guardrails, not the flashiest demo.
{{< /callout >}}

## Supported agents

### [GitHub Copilot]({{< relref "/github_copilot" >}})

The Copilot Coding Agent can pick up GitHub Issues, branch, patch, run
CI, and open a PR. Pair it with a repo-level
`.github/copilot-instructions.md` and a narrow issue template and you
have the shortest path to autonomous remediation for teams already on
GitHub Enterprise.

**Best when:** your remediation work already lives in GitHub Issues and
you want to stay inside the PR review loop you have today.

### [Devin]({{< relref "/devin" >}})

Devin is a hosted autonomous engineer. You point it at a task, it
works in its own sandbox, and it reports back. It's the most "end to
end agentic" of the bunch and the one that most rewards **Knowledge
entries** — per-repo runbooks Devin reads on every session.

**Best when:** you want a fully hosted, ticket-in → PR-out loop and
you're willing to invest in Knowledge curation.

### [Cursor]({{< relref "/cursor" >}})

Cursor has both an interactive Agent mode (inside the IDE) and
**Background Agents** (headless, running in the cloud). The Background
Agents are what make Cursor interesting for remediation — paired with
project rules (`.cursor/rules/*.mdc`) they'll chew through a backlog of
findings without a human at the keyboard.

**Best when:** your engineers already live in Cursor for day-to-day
work and you want agentic remediation without adopting another tool.

### [Codex]({{< relref "/codex" >}})

Codex reads `AGENTS.md` on every invocation — a single, focused repo
brief that describes how to build, test, and style changes. Pair it
with a narrow task prompt and a strict guardrails policy and it's an
excellent fit for mechanical, high-volume remediation.

**Best when:** you need the simplest possible recipe and you already
use OpenAI's stack elsewhere.

### [Claude]({{< relref "/claude" >}})

Claude is unusually strong at agentic work because of three things:
`CLAUDE.md` (repo context), **skills** (`.claude/skills/*/SKILL.md` —
reusable procedure files), and **hooks** (`PreToolUse` / `PostToolUse`
shell scripts that enforce guardrails at tool-call time). It's the
most customisable and, when well-configured, the most trustworthy.

**Best when:** you want deep, repo-specific guardrails and you're
willing to invest in skills as a first-class artifact.

## How to pick

A rough decision tree:

1. **Is there already a licensed AI coding agent on your team?**
   → Use it. Read its recipe.
2. **Are most engineers already in a specific IDE?** → Match the agent
   to it (Cursor for Cursor users, Copilot for VS Code / JetBrains with
   GitHub).
3. **Do you need the deepest guardrails?** → Claude's hooks and skills
   are the most mature story.
4. **Do you need fully hosted, ticket-in → PR-out with minimal IDE
   involvement?** → Devin.

You are allowed to run more than one. Most mature programs end up
using 2–3 agents for different classes of work — e.g. Devin for
backlog SCA findings, Claude for sensitive services, Copilot for
quick in-IDE fixes.

## What to read next

- The agent page you picked — read it top-to-bottom, guardrails first.
- **[Prompt Library]({{< relref "/prompt-library" >}})** — working
  instruction files, rules, and skills you can fork into your repo
  instead of writing from scratch.
- **[Docs]({{< relref "/docs" >}})** — site-wide conventions and the
  shape every recipe follows.
