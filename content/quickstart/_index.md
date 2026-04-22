---
title: Quick Start
linkTitle: Quick Start
weight: 2
toc: true
sidebar:
  open: true
description: >
  The easy button — a five-minute path to your first agentic
  remediation PR, with a one-page recipe for each of the five
  tools this site covers.
---

{{< callout type="info" >}}
**If you only have five minutes, read this page.** The longer
per-tool recipes, MCP catalog, and reference workflows are all
optional reading. This page exists so a developer, an AppSec
engineer, or a curious platform lead can go from zero to a
first agentic remediation PR before the end of a coffee break.
{{< /callout >}}

## The minimum viable shape

Every agentic remediation flow on this site, regardless of
which tool drives it, follows the same six-step shape. If
you're short on time, **do these six things, in order, for one
tool**:

1. **Pick one tool.** Claude, GitHub Copilot, Cursor, Codex,
   or Devin. You can add more later — start with one.
2. **Install it.** Follow the three-line install for that tool
   below.
3. **Add one prompt file.** A repo-root instruction file so the
   agent knows your house rules. Templates are on this page.
4. **Wire one MCP connector.** One source of context beyond
   local files — usually your ticket tracker or CVE feed.
   Skippable for a first run.
5. **Pick one recent finding.** A small, recent CVE or SDE
   finding. Don't start with a backlog triage.
6. **Let the agent draft a PR. Review it. Merge or bounce it.**
   That's the full loop.

Everything else on this site — recipes, reference workflows,
reviewer playbooks, compliance mappings — is what you layer on
top once this loop is working.

---

## Pick your tool

{{< cards >}}
  {{< card link="#claude-five-minute-path" title="Claude" subtitle="Claude Code + Agent SDK + MCP. Skills-based remediation, repo-level hooks, and a native GitHub Action." >}}
  {{< card link="#github-copilot-five-minute-path" title="GitHub Copilot" subtitle="Copilot Coding Agent. Issue-to-PR inside GitHub, with `copilot-instructions.md` as the house-rules file." >}}
  {{< card link="#cursor-five-minute-path" title="Cursor" subtitle="Cursor Rules + Background Agents. IDE-native authoring, long-running remediation in the cloud." >}}
  {{< card link="#codex-five-minute-path" title="Codex" subtitle="Codex CLI + `AGENTS.md`. Terminal-first agentic remediation with a growing agent-convention ecosystem." >}}
  {{< card link="#devin-five-minute-path" title="Devin" subtitle="Devin API + playbooks + knowledge. Managed remote sessions with structured runbooks." >}}
{{< /cards >}}

---

## Claude — five-minute path {#claude-five-minute-path}

**Install.**

```bash
# macOS / Linux
curl -fsSL https://code.claude.com/install | bash
# then, inside any repo:
claude
```

(Windows and detailed setup:
[Claude Code install docs](https://code.claude.com/docs/en/overview).)

**Create a `CLAUDE.md` at the repo root** with this starter:

```markdown
# Repository rules for Claude

- When asked to remediate a security finding, open a PR with
  one fix per PR. Do not batch unrelated changes.
- Always run the existing test suite before opening a PR.
- Do not modify files under `db/migrations/`,
  `.github/workflows/`, or `infra/prod/` without a linked
  approved design document.
- Stop and write a `TRIAGE.md` note if the fix requires a
  schema change, a breaking API change, or cross-service
  coordination.
```

**First remediation.** In the repo, run:

```
claude "Fix CVE-XXXX-YYYY in our dependencies.
Follow the rules in CLAUDE.md. Open a PR."
```

(Replace `CVE-XXXX-YYYY` with a real finding.)

**What you get.** A branch + PR with the fix, a test run, and
a PR body explaining what Claude changed and why. Review it
the way you'd review a human PR.

**Graduate to the full recipe when ready:**
[Claude recipe →]({{< relref "/claude" >}})

---

## GitHub Copilot — five-minute path {#github-copilot-five-minute-path}

**Install.** Nothing to install locally. Ensure your GitHub
plan includes **Copilot Coding Agent** (Enterprise or Business
with Coding Agent enabled — see the
[Copilot plans page](https://github.com/features/copilot)).

**Create `.github/copilot-instructions.md`** with this starter:

```markdown
# Instructions for the Copilot Coding Agent

You are remediating security findings in this repository.

Rules:
- One finding per PR. Use the branch name `fix/<cve-or-finding-id>`.
- Run `npm test` (or the project's equivalent) before opening the PR.
- Never edit `db/migrations/*`, `.github/workflows/*`, or
  `infra/prod/*`.
- If you cannot fix cleanly, leave a comment on the issue
  explaining why and stop. Do not open a partial PR.
```

**First remediation.** Open an issue in the repo describing
the finding:

```
Title: Remediate CVE-XXXX-YYYY in lodash

Body:
Bump lodash past the vulnerable range declared in CVE-XXXX-YYYY.
Run the test suite. Open a PR. See `.github/copilot-instructions.md`
for house rules.
```

Then **assign the issue to `@copilot`** (the Copilot Coding
Agent). A PR appears shortly after.

**What you get.** A PR authored by the coding agent, linked
back to the issue.

**Graduate to the full recipe when ready:**
[GitHub Copilot recipe →]({{< relref "/github_copilot" >}})

---

## Cursor — five-minute path {#cursor-five-minute-path}

**Install.** Download **Cursor** from
[cursor.com](https://www.cursor.com/) and sign in. Cursor is a
drop-in VS Code replacement; open your repo folder in it.

**Create `.cursor/rules/security-remediation.mdc`** with this
starter:

```markdown
---
description: "Rules for agentic security remediation"
globs: ["**/*"]
alwaysApply: true
---

# Security remediation rules

- One finding → one PR. Do not batch unrelated changes.
- Always run the test suite before proposing a diff.
- Do not modify `db/migrations/`, `.github/workflows/`, or
  `infra/prod/` without a linked approved design doc.
- If the fix requires a schema or API-contract change, stop
  and surface a triage note instead of editing.
```

**First remediation.** Open the Cursor chat (⌘L / Ctrl-L) and
paste:

```
Remediate the finding described in `triage/current.md`.
Follow `.cursor/rules/security-remediation.mdc`.
Produce a diff and run the tests.
```

For longer-running remediation across multiple files or hours,
use **Cursor Background Agents** (`Cursor → Background Agents
→ New`) with the same prompt.

**Graduate to the full recipe when ready:**
[Cursor recipe →]({{< relref "/cursor" >}})

---

## Codex — five-minute path {#codex-five-minute-path}

**Install.** Install the Codex CLI from OpenAI's
[Codex docs](https://platform.openai.com/docs/codex):

```bash
npm install -g @openai/codex
codex login
```

**Create an `AGENTS.md` at the repo root** with this starter:

```markdown
# Agents working in this repository

Scope: agentic security remediation.

Rules:
- One finding per PR. Branch name: `fix/<cve-or-finding-id>`.
- Before proposing changes, read CLAUDE.md / README.md for
  project-specific rules (they take precedence over this file
  when they conflict).
- Run `make test` (or project equivalent) before proposing a
  diff.
- Do not edit `db/migrations/`, `.github/workflows/`, or
  `infra/prod/`.
- If blocked, stop and write a structured triage note. Don't
  push a partial fix.
```

**First remediation.** From inside the repo:

```bash
codex "Remediate CVE-XXXX-YYYY. Follow AGENTS.md. Open a PR."
```

**Graduate to the full recipe when ready:**
[Codex recipe →]({{< relref "/codex" >}})

---

## Devin — five-minute path {#devin-five-minute-path}

**Install.** Nothing to install. Sign in at
[app.devin.ai](https://app.devin.ai) with a seat on a plan
that includes API / session access.

**Create a Knowledge entry** (Devin → Knowledge → New) titled
`security-remediation-rules` with:

```
One finding per PR. Branch: fix/<cve-or-finding-id>.
Run tests before committing.
Do not edit db/migrations/, .github/workflows/, or infra/prod/.
If blocked, stop and summarize the block in the session log.
```

**First remediation.** Create a Devin session with a task
prompt like:

```
Task: Remediate CVE-XXXX-YYYY in the `lodash` dependency.

Repo: <your repo>
Branch: fix/CVE-XXXX-YYYY

Follow the Knowledge entry `security-remediation-rules`.
Run the test suite. Open a PR back to `main`.
```

**Graduate to the full recipe when ready:**
[Devin recipe →]({{< relref "/devin" >}})

---

## Common pitfalls on the first run

These are the mistakes almost everyone makes on their first
attempt. Saving you the scars:

- **Starting with a 6-month-old finding.** The agent needs
  recent context; start with a finding from the last week.
- **Pointing at a repo without tests.** No tests = no signal
  on whether the fix works. Pick a repo with a passing suite.
- **Skipping the house-rules file.** Without an instruction
  file, the agent picks up default behaviour and you get
  inconsistent PRs. The five-line starter above is enough.
- **Letting the agent touch migrations, workflows, or prod
  infra on the first run.** Hard-block these in your rules
  file from day one. Loosen later if you need to.
- **Reviewing the PR as "did it do what I asked?" instead of
  "would I merge this from a coworker?"** The second question
  is the real test.

## After your first PR — what's next

Once the loop above is working end-to-end, layer in the
additional pieces in roughly this order:

1. **Add one MCP connector** so the agent can read your ticket
   tracker or CVE feed directly. See
   [MCP Servers]({{< relref "/mcp-servers" >}}).
2. **Harden the house-rules file.** Fork a prompt from the
   [Prompt Library]({{< relref "/prompt-library" >}}) or
   [reputable external sources]({{< relref
   "/prompt-library/sources" >}}).
3. **Enable deterministic automation** alongside the agent —
   Dependabot, Gitleaks, Earlybird, Trivy. See
   [Automation]({{< relref "/automation" >}}).
4. **Pick a reference workflow** — SDE remediation or
   vulnerable-dependency remediation — and pilot it. See
   [Security Remediation]({{< relref "/security-remediation" >}}).
5. **Read the reviewer playbook** so the humans on the other
   side of the PR are consistent. See
   [Reviewer Playbook]({{< relref
   "/security-remediation/reviewer-playbook" >}}).

## When to stop and re-plan

If after three runs the agent's PRs are consistently bounced,
stop and do one of these:

- **Tighten your house-rules file.** Most bounced PRs come
  from under-specified rules, not a bad model.
- **Shrink the scope.** Point the agent at a narrower
  problem (one file, one dependency) until the loop is clean.
- **Read the full per-tool recipe.** The five-minute path is
  deliberately minimal; the full recipe has the nuance you
  may be missing.

## See also

- [Agents]({{< relref "/agents" >}}) — full per-tool recipes
- [Fundamentals]({{< relref "/fundamentals" >}}) — primer on
  agents, prompts, and MCP
- [Prompt Library]({{< relref "/prompt-library" >}}) — starter
  prompts you can fork
- [Prompt Sources]({{< relref "/prompt-library/sources" >}}) —
  external libraries of pre-engineered prompts
- [Automation]({{< relref "/automation" >}}) — deterministic
  tools that pair with any agent
