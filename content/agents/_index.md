---
title: AI Coding Agents for Vulnerability Remediation
linkTitle: AI Agent Comparison
page_kind: collection
weight: 3
lastmod: 2026-08-21
toc: true
sidebar:
  open: true
description: >
  Compare Codex, Claude Code, Cursor, Copilot, Devin, Shiba Studio, Hermes,
  and OpenClaw for AI vulnerability remediation with bounded instructions
  and review gates.
---

Use this page to choose a governed agent that matches your finding source,
execution environment, and review path, then configure its native instruction
surface. This is a workflow-fit comparison for AI agents remediating traditional
software and repository vulnerabilities, not a model-quality benchmark or a
guide to vulnerabilities in AI systems. If the system under review is the
agent itself, including its tools, identities, memory, retrieved context,
browser, MCP or A2A connections, and incident controls, use
[AI Agent Security]({{< relref "/agentic-security" >}}). For integration
architecture that delivers recipes, finding evidence, and policy to an
existing agent, use
[AI agent security-context integration]({{< relref "/docs/agent-integration" >}}).
For the end-to-end method, return to
[AI vulnerability remediation playbooks]({{< relref "/security-remediation" >}}).

**Last updated August 21, 2026.** Capabilities and documentation were verified
against the linked primary sources. Rechecked August 23, 2026 against the
same official pages.
[Stephen M Abbott](/about/#stephen-m-abbott) maintains this workflow-fit
comparison with Security Recipes contributors in the public
[source and revision history](https://github.com/stevologic/security-recipes.ai/blob/main/content/agents/_index.md).
See the
[review methodology](/about/#editorial-principles) and
[corrections policy](/about/#corrections).

Start with the agent your team already uses. The remediation pattern works
across tools as long as the agent gets three things:

- A local rule file or knowledge entry.
- The specific security recipe for the finding.
- Only the context needed to produce a PR or triage note.

{{< callout type="info" >}}
**Do not switch agents just for a recipe.** The best first agent is usually the
one already connected to your repos, approvals, and review habits.
{{< /callout >}}

## Supported agents

{{< cards >}}
  {{< card link="/github_copilot/" title="GitHub Copilot" subtitle="Use repository instructions, narrow issues, code-scanning alerts, and the GitHub Copilot cloud agent." >}}
  {{< card link="/claude/" title="Claude Code" subtitle="Use `CLAUDE.md`, rules, skills, hooks, and Claude Security for repository analysis and separately reviewed patches." >}}
  {{< card link="/cursor/" title="Cursor" subtitle="Use Cursor Rules, local agents, Cloud Agents, dependency automation, and Security Review where available." >}}
  {{< card link="/codex/" title="Codex" subtitle="Use `AGENTS.md`, skills, and bounded tasks across the app, IDE, terminal, cloud, CI, and Codex Security." >}}
  {{< card link="/devin/" title="Devin" subtitle="Use Knowledge, Playbooks, and repository `.agents/skills/your-skill/SKILL.md` files for hosted alert-or-ticket-to-PR workflows." >}}
  {{< card link="#shiba-studio" title="Shiba Studio" subtitle="Use per-agent instructions, integration scopes, skills, and MCP servers on local worktree-bound agents powered by Grok/xAI." >}}
  {{< card link="#hermes-desktop" title="Hermes Desktop" subtitle="Use skills and sandboxed execution backends (local, Docker, SSH, Modal) with Nous Research's self-improving open-source agent." >}}
  {{< card link="#openclaw" title="OpenClaw" subtitle="Use workspace `AGENTS.md` operating rules and `SOUL.md` boundaries with a local Gateway and a bring-your-own model." >}}
{{< /cards >}}

## Compare supported remediation workflows

The table describes documented workflow surfaces, not which model is “best.”
Instruction files guide an agent; sandboxing, permissions, branch protection,
required CI, and human approval provide the enforceable boundary.

| Agent | Documented security work | Operating mode | Native repository instructions | Expected artifact and gate |
| --- | --- | --- | --- | --- |
| [Codex](/codex/) | Accepted repository findings, source and dependency fixes, security review, and verification | App, IDE, terminal, CI, or isolated cloud task | `AGENTS.md`, task prompt, Skills, plugins | Focused diff, tests, verification, branch or PR; local approvals and cloud isolation precede normal review and release gates |
| [Claude Code](/claude/) | Full-repository, branch, commit, and PR-diff security analysis with separately selected fixes | Local terminal, IDE, GitHub Actions, or managed Claude Security | `CLAUDE.md`, `.claude/rules/`, Skills, settings, hooks | Markdown/JSONL findings or a separate patch; Claude Security never applies a proposed patch automatically |
| [Cursor](/cursor/) | General repository fixes, dependency-vulnerability automation, and Security Review where licensed | IDE, CLI, autonomous Cloud Agents, or scheduled review | `.cursor/rules/*.mdc`, nested `AGENTS.md`, user or team rules | Local diff/worktree or cloud PR with run artifacts; protect the branch and require review and CI |
| [GitHub Copilot](/github_copilot/) | Issue-to-PR work and eligible code-scanning campaign alerts | GitHub Copilot cloud agent in an ephemeral Actions-powered environment | `.github/copilot-instructions.md`, path-specific instructions, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, organization instructions | One task branch and PR; required reviews still apply and the requester's approval does not replace them |
| [Devin](/devin/) | Dependabot, static-analysis, ticket, and CI-driven repository remediation | Hosted asynchronous workspace connected to source control and CI | Knowledge, Playbooks, repository `.agents/skills/<skill-name>/SKILL.md`, task prompt | Tested PR and CI evidence; existing branch protection, review, and SDLC controls remain authoritative |
| [Shiba Studio](#shiba-studio) | Bounded repository fixes through local agents and automations with per-agent integration scopes | Local web studio; agents work in their own git worktrees, powered exclusively by Grok/xAI | Per-agent instructions, skills, MCP servers | Branch or PR from an isolated worktree with a local audit trail; branch protection, review, and required CI stay authoritative |
| [Hermes Desktop](#hermes-desktop) | General agent able to take bounded repository tasks in sandboxed backends | Desktop app or self-hosted gateway; local, Docker, SSH, Singularity, or Modal execution | Skills ([open standard](https://agentskills.io)), agent-curated memory, task prompt | Reviewable diff or PR from a sandboxed run; scoped credentials, human review, and CI remain the enforceable gate |
| [OpenClaw](#openclaw) | Personal-assistant Gateway able to drive bounded repository work under workspace rules | Local Gateway daemon reachable from approved messaging channels | Workspace `AGENTS.md` and `SOUL.md`, workspace skills, `MEMORY.md` | Reviewable change from a scoped workspace; treat channel input as untrusted and keep review and CI authoritative |

### Codex

Codex supports local and cloud repository work, while Codex Security provides
dedicated finding discovery, validation, triage, and fix workflows. Cloud agent
tasks run in isolated environments and start with network access disabled during
the agent phase unless the environment is configured otherwise. The security
plugin and cloud environment require separate setup. Official
[Codex Security cloud setup](https://learn.chatgpt.com/docs/security/setup)
now documents a scan-to-PR path for connected GitHub repositories. Plugin
docs recommend `gpt-5.6-sol` with `xhigh` reasoning for scan quality; do
not pin that model name in prompts. Read the official documentation for
[fixing accepted findings](https://learn.chatgpt.com/docs/security/plugin/fix-findings),
[`AGENTS.md`](https://learn.chatgpt.com/docs/agent-configuration/agents-md),
[cloud environments](https://learn.chatgpt.com/docs/environments/cloud-environment),
and [approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security).

### Claude Code

The [Claude Security plugin](https://code.claude.com/docs/en/claude-security)
for Claude Code (`/plugin install claude-security@claude-plugins-official`,
Claude Code v2.1.154+) still runs `/claude-security` scans and writes
timestamped Markdown and JSONL findings. Suggested patches land in the
report folder; Anthropic's docs still state they are never applied
automatically. The managed
[Claude Security](https://claude.com/product/claude-security) product is
still a separate Enterprise public beta that scans on Claude Mythos 5.
Full plugin scans need Python 3.9.6+ and Git, may consume substantial
time or usage, and can miss findings; keep an independent review and test
gate. See
[Claude Security plugin](https://code.claude.com/docs/en/claude-security),
[managed Claude Security](https://claude.com/product/claude-security),
[security guidance](https://code.claude.com/docs/en/security-guidance),
[memory and instructions](https://code.claude.com/docs/en/memory), and
[permissions](https://code.claude.com/docs/en/permissions).

### Cursor

Cursor supports local repository work and autonomous Cloud Agents that return
reviewable changes. Its documented automations include dependency-vulnerability
remediation; Security Agents add PR and scheduled scanning on Cloud Agents
billed from the team usage pool. Current Security Agents docs no longer
label that feature beta. Agent rules are guidance, not a standalone
security boundary. See the official
[Rules documentation](https://cursor.com/docs/rules),
[CLI modes and approvals](https://cursor.com/docs/cli/using),
[Cloud Agents](https://cursor.com/changelog/cloud-in-agents-window),
[Security Agents Automations](https://cursor.com/automations/from-cursor/security),
and [Security Review](https://cursor.com/changelog/04-30-26).

### GitHub Copilot cloud agent

GitHub's current product name is the **GitHub Copilot cloud agent**. It can turn
a bounded issue into a branch and pull request, and eligible security campaigns
can ask it to address code-scanning alerts. Paid Copilot, repository and
organization policy, and the required GitHub security products apply; campaign
remediation is a public preview. Human review remains a real gate, including
when the requester is also a required reviewer. See the official documentation
for the [cloud agent](https://docs.github.com/en/copilot/concepts/agents/cloud-agent/about-cloud-agent),
[security-campaign remediation](https://docs.github.com/en/code-security/how-tos/manage-security-alerts/remediate-alerts-at-scale/fixing-alerts-in-security-campaign),
[custom-instruction support](https://docs.github.com/en/copilot/reference/custom-instructions-support),
and [review controls](https://docs.github.com/en/copilot/how-tos/copilot-on-github/use-copilot-agents/review-copilot-output).

### Devin

Devin documents hosted remediation flows for dependency alerts and static
analysis from tools such as SonarQube, Fortify, and Veracode. Knowledge,
Playbooks, and one active repository-scoped Skill guide a session; source
control, environment, and CI integration provide its working surface. Review
the integration permissions carefully because GitHub organization setup is an
administrative operation with broad repository access. See Devin's official
[SDLC integration](https://docs.devin.ai/essential-guidelines/sdlc-integration),
[Skills](https://docs.devin.ai/product-guides/skills),
[Knowledge](https://docs.devin.ai/product-guides/knowledge), and
[GitHub integration](https://docs.devin.ai/integrations/gh).

### Shiba Studio

[Shiba Studio](https://shiba-studio.io) is a local agent studio that routes
all intelligence through Grok/xAI. It is built by this site's maintainer, so
read this section as first-party documentation rather than an independent
review. Agents are autonomous workers with their own model, workspace,
git worktree, integration scopes, and skills; Automations own scheduling and
triggers; runs and approvals land in a local, auditable store, and MCP
servers plus built-in tools provide read-only context.

Set up a bounded remediation agent:

1. Install and start the studio (Node.js ≥ 22.5 and Git required):

   ```bash
   git clone https://github.com/stevologic/shiba-studio.git
   cd shiba-studio
   npm install
   npm run dev
   ```

   Then open `http://localhost:3000` and follow the dashboard's first-run
   checklist.
2. Connect a model source in **Settings** — an xAI API key, OAuth with X, the
   local Grok CLI, or an OpenAI-compatible local server.
3. Create an **Agent**, bind it to the repository workspace so it edits in
   its own git worktree, and grant only the integration scopes the finding
   needs (for example GitHub, but not social posting).
4. Put the remediation rules, stop conditions, and the matching
   [security recipe](/recipes/) link in the agent's instructions and skills.
5. Add read-only MCP context only when the finding needs it, run one
   low-risk finding, and review the PR before promoting the pattern to an
   Automation.

See the official
[getting started guide](https://github.com/stevologic/shiba-studio/blob/main/docs/getting-started.md)
and [repository documentation](https://github.com/stevologic/shiba-studio).

### Hermes Desktop

[Hermes Agent](https://hermes-agent.nousresearch.com/) is Nous Research's
MIT-licensed, self-improving agent; Hermes Desktop packages it for Windows,
macOS, and Linux as a public preview. It plans tasks in natural language,
executes in sandboxed backends (local, Docker, SSH, Singularity, or Modal),
writes and reuses skills compatible with the
[agentskills.io](https://agentskills.io) standard, and keeps agent-curated
memory across sessions. Providers include Nous Portal, OpenRouter, OpenAI,
or your own endpoint. For remediation work, pin the model and provider, put
repository rules and stop conditions in a dedicated skill, run edits in the
Docker backend with scoped credentials, and review self-created skills like
code before trusting them with security work — the learning loop is a
capability, not a control. See the official
[documentation](https://hermes-agent.nousresearch.com/docs/) and
[repository](https://github.com/NousResearch/hermes-agent).

### OpenClaw

[OpenClaw](https://openclaw.ai) is an MIT-licensed personal AI assistant
with a local Gateway, a bring-your-own-model design, and workspace
instruction files that load every session: operating rules in `AGENTS.md`,
persona and boundaries in `SOUL.md`, optional durable facts in `MEMORY.md`,
plus workspace-scoped skills. Install with the platform installer (`curl`/`iwr` from openclaw.ai, or
Docker/Nix/npm). The installer starts the onboarding wizard; later
configuration is `openclaw configure`. Confirm the Gateway with
`openclaw gateway status` (port 18789) and `openclaw dashboard`. Because
the Gateway can be reached from many messaging channels,
scope a remediation agent to a dedicated workspace, keep repository rules
and stop conditions in `AGENTS.md`, restrict tokens to the repositories in
scope, and treat inbound channel messages as untrusted input rather than
instructions. See the official
[getting started guide](https://docs.openclaw.ai/start/getting-started) and
[agent workspace documentation](https://docs.openclaw.ai/concepts/agent-workspace).

## Common setup pattern

Every agent page follows this shape:

1. Create or update the agent's native instruction file.
2. Add the remediation rules and stop conditions.
3. Link or vendor the relevant [security-recipes.ai recipe](/recipes/).
4. Add read-only MCP context only when the finding needs it.
5. Run one low-risk finding and inspect the PR or triage note.
6. Promote the pattern only after reviewers trust the output.

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

## Evaluate an agent before broader rollout

Do not count generated pull requests as successful remediation. Run the same
small, representative finding set through the agent and record:

- **True closure:** the original scan, protected regression, or safe reproducer
  no longer reports the finding.
- **Regression health:** focused and existing tests pass without disabling or
  weakening the security signal.
- **Diff quality:** the change is minimal, reviewable, and tied to an
  authoritative advisory, release, or safe coding pattern.
- **Reproducibility:** another reviewer can rerun the commands and recover the
  same resolved versions, test result, and source trail.
- **Reviewer burden:** rework, rejection, and false-dismissal rates are tracked,
  not hidden behind raw PR volume.
- **Boundary behavior:** the agent stops when ownership, fixed versions, tests,
  credentials, or production authority are missing.
- **Recovery evidence:** rollback and residual risk are explicit before merge.
- **Operating cost:** elapsed time and usage are measured against manual triage
  for the same finding class.

Common failure modes include a plausible but incorrect root cause, an incomplete
patch that leaves another vulnerable path, a breaking upgrade presented as a
routine bump, iterative drift into unrelated files, false dismissal of a real
finding, and confident output where no protected test exists. Preserve the
original signal, constrain one finding per run, and treat “cannot prove it” as
a valid triage result.

## See also

- [Quick Start]({{< relref "/quickstart" >}})
- [AI Agent Security]({{< relref "/agentic-security" >}})
- [Recipes]({{< relref "/recipes" >}})
- [MCP Integration]({{< relref "/mcp-servers" >}})
- [Integrate an AI Agent]({{< relref "/docs/agent-integration" >}})
