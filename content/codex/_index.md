---
title: Codex Vulnerability Remediation
linkTitle: Codex
weight: 4
date: 2026-04-21
lastmod: 2026-07-21
description: Use OpenAI Codex CLI and cloud agents to remediate vulnerabilities in isolated workspaces with scoped instructions, tests, rollback, and reviewed pull requests.
sidebar:
  open: true
---

{{< callout type="info" >}}
**Outcome.** A nightly Codex job pulls the open remediation backlog,
attempts each fix in an isolated sandbox, and posts PRs with detailed
remediation notes.
{{< /callout >}}

{{< callout type="warning" >}}
**In a hurry?** The
[**Quick Start**]({{< relref "/quickstart#the-loop" >}})
is a five-minute path to your first agentic remediation PR with
Codex. Come back here for the full recipe once that loop is working.
{{< /callout >}}

OpenAI's Codex (CLI + cloud agent) is purpose-built for sandboxed,
repo-aware tasks — a strong fit for **batch** remediation jobs. The
recipe is: a small driver script, a standing `AGENTS.md`, and a
per-task prompt template. Codex handles the rest inside its sandbox.

Use the [shared AI remediation guide]({{< relref "/security-remediation/" >}})
to define scope, rollback, evidence, and human approval before adapting the
workflow to Codex below.

Use the [Codex vulnerable-dependency recipe]({{< relref "/recipes/codex/vulnerable-dep-remediation" >}})
when the finding is a CVE, Dependabot alert, or other package advisory.
For a detected secret or PII leak, use the
[Codex sensitive-data remediation recipe]({{< relref "/recipes/codex/sensitive-data-remediation" >}}).

## Remediate a vulnerability with Codex

Install the [Codex Security plugin](https://learn.chatgpt.com/docs/security/plugin)
in the Codex app or CLI, then start a new chat for the repository.

1. For an existing CVE, GHSA, SARIF result, or scanner ticket, run
   `$codex-security:triage-finding`. Treat its verdict as evidence to
   review, not permission to change code. See the
   [triage workflow](https://learn.chatgpt.com/docs/security/plugin/triage-backlog).
2. After a person accepts one finding, run
   `$codex-security:fix-finding` with the finding ID and source report.
   Require the smallest safe patch, focused regression coverage, and
   verification that the issue no longer reproduces. See the
   [fix workflow](https://learn.chatgpt.com/docs/security/plugin/fix-findings).
3. Review the proposed diff before applying it. Run the repository's
   tests and the original reproducer, record remaining proof gaps, and
   merge only through the normal code-review process.

Use `$codex-security:security-scan` when the task is vulnerability
discovery rather than remediation of a known finding. Connected GitHub
repositories can use [Codex Security cloud](https://learn.chatgpt.com/docs/security/setup)
for the same finding-to-patch workflow with an editable threat model.

## Prerequisites

- Codex app or CLI access with the Codex Security plugin, or Codex Security cloud access
- One source finding with enough evidence to reproduce or validate it
- A repository checkout or connected GitHub repository with its normal tests available
- Human approval before applying a patch or merging a pull request

## General onboarding

The public path — what any individual or team can do today using
OpenAI's documented Codex CLI flow.

1. **Get an OpenAI account.** Sign up at
   [platform.openai.com](https://platform.openai.com/) or
   sign in with ChatGPT. An active eligible plan (or API credit) is
   required. See
   [OpenAI API pricing](https://openai.com/api/pricing).
2. **Install the Codex CLI.** See the section below or OpenAI's
   [quickstart](https://developers.openai.com/codex/quickstart).
3. **Authenticate.** Use OAuth (`codex login`), device-code
   flow (`codex login --device-auth`), or an API key. See
   [authentication](https://developers.openai.com/codex/auth).
4. **Configure the repo.** Add `AGENTS.md` at the repo root for
   house rules and a `.codex/config.toml` for per-repo tooling
   preferences. See
   [Codex config reference](https://developers.openai.com/codex/config-basic).
5. **Run non-interactively** with `codex exec --sandbox workspace-write
   --json` for CI / scheduled workflows. See
   [non-interactive mode](https://developers.openai.com/codex/noninteractive).
6. **Pick the right model.** Choose a currently supported model and
   reasoning level for the task; the
   [models page](https://developers.openai.com/codex/models)
   is the source of truth.
7. **Review enterprise privacy + trust.** See
   [OpenAI enterprise privacy](https://openai.com/enterprise-privacy)
   and
   [trust.openai.com](https://trust.openai.com).

**Vendor-side reference index:**

- [Codex CLI docs](https://developers.openai.com/codex/cli)
- [Codex quickstart](https://developers.openai.com/codex/quickstart)
- [Authentication](https://developers.openai.com/codex/auth)
- [CLI command reference](https://developers.openai.com/codex/cli/reference)
- [Non-interactive mode (`codex exec`)](https://developers.openai.com/codex/noninteractive)
- [Models](https://developers.openai.com/codex/models)
- [Config reference](https://developers.openai.com/codex/config-basic)
- [OpenAI enterprise privacy](https://openai.com/enterprise-privacy)
- [OpenAI API pricing](https://openai.com/api/pricing/)
- [OpenAI trust & compliance](https://trust.openai.com)

## Enterprise onboarding

{{< callout type="warning" >}}
**Enterprise access is organization-specific.** Before using Codex on
company code, confirm the approved OpenAI account, identity and
data-handling controls, execution or sandbox policy, network egress, and
exact repository scope with your security and platform owners. The
checklist below defines the decisions to record; feature names and
availability vary by plan.
{{< /callout >}}

1. **Request access.** File an IT ticket through your organization's
   approved service catalog for Codex access on the enterprise account.
2. **Enable the approved surface.** Give the team access to the
   Codex Security plugin or cloud repository connection. For separate
   headless CLI automation, use the authentication method approved by
   your platform team.
3. **Bind to corporate SSO.** Enterprise OpenAI accounts support
   SSO — bind the account to your identity provider per the
   standard IT guide.
4. **Approve the hosted endpoint.** Get the OpenAI API added to
   your egress allowlist for the CI runner that will execute the
   Codex driver through the normal network-change process.
5. **Complete internal training.** Read the internal rules of
   engagement for hosted-LLM use on production repos, and confirm
   the data-handling classification for anything you send to the
   API under your organization's AI usage policy.

## Install the Codex CLI

Requires Node.js 18+. See the official
[install / quickstart](https://developers.openai.com/codex/quickstart)
for the authoritative steps.

{{< tabs >}}
  {{< tab name="npm (all platforms)" >}}
```bash
npm i -g @openai/codex
```
  {{< /tab >}}
  {{< tab name="Homebrew (macOS)" >}}
```bash
brew install --cask codex
```
  {{< /tab >}}
  {{< tab name="Linux" >}}
```bash
npm i -g @openai/codex
```
  {{< /tab >}}
  {{< tab name="Windows (WSL)" >}}
```bash
# Inside WSL2 Ubuntu
npm i -g @openai/codex
```
  {{< /tab >}}
{{< /tabs >}}

Authenticate with `codex login`:

- **ChatGPT OAuth (default):** `codex login` opens a browser — works for
  ChatGPT Plus / Pro / Business / Enterprise plans.
- **Device code (headless):** `codex login --device-auth` prints a code
  to pair from another device.
- **API key (CI):** `printenv OPENAI_API_KEY | codex login --with-api-key`.

Confirm with `codex --version`. For CI runs, set `OPENAI_API_KEY` as a
secret; for ChatGPT-plan auth in CI, pre-bake the auth token into the
runner image. See [authentication](https://developers.openai.com/codex/auth)
for the full matrix.

## Recipe steps

### 1. Commit `AGENTS.md` at the repo root

`AGENTS.md` is Codex's session-level system prompt. Treat it like a
contributing guide written for a new engineer who needs to be
productive in 10 minutes.

```markdown
# AGENTS.md

## Project
Payments service. Node.js 20, TypeScript, Fastify, Postgres.
Monorepo managed by pnpm workspaces (`packages/*`).

## Setup
- Install: `pnpm install --frozen-lockfile`
- Build:   `pnpm -r build`
- Test:    `pnpm -r test`
- Lint:    `pnpm -r lint`

## Conventions
- TypeScript, strict mode. No `any` without a comment explaining why.
- Errors: never swallow; wrap with context.
- Tests: Vitest. Put unit tests next to code; integration tests in
  `test/integration/`.

## Remediation rules
- Branch: `fix/<finding-id>` (e.g. `fix/CVE-2026-1234`).
- PR title: `fix: <one-line summary>`.
- PR body: must link the finding ID and note blast radius.

## Out of scope
Do not modify (without explicit instruction):
- `db/migrations/**`
- `infra/terraform/**`
- `**/*.generated.ts`
- `pnpm-lock.yaml` unless the task is an explicit dep bump.

## Stop conditions
Stop and ask a human before:
- changing a public API signature,
- changing a DB column or constraint,
- disabling or skipping any test,
- upgrading across a major version.
```

### 2. Write a driver script

The driver reads findings off a queue, fills a prompt template, and
invokes Codex with workspace-write sandboxing. Keep it small — this
is the piece you rely on for years.

```bash
#!/usr/bin/env bash
# scripts/remediate.sh
# Uses `codex exec` (the non-interactive subcommand) with
# --sandbox workspace-write so the agent can read, edit, and run
# commands inside the workspace sandbox. See:
# https://developers.openai.com/codex/noninteractive
set -euo pipefail

QUEUE="${1:?usage: remediate.sh <queue-file>}"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

while IFS= read -r finding_id; do
  echo "→ remediating $finding_id"

  # Fresh clone per finding, so branches never cross-contaminate.
  git clone --depth 1 "$REPO_URL" "$WORKDIR/$finding_id"
  pushd "$WORKDIR/$finding_id" >/dev/null

  # Fill the per-task prompt (envsubst only substitutes listed vars).
  export FINDING_ID="$finding_id"
  PROMPT=$(envsubst '$FINDING_ID' < ../../prompts/remediate.tmpl.md)

  # Invoke Codex non-interactively with a hard wall-clock cap.
  # --sandbox workspace-write is the current non-interactive sandbox flag.
  # --json streams structured events to stdout for replay/audit.
  timeout 20m codex exec \
      --sandbox workspace-write \
      --json \
      "$PROMPT" \
      > "../../logs/$finding_id.jsonl" \
    || { echo "✗ $finding_id: codex failed"; popd; continue; }

  # Open the PR (Codex pushed the branch; we add the tracking metadata).
  gh pr create \
    --title "fix: remediate $finding_id" \
    --body "Closes $finding_id. Session log: logs/$finding_id.jsonl" \
    --base main \
    --head "fix/$finding_id" \
    --draft

  popd >/dev/null
done < "$QUEUE"
```

{{< callout type="info" >}}
**`codex exec` vs interactive `codex`.** `codex exec` is the
non-interactive subcommand designed for scripts and CI — it streams
output to stdout (or JSONL with `--json`) and exits when the task is
complete. Interactive `codex` opens the TUI and is not suitable for
headless runs. See the [command reference](https://developers.openai.com/codex/cli/reference)
for every flag.
{{< /callout >}}

### 3. Define a per-task prompt template

Keep task-specific wording out of `AGENTS.md` — put it in a
template the driver fills in per finding.

```markdown
<!-- prompts/remediate.tmpl.md -->
You are remediating a security finding.

Finding ID: $FINDING_ID

Steps:
1. Look up $FINDING_ID in the advisory database via the
   `advisory` CLI tool available in the sandbox.
2. Identify the affected package and fixed version.
3. Branch: `fix/$FINDING_ID`.
4. Apply the minimum change that closes the finding.
5. Run `pnpm -r lint --fix && pnpm -r test`.
6. If tests pass, commit and push the branch. If not, stop and
   write a summary to `REMEDIATION_NOTES.md` explaining what you
   tried and why it did not work.

Do not touch files outside the scope declared in AGENTS.md.
Do not disable tests.
```

### 4. Run in a sandbox

`codex exec --sandbox workspace-write` grants write access inside the
workspace. **Never** run broad remediation jobs on a developer laptop
or a shared runner with production credentials. The driver above spawns
fresh clones; run the whole thing inside a Docker container:

```dockerfile
# ci/codex-sandbox.Dockerfile
FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl jq gettext-base ca-certificates \
      python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @openai/codex pnpm gh

WORKDIR /workspace
COPY scripts/ ./scripts/
COPY prompts/ ./prompts/

ENTRYPOINT ["/workspace/scripts/remediate.sh"]
```

### 5. Run it from CI on a schedule (and wire it to tickets)

The driver can be triggered by whatever surface your findings arrive
on. Pick one — they all use the same Docker sandbox + queue.txt
contract.

{{< tabs >}}
  {{< tab name="Nightly schedule" >}}
```yaml
# .github/workflows/codex-remediate.yml
name: Nightly Codex remediation
on:
  schedule:
    - cron: "0 3 * * *"   # 03:00 UTC nightly
  workflow_dispatch:

jobs:
  remediate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - name: Build sandbox
        run: docker build -f ci/codex-sandbox.Dockerfile -t codex-sandbox .
      - name: Fetch open findings
        run: gh api /repos/${{ github.repository }}/dependabot/alerts \
              --jq '.[] | select(.state=="open") | .number' > queue.txt
        env: { GH_TOKEN: ${{ secrets.GITHUB_TOKEN }} }
      - name: Run Codex
        run: |
          docker run --rm \
            -v "$PWD/queue.txt:/workspace/queue.txt:ro" \
            -e OPENAI_API_KEY=${{ secrets.OPENAI_API_KEY }} \
            -e REPO_URL=https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }} \
            codex-sandbox /workspace/queue.txt
```
  {{< /tab >}}
  {{< tab name="GitHub Issues label" >}}
```yaml
# .github/workflows/codex-on-label.yml
name: Codex on label
on:
  issues:
    types: [labeled]

jobs:
  remediate:
    if: github.event.label.name == 'codex-remediate'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - run: docker build -f ci/codex-sandbox.Dockerfile -t codex-sandbox .
      - run: echo "${{ github.event.issue.number }}" > queue.txt
      - run: |
          docker run --rm \
            -v "$PWD/queue.txt:/workspace/queue.txt:ro" \
            -e OPENAI_API_KEY=${{ secrets.OPENAI_API_KEY }} \
            -e REPO_URL=https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }} \
            codex-sandbox /workspace/queue.txt
      - run: |
          gh issue comment ${{ github.event.issue.number }} \
            --body "Codex finished — see PRs linked above."
        env: { GH_TOKEN: ${{ secrets.GITHUB_TOKEN }} }
```
  {{< /tab >}}
  {{< tab name="Dependabot alert" >}}
```yaml
# .github/workflows/codex-on-dependabot.yml
# Kicks off the moment a new dependabot security advisory lands.
name: Codex on dependabot alert
on:
  dependabot_alert:
    types: [created, reopened]

jobs:
  remediate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: read
    steps:
      - uses: actions/checkout@v4
      - run: docker build -f ci/codex-sandbox.Dockerfile -t codex-sandbox .
      - run: echo "${{ github.event.alert.number }}" > queue.txt
      - run: |
          docker run --rm \
            -v "$PWD/queue.txt:/workspace/queue.txt:ro" \
            -e OPENAI_API_KEY=${{ secrets.OPENAI_API_KEY }} \
            -e REPO_URL=https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }} \
            codex-sandbox /workspace/queue.txt
```
  {{< /tab >}}
  {{< tab name="Jira / Linear webhook" >}}
Configure a Jira Automation rule (or Linear webhook) to POST to a
GitHub `workflow_dispatch` endpoint — that's the easiest way to keep
the ticket/PR paper trail without running an always-on intake service:

```bash
# Jira Automation → Send web request → POST
curl -sS -X POST \
  https://api.github.com/repos/$OWNER/$REPO/actions/workflows/codex-remediate.yml/dispatches \
  -H "Authorization: Bearer $GH_PAT" \
  -H "Accept: application/vnd.github+json" \
  -d '{
        "ref": "main",
        "inputs": {
          "ticket_key": "'"$TICKET_KEY"'",
          "brief":      "'"$TICKET_SUMMARY"'"
        }
      }'
```

In the workflow, accept `workflow_dispatch.inputs.ticket_key` and
`brief`, write them to `queue.txt` / the prompt template, and when
the PR opens, POST its URL back to the ticket via the REST API
(Jira `/rest/api/3/issue/{key}/comment`, Linear `commentCreate`).
  {{< /tab >}}
{{< /tabs >}}

### 6. Add cost + safety guardrails

- **One accepted finding per task** so context and review remain bounded.
- **Per-job wall-clock cap** via the driver's `timeout 20m`.
- **Daily PR cap** — if the driver has already opened N PRs today,
  it exits early. Compute this with a quick `gh pr list --search`
  before the loop.
- **Kill switch** — if a repo gets the `codex-paused` label on any
  issue, the driver skips that repo entirely.

## Verification

Queue a single low-risk finding and run the driver manually. Codex
should produce:

- a clean PR with a test and a remediation summary,
- a sandbox that cleaned up after itself,
- no secrets in logs,
- a session-log artifact you can replay.

If any of those are missing, fix them before scaling up — batch jobs
amplify small mistakes very quickly.

## Orchestration: what stays constant, what changes

Codex's batch-remediation recipe leans heavily on a **driver
script** — a small orchestrator that reads findings off a queue,
fills a prompt template, invokes Codex in a sandbox, and opens a
PR. The driver is the stable spine; everything it feeds Codex is
expected to change over time.

```mermaid
flowchart LR
    A[Finding queue<br/>file / Issues / DB] --> B[Driver script<br/>orchestrator]
    B --> C[Codex CLI / Cloud]
    C -.reads.-> P[Prompt layer<br/>AGENTS.md + task template]
    C -.calls.-> M[Model<br/>OpenAI API]
    C -.uses.-> T[Tool layer<br/>sandbox CLIs, package managers]
    C --> D[Sandbox branch + edits]
    D --> E[Tests + secret scan]
    E -->|pass| F[PR opened<br/>linked to finding ID]
    E -->|block| G[Skip + log]
```

What is **constant** (build once, leave alone):

- The driver script itself — queue poll, prompt fill, Codex
  invocation, PR open, session log capture.
- The sandbox container image and its tool allowlist.
- The one-finding task boundary, per-job wall-clock cap, and the
  kill-switch label.
- The PR template and the "link back to finding ID" requirement.

What **evolves** (expected to change, often):

- **Prompt.** `AGENTS.md` gets tuned quarterly. The task template
  (the narrow instructions inserted per finding) is iterated
  based on reviewer feedback.
- **Model.** The OpenAI model string is upgraded as newer Codex
  / GPT releases meaningfully improve on your labelled set. The
  driver doesn't care which model it's talking to.
- **Tools.** New ecosystem package managers, new scanners, and
  new registries plug in as additional sandbox CLIs the driver
  mounts. The orchestrator's control flow doesn't change.

This separation is what lets you migrate models or add an
ecosystem without rewriting the batch pipeline.

## Guardrails

- **Sandbox only.** Use `codex exec --sandbox workspace-write` inside an
  isolated runner; avoid host-level credentials in the workspace.
- **Quota per repo.** Cap how many PRs Codex may open in 24h per repo
  to avoid spam.
- **Secret scanning.** Route Codex output through your secret scanner
  before committing — LLMs occasionally inline env values into patches.
- **Structured output is evidence.** Keep the JSONL captured from
  `codex exec --json` for every run. When a reviewer asks why the agent
  acted, the event stream is part of the answer.

## Troubleshooting

- **Codex loops without converging.** Sharpen the task template,
  narrow it to one finding, and shorten the driver's wall-clock timeout.
- **Lockfile churn.** Add a pre-commit hook in the sandbox that runs
  `pnpm install --frozen-lockfile` to catch drift before pushing.
- **PRs opened against the wrong base.** Pin `--base main` in the
  driver; some repos default to `develop`.

## See also

- OpenAI: [Codex CLI docs](https://developers.openai.com/codex/cli) · [quickstart](https://developers.openai.com/codex/quickstart) · [authentication](https://developers.openai.com/codex/auth)
- OpenAI: [`codex exec` (non-interactive mode)](https://developers.openai.com/codex/noninteractive) · [CLI reference](https://developers.openai.com/codex/cli/reference) · [models](https://developers.openai.com/codex/models)
- [MCP Integration]({{< relref "/mcp-servers" >}}) — expose sandboxed tools as MCP for richer context
- Recipe: [Devin]({{< relref "/devin" >}}) — end-to-end agent alternative
- [Recipes]({{< relref "/recipes" >}}) — share your Codex driver prompts
