---
title: Contribute
linkTitle: Contribute
weight: 4
toc: true
sidebar:
  open: true
description: >
  How to contribute a recipe, a prompt, or a fix — the fork-and-PR
  workflow, branch naming, review expectations, and the prompt
  template.
---

Thanks for wanting to contribute! This project is **community-driven** —
we grow faster the more teams share back the recipes, prompts, and
guardrails that are working for them.

{{< callout type="info" >}}
The same guide lives at
[`CONTRIBUTING.md`](https://github.com/stevologic/security-recipes.ai/blob/main/CONTRIBUTING.md)
in the repo root, so GitHub's "Contribute" button points at it. The
two copies are intentionally redundant.
{{< /callout >}}

## TL;DR

1. **Fork** the repo on GitHub.
2. **Branch** off `main` — `recipe/<tool>-<topic>` or
   `prompt/<tool>/<short-name>`.
3. **Make your change** under the root-level `content/…` directory.
4. **Preview locally** from the repo root with `hugo server -D` (see
   [Running the site locally](#running-the-site-locally)).
5. **Open a PR** against `main` on
   [`stevologic/security-recipes.ai`](https://github.com/stevologic/security-recipes.ai).
6. Get **one reviewer from Security** and **one from the team that
   owns the prompt or recipe**.
7. On merge, the GitHub Actions workflow rebuilds the site and
   pushes to `gh-pages` automatically — no manual deploy.

## Fork-and-PR workflow

We use the classic GitHub fork-and-PR model. You do **not** need
push access to the upstream repo to contribute.

### 1. Fork

From the repository page on GitHub, click **Fork** (top right) and
pick your own account or a team org.

### 2. Clone your fork

```bash
git clone https://github.com/<your-user>/security-recipes.ai.git
cd security-recipes.ai
```

### 3. Add the upstream remote

This lets you pull new changes from the canonical repo into your
fork.

```bash
git remote add upstream https://github.com/stevologic/security-recipes.ai.git
git fetch upstream
```

### 4. Create a branch

Branch names should read like commit messages. Prefixes we use:

| Prefix      | Use                                                      |
| ----------- | -------------------------------------------------------- |
| `recipe/`   | New or updated per-agent recipe                          |
| `prompt/`   | New or updated Prompt Library entry                      |
| `docs/`     | Non-recipe documentation                                 |
| `chore/`    | Build, CI, deps, infra                                   |
| `fix/`      | Bug fixes (broken links, typos, wrong snippets)          |

```bash
git checkout -b prompt/claude/cve-triage upstream/main
```

### 5. Commit and push

Keep commits focused. Imperative mood, reference the recipe or prompt
in the subject line:

```text
Add Claude CVE-triage skill with transitive-dep guardrails

Closes #42.
```

```bash
git add content/...
git commit
git push origin prompt/claude/cve-triage
```

### 6. Open a PR against `main`

Open a pull request from your branch to
`stevologic/security-recipes.ai:main`. The PR template
prompts for the four things reviewers check:

- **What** the recipe or prompt does
- **Why** it belongs here (not a personal wiki)
- **Where** it's been running in production (team + service)
- **Known limits** — honest failure modes, not a pitch

### 7. Address review and merge

Squash-merge is the default. Once merged, the GH Actions pipeline
builds Hugo and publishes `gh-pages` in about a minute.

### Keeping your fork in sync

Periodically:

```bash
git checkout main
git fetch upstream
git merge upstream/main
git push origin main
```

## What you can contribute

Anything that makes agentic remediation more reliable, reviewable,
or repeatable for the next team:

- **A new agent recipe** — your `content/<tool>/_index.md` playbook.
- **An update to an existing recipe** — new guardrails, new failure
  mode, new verification step.
- **A prompt, rules file, or skill** — drop under
  `content/prompt-library/<tool>/`.
- **A CVE recipe prompt** — drop under `content/prompt-library/cve/`
  when a named CVE needs a specific remediation prompt.
- **A fix** — broken link, wrong command, outdated screenshot.
- **An issue** — file one if you spot something broken and don't
  have time to fix it yourself; the template asks for repro steps.

## Contributing marketplace integrations and workflow packs

The browser workbench marketplace is also contributed content.

If you are adding a new connector pack, report contract, or workflow bundle:

- edit the matching Hugo data file under `data/marketplace/`
- keep the runtime state honest: `live`, `live_or_copy`, `copy_only`, `config_only`, or `planned`
- document the auth shape, browser/CORS assumptions, and human-review expectation on a docs page
- include an example target system and example scope so reviewers can validate the payload shape

The marketplace files are split on purpose:

- `data/marketplace/input_channels.json` - context and scanner intake
- `data/marketplace/output_channels.json` - downstream delivery routes
- `data/marketplace/report_profiles.json` - normalized output contracts
- `data/marketplace/workflow_templates.json` - reusable bundles stitched from the above

For public discoverability, update the
[Marketplace and Workflow Gallery]({{< relref "/docs/marketplace-gallery" >}})
when your PR changes how a pack should be explained to operators.

## Contributing a new agent recipe

A "recipe" is a per-tool playbook. Every recipe follows the same
four-section skeleton so teams can skim and compare:

1. **Prerequisites** — licenses, accounts, integrations required
   first.
2. **Recipe steps** — a numbered, opinionated walkthrough. No
   "it depends."
3. **Verification** — how to know end-to-end that it worked.
4. **Guardrails** — the controls in place before you scale it up.

Use the archetype to scaffold:

```bash
hugo new content <tool>/_index.md
```

Things reviewers look for in a recipe PR:

- **Reproducible** — a peer followed it and got the same result.
- **Opinionated** — you picked one path and explained the trade-off.
- **Safe** — the Guardrails section is not an afterthought.
- **Current** — versions and pricing are dated so the reader knows
  when the page might have drifted.

## Contributing a prompt

The Prompt Library is organised by tool:

```text
content/prompt-library/
├── claude/
├── codex/
├── cursor/
├── cve/              # per-CVE remediation prompts and recipes
├── devin/
├── general/          # tool-agnostic prompts, patterns, hooks
└── github_copilot/
```

Drop your file in the subdirectory that matches the agent it
targets. If it's tool-agnostic (e.g. a triage framework you use
across every agent), put it in `content/prompt-library/general/`.
If it is anchored to a specific CVE, put it in
`content/prompt-library/cve/` so it appears in the CVE Recipes
catalogue.

### Template

Every prompt file uses the same frontmatter:

```markdown
---
title: "<Short, descriptive name — e.g. 'Claude CVE triage skill'>"
tool: "<claude | copilot | cursor | codex | cve | devin | general>"
author: "<your @handle>"
team: "<team name>"
maturity: "<experimental | production>"
model: "<model string you ran this on — e.g. Opus 4.7, gpt-5-codex>"
tags: ["triage", "sca", "..."]
weight: 99
---

## What this prompt does

One paragraph. What goes in, what comes out, what's the happy path.

## When to use it

Concrete trigger. "When a new Dependabot PR fails CI because the
breaking change wasn't auto-resolved."

## The prompt

    <the actual prompt, skill body, or rules file — fenced>

## Known limitations

2–3 cases where it misbehaves and what to do about them.

## Changelog

- YYYY-MM-DD — v1, first published.
```

Want to see the template in action? The
[Claude CVE triage skill]({{< relref "/prompt-library/claude/cve-triage-skill" >}})
is a fully worked example.

### CVE recipe prompts

CVE recipe prompts live under `content/prompt-library/cve/`. Use this
section when the prompt is tied to a named vulnerability and needs
specific remediation guidance beyond the generic vulnerable-dependency
workflow.

Name the file after the CVE and a short slug:

```text
content/prompt-library/cve/cve-YYYY-NNNN-short-name.md
```

In addition to the standard prompt frontmatter, include the CVE fields
that power the catalogue:

```yaml
cve: "CVE-YYYY-NNNN"
aliases: ["Popular Name"]
kev: false
severity: "high"
ecosystem: "language/package-manager"
disclosed: "YYYY-MM-DD"
```

A good CVE recipe prompt explains the affected versions, the
indicator-of-exposure, the remediation strategy, stop conditions, and
the exact verification steps a reviewer can run.

### What does _not_ belong

- Secrets, API tokens, internal hostnames, customer data. Scrub
  before opening the PR. This is public community-driven.
- One-shot prompts you used once. If it's not earning its keep,
  it's not ready.
- "Clever" jailbreaks. This library is for trustworthy,
  reviewable automation.

## Style and conventions

- **Markdown**, Hugo + Hextra shortcodes. The `{{</* callout */>}}`,
  `{{</* relref */>}}`, and `{{</* cards */>}}` shortcodes are the
  main ones you'll use.
- **Line length** — soft-wrap around 80 chars in prose, unless the
  line is a long URL or code.
- **Links** — prefer `{{</* relref "/<section>" */>}}` for internal
  links so Hugo validates them at build time.
- **Commands** — fenced with the language hint (` ```bash `,
  ` ```yaml `, etc.) so syntax highlighting kicks in.
- **Weight** — per-section ordering uses the `weight` frontmatter
  field. Keep within the existing ranges to avoid reshuffling the
  sidebar.
- **Dates** — absolute, ISO-8601 (`2026-04-21`), never "last week."

## Review expectations

A PR needs **two approvals** to merge:

1. **Security** — at least one reviewer from the security team.
   They check for safe guardrails, no leaked secrets, and that
   the recipe doesn't inadvertently create a worse problem than
   the finding it's fixing.
2. **Owning team** — at least one reviewer from the team that will
   be on-the-hook for the prompt or recipe. This is the sanity
   check that it actually reflects how the team works.

Expected turnaround is **3 business days** for a first review.
Ping the reviewers in chat if it's been longer — PRs go stale
fast.

## Running the site locally

Prereqs:

- [Hugo extended](https://gohugo.io/installation/) `>= 0.139`
- [Go](https://go.dev/dl/) `>= 1.21` (Hextra is a Hugo Module)
- Git

Run these from the repository root, the directory that contains
`hugo.yaml`; the current layout does not use a nested site directory.

```bash
hugo mod get -u
hugo server -D
# → http://localhost:1313
```

Prefer Docker?

```bash
docker build -t security-recipes .
docker run --rm -p 3000:80 security-recipes
# → http://localhost:3000
```

## Security and sensitive data

This repository is **public community-driven**. Before opening a PR:

- No customer data, PII, or production hostnames.
- No API keys, tokens, session cookies, or signed URLs.
- No internal-only URLs (Jira ticket IDs, internal wiki links) —
  link to the public equivalent if one exists, or drop the link.
- When in doubt, **ask Security to review before opening the PR**.

If you spot a security issue in the repo itself (leaked token in
history, live secret in a config), **do not open a public issue**.
Email `security@<your-org>.com` and we'll triage privately.

## License

By contributing, you agree that your contributions will be licensed
under the MIT License — the same terms as the rest of the project.
