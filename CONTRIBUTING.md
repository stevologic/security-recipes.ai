# Contributing to Agentic Remediation Recipes

Thanks for wanting to contribute! This project is **community-driven** — we
grow faster the more teams share back the recipes, prompts, and
guardrails that are working for them. This doc describes the
fork-and-PR workflow we use to land changes.

- [TL;DR](#tldr)
- [Fork-and-PR workflow](#fork-and-pr-workflow)
- [What you can contribute](#what-you-can-contribute)
- [Contributing a new agent recipe](#contributing-a-new-agent-recipe)
- [Contributing a prompt](#contributing-a-prompt)
- [Style and conventions](#style-and-conventions)
- [Review expectations](#review-expectations)
- [Running the site locally](#running-the-site-locally)
- [Security and sensitive data](#security-and-sensitive-data)
- [License](#license)

---

## TL;DR

1. **Fork** the repo on GitHub.
2. **Branch** off `main` — `recipe/<tool>-<topic>` or
   `prompt/<short-name>`.
3. **Make your change** under `hugo-site/content/…`.
4. **Preview locally** with `hugo server -D` (see [Running the site
   locally](#running-the-site-locally)).
5. **Open a PR** against `main` on the upstream repo.
6. Get **one reviewer from Security** and **one from the team that owns
   the prompt or recipe**.
7. On merge, the GitHub Actions workflow rebuilds the site and pushes
   to `gh-pages` automatically — you don't have to touch deploys.

---

## Fork-and-PR workflow

We use the classic GitHub fork-and-PR model. You don't need push
access to the upstream repo to contribute.

### 1. Fork

From the repository page on GitHub, click **Fork** (top right) and
pick your own account or a team org.

### 2. Clone your fork

```bash
git clone https://github.com/<your-user>/agentic-remediation-recipes.git
cd agentic-remediation-recipes
```

### 3. Add the upstream remote

This lets you pull new changes from the canonical repo into your fork.

```bash
git remote add upstream https://github.com/stevologic/agentic-remediation-recipes.git
git fetch upstream
```

### 4. Create a branch

Branch names should read like commit messages. Prefixes we use:

| Prefix      | Use                                                       |
| ----------- | --------------------------------------------------------- |
| `recipe/`   | New or updated per-agent recipe                           |
| `prompt/`   | New or updated entry under `content/prompt-library/`      |
| `docs/`     | Non-recipe documentation changes                          |
| `chore/`    | Build, CI, deps, infra                                    |
| `fix/`      | Bug fixes (broken links, typos, wrong snippets)           |

```bash
git checkout -b recipe/claude-triage-skill upstream/main
```

### 5. Make your change, commit, push

Keep commits focused. Imperative mood, reference the recipe/prompt
name in the subject line:

```
Add Claude CVE-triage skill with transitive-dep guardrails

Closes #42.
```

```bash
git add hugo-site/content/…
git commit
git push origin recipe/claude-triage-skill
```

### 6. Open a PR against `main`

On GitHub, open a pull request from your branch to
`stevologic/agentic-remediation-recipes:main`. The PR template
will prompt you for the four things reviewers will check:

- **What** the recipe/prompt does
- **Why** it belongs here (not just on a personal wiki)
- **Where** it's been running in production (team + service)
- **Known limits** — honest failure modes, not a pitch

### 7. Address review and merge

Squash-merge is the default. Once merged, the GH Actions pipeline
builds Hugo and publishes `gh-pages` in ~1 minute.

### Keeping your fork in sync

Periodically:

```bash
git checkout main
git fetch upstream
git merge upstream/main
git push origin main
```

---

## What you can contribute

Anything that makes agentic remediation more reliable, reviewable, or
repeatable for the next team:

- **A new agent recipe** — your `<tool>/_index.md` playbook.
- **An update to an existing recipe** — new guardrails, new failure
  mode, new verification step.
- **A prompt, rules file, or skill** — drop under
  `content/prompt-library/`.
- **A fix** — broken link, wrong command, outdated screenshot.
- **An issue** — file one if you spot something broken and don't
  have time to fix it yourself; the template asks for repro steps.

---

## Contributing a new agent recipe

A "recipe" is a per-tool playbook. Every recipe follows the same
four-section skeleton so teams can skim and compare:

1. **Prerequisites** — licenses, accounts, integrations required first.
2. **Recipe steps** — a numbered, opinionated walkthrough. No
   "it depends."
3. **Verification** — how to know end-to-end that it worked.
4. **Guardrails** — the controls in place before you scale it up.

Use the archetype to scaffold:

```bash
cd hugo-site
hugo new content <tool>/_index.md
```

Things reviewers look for in a recipe PR:

- **Reproducible** — a peer followed it and got the same result.
- **Opinionated** — you picked one path and explained the trade-off.
- **Safe** — the Guardrails section is not an afterthought.
- **Current** — versions and pricing are dated so the reader knows
  when the page might have drifted.

---

## Contributing a prompt

The Prompt Library lives under `hugo-site/content/prompt-library/`.
Every prompt file has the same frontmatter:

```markdown
---
title: "<Short, descriptive name — e.g. 'Claude CVE triage skill'>"
tool: "<claude | copilot | cursor | codex | devin>"
author: "<your @handle>"
team: "<team name>"
maturity: "<experimental | production>"
tags: ["triage", "sca", "..."]
---

## What this prompt does

One paragraph.

## When to use it

Concrete trigger.

## The prompt

    <the actual prompt, skill body, or rules file — fenced>

## Known limitations

2–3 cases where it misbehaves and what to do about them.

## Changelog

- YYYY-MM-DD — v1, first published.
```

**What does _not_ belong:**

- Secrets, API tokens, internal hostnames, customer data. Scrub before
  opening the PR. This is public community-driven.
- One-shot prompts you used once. If it's not earning its keep, it's
  not ready.
- "Clever" jailbreaks. This library is for trustworthy, reviewable
  automation.

---

## Style and conventions

- **Markdown**, Hugo + Hextra shortcodes. The `{{< callout >}}`,
  `{{< relref >}}`, and `{{< cards >}}` shortcodes are the main ones
  you'll use.
- **Line length** — soft-wrap around 80 chars in prose, unless the line
  is a long URL or code.
- **Links** — prefer `{{< relref "/<section>" >}}` for internal links
  so Hugo validates them at build time.
- **Commands** — fenced with the language hint (```` ```bash ````,
  ```` ```yaml ````, etc.) so syntax highlighting kicks in.
- **Weight** — per-section ordering uses the `weight` frontmatter
  field. Keep within the existing ranges to avoid reshuffling the
  sidebar.
- **Dates** — absolute, ISO-8601 (`2026-04-21`), never "last week."

---

## Review expectations

A PR needs **two approvals** to merge:

1. **Security** — at least one reviewer from the InfoSec team. We're
   checking for safe guardrails, no leaked secrets, and that the
   recipe doesn't inadvertently create a worse problem than the
   finding it's fixing.
2. **Owning team** — at least one reviewer from the team that will be
   on-the-hook for the prompt or recipe. This is the sanity check that
   it actually reflects how the team works.

Expected turnaround is **3 business days** for a first review. Ping
the reviewers in chat if it's been longer — PRs go stale fast.

---

## Running the site locally

Prereqs:

- [Hugo extended](https://gohugo.io/installation/) `>= 0.139`
- [Go](https://go.dev/dl/) `>= 1.21` (Hextra is loaded as a Hugo Module)
- Git

```bash
cd hugo-site
hugo mod get -u              # fetch the Hextra theme
hugo server -D               # http://localhost:1313
```

Prefer Docker?

```bash
docker build -t arr hugo-site/
docker run --rm -p 3000:80 arr
# → http://localhost:3000
```

---

## Security and sensitive data

This repository is **public community-driven**. Before opening a PR:

- No customer data, PII, or production hostnames.
- No API keys, tokens, session cookies, or signed URLs.
- No internal-only URLs (Jira ticket IDs, internal wiki links) — link
  to the public equivalent if one exists, or drop the link.
- When in doubt, **ask Security to review before opening the PR**.

If you spot a security issue in the repo itself (leaked token in
history, live secret in a config), **do not open a public issue**.
Email `security@<your-org>.com` and we'll triage privately.

---

## License

By contributing, you agree that your contributions will be licensed
under the [MIT License](./LICENSE) — the same terms as the rest of
the project.

---

Created by your friends in **InfoSec** ♥
