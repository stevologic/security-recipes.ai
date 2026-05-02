# Contributing to security-recipes.ai

Thanks for wanting to contribute! This project is **community-driven** — we
grow faster the more teams share back the recipes, prompts, and
guardrails that are working for them. This doc describes the
fork-and-PR workflow we use to land changes.

- [TL;DR](#tldr)
- [Fork-and-PR workflow](#fork-and-pr-workflow)
- [What you can contribute](#what-you-can-contribute)
- [Contributing a new agent recipe](#contributing-a-new-agent-recipe)
- [Contributing a prompt](#contributing-a-prompt)
- [Navigation: how the menus, sidebars, and hubs scale](#navigation-how-the-menus-sidebars-and-hubs-scale)
- [SEO and discoverability](#seo-and-discoverability)
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
3. **Make your change** under the root-level `content/…` directory.
4. **Preview locally** from the repo root with `hugo server -D` (see
   [Running the site locally](#running-the-site-locally)).
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
git clone https://github.com/<your-user>/security-recipes.ai.git
cd security-recipes.ai
```

### 3. Add the upstream remote

This lets you pull new changes from the canonical repo into your fork.

```bash
git remote add upstream https://github.com/stevologic/security-recipes.ai.git
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
git add content/...
git commit
git push origin recipe/claude-triage-skill
```

### 6. Open a PR against `main`

On GitHub, open a pull request from your branch to
`stevologic/security-recipes.ai:main`. The PR template
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

- **A new agent recipe** — your `content/<tool>/_index.md` playbook.
- **An update to an existing recipe** — new guardrails, new failure
  mode, new verification step.
- **A prompt, rules file, or skill** — drop under
  `content/prompt-library/`.
- **A CVE recipe prompt** — drop under `content/prompt-library/cve/`
  when a named CVE needs a specific remediation prompt.
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

The Prompt Library lives under `content/prompt-library/`:

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

Drop your file in the subdirectory that matches the agent it targets.
If it's tool-agnostic, put it in `content/prompt-library/general/`.
If it is anchored to a specific CVE, put it in
`content/prompt-library/cve/` so it appears in the CVE Recipes
catalogue.

Every prompt file has the same frontmatter:

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

**What does _not_ belong:**

- Secrets, API tokens, internal hostnames, customer data. Scrub before
  opening the PR. This is public community-driven.
- One-shot prompts you used once. If it's not earning its keep, it's
  not ready.
- "Clever" jailbreaks. This library is for trustworthy, reviewable
  automation.

---

## Navigation: how the menus, sidebars, and hubs scale

The site is built to absorb a steady stream of new recipes —
new CVEs, new classic-default patterns, new workflows — without
anyone needing to edit `hugo.yaml` or hand-curate a hub page
every time. Two rules keep that working:

### Rule 1 — The top-nav dropdown lists hubs, never leaf pages

The dropdown menus in `hugo.yaml` show **section hubs only**:

- `Security Remediation → Overview / Reviewer Playbook /
  Gatekeeping / Runtime Controls / Compliance` — and that's
  it. Individual workflow pages (`sast-findings/`,
  `base-images/`, `artifact-cache-purge/`, …) **do not**
  appear here.
- `Prompt Library → Claude / Cursor / Codex / Devin / Copilot
  / General / Reputable Sources / CVE Recipes / Classic
  Vulnerable Defaults` — per-tool and cross-cutting hubs.
  Individual prompts and CVE recipes **do not** appear here.

Why: a dropdown listing 50 CVE recipes (or 20 workflows) is
worse than no dropdown at all. The hub pages and the
auto-generated sidebar handle leaf navigation.

**If your contribution is a new hub category** (a brand-new
top-level grouping), edit `hugo.yaml`. **If your contribution
is a new recipe inside an existing hub**, do not.

### Rule 2 — Hubs auto-discover their pages

Each hub page (`content/<section>/_index.md`) renders its catalogue
through one of three shortcodes that walk the section tree:

- `{{< prompt-toc >}}` — for `content/prompt-library/` tool
  subsections and `classic-vulnerable-defaults`. Reads each child page's
  frontmatter and renders a card with title, description,
  maturity badge, author / team / model, and tags.
- `{{< cve-toc >}}` — for `content/prompt-library/cve/`. Groups by
  `ecosystem` frontmatter, sorts by `disclosed` date, shows
  severity and KEV badges.
- The Hextra `{{< cards >}}` shortcode — used on hubs where
  the editorial structure matters more than the page list
  (e.g., the `content/security-remediation/_index.md` page that
  separates "Active workflows" from "Program operations").

To add a new recipe, drop a markdown file in the section
folder with the right frontmatter:

**Prompt-library prompts** (`content/prompt-library/<tool>/*.md` and
`content/prompt-library/general/classic-vulnerable-defaults/*.md`):

```yaml
---
title: "Short, specific title"
linkTitle: "Short title"                 # shown in sidebar
description: "One sentence — becomes the card subtitle."
tool: "general"                           # or "claude" / "cursor" / etc.
author: "Your Name"
team: "Your Team"
maturity: "development"                   # development | beta | stable | production
model: "Opus 4.7"                         # the model you validated against
tags: ["tag1", "tag2"]
weight: 30                                # ordering within the section
date: 2026-04-25
---
```

**CVE recipes** (`content/prompt-library/cve/cve-XXXX-YYYYY-<slug>.md`):

```yaml
---
title: "CVE-XXXX-YYYYY — <name>"
linkTitle: "CVE-XXXX-YYYYY <name>"
description: "One sentence — becomes the card subtitle."
tool: "general"
author: "Your Name"
team: "Your Team"
maturity: "stable"
model: "Opus 4.7"
tags: ["cve", ...]
weight: 30
date: 2026-04-25
cve: "CVE-XXXX-YYYYY"                     # required for the listing
aliases: ["Popular Name", "Other Alias"]
kev: true                                 # CISA Known Exploited Vulnerability flag
severity: "critical"                      # critical | high | medium | low
ecosystem: "java/maven"                   # the catalogue groups on this
disclosed: "YYYY-MM-DD"                   # the catalogue sorts on this
---
```

When you push your branch, the next site build picks the new
file up automatically. No menu edits, no hub-page edits.

### Rule 3 — Long pages get an in-page TOC, not sub-pages

Recipe pages will keep growing as scenarios accumulate
(new ecosystems, new mitigations, new platform-specific
notes). The right shape stays: one recipe = one page, with
a clear `## H2` heading hierarchy and an in-page TOC
rendered automatically by Hextra on the right rail. Don't
split a recipe across multiple files unless the second file
is a genuinely different recipe.

If you find yourself wanting to split, ask:

- Is each section now a self-contained recipe a reader
  could pick up alone? Split.
- Or is the page a long single recipe with a lot of
  context? Keep it as one page; consistent `## H2` /
  `### H3` heading shape lets the right-rail TOC carry
  the navigation.

### What this means in practice

- **Adding a CVE recipe?** New file under
  `content/prompt-library/cve/`. Frontmatter as above. Done.
- **Adding a classic-default recipe?** New file under
  `content/prompt-library/general/classic-vulnerable-defaults/`.
  Frontmatter as above. Done.
- **Adding a new workflow?** New folder under
  `content/security-remediation/<slug>/_index.md`. Add a card to
  the section's `_index.md` cards block (editorial
  ordering matters there). Don't touch `hugo.yaml`.
- **Adding a brand-new hub category?** *Only then* edit
  `hugo.yaml` to add the dropdown entry, and add a
  `cascade` block in the new hub's `_index.md` to
  propagate sidebar settings to descendants.

The navigation contract is enforced by review — PRs that
add per-recipe entries to `hugo.yaml` or hand-list recipes
on hub pages will be asked to switch to the auto-discovery
shortcodes.

---

## SEO and discoverability

The site is built so contributors don't have to think about SEO —
the [SEO partial](layouts/partials/custom/seo.html)
emits Open Graph, Twitter Card, JSON-LD (Article, Organization,
WebSite, BreadcrumbList), canonical URLs, and robots / theme
meta on every page from page-level frontmatter, with sensible
fallbacks to site-level defaults in `hugo.yaml`. Hugo's
auto-generated `sitemap.xml` and the
[robots.txt template](layouts/robots.txt) are wired
to surface the new content to search engines and AI crawlers
on the next deploy.

What that means in practice:

- **You only set `description:` in your page's frontmatter.**
  Everything else (OG image, structured data, breadcrumbs,
  canonical URL) flows from the page's location in the tree
  and the site-level defaults.
- **Tags are SEO content.** The `tags:` array doubles as a
  `keywords` meta and as `article:tag` Open Graph properties
  and as the JSON-LD `keywords` field. Pick tags that a
  searcher would actually type.
- **`description` is what shows in search results.** Aim for
  one tight sentence, ≤160 characters. The partial truncates
  cleanly past 297 characters but you should rarely need to
  rely on that.
- **Custom OG image per page is optional.** Set
  `image: "/images/<your-card>.png"` (or `.svg`) in
  frontmatter to override the site default
  `static/images/og-card.svg` on a single page — useful for
  CVE recipes or workflow pages that warrant their own card.
- **Drafts and WIP** can opt out of indexing with
  `noindex: true` in frontmatter — the partial emits the
  matching `<meta name="robots" content="noindex,nofollow">`
  and search engines will drop the page from their index.

The full SEO frontmatter contract:

```yaml
---
# Always set:
title: "Page title"
description: "One-sentence summary used for search snippets."

# Recommended:
tags: ["concrete", "searchable", "tags"]
date: 2026-04-25            # used for `article:published_time`

# Optional overrides:
image: "/images/<page-card>.png"   # per-page OG image
imageWidth: 1200
imageHeight: 630
keywords: ["explicit", "list"]      # overrides tags-as-keywords
author: "Your Name"
noindex: true                       # opt out of indexing entirely
---
```

For brand-new top-level sections, also remember to:

- Update the site's `seo.sameAs` list in `hugo.yaml` if a
  new canonical URL (a project repo, a Mastodon, a
  Bluesky) should be linked into the Organization JSON-LD.
- Update `seo.defaultKeywords` if the new section
  introduces topic vocabulary that isn't already there.

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

1. **Security** — at least one reviewer from the security team.
   They check for safe guardrails, no leaked secrets, and that the
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

Run these from the repository root, the directory that contains
`hugo.yaml`; the current layout does not use a nested site directory.

```bash
hugo mod get -u              # fetch the Hextra theme
hugo server -D               # http://localhost:1313
```

Prefer Docker?

```bash
docker build -t security-recipes .
docker run --rm -p 3000:80 security-recipes
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

An open, community-driven playbook for **security engineering teams** ♥
