# Agentic Remediation Recipes

A Hugo docs site (built with the [Hextra](https://imfing.github.io/hextra/)
theme) that catalogs **community-driven recipes** for turning the AI coding
tools engineering teams already use — GitHub Copilot, Devin, Cursor,
Codex, and Claude — into autonomous security remediators.

## Purpose

The agentic landscape is moving faster than any single team's internal
documentation can keep up with. New models ship monthly, new agent
platforms launch quarterly, MCP connectors proliferate across every
SaaS an engineering org touches, and the guardrails that kept a pilot
safe last quarter may not cover the capabilities shipping next quarter.

This project exists for two reasons:

1. **A working reference for agentic security remediation.** A
   tool-agnostic, reviewer-gated, measurable shape of workflow that
   any security engineering team can adopt, adapt, and fork — rather
   than starting from a blank page every time a new capability lands.
2. **A common language for agentic enablement inside companies
   embracing this transformational moment.** Engineering leaders,
   security teams, platform teams, and compliance counterparts need
   a shared vocabulary and a shared mental model to have the same
   conversation. This site is designed to be that shared artifact —
   something a team can point at internally ("this is the shape we're
   adopting, this is the maturity stage we're in, this is the
   evidence we're producing") instead of re-explaining first
   principles in every meeting.

The recipes, prompts, reference workflows, metrics, reviewer
playbook, rollout model, compliance mapping, and threat model are
all written to be **industry-generic**: rename the labels, swap the
tools, bring your own policy — the shape travels. As the landscape
evolves, so does this site. Forks are encouraged; contributions back
are the whole point.

## What's in the site

The site is a polished landing page backed by a full docs experience,
and ships with:

- **Fundamentals** — plain-English primer on agents, prompts, MCP,
  and the vocabulary the rest of the site assumes.
- **Agents** — five per-tool recipe pages with install / configure /
  dispatch / guardrail sections.
- **Prompt Library** — tool-agnostic and per-tool prompts, including
  full OWASP Top 10 (2026) audit and remediation playbooks.
- **MCP Servers** — connector catalog, onboarding checklist, and a
  write-up on MCP gateways (when and why to put one in front of your
  connectors).
- **Agentic Security Remediation** — reference workflows a security
  team can operate on engineering's behalf: Sensitive Data Element
  and Vulnerable Dependency remediation.
- **Automation, not agentic** — what deterministic tooling still does
  best, and where agents should *not* replace it.
- **Contribute** — fork-and-PR guide for adding recipes, prompts, or
  workflows.

It's designed to be hosted on **GitHub Pages** with zero manual deploy
steps: pushing to `main` rebuilds and publishes. The Repository link
and the "Edit on GitHub" base resolve **dynamically** to whichever
repo hosts the site — no find-and-replace required before forking.

---

## Quick start

### Prerequisites

- [Hugo extended](https://gohugo.io/installation/) `>= 0.139`
- [Go](https://go.dev/dl/) `>= 1.21` (Hextra is loaded as a Hugo Module)
- Git

### Run locally

```bash
cd hugo-site
hugo mod get -u           # fetch the Hextra theme
hugo server -D            # http://localhost:1313
```

### Run in Docker

A multi-stage `Dockerfile` builds the site with Hugo extended and
serves it from `nginx:alpine`:

```bash
cd hugo-site
docker build -t agentic-remediation-recipes .
docker run --rm -p 8080:80 agentic-remediation-recipes
# open http://localhost:8080
```

### Add a recipe for a new agent

```bash
hugo new content <agent_name>/_index.md
```

Then edit the file. The archetype (`archetypes/default.md`) gives you a
ready-made skeleton with the four required sections (Install →
Configure → Dispatch → Guardrails).

### Contribute a prompt

Drop a new Markdown file under `content/prompt-library/<tool>/` (or
under `content/prompt-library/general/` for tool-agnostic prompts).
Every entry carries frontmatter with `author`, `team`, `maturity`, and
the `model` it was validated against. See any existing prompt — for
example, `content/prompt-library/general/owasp-top-10-2026-audit.md` —
as a template.

---

## Project layout

```
hugo-site/
├── hugo.yaml                       # Site config (menus, params, dynamic repoURL)
├── go.mod                          # Hugo module deps (Hextra)
├── archetypes/default.md           # `hugo new` template
├── assets/css/custom.css           # Hextra overrides — matches landing theme
├── content/
│   ├── _index.md                   # Home page (rendered by custom layout)
│   ├── fundamentals/_index.md      # Primer — agents, prompts, MCP, vocabulary
│   ├── docs/_index.md              # Docs landing — purpose of this site
│   ├── agents/_index.md            # Agents overview / decision tree
│   ├── github_copilot/_index.md    # Per-agent recipe
│   ├── devin/_index.md
│   ├── cursor/_index.md
│   ├── codex/_index.md
│   ├── claude/_index.md
│   ├── prompt-library/
│   │   ├── _index.md               # Library landing
│   │   ├── general/                # Tool-agnostic prompts (OWASP, review, triage)
│   │   ├── claude/                 # Claude skills, slash commands
│   │   ├── cursor/                 # Cursor rules + commands
│   │   ├── codex/                  # Codex CLI prompts
│   │   ├── devin/                  # Devin playbooks + knowledge
│   │   └── github_copilot/         # Copilot instructions + issue templates
│   ├── mcp-servers/_index.md       # Connector catalog + gateway write-up
│   ├── security-remediation/
│   │   ├── _index.md               # Security team workflow overview
│   │   ├── sensitive-data/         # SDE remediation workflow
│   │   └── vulnerable-dependencies/# Dep remediation workflow
│   ├── automation/_index.md        # Automation, not agentic
│   └── contribute/_index.md        # How to submit recipes/prompts
├── layouts/
│   ├── index.html                  # Custom landing page (polished hero + cards)
│   ├── partials/footer.html        # Footer override (copyright)
│   ├── partials/custom/head-end.html # Injects custom.css
│   └── shortcodes/prompt-toc.html  # Auto-TOC for prompt-library pages
├── static/
│   ├── .nojekyll                   # Tell GH Pages "this is not Jekyll"
│   └── images/
│       ├── logo.svg
│       └── covers/                 # Per-tool hero illustrations
├── Dockerfile                      # Multi-stage: Hugo extended → nginx:alpine
└── .github/workflows/hugo.yml      # GH Pages CI/CD + dynamic repoURL injection
```

The repo root also holds `CONTRIBUTING.md` (the fork-and-PR guide that
the top nav's **Contribute** link points at) and `LICENSE`.

---

## Site sections at a glance

| Section | What's in it |
| ------- | ------------ |
| **Fundamentals** | What an agent is; the five tools; prompts; MCP; MCP gateways; agentic remediation; vocabulary. |
| **Docs** | Orientation for the site — who it's for, how to read a recipe, how to contribute. |
| **Agents** | Per-tool recipes for GitHub Copilot, Claude, Cursor, Codex, Devin — each with Install → Configure → Dispatch → Guardrails, plus General and Enterprise onboarding. |
| **Prompt Library** | Tool-agnostic prompts under `general/` (OWASP Top 10 2026 audit, OWASP Top 10 2026 remediate) plus per-tool prompts for CVE triage, vulnerable deps, and SDE remediation. |
| **MCP Servers** | Why MCP exists; connector catalog (risk, ownership, ticket, knowledge, code, observability); MCP gateway patterns; integration on-ramp. |
| **Security Remediation** | Reference workflows a security team can operate: SDE and vulnerable deps. Each page describes the orchestration spine, guardrails, and what the workflow won't catch. Plus program metrics, reviewer playbook, rollout maturity model, compliance mapping. |
| **Automation** | The "just use a linter" checklist — deterministic automation that earns its keep before an agent ever runs. |
| **Contribute** | How to add a recipe, a prompt, or a new workflow. |

---

## Dynamic repository URL

The "Repository" link on the landing page and the "Edit on GitHub"
base are resolved from `params.repoURL`, which CI overrides at build
time:

```yaml
env:
  HUGO_PARAMS_REPOURL: "https://github.com/${{ github.repository }}"
  HUGO_PARAMS_EDITURL_BASE: "https://github.com/${{ github.repository }}/edit/${{ github.ref_name }}/hugo-site/content"
```

This means you can fork the repo under any org/user and the links
follow — no `hugo.yaml` edits required.

---

## Deploying to GitHub Pages

The project ships with a GitHub Actions workflow
(`.github/workflows/hugo.yml`) that:

1. Installs Hugo (extended) + Go.
2. Fetches the Hextra theme via Hugo Modules.
3. Runs `hugo --gc --minify` with `HUGO_PARAMS_REPOURL` wired to the
   hosting repo.
4. Pushes the compiled `public/` directory to a dedicated **`gh-pages`**
   branch using `peaceiris/actions-gh-pages`.

### One-time setup

1. **Push `hugo-site/` into a GitHub repo.**
   The workflow expects the Hugo project to live under `hugo-site/`.
   If you move it to the repo root, update `working-directory` and
   `publish_dir` in the workflow.

2. **Update `baseURL`.**
   In `hugo.yaml`, set `baseURL` to your GitHub Pages URL (e.g.
   `https://<user>.github.io/<repo>/`). The Repository link is
   dynamic — only `baseURL` needs updating per fork.

3. **Push to `main`.**
   The workflow runs, creates the `gh-pages` branch on first deploy,
   and every subsequent push force-updates that branch with the
   latest build (`force_orphan: true` keeps the branch small).

4. **Point GitHub Pages at `gh-pages`.**
   In the repo's **Settings → Pages**:
   - **Source:** Deploy from a branch
   - **Branch:** `gh-pages`  /  `(root)`

   Save. A minute later your site is live at
   `https://<user>.github.io/<repo>/`.

> **Custom domain?** Add a `static/CNAME` file containing your domain
> (it ends up at the root of `gh-pages`) and set `baseURL` in
> `hugo.yaml` to `https://your-domain/`.

> **Token permissions.** The workflow only needs the default
> `GITHUB_TOKEN` with `contents: write` — no PATs required.

---

## Customising

- **Colors / branding** — `assets/css/custom.css` sets the shared
  accent palette and the ambient orbs that carry the landing-page
  aesthetic into the docs.
- **Logo** — replace `static/images/logo.svg`.
- **Per-tool covers** — replace anything in `static/images/covers/`.
- **Landing page** — `layouts/index.html` is a fully custom home.
  Tweak the hero copy, tool tags, or the Prompt Library CTA there.
- **Navbar / footer** — see the `menu` and `params.footer` blocks in
  `hugo.yaml`. The footer template itself is overridden at
  `layouts/partials/footer.html` to guarantee the site-owned copyright
  wins over the theme default.

---

## Forking for an enterprise

The site is designed to be forked and customised without code
changes:

- `baseURL` is the only value you need to touch for hosting.
- `HUGO_PARAMS_REPOURL` overrides the Repository / Edit-on-GitHub
  link targets via CI.
- Per-agent pages carry an **Enterprise Onboarding** section as a
  placeholder — a forking enterprise fills it with its own
  identity-provider, policy, and deployment specifics while leaving
  the **General Onboarding** section intact.

See each per-agent recipe for the exact shape; the pattern is
consistent across all five.

---

## License

MIT — see `LICENSE`.

---

An open, community-driven playbook for **security engineering teams** ♥
