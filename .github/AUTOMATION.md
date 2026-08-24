# Hands-off automation

This repository is designed to run itself. Every scheduled and reactive
workflow below operates with the repository-scoped `GITHUB_TOKEN`; no personal
access token is required.

## The pipeline

| Workflow | Trigger | Responsibility |
| --- | --- | --- |
| Build (`build.yml`) | push to main or development, PRs, dispatch | Full test/build/image gate; publishes immutable deploy images on non-PR runs (`:SHA` for main, `:SHA-development` for staging) |
| CVE catalog sync (`cve-catalog-sync.yml`) | daily 09:23 UTC | Refreshes the rolling ten-year CVE catalog, runs OpenAI enrichment and recipe drafts, opens/merges its own PR through exact-SHA validation |
| Content refresh (`content-refresh.yml`) | daily 11:47 UTC | Researches one source-backed opportunity across reviewed remediation workflows, executable playbooks, or non-CVE recipes and submits a validated auto-merge PR when a substantive update is warranted |
| Leftover review (`leftover-review.yml`) | daily 13:17 UTC | Live-verifies leftover-gold CVE leftovers against GHAD/NVD; leftover-gold criticals and highs drain first, then each run reviews up to 100 leftover-gold medium and low pages and submits a validated auto-merge PR |
| CVE catalog validation (`cve-catalog-validate.yml`) | dispatch only | Runs the build-equivalent suite against one exact SHA and publishes the required `build` status for it |
| Production watchdog (`production-watchdog.yml`) | every 30 min | Probes the live site, catalog freshness, revision, and TLS; maintains the health issue; self-heals unbuilt revisions and stale catalogs |
| Automation shepherd (`automation-shepherd.yml`) | every 30 min | Dispatches missing main Builds after token-authored merges, updates stale auto-merge PR branches, and attaches missing build validations |
| Dependabot auto-merge (`dependabot-automerge.yml`) | Dependabot PRs | Arms auto-merge for verified patch/minor bumps |
| AI maintenance (`ai-maintenance.yml`) | failure of the workflows above | Codex investigates, fixes the root cause, and opens an auto-merge PR (or documents infra failures on the health issue) |
| AI issue maintenance (`ai-issue-maintenance.yml`) | owner-authored issue events + twice-daily sweep | Codex triages open issues filed by the owner or the automation: fixes via auto-merge PRs with `Closes #n`, closes resolved reports, labels worked issues `automation:ai-triaged` |

## Why the shepherd exists

GitHub never creates workflow runs for events that `GITHUB_TOKEN` caused,
except `workflow_dispatch` and `repository_dispatch`. Two consequences:

- A PR merged through token-enabled auto-merge produces a main revision with
  **no Build run** and therefore no deployable image.
- A PR branch updated with the token produces a head with **no `build`
  check**, so its auto-merge waits forever under the ruleset.

The shepherd closes both gaps with dispatches (the allowed exception): it
dispatches `build.yml` for unbuilt main revisions and dispatches the exact-SHA
validation — which publishes the required `build` commit status — for
auto-merge PR heads that have none.

## Merge policy

The `main` ruleset requires a PR and a passing `build` context with strict
up-to-date enforcement, and there are no bypass actors. Every automated merge
(Dependabot, catalog sync, AI fixes) therefore rides the same gate as a human
change: auto-merge armed, `build` proven on the exact head, branch current.

## Deployment

CI publishes immutable images tagged with the exact commit SHA to GHCR. The
production droplet pulls and applies the main-branch `:SHA` images to
`security-recipes.ai` on a 15-minute `deploy.sh` cron. The same cron also
pulls `:SHA-development` images for `origin/development` into the staging
slot served at `dev.security-recipes.ai`. The watchdog's `revision` probe
confirms the production handoff landed.

## Required configuration

| Item | Kind | Status | Purpose |
| --- | --- | --- | --- |
| `OPENAI_API_KEY` | secret | configured | CVE enrichment and recipe drafts, daily leftover-gold review, daily non-CVE content refresh, and Codex-powered AI maintenance (which no-ops with a notice if the secret is removed) |
| `CVE_AUTO_MERGE_ENABLED` | variable | `true` | Lets the catalog sync merge its own PR |
| `CVE_AUTOMATION_APP_CLIENT_ID` / `CVE_AUTOMATION_APP_PRIVATE_KEY` | variable / secret | optional | A dedicated GitHub App; when configured, its pushes trigger normal CI events and the dispatch workarounds above become unnecessary |
