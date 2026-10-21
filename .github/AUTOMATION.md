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
| Leftover review (`leftover-review.yml`) | daily 13:17 UTC | Live-verifies leftover-gold CVE leftovers against GHAD/NVD; leftover-gold criticals and highs drain first, then each run reviews up to 25 leftover-gold medium and low pages and submits a validated auto-merge PR |
| CVE catalog validation request (`cve-catalog-validate-request.yml`) | dispatch only | Verifies that an exact SHA is the live head of the requested same-repository PR without checking out or executing PR code |
| CVE catalog validation (`cve-catalog-validate.yml`) | dispatch only | Revalidates and runs the build-equivalent suite on the exact catalog SHA. It never posts commit statuses and never emits `karen-qa`. Required merge checks come from real workflow runs |
| Production watchdog (`production-watchdog.yml`) | every 30 min | Probes the live site, catalog freshness, revision, and TLS; maintains the health issue; self-heals unbuilt revisions and stale catalogs |
| Automation shepherd (`automation-shepherd.yml`) | every 30 min | Dispatches missing main Builds after token-authored merges, updates stale auto-merge PR branches, and attaches missing build validations |
| Dependabot auto-merge (`dependabot-automerge.yml`) | Dependabot PRs | Arms auto-merge for verified patch/minor bumps |
| AI maintenance (`ai-maintenance.yml`) | failure of the workflows above | Grok investigates, fixes the root cause, and opens an auto-merge PR (or documents infra failures on the health issue). Same prompt is the Cursor Automation playbook |
| AI issue maintenance (`ai-issue-maintenance.yml`) | owner-authored issue events + twice-daily sweep | Grok triages open issues filed by the owner or the automation: fixes via auto-merge PRs with `Closes #n`, closes resolved reports, labels worked issues `automation:ai-triaged`. Same prompt is the Cursor Automation playbook |
| Dev DNS record (`dev-dns-record.yml`) | dispatch, pull requests to main, and successful Build runs on main/development | Creates or repairs the DigitalOcean A record for `dev.security-recipes.ai` |

## Intelligence

GitHub Actions is the clock and host. Catalog enrichment uses the
official OpenAI Responses API. Grok remains the billed brain for the
other first-party jobs below. Optional `NVD_API_KEY` is passed only
into the catalog sync step so lastMod catch-up can use the
authenticated NVD rate limit.

| Job | Host | Brain |
| --- | --- | --- |
| CVE catalog enrichment | Actions (`cve-catalog-sync.yml`) | OpenAI Responses API (`gpt-5.6-luna` unless `OPENAI_MODEL` is set; optional Daybreak via `OPENAI_DAYBREAK_PROGRAM`) |
| Security health | Actions (`security-health.yml`) | xAI/Grok |
| Leftover review | Actions (`leftover-review.yml`) | Grok Build CLI |
| Content refresh | Actions (`content-refresh.yml`) | Grok Build CLI |
| AI maintenance | Actions (`ai-maintenance.yml`), optional Cursor Automation | Grok Build CLI / Cursor Grok model |
| AI issue maintenance | Actions (`ai-issue-maintenance.yml`), optional Cursor Automation | Grok Build CLI / Cursor Grok model |

Scheduled, bounded jobs stay in Actions because that is the cheaper
token path. Event-driven repair and issue triage already have precise
GitHub triggers in Actions; they use the same checked-in prompts as
Cursor Automations so a full cloud agent can take those two jobs later
without rewriting the instructions.

Prompts live in `.github/prompts/`. The Grok CLI installer is pinned in
`scripts/install_grok_cli.sh` (`GROK_CLI_VERSION`, currently `1.0.5`).
Headless runs go through `scripts/run_grok_agent.py`.

## Cursor Automations

Cursor Automations cannot be registered from the repository; create them
at [cursor.com/automations](https://cursor.com/automations) or with the
`/automate` skill. Use model **Grok 4.6** (or newer Grok when Cursor
lists it). Attach this repository. Enable pull-request creation.

Create these two if you want a full cloud agent on the event-driven
jobs:

| Automation | Trigger | Prompt | Notes |
| --- | --- | --- | --- |
| AI maintenance | GitHub **Workflow run completed**, only failures of Build, CVE catalog sync, Content refresh, Leftover review, Production watchdog, CVE catalog validation, Automation shepherd, AI issue maintenance, and Search indexing, on `main`, `automation/*`, or `dependabot/*` | `.github/prompts/ai-maintenance.md` | The agent reads `FAILED_WORKFLOW_*` when those env vars exist; otherwise it inspects the newest matching failed run |
| AI issue maintenance | GitHub **Issue opened/reopened** for `stevologic` or `github-actions`, plus a twice-daily schedule at `41 4,16 * * *` | `.github/prompts/ai-issue-maintenance.md` | Work at most three untriaged owner/automation issues; never close `automation:production-health` or `automation:cve-enrichment-health` |

Do not also create Cursor Automations for leftover review or content
refresh. Those are daily bounded queues and should stay on the Grok CLI
in Actions.

After both Cursor Automations are live and you have seen them open a
correct repair or triage PR, disable the `AI maintenance` and
`AI issue maintenance` GitHub Actions workflows in the Actions UI so
the two brains do not open duplicate PRs. Leave leftover review,
content refresh, CVE sync, and security-health on Actions.

## Why the shepherd exists

Most events caused by `GITHUB_TOKEN` cannot provide a hands-off workflow run;
bot-created pull-request runs can require approval, while `workflow_dispatch`
and `repository_dispatch` are the direct-dispatch exceptions. Two consequences:

- A PR merged through token-enabled auto-merge produces a main revision with
  **no Build run** and therefore no deployable image.
- A PR created or updated with the token can leave its head with **no completed
  `build` check**, so its auto-merge waits forever under the ruleset.

The shepherd closes both gaps with dispatches (the allowed exception): it
dispatches `build.yml` for unbuilt main revisions and dispatches the exact-SHA
validation request for auto-merge PR heads that have none. The request performs
only API identity checks. Validation executes the catalog SHA and does not
post commit statuses. Required merge checks come from those real workflow runs.

## Merge policy

The `main` ruleset requires a PR, a passing `build` context from GitHub
Actions, and a passing `karen-qa` context posted only by the Karen QA
GitHub App after human review. Catalog validation never posts commit
statuses and never emits `karen-qa`. Required merge checks come from real
workflow runs. Catalog auto-merge waits for that app check on the exact
head; if it is missing, the sync leaves the catalog PR open and reports
that it is waiting on `karen-qa` instead of failing the run with an
opaque HTTP 405. The workflow never self-posts `karen-qa`.
`catalog_updated_at` is the NVD sync watermark (annual-feed lastModifiedDate
or lastModified of catch-up records actually merged). A KEV-only delta
must not advance it. A fetched-but-dropped catch-up row must not either.
Every automated merge (Dependabot, catalog sync, AI fixes) therefore rides
the same gate as a human change: auto-merge armed, required contexts proven
on the exact head, branch current.

## Deployment

CI publishes immutable images tagged with the exact commit SHA to GHCR. The
production droplet pulls and applies the main-branch `:SHA` images to
`security-recipes.ai` on a 15-minute `deploy.sh` cron. The same cron also
pulls `:SHA-development` images for `origin/development` into the staging
slot served at `dev.security-recipes.ai`. That hostname needs a DigitalOcean
A record at the droplet (`64.227.98.210`). `deploy.sh` creates or repairs
that record from a token in `/etc/security-recipes/deploy.env`, doctl
config, or an already-authenticated `doctl` client;
`scripts/upsert_dev_dns_record.py` and the Dev DNS record workflow
do the same when `DIGITALOCEAN_ACCESS_TOKEN` is present in GitHub Actions.
Caddy obtains the staging certificate on config load/reload, not on each
handshake. After `dev.<apex>` resolves to the droplet, `deploy.sh`
reloads Caddy when HTTPS still has no cert so ACME can retry.
The watchdog's `revision` probe
confirms the production handoff landed. Never put `secrets` in a workflow
`if:` expression: GitHub records a zero-job push failure for the file and
`deploy.sh` will refuse the SHA.

## Required configuration

| Item | Kind | Status | Purpose |
| --- | --- | --- | --- |
| `XAI_API_KEY` | secret | must be added | Billed Grok secret for leftover-gold review, content refresh, AI maintenance, AI issue maintenance, and this repository's security-health action. Catalog enrichment no longer reads it. |
| `XAI_MODEL` | variable | optional, defaults to `grok-4.6` | Model id for Grok CLI jobs and the remediations suite. Bump when xAI publishes a newer coding model. |
| `OPENAI_API_KEY` | secret | must be added for catalog enrichment | Existing Actions secret used by CVE catalog sync for official OpenAI Responses API enrichment. Do not add a second OpenAI secret. |
| `OPENAI_MODEL` | variable | optional, defaults to `gpt-5.6-luna` | Model id for catalog enrichment. For Daybreak Blue set `gpt-6-sol`. |
| `OPENAI_DAYBREAK_PROGRAM` | variable | optional, unset by default | When set to `standard`, `daybreak_blue`, or `daybreak_red`, catalog enrichment sends `access_programs.cyber`. Unset keeps plain OpenAI requests. Defensive CVE work should use `daybreak_blue`. |
| `OPENAI_ENRICHMENT_LIMIT` | variable | optional, defaults to `20` | Hard-bounded 0–50 new or source-changed CVEs enriched per catalog sync. |
| `DIGITALOCEAN_ACCESS_TOKEN` | secret or droplet `deploy.env` | optional | Lets deploy.sh and the Dev DNS record workflow create `dev.security-recipes.ai` |
| `CVE_AUTO_MERGE_ENABLED` | variable | `true` | Lets the catalog sync merge its own PR |
| `CVE_AUTOMATION_APP_CLIENT_ID` / `CVE_AUTOMATION_APP_PRIVATE_KEY` | variable / secret | optional | A dedicated GitHub App; when configured, its pushes trigger normal CI events and the dispatch workarounds above become unnecessary |
| `NVD_API_KEY` | secret | optional | Authenticated NVD CVE 2.0 rate limit for the lastMod catch-up after annual feeds. Public unauthenticated pacing is used when absent; 403/429 fail the sync instead of publishing a stalled catalog |
