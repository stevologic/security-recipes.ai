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

GitHub Actions is the clock and host. Catalog enrichment defaults to
xAI `grok-4.7` via `CVE_ENRICH_MODEL`. OpenAI/Daybreak stay dormant
behind that same variable. Grok remains the billed brain for the
other first-party jobs below. Optional `NVD_API_KEY` is passed only
into the catalog sync step so lastMod catch-up can use the
authenticated NVD rate limit.

| Job | Host | Brain |
| --- | --- | --- |
| CVE catalog enrichment | Actions (`cve-catalog-sync.yml`) | xAI Responses API (`grok-4.7` unless `CVE_ENRICH_MODEL` is set; OpenAI/Daybreak via `gpt-6-sol+daybreak_blue`) |
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

## CVE catalog sync budget

`cve-catalog-sync.yml` uses `timeout-minutes: 150`. NVD fetches go through
`fetch_bytes` (`FETCH_DEADLINE_SECONDS = 300`, `FETCH_READ_CHUNK_SIZE = 64 KiB`)
with five attempts, a 180s per-read socket timeout, equal jitter on 5xx and
transport retries, and no sleep after the final attempt. One timer closes
the socket at the URL deadline so connect, headers, `read1()` body chunks,
and every redirect hop share the same cap. Each read uses
`min(per-read timeout, remaining deadline)` so the per-read timeout
shrinks as the deadline runs down.

```
PR #421 worst case per URL
  5 × 180s socket timeout          = 900s
  sleeps after all 5 attempts
    1 + 2 + 4 + 8 + 16             =  31s
                                 ≈ 931s ≈ 15.5 min/URL
  plus an unbounded body drip: urlopen's timeout is per
  socket read, HTTPResponse.read(n) loops until n bytes,
  and every recv resets the timeout. Karen: 1 byte / 0.5s
  against a 3s deadline returned after 49.5s; a 200 KB
  body ran past 120s. 10 redirect hops at 0.8s each took
  8s because each hop reused the full timeout.

This follow-up
  wall-clock deadline              = 300s = 5 min/URL
  deadline timer closes the socket
  read1() body chunks + per-read
    socket timeout                 = min(180s, remaining)
  sleeps only between attempts
    1 + 2 + 4 + 8                  ≤  15s (inside the deadline)
```

Catch-up can publish many successful lastMod pages before a later page
fails and is skipped. Each successful page can take the full 5 min
deadline (`NVD_API_PAGE_SIZE = 2000`, `NVD_API_MAX_PAGES = 15` per
120-day window). The previous 50-page cap at 5 min/page is 250 min and
would be cut off by the 150-minute job timeout, not the URL deadline.

Measured non-synchronize tail (max of each step across successful runs
39344800710, 39285941896, 39131123938, 39034763704, 38912226589):

```
setup through cache restore     0.6 min
generator + validate + tests    1.9 min
PR open + labels                0.3 min
exact-SHA delivery              8.3 min
other post-sync                 0.2 min
                              ≈ 11.3 min
```

Observed synchronize on those same successful runs (annual feeds +
enrichment, before the Oct 20–21 lastMod stall) is 23–43 min. Failed
run 39623444175 spent 106.2 min in synchronize and then skipped the
tail after `response.read()` raised `IncompleteRead` on a lastMod page.

Headroom after a 15-page stalled catch-up (each page at the 5 min cap,
which is also the code cap):

```
43 min observed feeds + enrichment
+ 15 × 5 min successful catch-up pages = 75 min
+ 11.3 min measured tail
= 129.3 min
150 − 129.3 = 20.7 min headroom
```

A skipped catch-up or a catalog PR waiting on `karen-qa` emits a
`::warning::` annotation plus a step-summary line. The workflow never
self-posts `karen-qa`. A data-only catalog PR that branch protection
still blocks is labeled `automation:protection-fallback` and the run
exits successfully so the next sync can retry, unless the same PR has
been in protection-fallback on 2 consecutive runs or whose fallback
label is older than 24h, in which case the run fails as a real alert.
The 24h clock starts when the fallback label is applied, not when the
PR was opened. Enrichment request or
time-budget leftovers (unprocessed candidates only) are written to
`data/cve/enrichment-carryover.json` and selected first on the next run;
that carry-over is not an alert. CVEs that fail enrichment are dropped
and are not carried over.

## Merge policy

The `main` ruleset requires a PR, a passing `build` context from GitHub
Actions, and a passing `karen-qa` context posted only by the Karen QA
GitHub App after human review. Catalog validation never posts commit
statuses and never emits `karen-qa`. Required merge checks come from real
workflow runs.

A catalog PR written by the CVE sync bot that changes **only**
allowlisted catalog data paths (`static/api/cve-catalog/`,
`content/recipes/cve/*.md`, `data/cve/ai-enrichments.json`,
`data/cve/ai-generated-recipes.json`, and
`data/cve/enrichment-carryover.json`) is data-only: it never needs
`karen-qa` or the CVE automation GitHub App. Prefix matching uses a
directory boundary, so `static/api/cve-catalog-evil/x` is not
allowlisted. `content/recipes/cve/` accepts only `*.md` files;
`content/recipes/cve/evil.py` fails closed. Pipeline outputs that change
MCP/gateway behaviour (`data/policy/mcp-gateway-policy.json`,
`data/context/secure-context-release-pack.json`,
`scripts/generated-output-ownership.json`, and `data/evidence/`) are
**not** allowlisted. The sync stages those files onto a separate branch
(`automation/cve-generated-outputs`) and opens a review PR labeled
`needs karen-qa` that is never self-merged. If they did not change, no
review PR is opened. A failure opening that review PR does not fail
the catalog PR delivery; the sync then raises a real alert (not a
warning) so a missed review is not silent. Catalog-only exact-SHA
validation scopes generator freshness to CVE-owned outputs and reports
Karen-gated evidence, policy, context, and ownership packs as pending
on `automation/cve-generated-outputs` instead of failing. Scope applies
only when `CVE_CATALOG_VALIDATION` is set and the exact-SHA diff vs
`CVE_CATALOG_VALIDATION_BASE` is data-only. A missing base fails closed
to the full freshness check. Only those generated-output paths are
Karen-gated; stale CVE-owned or unrelated outputs still block. Main and
non-catalog PRs still require every deterministic generator to pass
`--check`.

Self-merge is never gated on the PR author (`github-actions[bot]` can be
spoofed by any `GITHUB_TOKEN` workflow). The gate is all of: (a) the
exact-SHA diff vs base touches only those allowlisted paths, with no
rename out of or into a code path, symlink, or mode change; (b) a
passing exact-SHA validation produced inside this sync run on that SHA;
and (c) the head branch is `automation/cve-catalog-sync` and the head
SHA matches what this run pushed. The required `build` check is not
authentication; the path gate is the control. Dispatching
`cve-catalog-validate.yml` (job name `build`) on the catalog PR head
when the App is absent only attaches a real GitHub Actions check-run on
that SHA. It then merges with `match-head-commit`. If protection still
blocks the merge, the run leaves the PR open, labeled, and summarized,
and exits successfully; the next sync retries. If the same catalog PR
has been in protection-fallback on 2 consecutive runs or whose fallback
label is older than 24h, the run fails as a real alert. An already-merged catalog PR is
idempotent only when its head or merge SHA equals the expected SHA;
otherwise the run fails closed. A non-data-only diff (workflow, script,
docs, MCP server, non-`*.md` recipe, path traversal, symlink, mode
change, or rename into a code path) fails closed and still requires
`karen-qa` plus real checks.

Catalog auto-merge waits for that app check on a non-data-only exact
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
| `XAI_API_KEY` | secret | must be added | Billed Grok secret for catalog enrichment (`CVE_ENRICH_MODEL=grok-4.7`), leftover-gold review, content refresh, AI maintenance, AI issue maintenance, and this repository's security-health action. |
| `XAI_MODEL` | variable | optional, defaults to `grok-4.6` | Model id for Grok CLI jobs and the remediations suite. Bump when xAI publishes a newer coding model. Independent of catalog `CVE_ENRICH_MODEL`. |
| `CVE_ENRICH_MODEL` | variable | optional, defaults to `grok-4.7` | Single catalog provider/model switch. `grok-*` uses xAI/`XAI_API_KEY`. `gpt-*` uses OpenAI/`OPENAI_API_KEY`. Daybreak later: `gpt-6-sol+daybreak_blue`. |
| `OPENAI_API_KEY` | secret | optional until Daybreak | Existing Actions secret used only when `CVE_ENRICH_MODEL` selects an OpenAI model. |
| `OPENAI_DAYBREAK_PROGRAM` | variable | optional, unset by default | OpenAI-only overlay when `CVE_ENRICH_MODEL` is a `gpt-*` model without a `+program` suffix. Ignored for `grok-*`. |
| `CVE_ENRICHMENT_LIMIT` | variable | optional, defaults to `20` | Hard-bounded 0–50 new or source-changed CVEs enriched per catalog sync. |
| `DIGITALOCEAN_ACCESS_TOKEN` | secret or droplet `deploy.env` | optional | Lets deploy.sh and the Dev DNS record workflow create `dev.security-recipes.ai` |
| `CVE_AUTO_MERGE_ENABLED` | variable | `true` | Lets the catalog sync merge its own PR |
| `CVE_AUTOMATION_APP_CLIENT_ID` / `CVE_AUTOMATION_APP_PRIVATE_KEY` | variable / secret | optional | A dedicated GitHub App; when configured, its pushes trigger normal CI events and the dispatch workarounds above become unnecessary |
| `NVD_API_KEY` | secret | optional | Authenticated NVD CVE 2.0 rate limit for the lastMod catch-up after annual feeds. Public unauthenticated pacing is used when absent; 403/429 fail the sync instead of publishing a stalled catalog |
