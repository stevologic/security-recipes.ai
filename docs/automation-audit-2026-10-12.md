# Automation audit — 2026-10-12

This audit is scoped to `stevologic/security-recipes.ai`. It creates reviewable
changes for `development`; it does not merge or deploy them. Repository-wide
ownership remains `@stevologic` (including `.github/`). No credentials, access
grants, subscriptions, spend limits, or repository security settings change.

## Reconciliation and existing work

- Main: `cee14aacb46d9b1e33b2db8a0ef55ffd2407b545`; latest Build succeeded in
  [run 38185545489](https://github.com/stevologic/security-recipes.ai/actions/runs/38185545489).
- Development: `262964d498c8ad71e17ef30d8320203a4c84c9e7`, 3 ahead / 79 behind
  main. Its unique commits are `5a616624` (generated September CVE snapshot),
  `35668d56` (owner-authored cost reductions), and `262964d4` (matching tests).
  A reconciliation commit must retain both parents; do not reset this branch.
- The owner's 25-page leftover limit and daily issue sweep already reached
  main. Main subsequently added explicit dispatch kicks and a periodic
  shepherd backstop for token-authored changes that suppress event delivery.
  Keep those corrections; reduce the backstop to hourly.
- Development has 441 cached enrichments versus main's 442. All 40 IDs unique
  to development fail `enrichment_errors` against the current October catalog
  because their source fingerprints are stale. Keep their historical commit,
  use main's current verified generated snapshot, and do not publish stale
  enrichment as current evidence. 294 shared entries are identical; 107 differ.
- [Issue #289](https://github.com/stevologic/security-recipes.ai/issues/289)
  was resolved by merged #290 (`e9220170`) on September 8. Closed with that
  evidence and current main CI. Direct live XML verification was blocked by
  this environment's network gateway, so no fresh production probe is claimed.
- [Issue #349](https://github.com/stevologic/security-recipes.ai/issues/349)
  stays open and owned by catalog recovery. Its latest report selected 20,
  generated 6, failed 0, and left 14 unprocessed. Do not close a health issue
  until its own recovery path observes success.
- [PR #361](https://github.com/stevologic/security-recipes.ai/pull/361) changes
  only Ruff's minimum to 0.16.10. Exact-head Build passed, but the branch is
  behind and Dependabot classifies the update as semver-major. Reviewed with
  that evidence; no policy bypass or merge. New version updates target
  development and retain full checks and owner review.
- Recent merged SEO #381 and MCP #380/#378/#375 work is already present. No
  duplicate content or CVE-refresh PR is introduced.

## Schedule and task matrix

Times are UTC unless specified. Before means deployed main at the audit SHA.
Source refresh and consequential intelligence remain separate operations:
NVD/CISA ingestion, hashing, cache selection, validation, and delivery use no
LLM. Only bounded supplemental enrichment uses a model.

| Workflow/task | Before | Proposed | Reason / bounds |
| --- | --- | --- | --- |
| Build | main/development push, all PRs, dispatch | unchanged | Full lint/test/catalog/build/performance/container gates; exact revision images |
| CVE ingestion | daily 09:23 | unchanged | Daily source freshness; verified annual-feed cache and integrity hashes |
| CVE intelligence | at most 20 requests; xAI `grok-4.6` | default at most 5; `XAI_CVE_MODEL` override | Observed throughput is 6–9 per 15-minute budget; limits remain 0–50 and cached/source-changed selection stays intact |
| Content refresh | daily 11:47; Grok CLI | daily 12:17; `XAI_CONTENT_MODEL` | Start after the CVE job's 150-minute maximum window; at most one sourced topic; overdue watched packs retain daily attention |
| Leftover review | daily 13:17; probe before queue | Monday 14:17; queue before probe; `XAI_LEFTOVER_MODEL` | Queue is empty; retain dispatch and 25-page cap, avoid paid probes and CLI setup on empty queues |
| Production watchdog | twice hourly 17/47 | unchanged | Cheap deterministic availability/TLS/revision/freshness checks; 6-hour sync-heal cooldown |
| Shepherd | twice hourly 07/37 plus events/kicks | hourly 07 plus events/kicks | 336 → 168 scheduled starts/week; preserve token-event suppression recovery and two-attempt Build limit |
| AI repair | workflow failures; Grok CLI | same triggers; `XAI_REPAIR_MODEL` | Separate slot per failed run prevents dropped investigations; never retry real defects blindly |
| AI issue triage | owner events, workflow completions, daily 16:41 | same triggers; `XAI_TRIAGE_MODEL` | Check issue queue before model setup; correct stale documentation that claimed twice daily |
| Security health | all PRs, Monday 05:23; name-ranked automatic model | same cadence; explicit `XAI_HEALTH_MODEL` | Avoid inferring price or security-review quality from model names |
| Search indexing | daily 07:53 and every successful Build | daily 15:53 and successful production-main Builds | Skip PR/staging completions; verify the completed revision is live before submission; daily sweep covers deploy lag |
| CVE exact-SHA validation | explicit dispatch | unchanged | Read-only code execution, separate status writer, exact-head factual/security gates |
| CVE validation request | legacy dispatch-only identity check | retained | Current main dispatches validation directly; do not delete a useful legacy entry point without caller evidence |
| CVE 500k scale proof | monthly first day 05:17 | unchanged | Expensive deterministic scaling proof stays outside routine CI |
| Dev DNS repair | dispatch, main PR, successful Build main/development | dispatch and successful non-PR branch Builds; default-branch scripts | Prevent PR-selected code from receiving cloud/SSH secrets; preserve credential names and operator ownership |
| Dependency version updates | five Monday 06:00 Phoenix checks, main | grouped weekly development PRs, limit 3/ecosystem, staggered weekdays | npm Mon; pip Tue; Docker Wed 06:00; Compose Wed 07:00; Actions Thu; no LLM |
| Dependency security updates | GitHub alert-driven default-branch updates | unchanged | GitHub always targets security updates at the default branch; weekly version cadence does not delay them |

These reductions describe starts and request caps, not measured dollar savings.
This is a public repository: standard GitHub-hosted Actions usage is distinct
from paid provider tokens, custom/larger runners, and storage. Actual provider
usage and runner charges need billing data unavailable to this session.

## Model availability and provider boundaries

All first-party model workflows currently use xAI and `XAI_API_KEY`. Successful
authenticated Responses and Grok Build execution of `grok-4.6` are visible in
[content run 38156839855](https://github.com/stevologic/security-recipes.ai/actions/runs/38156839855)
and the October 11 catalog run. That is the demonstrated default. Each task's
new variable falls back to the existing `XAI_MODEL`, then this default; the
provider and API paths stay intact. A definitive HTTP 400/404 probe rejection
now disables paid work instead of being treated as transient readiness.

The user's xAI preference is `grok-4.7`. Its official
[model documentation](https://docs.x.ai/developers/models) identifies that API
ID and lists $2 input / $6 output per million tokens. This session has no xAI
credential to validate that model's account access or CLI quality. Do not claim
a migration or a cheaper model has passed evaluation. Select the task override
after an authenticated probe and representative evidence/review fixtures pass.

The user explicitly permits OpenAI Daybreak for CVE intelligence when existing
authenticated access supports it. The official
[Daybreak API guide](https://developers.openai.com/api/docs/guides/daybreak)
documents `gpt-6-sol` + `access_programs.cyber=daybreak_blue`; it also documents
`gpt-5.6-cyber` + `daybreak_red`, with separate organization/project approval.
Daybreak is an access program, not a model ID. The
[Cyber model page](https://developers.openai.com/api/docs/models/gpt-5.6-cyber)
lists $12.50 input / $75 output per million tokens; use a premium cyber model
only for work that benefits from it, not deterministic ingestion.

**Concrete blocker:** no `OPENAI_API_KEY` is exposed to this execution
environment, no Daybreak invocation tool is available, and the GitHub connector
cannot reveal or invoke repository provider secrets. Local API HTTPS calls also
receive gateway HTTP 403. Authenticated model/program availability therefore
cannot be verified. No Daybreak identifier is invented, no cross-provider
fallback is added, and the existing CVE provider remains unchanged pending
verification. No new secret, access grant, or purchase is requested or created.
The GPT-6.1 Sol everyday-work and GPT-6 Astra Ultra preferences apply to OpenAI
tasks; this repository has none currently. Do not move existing xAI jobs merely
to apply those roles.

## Quality, cost, and autonomy boundaries

- Preserve concurrency and exact-SHA checks. A common repair concurrency slot
  can drop pending work, so failure investigations remain keyed by run ID.
- Preserve source fingerprints, the 15-minute enrichment budget, retry/circuit
  breaker limits, reviewed Markdown precedence, factual evidence qualification,
  noindex behavior, and generated-recipe ownership/collision handling.
- Scheduled intelligence acts on bounded queues. CLI agents remain expensive
  compared with deterministic selection; inspect open work before starting.
- Actions remain SHA-pinned. `actions/setup-node` advances from v7.0.0 to
  verified release v7.1.0 (`949feb2413d6458794dcd2491c4babbbce0c15c1`),
  which adds Node-version validation and manifest-fetch retries. Checkout
  v7.0.1, setup-python v7.0.0, cache v6.1.0, and fetch-metadata v3.1.0 match
  their current published releases. The working Grok CLI pin stays intact.
  Dependabot supplies grouped,
  tested updates. The prior leftover prompt's volatile 33/24/57 count assertion
  becomes a manifest/policy check to avoid repair churn on ordinary refreshes.
- Preserve security-health advisory status (`fail-on: never`) and required
  factual/test/build checks; do not promote advisory LLM opinion to authority.
- Feature changes enter `development` via draft PR. After its full Build and
  staging validation, prepare a reviewed promotion PR to main. Main's existing
  deployment remains the release handoff; no merge/deploy authority is assumed.
- Existing scheduled catalog delivery is not silently rewritten into a new
  promotion system before that system is available and validated. Its custom
  gates and ownership remain explicit adoption constraints for the shared
  maintenance contract. Do not install a shared action without its published
  contract, immutable SHA, tests, and compatibility review.

## README evidence and local validation limits

README images are now one explicitly labeled, generated editorial photograph
of advisory/patch/proof review. No fabricated UI, badge images, or stale
screenshots remain in README files. Pixel inspection, optimized dimensions,
alt text, and provenance are recorded in
[the image record](../.github/readme/README.md). The WebP is 93,892 bytes.

The local package gateway blocks npm/PyPI downloads (HTTP 403); Eleventy,
FastMCP, Markdown, tomli, and Ruff cannot be installed here. Full checks/build
must remain blocking in integration CI. Focused stdlib Python checks and
available Node checks are run locally; missing prerequisites are reported
rather than bypassed. The first full Python discovery ran 704 tests with seven
missing-Markdown import errors, three skips, and four schedule assertions that
were subsequently aligned with the proposed clocks.


### Final local verification

- Focused Python suite: 209 tests passed, including real IndexNow workflow
  execution under a fake HTTP transport, paid-probe rejection, source/cache
  handling, and the exact-SHA delivery and workflow gates.
- Full Python discovery: 707 tests ran; no assertion failures, seven import
  errors from missing `Markdown`, and three skips.
- Full Node discovery: 124 tests, 105 passed, 19 module-load failures from
  missing `gray-matter`, `js-yaml`, `markdown-it`, or `nunjucks`.
- Catalog validation: 298,244 records, 37 indexable records, no failures or
  warnings. Python compilation, workflow YAML, 91 Bash run-block syntax checks,
  57/57 generated-artifact freshness checks, and `git diff --check` passed.
- `python scripts/run_checks.py` stops at missing Ruff. `npm run build` stops
  at missing FastMCP in its prerequisite gate. These gates remain enforced;
  no unvalidated promotion to main is created.


### Integration findings and shared-action adoption

Build run 38216515021 passed the full repository checks (including Ruff and
859 Python tests), site/performance gates, and deployment-image validation.
The advisory Security health run completed using authenticated xAI `grok-4.6`,
but reported supply-chain and container **fail** verdicts under the existing
`fail-on: never` policy. Workflow success is not a clean security verdict.

One actionable boundary is corrected here: Dev DNS no longer runs on PRs or
PR-origin Build completions, and repair scripts always come from the protected
default branch before cloud/SSH secrets reach repository code. Existing Docker
mutable tags/root runtime, unhashed Python installs, and AI auto-merge review
controls remain explicit findings for owner follow-up, not assumed fixes.
Main's ruleset is active; development's existing ruleset is disabled. This
draft arms no auto-merge and changes no ruleset or access grant. Development
review and full staging validation remain required before promotion.

The shared maintenance pilot is owner-reviewed work at
https://github.com/stevologic/oss-deps-explorer/pull/32, with proposed immutable
source `actions/maintenance@5e2d7d9b9bf38b5206105168350a817ab3d6c75d`.
Adoption requires the pilot's combined-tree CI, a least-privilege GET-only
policy, cache/artifact and token-boundary review, and compatibility with this
repository's custom CVE/content/validation/deployment gates. Do not infer merge,
close, branch deletion, deployment, model access, or spending authority from
that inventory contract. No shared workflow is enabled by this change.
