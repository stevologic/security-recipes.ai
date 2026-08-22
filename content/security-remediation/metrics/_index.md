---
title: Program Metrics & KPIs
linkTitle: Program Metrics & KPIs
weight: 10
date: 2026-04-22
lastmod: 2026-08-21
sidebar:
  open: true
description: >
  Measure an AI vulnerability remediation program with time-to-remediate,
  agent acceptance, reviewer burden, escaped defects, rollback, and risk
  reduction.
---

{{< callout type="info" >}}
**Why this page exists.** A remediation program without numbers is
indistinguishable from a status meeting. This page lists the
measurements that let a security team (a) demonstrate risk is
actually dropping, (b) catch quality regressions early, and (c)
decide which workflows to expand, pause, or retire.
{{< /callout >}}

## What to count

Six KPI families cover most of the questions leadership, audit,
and engineering management actually ask. Pick a baseline cadence
(weekly for program ops, monthly for leadership, quarterly for
audit) and keep the same definitions over time — the trend is
more useful than any single reading.

### 1. Time-to-remediate (TTR / MTTR / MTTC)

Time from **finding opened** to **fix merged** (or **finding
closed** for ticket-only workflows). Track the distribution, not
just the mean — the p50, p90, and p99 tell three different stories.

- **Before vs. after.** The single most useful chart in the program.
  TTR for findings that go through an agentic workflow vs. the
  manual baseline for the same finding class.
- **Per severity.** Critical / High / Medium / Low curves should
  diverge. If they don't, the triage gate isn't working.
- **Per workflow.** SCA, SDE, SAST — one curve per remediation class.

### 2. Agent acceptance rate

Of PRs the agent opens, what fraction merge without reviewer-forced
code changes?

- **Merge-as-is rate** — merged with zero reviewer commits.
- **Merge-with-edits rate** — merged after reviewer pushed changes.
- **Rejection rate** — closed without merge.

A healthy program sits at **70–90% merge-as-is** for a mature
workflow and **50–70%** for a new one. Below 50%, the prompt or
the eligibility gate needs work.

### 3. Reviewer burden

Reviewing agent PRs is work. Measure it.

- **Reviewer minutes per PR** — from opening the PR to first review
  decision, by reviewer (humans under-report, GitHub timestamps
  don't).
- **Escalations to on-call per week** — the PR-reviewer-can't-decide
  signal. A rising number means the prompt is drifting out of
  scope.
- **Queue depth** — open unresolved agent PRs, trended. A growing
  queue means the agent is producing faster than humans can review,
  which is a throttling decision, not a success.

#### Auto-approve drift

A sub-metric inside reviewer burden, and the one most worth
graphing on its own. Published vendor telemetry through 2025–2026
showed reviewer auto-approve rates on agent PRs roughly *doubling*
between a reviewer's first ~50 PRs and their ~500th — trust gets
co-constructed silently as the workflow feels routine. This is the
quantitative form of the rubber-stamp anti-pattern in the
[Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook#anti-patterns-to-call-out" >}}).

- **Per-reviewer auto-approve rate over time.** Bucket reviewers
  by cumulative agent-PR count (0–50, 51–200, 201–500, 500+) and
  track the merge-as-is rate in each bucket. A healthy program
  shows the rate converging, not climbing.
- **Time-to-first-comment.** As a drift proxy: the median time
  between PR open and the reviewer's first substantive comment,
  per reviewer, per workflow. When it compresses below roughly
  sixty seconds for non-trivial diffs, the review is almost
  certainly being skimmed.
- **Manual-review-required tag coverage.** A small fixed list of
  change classes (secret writes, dep-manifest edits, CI config,
  MCP client config, prompt / skill / rule files) is tagged by
  the orchestrator. Auto-approve rate on tagged PRs should be
  zero by policy. Anything non-zero here is an incident, not a
  trend.

### 4. False-positive and false-negative rates

- **False positives** — agent opened a PR that the reviewer
  concluded was not actually a fix, or the finding was a known
  no-op. FP rate is the anchor for prompt-tuning work.
- **False negatives** — findings that should have been eligible but
  were routed to manual triage. Harder to measure; sample the
  triage queue and relabel a cohort each quarter.
- **Regression rate** — PRs that merged and later got reverted.
  This is the quality signal that matters most; it's the
  downstream cost of everything else being misconfigured.
- **Invented-floor stops** — runs that correctly wrote TRIAGE.md
  because no vendor or GHSA named a patched release. Count these
  as successful control outcomes, not automation failures.

### 5. Cost

Agentic work is not free. Measure the whole cost, not just the
line item.

- **LLM cost per finding** — tokens × price, attributed to the
  workflow.
- **Reviewer cost per finding** — reviewer minutes × loaded rate.
- **Platform cost** — MCP gateway infrastructure, sandbox runtime
  seats, observability.
- **Avoided cost** — engineer-hours saved vs. the manual baseline.
  Subtract the three costs above from this to get the net.

If the net is negative at the program level, pause the workflow and
revisit the task selection, evidence quality, and reviewer burden.

### 6. Coverage

What fraction of findings in scope actually reach the agent?

- **Eligibility rate** — of total findings in a workflow class,
  how many the classifier marks eligible.
- **Repo coverage** — of repos in scope, how many have opted in
  (if opt-in) or have the runtime wired up (if opt-out).
- **Language / ecosystem coverage** — which lockfile types,
  frameworks, or deployment targets are supported today vs. the
  long tail.

{{< playbook-workflow >}}

## What a good month looks like

A single example report — the trends, not the numbers — that a
program manager can paste into a deck:

> **SCA workflow, month over month.** MTTR down from 14 days
> (p50) to 2 days (p50). Merge-as-is rate 82%. Reviewer minutes
> per PR holding at 4. Regression rate 0.4% (one revert, root
> cause: flaky test unrelated to the bump). Eligibility rate 63%
> — up from 58%, driven by Python `uv` support shipping. Net cost
> −$18k / month (savings) after LLM, reviewer, and platform costs.

The point is not the specific numbers; it's that every workflow
has *all six families* measured and every number has a defined,
stable source of truth.

## Where the numbers come from

Keep the measurement stack boring and separate from the
orchestrator. If the orchestrator computes its own KPIs, no one
trusts them.

- **Finding lifecycle events** — source systems emit (or are polled
  for): `finding_opened`, `finding_closed`, `finding_reopened`.
- **PR lifecycle** — GitHub / GitLab webhooks: `pr_opened`,
  `pr_merged`, `pr_closed`, `pr_commented_by_reviewer`.
- **Orchestrator runs** — queue-depth, dispatch decisions,
  triage-note counts, agent-stop reasons.
- **LLM billing** — per-run token counts from the agent platform
  plus the posted rate card.
- **Reviewer timing** — `pr_review_submitted` minus `pr_opened`
  per reviewer per PR, aggregated.

Pipe all of it into the same warehouse as the rest of engineering
KPIs (Snowflake, BigQuery, etc.). Dashboards live next to the
DORA metrics, not in a separate security portal.

## KPIs for a new workflow (the pilot pack)

Before promoting a workflow from "pilot" to "active," the
following readings should stabilise:

- **MTTR** ≤ 30% of the manual baseline for the same finding class.
- **Merge-as-is rate** ≥ 50%, trending up week over week.
- **Regression rate** ≤ 1%.
- **Reviewer minutes per PR** within 2× the baseline for a
  comparable human-authored PR.
- **Eligibility rate** ≥ 40% (so the workflow is actually
  absorbing enough volume to matter).
- **Cost per finding** ≤ the blended cost of a human remediator
  (loaded) for the same class.

If any of those miss, fix before expanding — don't expand hoping
the averages come in.

## Kill signals

Turn a workflow off when any of the following holds, and don't
turn it back on until the root cause is understood:

- Regression rate > 3% over a rolling 2-week window.
- Reviewer escalations > 10% of PRs for two consecutive weeks.
- A single repo concentrates > 40% of rejections (often a sign the
  classifier is misrouting).
- Any incident where the agent caused a production outage, no
  matter how small.
- Auto-approve rate on any manual-review-required change class
  is greater than zero, even once. That's not a trend; it's a
  control failure.
- Per-reviewer auto-approve rate climbing > 10 percentage points
  quarter over quarter with no corresponding drop in regression
  rate — trust is accumulating faster than the agent is earning
  it.

## What not to measure (or: anti-metrics)

- **Raw PR count.** Counts reward the agent for opening more PRs,
  not for closing risk. Use findings closed instead.
- **Token count per PR.** The LLM budget is a cost, not a goal.
  Optimising tokens without watching quality is how prompt quality
  gets quietly destroyed.
- **Reviewer approvals per hour.** Rewards rubber-stamping. If the
  program needs a throughput number, use findings closed.

## See also

- [Agentic Security Remediation]({{< relref "/security-remediation" >}}) — the workflows the metrics cover
- [Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}}) — the human-in-the-loop side
- [Rollout & Maturity Model]({{< relref "/security-remediation/maturity" >}}) — how the numbers gate stage changes
- [Agentic AIVSS Risk Scoring]({{< relref "/security-remediation/agentic-aivss-risk-scoring" >}}) — a reviewable way to score agent-specific likelihood, impact, and control strength
- [Automation]({{< relref "/automation" >}}) — the deterministic baseline the agent is compared against
