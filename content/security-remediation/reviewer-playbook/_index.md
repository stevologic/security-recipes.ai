---
title: Reviewer Playbook
linkTitle: Reviewer Playbook
weight: 11
date: 2026-04-22
lastmod: 2026-07-21
sidebar:
  open: true
description: >
  Review AI-agent pull requests and triage notes for scope, evidence, tests,
  rollback, authorization, and residual risk without turning approval into a
  rubber stamp.
---

{{< callout type="info" >}}
**Why this page exists.** Reviewer-gating is the linchpin of every
workflow on this site. If the review step degrades to
rubber-stamping, the agent's mistakes become the team's mistakes.
This page is the concrete checklist that keeps that from happening.
{{< /callout >}}

## The review is not a code review (alone)

An agent-opened PR needs two reviews overlaid on the same diff:

1. **A standard code review** — correctness, style, test coverage.
   The same review the team does for any PR.
2. **A provenance review** — does the PR reflect what the agent
   was *allowed* to do, and does it close the finding it claims
   to close?

The provenance review is where most agent-PR regressions get
caught. It's also the step reviewers most often skip.

{{< playbook-workflow >}}

## Proof by default

Proof by default does not mean the reviewer manually hunts for evidence after
the agent opens a PR. It means the recipe defines the evidence contract before
the agent starts, and the agent must return that proof packet as part of the
work.

The automated part is collection and formatting. A good recipe tells the agent
which command outputs, scanner re-runs, changed files, lockfile diffs, test
results, screenshots, logs, or reproduction checks belong in the PR body or
attached report. The agent can run those checks, summarize the results, and
link to the generated artifacts without asking the reviewer to discover them
from scratch.

The manual part is judgment. A human still decides whether the proof is relevant
and sufficient. Green tests are not proof if they did not exercise the vulnerable
path. A scanner clean result is not proof if the scanner did not cover the
changed component. A screenshot is not proof if it shows the wrong state. The
reviewer is checking the fit between claim, diff, and evidence.

A proof packet should answer four questions:

- **Scope:** Which one finding is this PR claiming to close?
- **Change:** Which files changed, and are they inside the recipe allowlist?
- **Validation:** Which tests, scanner re-runs, or reproduction checks ran?
- **Residual risk:** What was not checked, and why is that acceptable or a
  reason to stop?

If a PR arrives without that packet, treat it as incomplete. Ask the agent or
workflow owner to regenerate the run with the required proof instead of trying
to reconstruct it manually during review.

## Human in the loop

Human in the loop means humans own the merge decision, not every keystroke. The
agent can draft a patch, run checks, assemble the proof packet, and explain the
blast radius. A person still approves the scope, interprets ambiguous risk, and
decides whether the change is safe to merge.

The loop has three human gates:

1. **Before the run:** choose the matching recipe and confirm the finding is
   narrow enough for agent work.
2. **During the run:** stop or redirect when the agent hits an out-of-scope
   file, missing context, risky dependency, or unclear owner.
3. **Before merge:** review the diff and proof packet, then approve, reject, or
   send the PR back for a narrower retry.

This is why "human review" should link here instead of a generic agent setup
page. Agent setup explains how to give a tool instructions; this playbook
explains how a team keeps ownership of the result.

Do not turn the human gate into a ceremonial click. Require a named reviewer,
a visible checklist result, and a rejection path. If the workflow is routine
enough that reviewers start approving without reading, pause or narrow the
workflow before auto-approve drift becomes policy by accident.

## The seven-question checklist

Every agent PR gets the same seven questions before approval.
Reviewers who can't answer any one of them should push back in
the PR rather than approving and hoping.

### 1. What finding does this PR claim to close?

The PR body must link to a specific, scoped finding. "Security
cleanup" is not a finding. If the PR links to multiple findings,
that's a flag — the workflow should be one-finding-per-PR.

### 2. Does the diff stay inside the declared allowlist?

Every workflow declares a file / directory allowlist (lockfiles
for SCA, log formatters and configs for SDE, etc.). A PR that
touches files outside the allowlist is out of scope — reject
and leave a comment, don't "approve with changes."

### 3. Are the tests real?

- Did the agent *add* a test (ideal) or merely *run* existing
  tests? Added tests should fail against the old code.
- Were any tests modified to pass? That's a flag — the agent
  should not weaken assertions to satisfy the diff.
- Did CI actually run the full suite, or only a subset? Check
  the CI summary, not the PR summary.

### 4. Is the finding actually closed?

For SCA, the lockfile no longer lists the vulnerable version.
For SDE, the DLP scanner's re-run is clean in the PR checks.
For SAST / pentest-driven fixes, the reproduction steps from
the finding no longer reproduce. If the PR claims closure
without evidence, ask for it.

### 5. What's the blast radius?

The PR body should state who / what this change affects. Common
miss-cases:

- A lockfile bump that updates a shared dep consumed by a public
  SDK — downstream consumers now need to pick up the bump.
- A log-format redaction that also changes a field name that a
  dashboard or alert depends on.
- A middleware-layer authz fix that touches a header every
  downstream service already reads.

Reviewer's job: ask "who else relies on this?" and confirm the
answer is in the PR, not inferred.

### 6. Is it reversible?

Can this PR be reverted cleanly in under five minutes if prod
behaviour regresses? If the answer involves a data migration, a
config toggle that has to happen in a specific order, or
anything more than `git revert && merge`, that's a flag. Either
the agent stepped outside its scope, or the scope is wrong.

### 7. Did the agent skip anything?

- `[skip ci]` / `[skip test]` markers — reject, no exceptions.
- Commit messages that paper over changes ("cleanup," "refactor")
  when the diff is material.
- Force-pushes that rewrite history after your review started —
  re-review the whole thing.

## When to stop-and-ask the owning team

Not every review has to end in approve-or-reject. The reviewer's
third option is **redirect**: drop the PR back to the owning team
with a specific question. Good reasons to redirect:

- The fix looks correct but depends on behaviour the reviewer
  can't verify from inside the PR (feature flags, environment
  variables, downstream consumers).
- The finding is legitimate but the chosen remediation pattern
  doesn't match house conventions (e.g., ad-hoc `if` check where
  policy middleware already exists).
- The diff is correct but the test added doesn't actually exercise
  the fix path.

Redirecting is not a rejection — it's an acknowledgement that the
owning team has context the reviewer doesn't.

## Signs the prompt needs tuning

Reviewers are the fastest source of prompt-drift signal. Escalate
the following patterns to whoever owns the workflow, not just to
the current PR:

- Same class of false positive showing up across multiple repos
  in a week.
- Repeatedly-identical PR bodies with boilerplate the reviewer
  has to skim past — signal the prompt is over-verbose.
- The agent picking the same (wrong) remediation pattern for a
  specific finding type — the prompt's category guidance is off.
- Repeated triage notes citing the same stop condition — either
  tighten eligibility (so the agent stops earlier) or broaden the
  prompt (so it can handle it).

A simple log (shared doc, issue tracker label, Slack channel) of
"reviewer observations" per week is enough. What matters is that
signals land somewhere the workflow owner reads.

## Escape valves

### The decline-cleanly template

When rejecting, leave a comment that names exactly one of:

- **Out of scope.** The agent touched files it shouldn't have.
- **Wrong pattern.** The fix direction doesn't match house conventions.
- **Insufficient evidence.** The closure claim isn't backed by a
  re-run.
- **Blast radius unclear.** Need more context before merge.

Those four buckets cover ~95% of rejections. Tagging them
consistently gives workflow owners the per-week histogram they
need.

### The pause label

If a workflow is producing enough noise that every PR feels like
a liability, pause the workflow. Every recipe on this site ships
with a pause mechanism (a label, a flag, or an MCP call). Use it —
it is better to have a paused workflow than a bad-PR firehose.

## Reviewer onboarding

A new reviewer is ready to gate agent PRs after:

1. **Shadow review** — they sit with an experienced reviewer on
   10 PRs across at least two workflows.
2. **Co-review** — they write their own review; the experienced
   reviewer signs off before the agent PR merges. 10 PRs.
3. **Solo review with backup** — they approve independently, but
   a second reviewer is designated for any escalation. 2 weeks.

Only then are they listed as a primary reviewer on the workflow.
The seven-question checklist is their running reference.

## Anti-patterns to call out

- **"LGTM" with no comment** — if the diff warranted no comment,
  at least tag which checklist items were verified (a short
  copy-paste is fine).
- **Review-by-CI** — CI is green, so approve. CI is necessary,
  not sufficient; the seven questions above are not automatable.
- **Reviewer-as-editor** — pushing commits to the branch instead
  of asking the agent to retry. Doing that hides the drift; the
  next PR from the same workflow will make the same mistake.
- **Serial approver** — one person approves every agent PR. Means
  one person is the single point of failure. Distribute.
- **Auto-approve drift.** Published telemetry from multiple agent
  vendors now shows reviewer auto-approve rates climbing with
  session count — roughly doubling between a reviewer's first
  ~50 agent PRs and their ~500th. Autonomy is being quietly
  *co-constructed* between agent and reviewer; no one decided to
  hand over more trust, it just accumulated. Defense: pre-declare
  which approval types must remain manual no matter how routine
  the workflow feels — secrets writes, dependency manifest edits,
  CI / pipeline changes, MCP client config, and any prompt /
  skill / rule file. Track per-reviewer auto-approve rate over
  time (see
  [Program Metrics → auto-approve drift]({{< relref "/security-remediation/metrics#auto-approve-drift" >}}));
  a steadily-rising line is the signal that the habit is
  degrading even though no single PR looks wrong.

## See also

- [Program Metrics & KPIs]({{< relref "/security-remediation/metrics" >}}) — the reviewer-burden and merge-as-is numbers
- [Rollout & Maturity Model]({{< relref "/security-remediation/maturity" >}}) — when to expand, when to pause
- [Sensitive Data Element Remediation]({{< relref "/security-remediation/sensitive-data" >}}) — example allowlist and closure checks
- [Vulnerable Dependency Remediation]({{< relref "/security-remediation/vulnerable-dependencies" >}}) — example guardrails and evidence expectations
