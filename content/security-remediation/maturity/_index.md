---
title: Rollout & Maturity Model
linkTitle: Rollout & Maturity Model
weight: 12
sidebar:
  open: true
description: >
  Crawl / walk / run staging for adopting agentic remediation —
  pilot exit criteria, expansion signals, kill signals, and what
  to measure at each stage. A reference roadmap any organization
  can adapt.
---

{{< callout type="info" >}}
**Why this page exists.** The failure mode of agentic adoption is
not "doesn't work." It's "works for one class on one repo, then
the program owner tries to ship it org-wide Monday and discovers
the guardrails were load-bearing on accident." This page
sequences the rollout so that doesn't happen.
{{< /callout >}}

## The five stages

A realistic adoption curve runs through five stages. The jump
from one to the next is the interesting decision; no single stage
is a destination.

1. **Stage 0 — Probe.** A single engineer runs a recipe against
   their own repo, manually, reading every diff.
2. **Stage 1 — Pilot.** One workflow, one repo, scheduled. Every
   PR reviewed by the pilot team.
3. **Stage 2 — Tier-A expansion.** Same workflow, expanded to 5–10
   repos that share the same language / framework / lockfile.
4. **Stage 3 — Org-wide for that workflow.** All repos in scope,
   with routing by CODEOWNERS and the reviewer pool expanded.
5. **Stage 4 — Multi-workflow.** A second workflow (different
   finding class) layered on top of the orchestration spine.

Every stage has entry criteria, a running posture, exit criteria,
and an explicit kill signal. Skipping a stage is how programs
stall; adopting the next before the current is stable is how they
regress.

## Stage 0 — Probe

**Goal:** prove to yourself (one engineer) that the recipe does
what the docs claim, on a real repo, with real data.

**Posture:**

- One engineer, one repo, one finding class.
- Manual trigger, manual review, no scheduling.
- All prompts are read end-to-end; all guardrails are
  double-checked against the repo's actual layout.

**Exit criteria:**

- 5 consecutive clean runs against real findings.
- Engineer can narrate what the prompt does, why it stops where
  it does, and what it would do in an edge case the docs don't
  cover.

**Kill signal:**

- Any run that the engineer can't explain. Stop. Do not move to
  pilot.

**What not to do yet:**

- Onboard another repo. The guardrails tuned for Repo A rarely
  transfer cleanly.
- Wire up metrics. At this stage, a single engineer's eyes are
  the metric.

## Stage 1 — Pilot

**Goal:** prove the recipe works *without the probing engineer's
eyes* on every run.

**Posture:**

- One workflow, one repo, scheduled (hourly for SDE, on-advisory
  for SCA).
- A **named pilot team** reviews every PR and triage note.
- Weekly retros on the prompt, the guardrails, and any false
  positives.
- Full metrics set wired up (see [Program Metrics & KPIs]({{< relref "/security-remediation/metrics" >}})).

**Exit criteria** (all must hold for 30 days):

- MTTR ≤ 30% of the manual baseline.
- Merge-as-is rate ≥ 50%, trending up.
- Regression rate ≤ 1%.
- Reviewer minutes per PR ≤ 2× a comparable human-authored PR.
- Zero incidents attributable to the agent.
- The pause label has been exercised in a drill.

**Kill signal:**

- Any agent-caused production incident.
- Two consecutive weeks with regression rate > 3%.
- Reviewer burden trending up, not down.

## Stage 2 — Tier-A expansion

**Goal:** prove the workflow generalises across repos that share
the pilot repo's shape.

**Posture:**

- 5–10 repos selected for similarity (same language, same lockfile
  format, similar test coverage).
- Reviewer pool expanded — 2–3x the pilot pool.
- Per-repo opt-in. The opt-in mechanism (flag file in the repo,
  CI configuration, tag in the service catalog) is explicit and
  easy to rescind.
- Per-repo rollback playbook written down.

**Exit criteria:**

- All pilot metrics hold across the 5–10 repos, not just on
  average.
- At least one repo has exercised a rollback cleanly.
- No single repo accounts for > 40% of false positives.

**Kill signal:**

- A repo where the workflow cannot meet pilot metrics, even with
  per-repo prompt tuning — that repo comes out of scope, rather
  than the workflow being tuned to its edge cases.

**Classic mistake:** treating the Tier-A repos as "Tier A" by
default forever. Most repos either stabilise into org-wide eligible
or drop out within a quarter. Keep the tier explicit; don't let it
become a de facto production tier.

## Stage 3 — Org-wide (same workflow)

**Goal:** the workflow is running on every repo in scope, with
routing handled by the orchestrator.

**Posture:**

- CODEOWNERS-based reviewer routing so no one person is the
  single point of failure.
- Metrics dashboards in front of engineering leadership, not just
  the workflow owner.
- Opt-out, not opt-in — a repo with a CI config reaches eligible
  unless a documented reason exists.
- Monthly prompt review; quarterly model review.

**Exit criteria:**

- Stable for 90 days with pilot metrics holding.
- Compliance / audit evidence generated and reviewable (see
  [Compliance & Audit]({{< relref "/security-remediation/compliance" >}})).
- A second reviewer pool is ready (training, shadowing
  complete).

**Kill signal:**

- Reviewer pool burnout. If reviewer minutes per PR climb for two
  consecutive months, the workflow isn't scaling — pause
  expansion and tune the prompt.

## Stage 4 — Multi-workflow

**Goal:** a second workflow (different finding class) sharing the
orchestration spine.

**Posture:**

- The orchestrator treats workflows as plug-ins — adding one is a
  configuration change, not an engineering project.
- Metrics are per-workflow *and* aggregated at the program level.
- Conflict rules are explicit: if two workflows propose changes
  to the same file (e.g., SCA bump and SAST fix), the orchestrator
  serializes them, doesn't race.

**Exit criteria:**

- Each additional workflow re-enters at Stage 1 on its own; the
  spine doesn't skip pilot validation for the workflow's
  specifics.

**Kill signal:**

- Coupling between workflows. If tuning one requires changes to
  another, the orchestrator isn't as decoupled as it claims.

## Change controls at each stage

| Stage | Prompt changes | Model changes | Tool / MCP changes |
| ----- | -------------- | ------------- | ------------------ |
| 0 Probe | Free | Free | Free |
| 1 Pilot | 1 reviewer | Halts pilot; re-runs exit criteria | 1 reviewer |
| 2 Tier-A | 1 reviewer + dryrun | Re-pilot | 2 reviewers |
| 3 Org-wide | 2 reviewers, changelog | Re-pilot + staged rollout | 2 reviewers + changelog |
| 4 Multi | Per-workflow change control | Per-workflow re-pilot | Per-workflow change control |

The table is deliberately stricter as stages advance. Doing it
the other way — lighter controls when more is at stake — is how
a well-tuned pilot silently degrades in production.

## Common anti-patterns

- **The "strategic pilot."** A pilot selected for political
  visibility rather than technical fit. The metrics look
  great; the workflow never generalises.
- **The "single heroic reviewer."** One person reviews every PR.
  They leave. The program stops.
- **The "prompt scope creep."** Every failure mode adds a new
  paragraph to the prompt. Eventually the prompt is so long the
  model's instruction-following degrades. Regular prompt
  pruning is part of maintenance.
- **The "dashboard never opened."** Metrics exist, nobody reads
  them. The first time anyone notices is when an incident
  postmortem digs them out. Put the dashboard on a wall or on a
  weekly review agenda.

## See also

- [Program Metrics & KPIs]({{< relref "/security-remediation/metrics" >}}) — the numbers every stage must clear
- [Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}}) — what the reviewer pool actually does
- [Compliance & Audit]({{< relref "/security-remediation/compliance" >}}) — the evidence Stage 3 requires
- [Agentic Security Remediation]({{< relref "/security-remediation" >}}) — the workflows the stages advance through
