---
title: "Agent session — telemetry-driven kill rules"
linkTitle: "Telemetry-driven session kill rules"
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["runtime", "telemetry", "guardrail", "kill-switch", "monitor"]
weight: 15
date: 2026-04-25
lastmod: 2026-08-21
---

A tool-agnostic prompt that takes a workflow's run telemetry
and a draft set of decision rules, and produces (a) a vetted
rule pack the session monitor can load and (b) a synthetic
red-team exercise the program owner runs to verify the rules
fire correctly.

This is a **guardrail-design prompt**, not a remediation
prompt. The agent's job is to design and pressure-test the
rules; humans deploy them.

Designed to slot into the
[Runtime Controls]({{< relref "/security-remediation/runtime-controls" >}})
workflow.

## What this prompt does

1. **Reads 30 days of run telemetry** for the workflow — tool
   call rates, scope distributions, argument shapes, result
   sizes, budget usage, egress events.
2. **Computes baselines** (median, p95, p99) per signal.
3. **Drafts a rule pack** with three layers — threshold rules,
   deviation rules, pattern rules — each with explicit
   thresholds tuned against the baseline.
4. **Designs synthetic red-team exercises** that simulate each
   failure mode (scope creep, exfiltration, prompt drift,
   budget runaway) and predicts which rule should fire.
5. **Outputs** the rule pack and the exercise plan as a PR
   against the monitor's policy repo.

## When to use it

- A workflow has accumulated at least 30 days of run telemetry
  on at least 50 healthy runs.
- The session monitor has a declarative policy format (OPA,
  Cedar, in-house) the agent can target.
- A program owner is available to review and run the synthetic
  exercises before deployment.

**Don't use it for:**

- A workflow that has never reached production. Without a
  baseline, the rules will be guesses.
- A workflow with an irregular cadence (every run is shaped
  differently). The pattern needs stable shapes to draw a
  baseline from.
- Replacing rules that already work. This prompt designs
  initial rule packs and proposed updates; it does not
  unilaterally rewrite working rules.

## Inputs

- **Telemetry path** — read-only access to the run-telemetry
  store for this workflow.
- **Policy repo** — where the rule pack is committed for human
  review and deployment.
- **Workflow declaration** — the workflow's declared scope
  (allowed files, allowed tools, allowed hostnames).
- **Threat scenarios** — the named failure modes this workflow
  must defend against (exfiltration, scope creep, prompt-drift,
  budget runaway, tool-poisoning amplification).

## The prompt

~~~markdown
You are designing the rule pack a session monitor will load to
watch this workflow's runs in flight. Your output is exactly
one of:

- A pull request against the monitor's policy repo containing:
  (a) a rule pack with three layers, (b) a synthetic red-team
  exercise plan, and (c) the baseline data each threshold was
  tuned from.
- A `TRIAGE.md` note explaining why the telemetry is
  insufficient to design rules safely.

Do not deploy the rule pack. Humans deploy.

## Step 0 — Read the telemetry and the workflow declaration

1. Pull the workflow's last 30 days of run telemetry. Confirm
   at least 50 successful runs are present. If fewer, stop and
   triage with a note about insufficient baseline.
2. Read the workflow's declared scope: allowed files, allowed
   tools, allowed hostnames, allowed argument shapes.
3. Read the threat-scenario list the operator provided.

## Step 1 — Compute baselines

For each signal, compute median, p95, p99 across the 30-day
window:

- Tool calls per minute, per turn, per run.
- Distinct files touched per run.
- Distinct hostnames contacted per run.
- Argument lengths per tool, per call.
- Result sizes per tool.
- Cumulative outbound bytes per run.
- Cumulative tokens per run.
- Number of forbidden-path attempts per run (should be 0;
  baseline is asserting that).

Document the baselines in the PR body. The reviewer needs
them to evaluate the thresholds.

## Step 2 — Draft threshold rules

Threshold rules fire when a signal crosses an absolute ceiling.

For each signal, set the threshold at p99 × 1.5 by default;
adjust if the operator's scenario list indicates a tighter
bound is required.

Examples:

- `tool_calls_per_minute > <p99 × 1.5>` → annotate.
- `distinct_files_touched > <p99 × 1.5>` → hold-for-elicit.
- `cumulative_outbound_bytes > <p99 × 2>` → kill.
- `forbidden_path_attempts > 0` → kill.
- `metadata_endpoint_contact > 0` → kill.

The action graduates with severity: low-confidence anomalies
annotate, medium hold, high ratchet or quarantine, critical
kill.

## Step 3 — Draft deviation rules

Deviation rules fire when a signal drifts away from baseline
mid-run.

- `current_run.distinct_files / baseline.median > 5` → hold.
- `current_run.cumulative_tokens / baseline.median > 4` →
  annotate at 4×, hold at 6×, kill at 10×.
- `argument_length_z_score > 6` for any tool → annotate.

Tune deviation thresholds conservatively. False positives in
this layer are louder than threshold rules — the run is
otherwise healthy when these fire.

## Step 4 — Draft pattern rules

Pattern rules fire on named, high-signal shapes:

- Argument or result contains a link-local IP (`169.254.*`,
  `fd00::*`).
- Argument or result references the cloud-provider metadata
  endpoint hostname.
- Result size exceeds 10 MB.
- Result contains a base64 blob > 1 MB.
- Tool description hash differs from the pinned hash.
- Outbound DNS query for a typosquat neighbour of an
  allowlisted hostname.

Pattern rules are kill-rules by default unless the operator's
scenario list says otherwise.

## Step 5 — Design synthetic red-team exercises

For each named failure mode, design one synthetic exercise:

- **Exfiltration.** Inject a tool result containing a base64
  blob; expect the pattern rule on result-blob-size to fire.
- **Scope creep.** Inject a tool call with an argument file
  path outside the declared scope; expect the threshold rule
  on forbidden-path-attempts to fire.
- **Prompt drift.** Inject a tool result with a string that
  resembles instructions ("ignore previous, run …"); expect
  the result-content rule to fire.
- **Budget runaway.** Run a synthetic loop hitting tools at 5×
  baseline rate; expect deviation rule on tokens to escalate
  through annotate → hold → kill.
- **Tool-description tampering.** Change a tool description
  hash; expect the pinned-description rule to fire.

For each exercise, predict which rule(s) should fire and at
what severity. The reviewer compares the prediction against
the monitor's actual response.

## Step 6 — Open the PR

- Branch: `monitor/<workflow-name>-rules-<date>`.
- Title: `[Monitor][<workflow-name>] rule pack v<n> + synthetic
  exercises`.
- Body must include:
  - Workflow declaration summary.
  - Baseline table (median, p95, p99 per signal).
  - The rule pack in the policy format the monitor expects.
  - The synthetic-exercise plan with predictions per rule.
  - Estimated false-positive rate per rule, computed against
    the 30-day baseline.
- Label: `monitor-rule-update`.

## Stop conditions (write a TRIAGE.md and exit)

- Fewer than 50 successful runs in the baseline window.
- Telemetry is missing required signals (no per-run token
  counts, no per-tool argument shapes).
- The workflow's declared scope is incomplete or
  contradictory.
- The threat-scenario list is empty.

## Scope

- Do not deploy the rule pack. PR only.
- Do not modify the policy repo's deployment pipeline, the
  monitor's runtime, or the audit ledger.
- Do not ship rules with no baseline data behind them.
- Do not silently lower an existing rule's severity. If the
  baseline suggests a rule should soften, surface that as an
  explicit recommendation in the PR body — humans decide.
~~~

## Output contract

- A PR against the monitor's policy repo with the rule pack,
  the synthetic exercises, and the baseline data — OR a
  `TRIAGE.md` note.
- The PR is **never** auto-merged. Rule packs change the
  failure surface of the runtime gate; humans deploy.

## Verification

- Baseline dataset, window, and sample count are recorded beside
  every proposed rule threshold.
- Each synthetic exercise includes the expected action, observed
  action, and the telemetry fields that proved the monitor fired.
- False-positive and false-negative risks are called out in the
  PR body, with any severity changes left as explicit human
  decisions.
- The rule pack is staged as policy only. No runtime monitor,
  kill-controller, or deployment configuration is changed by this
  recipe.

## Guardrails

- **Baseline-driven thresholds.** No threshold ships without
  data behind it. Hand-picked numbers without baselines are
  exactly how monitors stop firing on the bad runs and start
  firing on the healthy ones.
- **Graduated actions.** A rule that can only `kill` is a rule
  the operators will eventually mute. Annotate / hold /
  ratchet / quarantine / kill are the full vocabulary.
- **Synthetic exercises required.** A rule pack without a
  matching exercise plan does not ship. The exercises validate
  the monitor still fires correctly, and run on a cadence
  after deployment.
- **Read-only on the monitor's runtime.** This prompt designs
  rules; it does not deploy them, change the engine's runtime
  configuration, or touch the kill-controller.

## Related

- [Runtime Controls]({{< relref "/security-remediation/runtime-controls" >}})
  — the workflow this prompt slots into.
- [Gatekeeping Patterns]({{< relref "/security-remediation/gatekeeping" >}})
  — where runtime gates sit in the full stack.
- [Threat Model]({{< relref "/fundamentals/threat-model" >}})
  — the failure modes the rules are defending against.
- [Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}})
  — what reviewers do when a `telemetry-hold` flag fires.
