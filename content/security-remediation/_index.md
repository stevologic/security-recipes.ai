---
title: Agentic Security Remediation
linkTitle: Agentic Security Remediation
weight: 9
sidebar:
  open: true
description: >
  Reference workflows a security engineering team can operate on
  behalf of the wider organization — using agentic remediation
  where it earns its keep, and stopping cleanly where it doesn't.
---

{{< callout type="info" >}}
**TL;DR.** These are **reference workflows a security team operates**
on engineering's behalf — not ones engineering teams are asked to
run themselves. The Prompt Library is the shared cookbook; this
section is the menu a security team cooks from. Engineering doesn't
have to do anything — the output is PRs, tickets, or triage notes.
{{< /callout >}}

Agentic automation is most valuable in places where risk reduction
is measurable, the fix shape is narrow, and the blast radius of a
bad change is small enough that a tight guardrail can catch it.
The workflows below fit that profile. Everything else a security
team runs manually — or hands to a human with a checklist — until
the automation is demonstrably safer than a hurried engineer at
11 p.m.

## How we decide what to automate

Before a workflow lands here, it has to satisfy four tests:

- **Bounded scope.** The agent can only touch files in a
  pre-declared allowlist (e.g. lockfiles, a specific YAML) — never
  arbitrary source.
- **Reversible output.** The agent's output is always a PR, never a
  merge. A human reviewer remains the last line of defense.
- **Measurable outcome.** We can tell whether the fix actually
  moved risk, not just whether a PR landed.
- **Clean failure mode.** When the agent can't fix something, it
  writes a structured triage note and stops — it does not guess.

## Active workflows

{{< cards >}}
  {{< card link="/security-remediation/sensitive-data/" title="Sensitive Data Element Remediation" subtitle="Detect and redact unexpected PII / secrets appearing in logs, schemas, and shared configs." >}}
  {{< card link="/security-remediation/vulnerable-dependencies/" title="Vulnerable Dependency Remediation" subtitle="Bump transitive and direct dependencies in response to CVEs and Dependabot advisories." >}}
{{< /cards >}}

## Program operations

The workflows above are how the program *acts*. The pages below
are how it's *run* — the measurement, review, rollout, and
compliance layers every program needs whether it has one workflow
or ten.

{{< cards >}}
  {{< card link="/security-remediation/metrics/" title="Program Metrics & KPIs" subtitle="MTTR, merge-as-is rate, reviewer burden, false positives, cost per finding — what to measure and what a good month looks like." >}}
  {{< card link="/security-remediation/reviewer-playbook/" title="Reviewer Playbook" subtitle="The seven-question checklist for gating agent PRs, plus onboarding, redirect patterns, and prompt-drift signals to escalate." >}}
  {{< card link="/security-remediation/maturity/" title="Rollout & Maturity Model" subtitle="Crawl / walk / run adoption — pilot exit criteria, expansion signals, and the kill signals that pause a workflow." >}}
  {{< card link="/security-remediation/compliance/" title="Compliance & Audit" subtitle="How this shape of workflow maps onto SOC 2, ISO 27001, PCI DSS, and NIST SSDF — evidence to produce and questions auditors will ask." >}}
{{< /cards >}}

## On deck

Candidate workflows teams scope next typically sit in a shared
backlog. The same four tests apply — bounded scope, reversible
output, measurable outcome, clean failure mode — before any of
them move to "Active."

- **More to come.** As the orchestration spine matures, new
  workflows land where the cost/benefit math is clearly in agents'
  favor. If you have a candidate, see
  [Contribute]({{< relref "/contribute" >}}).

## How orchestration fits together

Every agentic remediation workflow here shares one orchestration
spine:

1. **Intake** — a finding lands in the risk system (CVE feed, DLP
   scanner, SAST, manual report).
2. **Dispatch** — the orchestrator decides whether the finding is
   eligible for an agent (scope, blast radius, cost caps).
3. **Run** — an agent attempts the remediation inside a sandbox
   with a strict tool allowlist.
4. **Verify** — tests + guardrail checks run; if anything fails,
   the agent stops and writes a triage note.
5. **Review** — a human reviewer (and the owning team) approve
   before merge.

The **orchestrator** is intentionally boring — a queue, a
dispatcher, and a reviewer loop. What changes over time are the
three inputs the orchestrator feeds into each step: the **prompt**
(as we learn what works), the **model** (as better models ship),
and the **tools / MCP connectors** (as we connect new sources of
context). See any of the per-agent pages under
[Agents]({{< relref "/agents" >}}) for a worked example of that
separation of concerns.

## What engineers will see

- **PRs** tagged with an auto-remediation label (`sec-auto-remediation`
  is the illustrative example used throughout this site — rename to
  your org's convention) with a reviewer from the security team on
  the review line.
- **Triage tickets** when the agent stops — these are not asks for
  engineers to debug the agent, they're asks for a human fix.
- **A changelog** on each workflow page below, so readers can see
  when its behaviour changed and why.

## What this section is not

- A mandate to run these workflows in your own repos. The Prompt
  Library is where you'd pick up recipes to run yourself.
- A promise that automation will catch everything. Every workflow
  lists what it **won't** catch — read those sections before
  leaning on it.

## See also

- [Prompt Library]({{< relref "/prompt-library" >}}) — the recipes security and engineering teams share
- [Agents]({{< relref "/agents" >}}) — per-tool orchestration recipes
- [Contribute]({{< relref "/contribute" >}}) — suggest a new workflow
