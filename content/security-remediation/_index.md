---
title: Agentic Security Remediation
linkTitle: Agentic Security Remediation
weight: 9
sidebar:
  open: true
description: >
  Workflows Information Security is standing up to drive down risk
  on engineers' behalf — using agentic remediation where it earns
  its keep, and stopping cleanly where it doesn't.
---

{{< callout type="info" >}}
**TL;DR.** These are the agentic workflows **InfoSec operates**, not
ones we're asking engineering teams to run. The Prompt Library is
the shared cookbook; this section is the menu InfoSec is cooking
from. You don't have to do anything — you'll see the output as PRs,
tickets, or triage notes.
{{< /callout >}}

Agentic automation is most valuable in places where risk reduction
is measurable, the fix shape is narrow, and the blast radius of a
bad change is small enough that a tight guardrail can catch it.
The two workflows below fit that profile. Everything else InfoSec
runs manually — or hands to a human with a checklist — until we're
confident the automation is safer than a hurried engineer at
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
  {{< card link="/security-remediation/penetration-testing/" title="Agentic Penetration Testing" subtitle="Autonomous recon, scoped fuzzing, and auth / IDOR / SSRF walk-throughs against pre-production targets — findings returned as triage tickets." >}}
{{< /cards >}}

## On deck

These are the workflows InfoSec is scoping next. Same four tests
apply — bounded scope, reversible output, measurable outcome, clean
failure mode — before any of them move to "Active."

- **More to come.** As the orchestration spine matures, we'll add
  workflows where the cost/benefit math is clearly in agents' favor.
  If you have a candidate, see [Contribute]({{< relref "/contribute" >}}).

## How orchestration fits together

All InfoSec agentic workflows share one orchestration spine:

1. **Intake** — a finding lands in our risk system (CVE feed, DLP
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

- **PRs** tagged `sec-auto-remediation` with a human from
  InfoSec on the review line.
- **Triage tickets** when the agent stops — these are not asks for
  you to debug the agent, they're asks for a human fix.
- **A changelog** on each workflow page below, so you can see when
  its behaviour changed and why.

## What this section is not

- A mandate to run these workflows in your own repos. The Prompt
  Library is where you'd pick up recipes to run yourself.
- A promise that automation will catch everything. Every workflow
  lists what it **won't** catch — read those sections before
  leaning on it.

## See also

- [Prompt Library]({{< relref "/prompt-library" >}}) — the recipes InfoSec and engineering teams share
- [Agents]({{< relref "/agents" >}}) — per-tool orchestration recipes
- [Contribute]({{< relref "/contribute" >}}) — suggest a new workflow
