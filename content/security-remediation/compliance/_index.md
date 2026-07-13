---
title: Compliance & Audit
linkTitle: Compliance & Audit
weight: 13
sidebar:
  open: true
description: >
  How agentic remediation evidence maps onto common control
  frameworks — SOC 2, ISO 27001, PCI DSS, NIST SSDF — and what
  records an auditor will expect to see. Vendor-neutral,
  framework-agnostic guidance.
---

{{< callout type="warning" >}}
**This is not legal advice.** Frameworks evolve; interpretations
vary by auditor. Use this page as a starting point for a
conversation with your compliance and legal counterparts, not as
a compliance guarantee. The control IDs below are illustrative —
map them to your auditor's current framework version.
{{< /callout >}}

## Why this page exists

Enterprise adoption of agentic remediation stalls in exactly two
places: the reviewer pool (covered in the
[Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}}))
and compliance. The second stall is avoidable — agentic
workflows, when designed around the orchestration spine this site
describes, produce more audit evidence than the manual processes
they replace, not less. But only if you name the controls up
front and log accordingly.

{{< playbook-workflow >}}

## The three universal requirements

Nearly every framework wants the same three things. If the
workflow produces these, framework-specific mapping is mostly
renaming.

### 1. Change management evidence

For every code change, an auditor wants to see:

- **Who requested it** — in this case, the finding ID from a
  scanner or ticket system.
- **Who implemented it** — the agent, identified by a run ID,
  linked to the prompt + model + tools it used.
- **Who reviewed it** — a human reviewer, with a decision record
  (approval, request-for-changes, reject).
- **What was changed** — the diff, the files affected, the test
  results.
- **When each of the above happened** — timestamps with timezone,
  preserved.

The PR itself is the majority of this record, if the PR body and
reviewer comments are structured enough to be parsed later.

### 2. Separation of duties

The agent can propose; it cannot merge. The human who reviews
cannot be the same one who authored (the agent's run is
attributable; a human who disabled the agent and ran it under
their own identity would fail the separation test). Codify this
in branch protection rules, not in process documents.

### 3. Logged, reviewable access

Every tool the agent calls, every MCP response it consumed, every
credential it used — all logged, with run-ID attribution,
retained for the framework's retention window. An auditor who
asks "what did the agent do in October" should get a report in
minutes, not weeks.

## Framework-by-framework mapping

The control IDs below are illustrative. Confirm with your
auditor and your framework's current version.

### SOC 2 (Trust Services Criteria)

- **CC7.1 — Change management.** The PR record plus the reviewer
  decision log is the control evidence. The agent is a tool; the
  reviewer is the control owner.
- **CC6.1 — Logical access.** MCP gateway logs (scoped tokens,
  per-run identities, audit trail). The agent must be treated as
  its own identity principal with a named human owner, a
  least-privilege role, and an instant revocation path — not a
  shared bot account, not the dispatching user's token. See
  [Emerging Patterns → agent identity]({{< relref "/fundamentals/emerging-patterns#agent-identity-as-a-first-class-principal" >}})
  for the design posture auditors are beginning to expect.
- **CC7.2 — System monitoring.** The metrics dashboards from
  [Program Metrics & KPIs]({{< relref "/security-remediation/metrics" >}}) —
  regression rate, reviewer queue depth, anomalous-tool-call
  alerts.
- **CC7.4 — Incident response.** The pause label drill (Stage 1
  exit criteria) + the kill signals in
  [Rollout & Maturity Model]({{< relref "/security-remediation/maturity" >}}).

### ISO/IEC 27001:2022 (Annex A)

- **A.8.28 — Secure coding.** Prompts and rules files are part of
  the secure-coding standard. CODEOWNERS on prompts is the
  control.
- **A.8.31 — Separation of development and production.** The
  agent does not have production credentials by default;
  production access, when required, is time-boxed, scoped, and
  routed through the same break-glass process used for humans.
- **A.8.9 — Configuration management.** The orchestrator's
  workflow configs (eligibility rules, allowlists, rate caps) are
  version-controlled and change-reviewed.
- **A.5.23 — Information security in use of cloud services.**
  Applies if the model provider is a cloud service. Record the
  provider, the region, and the data-handling classification for
  what the agent sends.

### PCI DSS 4.0

Applicable when any agent reaches the cardholder data environment
(CDE) — for most programs it should not.

- **Requirement 6.4 — Changes to system components.** Same change
  management evidence as SOC 2 CC7.1, plus PCI's specific
  documentation fields.
- **Requirement 7 — Restrict access by need to know.** The agent
  does not get read access to CDE-classified data unless the
  workflow specifically requires it. Most don't.
- **Requirement 10 — Log and monitor.** One-year retention
  minimum; MCP gateway logs and orchestrator run logs qualify.
- **Requirement 6.3.2 — Review of custom code.** The reviewer
  playbook is the evidence. Auditors often ask specifically about
  AI-generated code review practices; answer with the seven-question
  checklist.

### OWASP Top 10 for Agentic Applications (ASI01–ASI10)

A separate list from the LLM Top 10, published by OWASP in
early 2026, naming the failure modes that are specific to
*agents* — delegated trust, persistent memory, multi-agent
coordination, autonomous tool use. Auditors and AppSec teams
are increasingly asking remediation programs to map their
controls onto it; getting ahead of that conversation is
cheaper than retrofitting.

The IDs that map most directly onto the workflows on this site:

- **ASI01 — Goal Hijacking.** *Ranked #1 in the 2026 list.*
  The agent's task is redirected by attacker-influenced input —
  a crafted finding, a poisoned advisory, a PR comment the
  agent summarises. Because an agent cannot reliably
  distinguish instructions from data, a single malicious input
  can redirect the agent to perform harmful actions using its
  legitimate tools and access. Expect this one to come up in
  every audit. Mitigation lives in the
  [Threat Model]({{< relref "/fundamentals/threat-model#1-prompt-injection" >}})
  (prompt injection) plus the reviewer gate plus the dual-LLM
  isolation pattern (
  [Emerging Patterns → dual-LLM]({{< relref "/fundamentals/emerging-patterns#dual-llm-control-flow-isolation" >}})).
- **ASI02 — Tool Misuse.** The agent calls a tool for a purpose
  outside the workflow's intent. Mitigation: tool allowlists,
  per-run credentials, write-approval hooks (
  [Threat Model → tool abuse]({{< relref "/fundamentals/threat-model#3-tool-abuse" >}})).
- **ASI04 — Agentic Supply Chain.** Compromise via prompts,
  skills, instruction files, or MCP configuration. Mitigation:
  CODEOWNERS on every prompt-layer file, including MCP client
  configs (
  [Threat Model → supply chain]({{< relref "/fundamentals/threat-model#5-supply-chain-attacks-on-the-prompts-themselves" >}})).
- **ASI05 — Unexpected Code Execution.** Tools or sandboxes
  reaching execution paths the design didn't intend. Mitigation:
  policy-as-code at the gateway, ephemeral per-run sandboxes
  (
  [Emerging Patterns → policy-as-code]({{< relref "/fundamentals/emerging-patterns#policy-as-code-for-agent-tool-calls" >}})).
- **ASI06 — Memory & Context Poisoning.** Long-lived state
  (skills, persistent memory, accumulated context) carrying
  attacker payloads forward. Mitigation: pin and diff prompts,
  skills, and tool descriptions; treat memory as a code-review
  surface, not a docs surface.

The remaining IDs (ASI03, ASI07–ASI10) cover identity,
multi-agent coordination, supervisor failures, and untraceable
behaviour; they apply unevenly to single-agent remediation
programs. Map your design review checklist against the full
list once a year and document the gaps.

### NIST SSDF (SP 800-218)

- **PS.3 (Archive and protect each software release).** The PR
  squash-merge + SBOM emission are the archive.
- **PW.4 (Reuse existing, well-secured software).** Agent-proposed
  bumps are exactly this — bring components to the
  latest-secure version.
- **PW.7 (Review and/or analyze code).** Human reviewer gate,
  plus SAST/SCA/DAST running in CI regardless of author.
- **RV.1 (Identify and confirm vulnerabilities).** The agent's
  finding intake is this control; the finding-ID-to-PR trace is
  the confirmation.

### FedRAMP / GovCloud contexts

For regulated contexts where the model provider matters: use an
LLM endpoint deployed inside the accredited boundary (dedicated
inference endpoint, in-boundary inference). Treat the per-run
token budget as a spending control. Sampling of agent-authored
PRs by a second reviewer is often the simplest way to satisfy an
auditor's "AI-specific review" expectation.

### EU AI Act and equivalents

For EU-scoped programs, the EU AI Act's GPAI and high-risk-
system obligations are progressively in force through 2026 —
**2 August 2026** is the date several material obligations
(transparency, risk management documentation, conformity
assessment for high-risk uses, Annex III enforcement) attach
to providers and deployers. Penalties scale with turnover:
prohibited-practice violations reach €35M or 7% of global
turnover; general non-compliance reaches €15M or 3%. An
agentic remediation program is unlikely to be a "high-risk
system" by itself, but any agent that touches identity,
employment, credit, or safety-classified code paths can pull
the program into scope through its data flows.

Practical preparation for a remediation program:

- **Inventory the AI systems in the pipeline.** Every model, every
  agent platform, every MCP server that touches a model. Keep
  the inventory current; regulators expect it to exist before
  they ask.
- **Classify each workflow.** Most SCA/SDE remediation
  workflows are low-to-limited risk, but any agent that
  decides *who* gets a fix, *which* service gets patched
  first, or *whether* a user is affected can drift into
  high-risk territory through its outputs.
- **Evidence the human-oversight control.** Reviewer-gated
  PRs are already this, but the Act wants the oversight
  documented as a *designed* control, not as an operational
  habit. Treat the reviewer gate as a named compliance
  control with an owner, a metric, and an escalation path.
- **Document the model-provider contract.** Data residency,
  training opt-out, retention, incident notification. Map
  them once with legal, version the record, revisit annually.

Equivalent regimes (UK AI Bill, Colorado AI Act and other US
state-level accountability acts, Canada's AIDA draft,
Singapore Model AI Governance Framework v2) ask for similar
documentation; the same evidence pack tends to satisfy most of
them with minor relabeling. The exception is any regime that
imposes a *specific* auditable log format — keep the evidence
pack structured enough that a relabeling pass is all that's
required.

## Evidence collection checklist

A program ready for audit produces, without special effort, the
following artifacts on demand:

- **Run log** — run ID, workflow, trigger, input, tools called,
  tokens spent, outcome (PR / triage / stop), for every run in
  the audit window.
- **PR → finding linkage** — every auto-remediation PR links back
  to a specific finding in the scanner / ticket system.
- **Reviewer decision log** — who approved, who rejected, who
  pushed changes, per PR.
- **Prompt / rule / skill change log** — every change to a
  prompt file with a reviewer attached.
- **Model / tool change log** — every model upgrade or tool
  addition, with the pilot re-run evidence behind it.
- **Incident record** — every pause, every revert, every
  kill-signal hit, with root cause and resolution.
- **Metrics snapshot** — program metrics at end of each audit
  period, signed off by the program owner.

If any of those requires a special report to produce, the
instrumentation isn't complete yet.

## What auditors ask (that isn't in the framework text)

Auditors increasingly ask AI-specific questions not yet codified
in the framework. Have answers for:

- **"How do you know the agent didn't do something malicious?"**
  The threat model (see
  [Threat Model]({{< relref "/fundamentals/threat-model" >}})),
  plus the reviewer gate, plus anomaly detection on tool-call
  sequences.
- **"What if the model hallucinated a fix?"** Closure evidence
  (re-run of the scanner, test added for the original weakness)
  is the backstop.
- **"What data did you send to the model provider?"** The
  data-handling classification for the workflow's inputs. If
  source code is sent, say so, and point to the provider
  agreement.
- **"Can you roll back?"** Yes — reference the reviewability
  control in the sensitive-data and vulnerable-dependency
  workflows: one finding, one PR, cleanly revertable.
- **"What happens if the model provider has a breach?"** The
  pause mechanism halts all runs; credentials are rotated;
  historical work is not retroactively compromised because the
  agent cannot merge (separation of duties).

## Data-handling considerations

The agent program is a new flow of data to a third-party service
(the model provider, plus any MCP-reachable SaaS). Before
scaling:

- **Inventory what gets sent.** Source code? Ticket summaries?
  SBOM contents? Different classifications; different compliance
  implications.
- **Match to the classification policy.** An agent that reads
  internal documents should be allowed only the classifications
  the endpoint is approved for.
- **Regional / residency constraints.** If engineering data must
  stay in a specific region, the model endpoint must be in that
  region. Confirm before onboarding.
- **Retention at the provider.** Zero-retention is the default
  ask. Confirm the setting is on, not just available.

## The audit-ready orchestration spine

Every workflow on this site follows the same spine. Mapped to
audit roles:

1. **Intake** → logged (finding source, timestamp, ID).
2. **Dispatch** → logged (eligibility decision, reason).
3. **Run** → logged (run ID, tools called, tokens, outcome).
4. **Verify** → logged (test results, scanner re-run, guardrail
   checks).
5. **Review** → logged (reviewer, decision, comments, timestamps).

Five logs, five evidence streams, one chain of custody per
finding. If an auditor can't follow that chain in ten minutes,
fix the instrumentation.

## See also

- [Program Metrics & KPIs]({{< relref "/security-remediation/metrics" >}}) — the metrics auditors expect to see dashboards for
- [Evidence Bundles]({{< relref "/security-remediation/evidence-bundles" >}}) — portable audit artifacts for agentic remediation runs
- [Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}}) — the human-review control evidence
- [Agentic Assurance Pack]({{< relref "/security-remediation/agentic-assurance-pack" >}}) — the generated index for control evidence and AI/Agent BOM readiness
- [Agentic Readiness Scorecard]({{< relref "/security-remediation/agentic-readiness-scorecard" >}}) - the generated workflow promotion gate for scale and pilot decisions
- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}}) - the adversarial eval evidence layer
- [Threat Model]({{< relref "/fundamentals/threat-model" >}}) — the basis of the anomaly-detection answer
- [MCP Integration]({{< relref "/mcp-servers" >}}) — the access-logging layer
