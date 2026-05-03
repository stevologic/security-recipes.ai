---
title: Agentic Security Remediation
linkTitle: Agentic Security Remediation
weight: 9
sidebar:
  open: true
cascade:
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
  {{< card link="/security-remediation/sast-findings/" title="SAST Finding Remediation" subtitle="Triage SAST findings, drop the false positives with audit, and auto-fix the long tail of bounded fix shapes." >}}
  {{< card link="/security-remediation/base-images/" title="Base Image & Container Layers" subtitle="Bump `FROM` lines, refresh OS-package layers, and rebuild derived multi-stage images on OS-level CVEs." >}}
  {{< card link="/security-remediation/artifact-cache-purge/" title="Artifact Cache & Mirror Quarantine" subtitle="When a published artifact is compromised, evict it from every internal proxy, container registry, and CI cache that might still serve it." >}}
  {{< card link="/security-remediation/classic-vulnerable-defaults/" title="Classic Vulnerable Defaults" subtitle="Mitigate and uplift the durable, recurring weaknesses that keep landing — pickle, unsafe YAML, JNDI lookups, JWT `none`, XXE, and friends." >}}
  {{< card link="/security-remediation/crypto-payments/" title="Cryptocurrency & Crypto Payments Security" subtitle="Harden wallet operations, address handling, and settlement controls where one wrong transaction is irreversible." >}}
  {{< card link="/security-remediation/defi-blockchain/" title="DeFi & Blockchain Protocol Security" subtitle="Secure smart-contract, oracle, bridge, and governance operations with runbooks designed for on-chain blast radius." >}}
{{< /cards >}}

## Program operations

The workflows above are how the program *acts*. The pages below
are how it's *run* — the measurement, review, rollout, gating,
identity, runtime, and compliance layers every program needs whether it
has one workflow or ten.

{{< cards >}}
  {{< card link="/security-remediation/agentic-threat-radar/" title="Agentic Threat Radar" subtitle="Source-backed threat signals, buyer triggers, mapped controls, and product roadmap priorities for agentic AI and MCP security." >}}
  {{< card link="/security-remediation/agentic-measurement-probes/" title="Agentic Measurement Probes" subtitle="Generated traceability probes for context, MCP authorization, identity, memory, egress, red-team replay, readiness, receipts, and threat alignment." >}}
  {{< card link="/security-remediation/control-plane/" title="Workflow Control Plane" subtitle="Machine-readable workflow manifests for scope, MCP context, gates, evidence, KPIs, and kill signals that agents and auditors can consume directly." >}}
  {{< card link="/security-remediation/mcp-gateway-policy/" title="MCP Gateway Policy Pack" subtitle="Generated enforcement policy for scoped tool access, branch writes, runtime kill signals, and evidence records." >}}
  {{< card link="/security-remediation/mcp-runtime-decision-evaluator/" title="MCP Runtime Decision Evaluator" subtitle="Deterministic allow, hold, deny, and kill-session decisions for each agent tool call before it reaches enterprise systems." >}}
  {{< card link="/security-remediation/mcp-connector-intake-scanner/" title="MCP Connector Intake Scanner" subtitle="Generated admission decisions, control gaps, registry patch previews, and red-team drills for new or changed MCP servers before connector promotion." >}}
  {{< card link="/security-remediation/mcp-authorization-conformance/" title="MCP Authorization Conformance" subtitle="Generated resource, audience, PKCE, token-passthrough, session-binding, and scope-drift decisions before MCP tool calls execute." >}}
  {{< card link="/security-remediation/mcp-connector-trust-registry/" title="MCP Connector Trust Registry" subtitle="Generated connector trust pack for MCP namespaces, tiers, access modes, evidence, promotion criteria, and runtime kill signals." >}}
  {{< card link="/security-remediation/agentic-assurance-pack/" title="Agentic Assurance Pack" subtitle="Generated trust pack for AI platform review, procurement, audit evidence, and AI/Agent BOM readiness." >}}
  {{< card link="/security-remediation/agentic-readiness-scorecard/" title="Agentic Readiness Scorecard" subtitle="Generated scale, pilot, gate, and block decisions from workflow, MCP policy, connector trust, identity, assurance, and red-team evidence." >}}
  {{< card link="/security-remediation/agent-capability-risk-register/" title="Agent Capability Risk Register" subtitle="Generated low, medium, and high residual-risk tiers from system criticality, AI autonomy, MCP permissions, impact radius, and control credits." >}}
  {{< card link="/security-remediation/agent-memory-boundary/" title="Agent Memory Boundary" subtitle="Generated memory classes, TTLs, tenant boundaries, provenance, rollback expectations, and runtime decisions before agent state is stored or replayed." >}}
  {{< card link="/security-remediation/agent-skill-supply-chain/" title="Agent Skill Supply Chain" subtitle="Generated provenance, permission, isolation, package-hash, signature, sandbox, and runtime decisions for agent skills, rules, hooks, and extensions." >}}
  {{< card link="/security-remediation/agentic-system-bom/" title="Agentic System BOM" subtitle="Generated Agent/AI Bill of Materials for workflows, agent classes, identities, MCP connectors, evidence, evals, and drift triggers." >}}
  {{< card link="/security-remediation/agentic-run-receipts/" title="Agentic Run Receipts" subtitle="Generated proof templates for each governed agent run: identity, context, tool decisions, egress, approvals, verifier output, evidence, and revocation." >}}
  {{< card link="/security-remediation/secure-context-trust-pack/" title="Secure Context Trust Pack" subtitle="Generated provenance, source hashes, trust tiers, retrieval decisions, and workflow context packages for MCP-backed agents." >}}
  {{< card link="/security-remediation/context-poisoning-guard/" title="Context Poisoning Guard" subtitle="Generated pre-retrieval scanner for prompt-injection, tool-poisoning, approval-bypass, hidden-instruction, and exfiltration markers in registered context." >}}
  {{< card link="/security-remediation/secure-context-firewall/" title="Secure Context Firewall" subtitle="Deterministic allow, hold, deny, and kill-session decisions before MCP-backed context is returned to an agent." >}}
  {{< card link="/security-remediation/context-egress-boundary/" title="Context Egress Boundary" subtitle="Generated data-boundary policy and runtime decisions before context leaves a tenant, model provider, MCP server, telemetry sink, or public corpus." >}}
  {{< card link="/security-remediation/agentic-red-team-drills/" title="Agentic Red-Team Drill Pack" subtitle="Generated adversarial eval drills for prompt injection, goal hijack, approval bypass, token passthrough, connector drift, loops, and evidence integrity." >}}
  {{< card link="/security-remediation/agent-identity-ledger/" title="Agent Identity & Delegation Ledger" subtitle="Generated non-human identity contracts for approved agents, delegated MCP scopes, explicit denies, review ownership, and runtime revocation." >}}
  {{< card link="/security-remediation/metrics/" title="Program Metrics & KPIs" subtitle="MTTR, merge-as-is rate, reviewer burden, false positives, cost per finding — what to measure and what a good month looks like." >}}
  {{< card link="/security-remediation/reviewer-playbook/" title="Reviewer Playbook" subtitle="The seven-question checklist for gating agent PRs, plus onboarding, redirect patterns, and prompt-drift signals to escalate." >}}
  {{< card link="/security-remediation/gatekeeping/" title="Gatekeeping Patterns" subtitle="The catalog of admission, mid-run, pre-merge, post-merge, runtime, and cross-cutting gates — pick a stack, not a single gate." >}}
  {{< card link="/security-remediation/runtime-controls/" title="Runtime Controls" subtitle="Inline action proxies and telemetry-driven session disablement — what the gate at the *running* agent looks like, not at its PR." >}}
  {{< card link="/security-remediation/maturity/" title="Rollout & Maturity Model" subtitle="Crawl / walk / run adoption — pilot exit criteria, expansion signals, and the kill signals that pause a workflow." >}}
  {{< card link="/security-remediation/compliance/" title="Compliance & Audit" subtitle="How this shape of workflow maps onto SOC 2, ISO 27001, PCI DSS, and NIST SSDF — evidence to produce and questions auditors will ask." >}}
{{< /cards >}}

## Per-CVE recipes

When a finding is a *named* CVE — Log4Shell, xz-utils,
Heartbleed, regreSSHion, the headline supply-chain story of
the month — generic workflows are not always enough. The CVE
has its own blast radius, its own quirks, and its own
"remediation that looks right and isn't." See
[CVE Recipes]({{< relref "/prompt-library/cve" >}}) for
per-CVE prompts that an agent can run end-to-end without
breaking the code around the fix.

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
