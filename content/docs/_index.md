---
title: Docs
linkTitle: Docs
weight: 1
toc: true
sidebar:
  open: true
description: >
  What security-recipes.ai is, who it's for, how the site is
  structured, and how to get value out of it in your first 10 minutes.
---

**security-recipes.ai** is a community-driven library of opinionated
playbooks for turning the AI coding tools engineers already use —
GitHub Copilot, Devin, Cursor, Codex, and Claude — into **autonomous
remediators** that close risk instead of logging it.

{{< callout type="info" >}}
**New here?** Read this page top-to-bottom once, then jump to the
[Agents]({{< relref "/agents" >}}) section and pick the tool your team
already uses.

**Newer than that?** If "agent," "MCP server," or "skill" aren't
everyday vocabulary yet, start with
[**Fundamentals**]({{< relref "/fundamentals" >}}) — it's the
plain-English primer on every term used on the rest of the site.
{{< /callout >}}

## Why this exists

Modern security programs produce far more findings than humans can fix
in any reasonable time. Meanwhile, every engineering team in the company
has adopted at least one AI coding agent that is perfectly capable of
branching a repo, writing a patch, running tests, and opening a PR.

The gap isn't capability. It's **the recipe**: the specific
configuration, rules, hooks, MCP connectors, and house conventions that
turn a general-purpose coding assistant into a dependable, low-risk
remediation worker.

This site is where we collect those recipes — reviewed, versioned, and
community-driven.

## What's a "recipe"?

A recipe is a short, opinionated walkthrough that answers a single
question:

> How do I enable agentic remediation in _this_ specific tool?

Every recipe follows the same four-section skeleton so teams can skim
and compare:

1. **Prerequisites** — licenses, accounts, and integrations required first.
2. **Recipe steps** — a numbered, opinionated walkthrough. No "it depends."
3. **Verification** — how to know end-to-end that it actually works.
4. **Guardrails** — the controls to put in place before scaling up.

If a page is missing guardrails, treat it as a draft and flag it in
a PR.

## How to integrate with your agent

Once you've picked a recipe, the question is how to get it in
front of your agent at the right time. The
[**Integrate an AI Agent**]({{< relref "/docs/agent-integration" >}})
guide catalogues five durable shapes — direct fetch, vendored
snapshot, MCP knowledge server, skill / rules-file inlining,
and CI-time injection — with per-agent walkthroughs for
Copilot, Claude, Cursor, Codex, and Devin.

{{< cards >}}
  {{< card link="/how-to-use/" title="Visual Guide ->" subtitle="A four-panel walkthrough for using the site: explore the map, run one agent PR, operate workflows, then scale with MCP-backed context." >}}
  {{< card link="/docs/agent-integration/" title="Integrate an AI Agent →" subtitle="Five integration shapes, per-agent walkthroughs, and the cross-cutting concerns (pinning, audit, fetched-content hygiene) that keep an integration trustworthy." >}}
  {{< card link="/security-remediation/control-plane/" title="Workflow Control Plane ->" subtitle="Declarative workflow manifests for scope, MCP context, gates, evidence, KPIs, and kill signals." >}}
  {{< card link="/security-remediation/mcp-gateway-policy/" title="MCP Gateway Policy Pack ->" subtitle="Generated policy contract for enforcing scoped MCP tool access and runtime kill signals." >}}
  {{< card link="/security-remediation/mcp-connector-intake-scanner/" title="Connector Intake Scanner ->" subtitle="Generated admission decisions, control gaps, registry patch previews, and red-team drills for new or changed MCP servers." >}}
  {{< card link="/security-remediation/mcp-authorization-conformance/" title="MCP Authorization Conformance ->" subtitle="Generated resource, audience, PKCE, token-passthrough, session-binding, and scope-drift decisions for MCP tool calls." >}}
  {{< card link="/security-remediation/mcp-elicitation-boundary/" title="MCP Elicitation Boundary ->" subtitle="Generated form-mode and URL-mode controls for MCP user prompts, sensitive flows, external auth, URL safety, consent, and receipts." >}}
  {{< card link="/security-remediation/mcp-tool-risk-contract/" title="MCP Tool Risk Contract ->" subtitle="Generated annotation trust, workflow scope, and session-combination decisions before MCP tools are invoked." >}}
  {{< card link="/security-remediation/mcp-tool-surface-drift-sentinel/" title="MCP Tool Surface Drift ->" subtitle="Generated fingerprints for MCP tool descriptions, schemas, annotations, and capability metadata, with runtime drift decisions before changed tools are trusted." >}}
  {{< card link="/security-remediation/agentic-protocol-conformance/" title="Protocol Conformance Pack ->" subtitle="Generated MCP and A2A protocol conformance evidence with runtime decisions for authorization, annotations, tool drift, Agent Cards, identity, handoff, and prompt-injection boundaries." >}}
  {{< card link="/security-remediation/mcp-connector-trust-registry/" title="MCP Connector Trust Registry ->" subtitle="Generated MCP namespace inventory with trust tiers, controls, evidence, promotion criteria, and kill signals." >}}
  {{< card link="/security-remediation/enterprise-trust-center-export/" title="Enterprise Trust Center Export ->" subtitle="Generated buyer-diligence packet that bundles secure-context, MCP, identity, handoff, eval, readiness, and runtime evidence." >}}
  {{< card link="/security-remediation/agentic-posture-snapshot/" title="Agentic Posture Snapshot ->" subtitle="Generated enterprise posture score, workflow posture decisions, XPIA risk factors, MCP/A2A trust rollups, and source hashes." >}}
  {{< card link="/security-remediation/model-provider-routing-gate/" title="Model Provider Routing Gate ->" subtitle="Generated provider/model route decisions before secure context crosses a frontier, private, local, or unsanctioned model boundary." >}}
  {{< card link="/security-remediation/browser-agent-boundary/" title="Browser Agent Boundary ->" subtitle="Generated browser workspace classes, task profiles, ambient-authority controls, and runtime decisions for untrusted pages, logged-in sessions, localhost, downloads, and external sends." >}}
  {{< card link="/security-remediation/agentic-exposure-graph/" title="Agentic Exposure Graph ->" subtitle="Generated relationship graph for risk-ranked paths across secure context, identities, MCP namespaces, authorization, egress, readiness, risk, and receipts." >}}
  {{< card link="/docs/secure-context-release/" title="Secure Context Release Gate ->" subtitle="Generated release manifests for open-reference, production MCP, and trust-center channels with source hashes, signature gates, eval evidence, and rollback signals." >}}
  {{< card link="/security-remediation/agentic-assurance-pack/" title="Agentic Assurance Pack ->" subtitle="Generated control evidence and AI/Agent BOM seed for enterprise review, procurement, and audit." >}}
  {{< card link="/security-remediation/agentic-readiness-scorecard/" title="Readiness Scorecard ->" subtitle="Generated scale, pilot, gate, and block decisions for enterprise workflow promotion." >}}
  {{< card link="/security-remediation/agent-capability-risk-register/" title="Capability Risk Register ->" subtitle="Generated capability and residual-risk tiers for agentic workflows before MCP access expands." >}}
  {{< card link="/security-remediation/agent-memory-boundary/" title="Agent Memory Boundary ->" subtitle="Generated memory classes, TTLs, tenant boundaries, provenance, rollback expectations, and runtime decisions before agent state is stored or replayed." >}}
  {{< card link="/security-remediation/agentic-red-team-drills/" title="Red-Team Drill Pack ->" subtitle="Generated adversarial eval coverage for agentic workflows, MCP policy, connector trust, and runtime evidence." >}}
  {{< card link="/security-remediation/agent-identity-ledger/" title="Agent Identity Ledger ->" subtitle="Generated non-human identity and delegation contracts for approved workflows, agents, MCP scopes, and revocation." >}}
  {{< card link="/security-remediation/agentic-run-receipts/" title="Agentic Run Receipts ->" subtitle="Generated proof templates for identity, context, tool decisions, egress, approvals, verifier output, evidence, and revocation." >}}
  {{< card link="/security-remediation/context-egress-boundary/" title="Context Egress Boundary ->" subtitle="Generated data-class, destination-class, tenant-boundary, residency, DPA, and secret-egress decisions for MCP-backed context movement." >}}
  {{< card link="/security-remediation/secure-context-lineage-ledger/" title="Secure Context Lineage ->" subtitle="Generated source-to-run context lineage with attestation, poisoning scan, route, egress, handoff, telemetry, receipt, and reuse decisions." >}}
{{< /cards >}}

## How the site is organised

- **[Fundamentals]({{< relref "/fundamentals" >}})** — plain-English
  primer on the concepts every other page assumes you already know.
  Start here if you're new to this space.
- **[Agents]({{< relref "/agents" >}})** — one folder per supported
  AI coding tool. This is the main surface of the site; each page is
  a recipe.
- **[Prompt Library]({{< relref "/prompt-library" >}})** — the actual
  prompts, rules files, skills, and instruction files that teams are
  using in production, contributed back so you don't start from zero.
- **[MCP Server Access]({{< relref "/mcp-servers" >}})** — the
  context layer: what data sources agents can reach, under what
  scopes.
- **[Security Remediation]({{< relref "/security-remediation" >}})**
  — reference agentic workflows a security team can run on
  engineering's behalf.
- **[Automation]({{< relref "/automation" >}})** — deterministic
  tools that earn their keep before you reach for an LLM.
- **Docs** (you are here) — meta-information about how this site works
  and how to contribute.

## Who this is for

- **Security engineers** who want to automate opening fix-PRs for every
  new finding instead of hand-delivering them to product teams.
- **Platform engineers** who own the developer tooling stack and need a
  consistent agentic story across teams and tools.
- **Engineering managers** evaluating which AI agent to bet on for
  remediation work — and what guardrails have to come with it.

## Suggested first 10 minutes

1. If anything on this site reads as jargon, start with
   **[Fundamentals]({{< relref "/fundamentals" >}})** — the primer
   on what an agent is, what the tools do, why prompts matter, and
   what MCP servers are.
2. Skim the **[Agents overview]({{< relref "/agents" >}})** and pick
   the tool your team already has licenses for.
3. Open that agent's recipe and read the **Guardrails** section first.
   If you can't meet those controls yet, that's your actual first
   project — not the recipe.
4. Check the **[Prompt Library]({{< relref "/prompt-library" >}})** for
   any instruction files, skills, or rules that apply to your tool.
   Fork them into your repo rather than writing from scratch.

## Contributing — this is community-driven

This project is designed to grow through contributions from every team
that adopts it. If you have a working recipe, a polished prompt, or a
skill that's been earning its keep, **open a PR**.

See the [Contribute guide]({{< relref "/contribute" >}}) for the fork-and-PR
workflow and the checklist reviewers look for.

Everything merged here must be:

- **Reproducible** — another team can follow the steps and get the same
  result.
- **Opinionated** — "it depends" is not a recipe. Pick a path.
- **Safe** — every recipe ends with guardrails, not just a happy path.

## License

Recipes are published under the MIT license. Logos and brand names
remain the property of their respective owners.
