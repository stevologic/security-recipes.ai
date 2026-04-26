---
title: Production MCP Server
linkTitle: Production MCP Server
weight: 10
toc: true
sidebar:
  open: true
description: >
  The trusted secure context layer for agentic AI and MCP servers.
  Production MCP architecture, free vs premium tiers, and how to wire
  scoped context for faster reviewer-gated remediation.
---

{{< callout type="info" >}}
**Why this page exists.** An agent is only as fast as the
context it can reach. The more of your organization's signals
are exposed — safely — through MCP, the shorter the distance
between a new finding and a reviewed PR. This section catalogs
what's wired up today, what's on deck, and how to integrate a
new source.
{{< /callout >}}

## SecurityRecipes production MCP vision

SecurityRecipes is building **the trusted secure context layer for agentic AI and MCP servers**.

- **Free tier (open):** public recipe retrieval, community prompt context, and baseline connector patterns.
- **Premium tier (production MCP):** agent-verified prompt packs, higher-rate endpoints, enterprise policy controls, and premium-only remediation features available exclusively through the MCP server.

This model keeps foundational knowledge open while funding production-grade context infrastructure.

## Why agentic workflows need direct data access

A remediation agent that has to ask a human for the current
CVSS score, the owning team, the affected service, or the
relevant runbook is not actually an agent — it's a chatbot with
extra steps. The single biggest lever on time-to-fix is
**shortening the context hop**: letting the agent read the
finding, the ownership graph, the runbook, and the ticket state
directly rather than waiting for a human to copy-paste them
into a prompt.

MCP (the Model Context Protocol) is the integration standard
that makes that direct access practical without handing out
broad credentials. Each data source exposes a narrow, typed
interface; each agent is granted least-privilege access to the
specific tools it needs; audit logs and rate limits live at the
connector, not inside the agent.

Done well, this pattern gives security teams two things at
once: **faster remediation** (because the agent stops waiting on
humans for context) and **tighter control** (because every
tool call is a scoped, logged, reviewable API call — not a
screen-scrape of a private system).

## What good MCP access looks like

A healthy MCP integration is recognizable by a short checklist:

- **Scoped.** The agent's token grants exactly the operations
  it needs — most connectors should start **read-only**, with
  write scopes enabled per-flow.
- **Typed.** The tool surface exposes named operations
  (`get_finding`, `list_owners`, `update_ticket`) rather than a
  generic "run SQL" escape hatch.
- **Logged.** Every tool call is captured with agent identity,
  task ID, and arguments — so a reviewer can reconstruct what
  the agent saw and did.
- **Rate-limited.** Per-agent, per-tool caps live at the
  connector to prevent a loop from turning into a DoS.
- **Reversible.** Write operations that touch external systems
  are idempotent where possible, and always logged with the
  arguments that would be needed to undo them.

Any connector that misses one of these needs a retrofit before
it gets promoted from "experimental" to "production."

## MCP gateways

Once you have more than two or three MCP servers wired up, the
sanest way to keep them under control is to put a **gateway** in
front of them. The gateway is a single brokered endpoint every
agent connects to; it fans out to the right backend MCP server
based on the tool namespace (e.g., `snyk.*` → the Snyk connector,
`jira.*` → the Jira connector) and centralises the concerns you'd
otherwise have to duplicate per server.

### What a gateway gives you

- **One endpoint per agent.** Claude, Cursor, Devin, GitHub
  Copilot, and Codex all point at the same gateway URL. Add or
  rotate a backend without touching every agent workspace's
  config.
- **Centralised auth.** The gateway holds the per-backend
  credentials. Agents authenticate to the gateway with their own
  identity; the gateway mints or relays the appropriately scoped
  token to the backend. Rotating a Snyk or Jira token is a
  one-place change.
- **Policy in one hop.** Per-agent allowlists, per-tool rate
  limits, approval-required flags on write operations, and field
  redaction all live at the gateway. Update policy once and it
  applies to every agent.
- **Uniform audit.** Every tool call — regardless of agent or
  backend — lands in a single audit stream with a consistent
  schema (agent identity, task ID, tool, arguments, result
  status). Reviewers have one place to answer "why did the agent
  do that?".
- **Caching and shaping.** Cache expensive reads (e.g., a large
  finding detail fetch that dozens of agent sessions would
  otherwise repeat), and normalise quirky vendor responses into a
  shape the agent prompts are written against.
- **Break-glass for writes.** Route sensitive write operations
  through a "log and queue" path that requires human approval
  before the backend call actually fires, without agents having
  to know anything about that approval step.

### Gateway checklist

Treat a gateway as a production service in its own right. Before
it routes any workload, the following should be true:

- **Per-agent identity.** Each agent (Claude, Cursor, etc., and
  each named workflow inside them) authenticates with its own
  credential. No shared "bot" token.
- **Scoped routing.** Tools a given agent isn't cleared for
  aren't merely hidden — they're refused at the gateway with a
  logged deny.
- **Rate limits at multiple levels.** Per-agent, per-tool,
  per-backend. A loop in one agent shouldn't be able to exhaust
  a shared Snyk API budget.
- **Write approval hooks.** Any backend write operation (open
  a ticket, change a label, push a file) can be configured to
  require approval — even if the default is "allow".
- **Replayable logs.** Audit records capture enough to reconstruct
  the call. Secrets and obviously sensitive fields are redacted
  at capture time, not at query time.
- **Health and degradation paths.** When a backend is down, the
  gateway returns a typed error the agent can handle — it does
  not silently stall the agent loop.
- **Versioning.** Tool schemas are versioned so a backend change
  doesn't break every agent at once.

### When to introduce a gateway

You probably don't need one on day one. Start with a single MCP
server wired directly to one agent, get a remediation flow
working, then introduce a gateway **before** the fleet gets
messy:

- **Two backends, one agent** — still fine without a gateway.
- **One backend, three agents** — a gateway starts to pay for
  itself in credential management alone.
- **Three+ backends, two+ agents** — running without a gateway
  means credentials, rate limits, and audit logs are drifting in
  three different places. Introduce one.

A gateway is also the right place to host **experimental**
connectors — wire them in behind a feature flag, observe the
traffic, and promote to "production" only once the checklist
above is green.

## Connector catalog

The catalog is organized by the kind of signal each connector
exposes. Entries marked _placeholder_ are integrations on the
roadmap but not yet rolled out; the shape of the page is staged
so owning teams can flesh them out with the same template.

### Risk & finding sources

- **CVE / advisory feeds** — _placeholder._ How to expose a
  deduplicated CVE stream to agents, and which fields to
  include (CVSS, EPSS, exploit-known).
- **SCA scanners** (Snyk, Dependabot, OSV-Scanner) —
  _placeholder._
- **SAST scanners** (CodeQL, Semgrep) — _placeholder._
- **DLP / secret scanners** (Gitleaks, TruffleHog, GitGuardian)
  — _placeholder._
- **Cloud posture** (Wiz, Prisma Cloud, internal CSPM) —
  _placeholder._

### Ownership & routing sources

- **CODEOWNERS + repo metadata** — _placeholder._ How agents
  should resolve "who owns this?" without guessing.
- **Service catalog** (Backstage or equivalent) —
  _placeholder._
- **On-call / paging** (PagerDuty, Opsgenie) — _placeholder._
- **Identity & group membership** (Okta, Entra) —
  _placeholder._

### Ticket & workflow sources

- **Issue trackers** (Jira, Linear, GitHub Issues) —
  _placeholder._ Read finding context, update status, attach
  remediation links.
- **Incident trackers** — _placeholder._
- **Change management** (ServiceNow, Jira SM) — _placeholder._

### Knowledge & runbook sources

- **Runbooks** (Confluence, Notion, internal wikis) —
  _placeholder._
- **Architecture decision records** — _placeholder._
- **Past post-mortems** — _placeholder._

### Code & build sources

- **Source hosts** (GitHub, GitLab, Bitbucket) — _placeholder._
- **CI / build systems** (GitHub Actions, Buildkite, Jenkins,
  etc.) — _placeholder._
- **Artifact registries** (JFrog, GitHub Packages, npm, PyPI
  mirrors) — _placeholder._

### Observability & telemetry sources

- **Metrics & dashboards** (Grafana, Datadog) — _placeholder._
  Useful for agents that need to confirm a fix actually moved
  the needle.
- **Traces & logs** (Datadog APM, Honeycomb, OpenTelemetry
  backends) — _placeholder._
- **Error trackers** (Sentry, Rollbar) — _placeholder._

## How to integrate a new MCP source

Every new connector goes through the same lightweight
on-ramp. The goal is that adding a source is a
configuration-level change, not a re-architecture — the
orchestration on each agent page doesn't change when a new
connector shows up.

1. **Identify the smallest useful tool surface.** Start with
   read-only operations. `list_*`, `get_*`, `search_*`. Resist
   the temptation to add writes on day one.
2. **Draft the tool schema.** Named operations, typed
   arguments, and explicit error shapes — so agents can
   recover without free-text parsing.
3. **Deploy the connector with a scoped token.** Short-lived
   credentials, per-agent identity, per-tool rate limits.
4. **Wire it into one agent first.** Pick the agent that has
   the clearest next remediation flow that benefits, run a
   small eval, then fan out.
5. **Document the integration on this site.** Owning team,
   scopes required, rate limits, known gotchas, escalation
   contact. Future agents (and future engineers) will thank
   you.
6. **Promote from experimental → production.** Once the
   checklist in "What good MCP access looks like" is green and
   at least one workflow depends on it, flip the maturity tag.

## Agent-specific wiring

Each supported agent takes MCP configuration in a slightly
different place. The connectors themselves don't change — the
wiring does.

- **Claude.** Configured as MCP servers in the Claude Code /
  Agent SDK settings. See the
  [Claude recipe]({{< relref "/claude" >}}) for examples.
- **Cursor.** Configured via `.cursor/mcp.json` at the repo or
  workspace level. See the
  [Cursor recipe]({{< relref "/cursor" >}}).
- **Devin.** Integrations are wired at the workspace level; see
  the [Devin recipe]({{< relref "/devin" >}}) for the
  session-brief conventions that tell Devin which tools to
  reach for.
- **GitHub Copilot.** MCP support is tied into the Coding Agent
  configuration; see the
  [Copilot recipe]({{< relref "/github_copilot" >}}).
- **Codex.** Invoked via the driver script's sandbox — each
  connector is mounted as a CLI tool Codex can call. See the
  [Codex recipe]({{< relref "/codex" >}}).

## Ecosystem developments to track

MCP is still evolving. A few 2026-era developments are worth
tracking because they change the shape of connector / gateway
design materially:

- **Server discovery via `.well-known` metadata ("Server Cards").**
  A maturing pattern where servers publish structured capability
  metadata at a predictable URL, so agents, gateways, and
  registries can enumerate what a server exposes without first
  connecting to it. Useful in gateway catalogs and in the
  experimental → production promotion step above.
- **SSO-integrated auth, away from static client secrets.** The
  enterprise-readiness push for MCP emphasises OIDC / SSO-bound
  identities for agents, short-lived tokens, and audit trails on
  the auth path itself — so revocation, group membership, and
  separation of duties follow the same controls your other
  internal tooling already obeys. Plan the gateway to carry
  identity end-to-end: the agent's user-or-workload identity
  should be the thing the backend sees, not a shared service
  account, so deny-logs and scope checks are meaningful at
  audit time.

## Where MCP is heading in 2026

MCP has moved from "a spec for a handful of local stdio servers"
to enterprise infrastructure in roughly eighteen months. The
shape of what agents can do — and how remediation programs
should plan for them — is being redrawn by a short list of
primitives that are either shipping or on the near-term roadmap.
These notes distil the public direction as of the
[April 2026 "Future of MCP" keynote](https://www.youtube.com/watch?v=v3Fr2JR47KA)
by David Soria Parra (Anthropic, MCP co-creator) and align with
the corresponding Anthropic API documentation for the
[tool search](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool)
and [programmatic tool calling](https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling)
features.

{{< callout type="info" >}}
**Headline claim from the keynote.** *"2026 is the year agents go
to production."* The argument is that the protocol work of 2024–
2025 (remote transports, authorization, elicitation, tasks) has
now landed the pieces an agent needs to run against real
enterprise data, under real auth, for long enough to finish real
work. Your remediation program's planning horizon should reflect
that — not as hype, but as permission to design around primitives
that are genuinely available rather than workarounds.
{{< /callout >}}

### The protocol timeline that got us here

A short chronology, because design decisions for your connector
fleet depend on which primitives you can assume are available:

| When | Milestone | What it unlocked |
| --- | --- | --- |
| Nov 2024 | Core MCP open-sourced | Local stdio servers; the client / server / tool shape. |
| Mar 2025 | Remote transports | HTTP-based MCP servers; network boundaries between agent and tools. |
| Jun 2025 | Authorization | OAuth-style delegated auth on MCP; the foundation for SSO-integrated agents. |
| Sep 2025 | Elicitation | Servers can request structured input from the user mid-execution. |
| Dec 2025 | Tasks primitive (experimental) | Async, long-running agent workflows coordinated through MCP. |
| Q1 2026 | MCP applications | Packaged UX surfaces delivered over MCP — the "apps for agents" shape. |

The ecosystem-adoption numbers from the keynote are striking on
their own: MCP SDKs were pulling on the order of **110 million
downloads per month** by early 2026 — a scale the React ecosystem
took roughly three years to reach. Whatever else is true, MCP is
where connector investment is happening.

### Progressive tool discovery (tool search)

The thing that most directly affects the design of an agentic
remediation program is how agents handle **large tool catalogs**.
A typical multi-connector setup (GitHub + Slack + Sentry +
Grafana + Splunk) consumes on the order of **55k tokens of
context in tool definitions alone** before the agent does any
work; selection accuracy also degrades noticeably past **30–50
available tools**.

Progressive discovery flips this. Instead of loading every tool
upfront:

- Tools are marked `defer_loading: true`; they are *not* in the
  system-prompt prefix.
- A **tool search** tool (regex or BM25 variant) sits in the
  initial surface. When the agent needs a capability, it searches
  the catalog, the API returns 3–5 `tool_reference` blocks, and
  those are expanded inline into full tool definitions.
- Claude Code applies this automatically, deferring any MCP
  server whose tool definitions would otherwise consume more
  than ~10% of the context window; reported reductions are on
  the order of **>85%** of the tool-definition token cost.

Why this matters for remediation specifically: it collapses the
old "one gateway, one agent, curated per-workflow toolset"
constraint. You can plausibly expose a 200-, 500-, or even
low-thousands-of-tools catalog to a single remediation agent and
rely on the discovery layer to keep context spend sane. The
practical consequence is that **the gateway becomes the catalog**,
and per-workflow tool trimming becomes an optimisation, not a
correctness requirement.

Guardrail implication: tool poisoning (see the
[Threat Model]({{< relref "/fundamentals/threat-model" >}}))
gets more surface area, because more tools are reachable more
cheaply. The mitigation ("pin tool descriptions; diff on update")
is now table stakes, not an edge concern.

### Programmatic tool calling

The second shift is in *how* agents chain tools. Classic tool use
round-trips through the model for every call: the model emits a
`tool_use`, the caller returns a `tool_result`, the model
reasons, emits the next `tool_use`, and so on. For any workflow
with 3+ dependent calls, that's expensive, slow, and lossy —
every intermediate result sits in context.

Programmatic tool calling lets the model **write code that orchestrates
the tools**, inside a code-execution sandbox. Tools marked
`allowed_callers: ["code_execution_20260120"]` are callable as
async Python functions; the model writes a script with the usual
shape (loops, branches, error handling, filters, early
termination) and only the final result enters context. Anthropic
reports order-of-magnitude reductions in token use and latency
on multi-step workflows; the feature is generally available on
the first-party Claude API for Claude Sonnet 4.5+ and Opus 4.5+.

Concrete remediation patterns this unlocks:

- **Batch triage across many findings.** Instead of N model turns
  to triage N findings, a single code-execution run fetches,
  filters by reachability/severity, and returns only the cohort
  that needs human review.
- **Large-diff reasoning.** Pull the affected files, run
  property tests, filter to the failures, summarise. The raw
  file contents never enter the model's context.
- **Multi-source correlation.** Query the advisory feed, the
  SBOM, and the CODEOWNERS graph in one script; return the
  three-tuple per affected repo.

Constraint to know about: MCP-connector tools cannot currently
be called programmatically on the Claude API. If you want the
programmatic pattern today, either expose those tools as
first-party API tools or run your own sandboxed code-execution
pattern per the Anthropic
[programmatic tool calling docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling).
This is likely to change — worth tracking.

### Elicitation: the agent asking *you* for structured input

Historically, MCP was a one-way street: the client asked, the
server answered. **Elicitation** (shipped in the MCP spec in
September 2025) lets a server pause mid-execution and request
*structured* input from the user — a schema-typed form rather
than a free-text prompt.

Why this matters for remediation:

- **Mid-run clarifications become safe.** A triage tool that
  discovers a finding could be either vulnerable-dependency *or*
  vulnerable-config can surface an elicitation — "which path
  should I take?" — with a typed answer, instead of asking the
  model to guess or flipping to a free-form chat.
- **Break-glass approvals have a home.** Write-path operations
  that require a human OK (merge, registry push, ticket bulk-op)
  can live as an elicitation step. The approval is structured
  (a boolean + optional justification), auditable, and native
  to the protocol, rather than a bolt-on in the orchestrator.
- **Secret-handling stays out of prompts.** A server can
  elicit a one-time credential from the user and scope it to the
  current task — instead of asking the agent to hold or remember
  it.

If you're designing a new connector in 2026, plan for which of
your write-path operations are elicitation targets and which are
silent reads, rather than inventing a separate approval channel.

### Long-running tasks and the tasks primitive

The experimental **tasks** primitive (Dec 2025) addresses the
mismatch between an agent's operational unit (seconds) and
real remediation work (minutes to hours — reproduction,
test-suite runs, pipeline waits, staged rollouts). Instead of
forcing the agent to hold a connection open, a task is
**submitted to the server**, the server returns a task handle,
and the agent (or the orchestrator) polls or receives callbacks
as the task progresses.

Design implications:

- Connectors for CI systems, long test suites, and staged
  deploys become first-class, not workarounds built on retry
  loops inside the agent.
- The orchestrator's queue model maps cleanly onto MCP tasks;
  if you already have a queue, the migration path is
  "register the task with the upstream server, track it in
  the queue" rather than a rewrite.
- Observability shifts — a single user intent ("remediate
  this CVE") may translate to a tree of tasks across several
  servers; plan for a correlation ID that spans them.

### MCP applications

The Q1 2026 arrival of **MCP applications** generalises the
server into something closer to an app surface: packaged UI +
tools + skills, delivered over MCP, that a host agent can embed
or hand off to. Concretely, this is how "ask the agent to
remediate a CVE" could become "the agent hands off to the SCA
vendor's MCP application, which owns the scanning / reproduction
UX, and returns a typed result." You keep the reviewer gate;
you skip the integration plumbing.

This is the primitive to watch for in 2026–2027 vendor
roadmaps. Expect SCA, SAST, DAST, and ticket vendors to ship
MCP applications in preference to one-off integrations, and
plan gateway design for multiple co-resident applications
instead of a single tool fan-out.

### What this means for program design

A short synthesis to carry back into your own planning:

- **Design for larger connector catalogs.** The old constraint
  "keep the per-agent tool count under ~30" is relaxed by tool
  search. Start thinking in terms of *gateway coverage*, not
  *per-agent curation*.
- **Split "tool use" from "tool orchestration."** Programmatic
  tool calling is a different programming model. Workflows
  with 3+ dependent calls, large intermediate data, or batch
  shape are candidates to port to the programmatic pattern.
- **Use elicitation for approvals and clarifications.**
  Replace free-text "are you sure?" turns with typed
  elicitations. The reviewer workflow
  ([Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}}))
  has a natural home here.
- **Adopt the tasks primitive for anything over ~30 seconds.**
  Don't keep agents holding connections open for long CI runs;
  let the primitive do it.
- **Keep guardrails pinned.** Tool descriptions, skill
  instructions, and elicitation schemas are prompt-layer
  inputs. Version, review, and diff them the same way you do
  the system prompt — see
  [Threat Model → tool poisoning]({{< relref "/fundamentals/threat-model#2-poisoned-mcp-responses-and-tool-descriptions" >}}).

Cross-link into the pattern catalog for deeper reading on each
of these:
[Emerging Patterns → progressive discovery]({{< relref "/fundamentals/emerging-patterns#progressive-tool-discovery-and-tool-search" >}})
·
[Emerging Patterns → programmatic tool calling]({{< relref "/fundamentals/emerging-patterns#programmatic-tool-calling" >}})
·
[Emerging Patterns → elicitation]({{< relref "/fundamentals/emerging-patterns#elicitation-structured-input-from-the-user" >}})
·
[Emerging Patterns → tasks primitive]({{< relref "/fundamentals/emerging-patterns#mcp-tasks-primitive-for-long-running-work" >}}).

## Free vs Premium MCP access

| Capability | Free Tier (Site + MCP) | Premium Tier (Production MCP) |
| --- | --- | --- |
| Public recipes and handbook content | ✅ | ✅ |
| Community prompt retrieval | ✅ | ✅ |
| Agent-verified premium prompts | ❌ | ✅ |
| Premium-only tools and workflows | ❌ | ✅ |
| Production throughput and SLAs | ❌ | ✅ |
| Enterprise policy packs | ❌ | ✅ |

Premium features are intentionally delivered via MCP so access is scoped, auditable, and controllable.
