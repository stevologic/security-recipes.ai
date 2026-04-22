---
title: MCP Server Access
linkTitle: MCP Server Access
weight: 10
toc: true
sidebar:
  open: true
description: >
  The context layer behind agentic remediation. Catalog of MCP
  data sources, how to wire them into each agent, and why
  giving agents direct, scoped access to the right signals is
  how risk reduction actually speeds up.
---

{{< callout type="info" >}}
**Why this page exists.** An agent is only as fast as the
context it can reach. The more of your organization's signals
are exposed — safely — through MCP, the shorter the distance
between a new finding and a reviewed PR. This section catalogs
what's wired up today, what's on deck, and how to integrate a
new source.
{{< /callout >}}

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

## What this section is not

- A substitute for your data-classification policy. If a
  system holds sensitive data, the rules for how an agent may
  read it live in policy — this section documents the
  *mechanics*, not the authorization.
- A mandate to connect everything. "Democratizing data" does
  not mean "remove the fence." It means: for each signal an
  agent can prove it needs, make the path to getting it
  narrow, typed, scoped, and logged — so the answer is "yes,
  and here's the audit trail," not "ask a human, wait a day."

## See also

- [Agents]({{< relref "/agents" >}}) — per-tool orchestration recipes
- [Prompt Library]({{< relref "/prompt-library" >}}) — prompts that make use of these connectors
- [Agentic Security Remediation]({{< relref "/security-remediation" >}}) — workflows that depend on these integrations
- [Contribute]({{< relref "/contribute" >}}) — submit a new connector writeup
