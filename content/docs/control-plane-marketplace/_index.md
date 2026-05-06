---
title: "Control Plane Marketplace"
description: "Input channels, output routes, report packs, and workflow templates for the client-side SecurityRecipes browser workbench."
date: 2026-05-03
lastmod: 2026-05-05
tags:
  - marketplace
  - browser
  - byot
  - integrations
  - workflows
  - scanning
---

# Control Plane Marketplace

SecurityRecipes now treats the browser workbench as a small **client-side control plane**:

1. **Input channels** pull context into the session.
2. **Recipes** sit in the middle and shape the agent's bounded job.
3. **Report profiles** define the output contract.
4. **Output channels** hand the result downstream.

The goal is to let a team run useful AI security work in the browser with **bring-your-own tokens**, while still keeping the integration shape explicit, reviewable, and forkable.

Routing policies now sit alongside that path. They turn severity, owner, workflow, source, and asset criticality into consistent downstream defaults before a case, ticket, or webhook leaves the browser.

The browser workbench now also includes a **Reports desk** that bridges those layers: take a saved case, an exposure queue item, or a grouped browser-local investigation session, apply a report profile plus output route, and turn it into a reusable handoff packet without leaving the browser shell.

The **Agents** planner now also includes a **Launch readiness** lane. It audits the active run for missing provider credentials, weak target anchoring, selected-source freshness gaps, workflow-pack review blockers, and route prerequisites before the operator generates a plan or attempts downstream delivery.

Captured cases and generated reports now preserve that readiness packet so downstream reviewers can see whether a run was live-ready, review-ready, or still blocked when the artifact was produced.

The Reports desk, Caseboard, Router, and daily ops brief now also derive a
**handoff drift** view that compares a saved case's captured readiness
against the current browser handoff context before the operator routes
anything downstream.

## Why this exists

Recent market signals point in the same direction:

- Integration breadth matters, but only when it is governed. Airia's February 26, 2026 MCP update emphasized change detection, version pinning, and audit logging across a large connector catalog.
- Security teams want AI outputs to fit existing pipelines. Command Zero's April 29, 2026 API and MCP release explicitly positioned AI investigations as something to embed into existing SecOps flows.
- The market has moved from experimentation to integration. Wiz's April 29, 2026 State of AI in the Cloud recap framed 2026 as "the year of integration" and called out agents plus MCP servers as a new control-plane attack surface.
- Security teams still lose too much time to manual handoffs. Tines' January 28, 2026 Voice of Security report highlighted persistent repetitive work, which is exactly the gap structured workflow templates and normalized report bundles should close.
- APIs, MCP servers, and data access now behave like one attack surface. Salt Security's April 8, 2026 report framed the agentic stack as LLMs, MCP servers, APIs, and data operating together.
- The browser is now a real AI operating surface. The March 6, 2026 browser security report highlighted widespread AI tool use, sensitive inputs, and extension risk inside the browser itself.
- Setup visibility is now part of the product, not just admin plumbing. Microsoft's [Use plugins in Security Copilot](https://learn.microsoft.com/en-us/copilot/security/use-plugins) page, last updated October 20, 2025, explicitly calls out plugin state filters and per-plugin personalization settings, and its [Security Copilot workflows overview](https://learn.microsoft.com/en-us/copilot/security/workflows-overview), last updated March 18, 2026, frames plugin configuration and agent success review as part of the same operator workflow.
- Workflow customization is now part of the product baseline. [Tines](https://explained.tines.com/en/articles/12709787-templates-in-tines) now distinguishes public and private templates, [Cortex XSOAR](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Cortex-Marketplace) continues to center its marketplace on contributed content packs and playbooks, and [Torq](https://torq.io/hyperautomation/) is pushing AI-generated workflows and integrations.
- SecOps products are collapsing cases and automation into one operating surface. [Elastic's March 23, 2026 Workflows launch](https://www.elastic.co/blog/workflows-soar) framed alert triage, investigation, and response as one native flow instead of separate tools.
- Operators increasingly expect delivery state to stay traceable after the run. [Microsoft Security Copilot documentation](https://learn.microsoft.com/en-us/copilot/security/) now exposes both audit-log guidance and admin activity export APIs, [CrowdStrike Charlotte AI](https://www.crowdstrike.com/en-us/platform/ai-security/) positions traceable answers and user-authorized actions as part of safe agent deployment, and [Cortex XSOAR War Room](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-SaaS-Documentation/Use-the-War-Room-in-an-investigation) keeps automatic and manual investigation actions in one audit trail.

This marketplace is SecurityRecipes' answer: **keep the integration plane visible, typed, and client-owned**.

## Contribution model

Marketplace entries are designed to be submitted the same way recipes are:

- Add or edit JSON under `data/marketplace/`
- Add or update docs that explain the intended operator workflow
- Open a pull request for review

The marketplace is intentionally split into five catalogs:

- `catalog.json`: positioning, runtime model, and market signals
- `input_channels.json`: context and finding sources
- `output_channels.json`: downstream delivery routes
- `report_profiles.json`: report shapes and evidence contracts
- `workflow_templates.json`: opinionated bundles that stitch the other pieces together

Contribution packets and browser-local drafts now also support a shared
**pack governance** block: version, owner, review date, review cadence,
docs link, capability tags, and explicit pack-to-pack dependency
references.

The Hugo home build now also emits public JSON feeds for those same contracts at the site root, including a combined `marketplace-control-plane.json` manifest. That gives external tools a stable discovery surface without changing the BYO-token browser runtime model.

Routing policies are intentionally separate from those public catalogs. Most teams treat assignment, approval, and ticket-project defaults as tenant-local operating policy, so SecurityRecipes keeps them browser-local while still publishing portable schemas for review and handoff.

The public docs surface now also publishes a derived
`/marketplace-readiness.json` feed and a gallery-side readiness matrix
that explains the current requirement and blocker model for each input
or output pack. The goal is to make "why is this still only
live-or-copy?" or "what is still blocking this route from becoming
browser-live?" answerable without opening the chatbot shell.

The Router and Asset portfolio preview now sit one layer above that
readiness model: they derive a browser-local portfolio coverage snapshot
that scores each service portfolio by owner capture, case coverage,
routing coverage, and live-delivery blockers. That same JSON now travels
inside normalized report bundles so downstream review can see which
business services are still unrouted, blocked, or only handoff-ready.

## Major-vendor starter catalog

The public marketplace now ships a broader starter catalog so the workbench feels more like a complete client-side security application instead of a narrow chat surface.

The current catalog now covers starter packs for:

- code and issue systems such as GitHub, GitLab, and Azure DevOps
- scanner and incident sources such as SARIF, SBOM, Snyk, Security Hub, Defender XDR, Sentinel, CrowdStrike, Tenable, DefectDojo, Prisma Cloud, and Google Cloud SCC
- downstream routes such as ServiceNow, Jira, Linear, GitLab Issues, Azure DevOps Work Items, Splunk, Elastic, PagerDuty, Teams, Google Chat, Cortex XSOAR, IBM SOAR, and generic webhooks

That does **not** mean every route is live in the browser today.
The contract model stays explicit:

- `live` or `live_or_copy` means the browser workbench can already drive it with browser-local credentials
- `planned` means the repo now ships a reviewed starter contract so operators can inspect, fork, and extend the shape before a live browser implementation lands
- report profiles and workflow packs remain first-class reusable contracts in the middle so teams can standardize output even when they swap inputs or destinations

## Workflow Pack Lab

The browser workbench now includes a **Workflow Pack Lab** inside the Control Plane tab.

It fills the gap between "the marketplace is public" and "operators can actually contribute":

- clone a curated or community pack as a starting point
- capture the current agent planner configuration as a reusable pack
- save private workflow packs in browser storage without introducing a server dependency
- apply those local packs back into the agent planner
- copy a contribution-ready JSON packet for `data/marketplace/workflow_templates.json`

This keeps the runtime honest and client-side:

- local packs stay private until the operator chooses to export them
- the public site still comes from Hugo data files and pull requests
- contribution export stays aligned to the same workflow-template contract the site already publishes

## Report Profile Lab

The Control Plane tab now also includes a **Report Profile Lab** for
browser-local authoring of normalized report and evidence contracts.

It closes the next gap between "we can route a result" and "the result
shape itself is reusable and reviewable":

- clone or author a report profile locally in browser storage
- capture the intended format, sections, and example JSON payload in one place
- apply a local report profile back into the Agents planner before a run
- copy a contribution-ready JSON packet for `data/marketplace/report_profiles.json`
- let local workflow packs and routing policies reference browser-local report contracts before anything is made public

This follows the direction visible in current security products:

- [Cortex XDR report templates](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-5.x-Documentation/Run-or-schedule-reports)
  now treat report templates as importable and exportable JSON artifacts,
  which supports making report profiles first-class portable contracts
  instead of leaving them as fixed built-ins
- [Microsoft Defender incident reports](https://learn.microsoft.com/en-us/defender-xdr/security-copilot-m365d-create-incident-report)
  position AI-generated incident reporting as a first-class operator
  surface, which supports keeping report structure explicit alongside
  prompts, cases, and downstream routes

SecurityRecipes keeps the same shape, but stays honest to the BYO-token
browser model:

- local report profiles stay private until the operator chooses to export them
- workflow packs, routing policies, and agent runs can reuse the same local report contract
- the public marketplace source of truth remains Hugo data files plus pull requests

## Integration Pack Lab and local library export

The Control Plane tab now also includes an **Integration Pack Lab** for
browser-local authoring of input-channel and output-channel contracts.

It fills the next gap in the marketplace story:

- clone an existing input or output pack as a starting point
- author a private input or output contract in browser storage
- capture auth modes, runtime support, delivery expectations, and JSON config in one place
- copy a contribution-ready JSON packet for `data/marketplace/input_channels.json` or `data/marketplace/output_channels.json`
- export or import the entire local marketplace library so private input, output, report, and workflow contracts can move between browser profiles before they become public PRs

This is directly aligned with how the market is now describing automation
content:

- [Tines](https://explained.tines.com/en/articles/12709787-templates-in-tines)
  explicitly distinguishes public and private reusable templates
- [Cortex XSOAR](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.10/Cortex-XSOAR-On-prem-Documentation/Content-pack-contributions)
  documents reviewed content-pack contributions and Git-friendly export paths
- [Torq](https://kb.torq.io/en/articles/10662506-integration-builder-create-custom-integrations)
  documents custom integration builders with auth parameters, docs references,
  and test setup

SecurityRecipes keeps the same shape, but stays honest to the BYO-token
browser model:

- author locally first
- keep secrets and draft contracts in browser storage
- export only when an operator is ready to open a pull request
- keep the public marketplace source of truth in Hugo data files

## Public schemas and in-browser validation

The control plane now publishes first-class schema files for the browser
authoring flow:

- `/marketplace-schemas/index.json`
- `/marketplace-schemas/input-channel-contribution.schema.json`
- `/marketplace-schemas/output-channel-contribution.schema.json`
- `/marketplace-schemas/report-profile-contribution.schema.json`
- `/marketplace-schemas/workflow-template-contribution.schema.json`
- `/marketplace-schemas/local-library.schema.json`
- `/marketplace-schemas/case-file.schema.json`
- `/marketplace-schemas/case-library.schema.json`
- `/marketplace-schemas/asset-library.schema.json`
- `/marketplace-schemas/operations-history.schema.json`
- `/marketplace-schemas/operations-session.schema.json`
- `/marketplace-schemas/routing-policy.schema.json`
- `/marketplace-schemas/routing-library.schema.json`

That closes an important gap between "the browser can export JSON" and
"the browser is producing contribution-ready contracts":

- workflow, report, and integration drafts can now be validated in the browser before the operator copies a submission packet into a Hugo pull request
- local marketplace-library export now validates before copy/download, and local library import validates before anything is merged into browser storage
- the root `marketplace-control-plane.json` manifest now advertises the schema URLs so downstream tooling can discover both the data feeds and the authoring contracts from one place

This mirrors how mature marketplace systems are now handling contribution
quality:

- [Cortex XSOAR](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.10/Cortex-XSOAR-On-prem-Documentation/Content-pack-contributions)
  validates contributions before submit or download and exposes raw JSON
  error output when validation fails
- [Torq](https://kb.torq.io/en/articles/10662506-integration-builder-create-custom-integrations)
  treats documentation links, auth parameters, and test setup as
  first-class parts of integration authoring rather than hidden
  implementation details

SecurityRecipes keeps the same pattern, but stays BYO-token and
client-side:

- validate locally
- keep draft contracts in browser storage until the operator chooses to export them
- publish only the reviewed Hugo data files plus the generated public feeds and schemas

## Pack governance and dependency health

The marketplace now treats contributed packs more like real security
content bundles instead of flat connector stubs.

Every input pack, output pack, report profile, and workflow pack can now
carry:

- a version token such as `1.0.0`
- an owner field for the team or operator responsible for the contract
- a reviewed-at date plus review cadence in days
- a docs link that points back to the operating explanation
- explicit required or optional pack references for compatibility checks

That closes the gap between "a pack exists" and "a team can promote or
reuse it safely":

- the browser Control Plane now shows overdue review cadence and missing
  required-pack references before a pack is reused
- workflow packs now expose their pack graph more honestly, which is
  useful when one route, report profile, or input source is still only a
  starter contract
- contribution packets can now carry the same ownership and dependency
  metadata that mature security marketplaces expect during review

This follows current product direction in the market:

- [Cortex XSOAR's January 28, 2026 content-pack installation guidance](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Administrator-Guide/Content-Pack-Installation)
  explicitly calls out version history plus required and optional pack
  dependencies as first-class install concerns
- [Microsoft Security Copilot's plugin overview](https://learn.microsoft.com/en-us/copilot/security/plugin-overview)
  continues to frame tools and plugins as explicit operator-visible
  capability catalogs rather than invisible implementation details
- [Tines templates](https://explained.tines.com/en/articles/12709787-templates-in-tines)
  continue to distinguish reusable private and public building blocks,
  which makes ownership and review metadata part of the normal workflow

SecurityRecipes keeps the same shape, but stays honest to the browser
runtime:

- pack governance metadata is portable JSON, not server-side hidden state
- review cadence stays visible before a run or export happens
- dependency checks stay explicit so a workflow cannot quietly depend on
  a private local pack that never shipped with the rest of the library

## Operations Ledger

The navigator now also keeps a browser-local **operations ledger**.

It fills the gap between "the browser can do the work" and "an operator can explain what just happened":

- record source refreshes, browser chat sessions, agent runs, case saves/status changes, and report or brief exports in one local history
- group correlated source pulls, agent runs, case captures, and handoff exports into browser-local investigation sessions that can be inspected or exported as one JSON contract
- surface that history inside Navigator as both a process-log view and an investigation-session explorer instead of leaving state changes buried across tabs
- filter the ledger by category, state, or free-text; inspect one record as JSON; and jump back into the linked source, queue, case, or planner surface from the same navigator flow
- export either the full ledger as markdown or JSON, or one grouped investigation session as JSON when a reviewer, auditor, or downstream tool needs the exact correlated run context
- keep the history private to the browser profile until the operator explicitly copies or downloads it

This aligns with where the market is moving:

- [Microsoft Security Copilot navigation and prompting docs](https://learn.microsoft.com/en-us/copilot/security/navigating-security-copilot) now treat process logs and session history as first-class workflow surfaces
- [Microsoft Security Copilot audit log guidance](https://learn.microsoft.com/en-us/copilot/security/audit-log) explicitly frames prompt, response, and activity metadata as audit artifacts
- [Cortex XSOAR incident management docs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.11/Cortex-XSOAR-Administrator-Guide/Incident-Management) continue to position the incident investigation surface as the place to review status, timeline, and escalations together
- [Cortex XSOAR War Room docs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-SaaS-Documentation/Use-the-War-Room-in-an-investigation) continue to position the incident timeline as the place to document automatic and manual actions in one source
- [Elastic Attack Discovery docs](https://www.elastic.co/docs/solutions/security/ai/attack-discovery) now emphasize saving discoveries for later review, reporting, tracking, and search/filter operations instead of treating AI findings as one-shot output

SecurityRecipes keeps the same direction, but stays honest to the BYO-token browser model:

- history stays in browser storage
- export is operator-triggered
- the public schema makes the handoff contract explicit without introducing server-side state

## Asset and Ownership Board

The browser workbench now also includes an **Asset and Ownership Board**.

It closes the gap between "we have a queue" and "we know who should own
the fix":

- register repositories, services, hosts, APIs, tenants, or cloud resources locally in the browser
- capture owner team, owner contact, environment, aliases, and business criticality on one portable contract
- import or export a full asset library as JSON, or ingest a quick CSV/TSV inventory the same way other SecOps tools bulk-load criticality
- enrich Exposure Board items and Caseboard entries with matched asset context before a ticket, webhook, or reviewer handoff leaves the browser
- group repositories, services, APIs, data stores, or cloud resources into browser-local service portfolios so the queue can roll up to something a real SecOps team owns
- capture lightweight related-asset links so the Router can surface a small service-map view instead of treating every repository or hostname as an island

This follows how current exposure and SecOps platforms are describing the
problem:

- [Wiz ASM](https://www.wiz.io/solutions/asm) now positions exposure
  management around what is exploitable, what the business impact is, and
  who owns the fix
- [Microsoft Security Exposure Management](https://learn.microsoft.com/en-us/security-exposure-management/microsoft-security-exposure-management)
  frames the product around a unified view across assets and workloads plus
  protection of critical assets
- [Elastic Asset Criticality](https://www.elastic.co/docs/solutions/security/advanced-entity-analytics/asset-criticality)
  supports bulk criticality assignment from inventory files so downstream
  alerts can inherit business priority

SecurityRecipes keeps the same product direction, but remains honest to
the browser-first runtime:

- the asset register stays in browser storage until the operator exports or deletes it
- the import/export contract is schema-backed and machine-readable
- asset enrichment affects local queueing and case context; it does not imply that any external CMDB or ticketing system was updated

## Routing Policy Lab

The Control Plane now also includes a **Routing Policy Lab**.

It closes the gap between "we know the owner" and "the correct downstream path is chosen consistently":

- author browser-local routing policies that match on severity threshold, asset criticality, workflow value, source channel, owner team, or environment
- match on service portfolio IDs when one business service spans multiple repositories, APIs, or backing stores
- recommend the downstream output route, report profile, approval gate, context pack, cadence, and ticket/project defaults before the operator delivers anything
- apply the same routing decision from the Exposure Board, Caseboard, and Agents planner so triage and delivery share one local rule set
- export or import single policies or full routing libraries on published schema contracts

This follows the direction visible in current SecOps platforms:

- [Microsoft Sentinel automation rules](https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules) center triggers, conditions, ordered actions, incident owner assignment, severity changes, and playbook execution in one rule surface
- [Elastic Security workflows](https://www.elastic.co/docs/explore-analyze/workflows/use-cases/security) now describe security workflows as a place to respond automatically, create and populate cases, route notifications by severity, and investigate with AI assistance
- [Elastic Security cases](https://www.elastic.co/docs/solutions/security/investigate/security-cases) keep external escalation tied to case context and connectors such as Jira and ServiceNow, which supports pre-filling downstream destination metadata instead of leaving every handoff manual
- [ServiceNow CMDB-based mapping](https://www.servicenow.com/docs/r/it-operations-management/service-mapping/cmdb-based-mapping.html) maps application services from related host and dependency context, which supports carrying a light service-map layer into browser-local routing instead of routing only on one asset at a time

SecurityRecipes keeps the same product shape, but remains honest to the
browser-first runtime:

- routing rules stay in browser storage unless the operator explicitly copies or downloads them
- a routing recommendation does not send data anywhere; it only preconfigures the planner or case handoff
- operators can still override a recommendation before any live connector runs

## Routing explainability and auditability

The browser workbench now surfaces the routing decision itself instead of
treating policy matches as hidden glue:

- the **Agents** tab now shows a routing explainability panel with the
  matched policy, candidate signals, recommended route/report/review
  defaults, integration defaults, and current planner divergence
- the **Router** tab now shows a planner routing audit card so an
  operator can see the same decision without leaving the orchestration
  surface
- normalized report bundles and delivery envelopes now carry the same
  routing analysis JSON, so downstream review can inspect the decision
  context instead of trusting a silent route selection

That direction lines up with how the market is describing governed
automation now:

- [Microsoft Sentinel automation rules](https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules)
  emphasize ordered conditions, actions, and escalation logic in one
  surface
- [ServiceNow flow execution details](https://www.servicenow.com/docs/r/build-workflows/workflow-studio/flow-execution-details.html?contentId=TQmEZT4017Q7XcTIkebtNA)
  exposes runtime state, values, and logs directly in the workflow UI
- [Tines](https://www.tines.com/) now explicitly positions deterministic
  workflows as the right place for triage, routing, and explainability

SecurityRecipes keeps the same governance goal, but remains browser-first:

- the routing analysis is local unless the operator copies or downloads it
- divergence is visible before any external write happens
- route readiness is explicit, including missing browser-held integration
  settings for live or live-or-copy routes

The new public readiness matrix pushes that visibility one step further:

- the site can now explain the auth pattern, runtime requirement, and
  current platform blocker for each published input or output contract
- external tools can consume the same explanation through
  `/marketplace-readiness.json` instead of scraping badge text out of the
  docs page
- the in-app Control Plane cards now reuse the same readiness model so
  the browser shell and the public gallery no longer drift

The browser **Security navigator** now adds a source-sync layer on top
of that readiness story:

- the navigator home view includes a source freshness watch that shows
  which browser-local snapshots are current, which ones are stale, and
  which planner-selected sources were never loaded successfully
- the navigator now also adds a source recovery hub that classifies
  credential rejects, browser fetch blockers, setup gaps, and file
  format issues, then gives the operator copyable diagnostics plus
  direct retry or setup actions
- GitHub, deps.dev, Snyk, and Confluence can now be refreshed inline
  from that surface without bouncing back into settings first
- SARIF and SBOM stay honest to the browser sandbox: the navigator sends
  those channels back to the local upload surface instead of pretending
  the browser can silently re-open files
- bulk "refresh due sources" runs stay explicit and BYO-token: they only
  re-pull browser-safe API sources that are already in scope for the
  current workbench state

That moves the workbench closer to the way mature SecOps products now
surface ingestion health:

- [Google SecOps Health Hub](https://docs.cloud.google.com/chronicle/docs/reports/data-health-monitoring-and-troubleshooting-dashboard)
  centralizes failed sources and remediation context for data pipelines
- [Microsoft Security Exposure Management prerequisites](https://learn.microsoft.com/en-us/security-exposure-management/prerequisites)
  call out explicit freshness windows and current-snapshot behavior for
  connector-driven graph data

## Mission control and daily ops brief

The navigator home now also includes a **Mission control** layer so the
workbench feels like an operator console instead of a set of separate
browser panels:

- surface due, failed, running, and generated browser-scheduled agent actions
- let an operator run a due scheduled action immediately from the navigator instead of hunting for it in the queue
- summarize the current queue head, open cases, source issues, and top portfolio coverage gap in one place
- highlight saved cases whose current handoff context has drifted from the captured run so they can be revalidated before delivery
- export a browser-local daily ops brief as markdown for copy/paste or JSON for downstream review and automation

That direction lines up with the current product baseline in larger
security platforms:

- [Microsoft Security Copilot prompting and promptbooks](https://learn.microsoft.com/en-us/copilot/security/prompting-security-copilot)
  now position promptbooks as reusable role-based task flows that are
  surfaced directly from the home screen
- [Elastic Attack Discovery](https://www.elastic.co/docs/solutions/security/ai/attack-discovery)
  now supports scheduled discoveries, saved review state, shareable
  results, and connector-based notifications from the same operating
  surface
- [Google SecOps Health Hub](https://docs.cloud.google.com/chronicle/docs/reports/data-health-monitoring-and-troubleshooting-dashboard)
  centralizes source-health, failure, and remediation context instead of
  leaving ingestion troubleshooting scattered across setup pages

SecurityRecipes keeps the same operational shape, but stays honest to the
browser-first BYO-token runtime:

- the mission board is derived entirely from browser-local schedules,
  queue state, cases, routes, and source health
- running a scheduled action from the navigator still requires the tab to
  be open and uses the saved browser-local provider credential
- the exported daily ops brief is local until the operator copies,
  downloads, or routes it downstream

The next governance layer is service coverage itself:

- [Microsoft Security Exposure Management initiative metrics](https://learn.microsoft.com/en-gb/security-exposure-management/security-metrics)
  measure exposure for a scoped set of assets and call out state,
  progress, affected assets, weight, and associated recommendations
- [Elastic entity risk scoring](https://www.elastic.co/docs/solutions/security/advanced-entity-analytics/entity-risk-scoring)
  combines alerts and asset criticality into a recurring score so
  operators can prioritize the entities that are drifting upward

SecurityRecipes now mirrors that pattern locally:

- the **Router** and **Assets** tabs show a per-portfolio coverage state
  and score instead of treating the service map as passive reference data
- coverage snapshots call out owner gaps, unrouted exposures,
  starter-contract routes, and live configuration blockers
- linked assets now derive upstream and downstream portfolio fan-out so
  the browser can show which service dependencies still widen blast
  radius when one route or owner gap remains unresolved
- normalized report bundles now carry `portfolio_coverage_analysis`
  alongside routing analysis so exported review packets explain which
  services are still uncovered and why

That exported `portfolio_coverage_analysis` contract now sits on a
published schema at `/marketplace-schemas/portfolio-coverage.schema.json`
so downstream consumers can validate the dependency-aware snapshot
instead of treating the Router copy action as an undocumented blob.

## Exposure Board

The browser workbench now also includes an **Exposure Board**.

It fills the next gap between "bounded context is available" and "an
analyst has a real queue to work":

- turn cached SARIF, SBOM, Snyk, Defender XDR, and Sentinel summaries already in the browser into a small prioritized queue
- group findings into actionable clusters instead of leaving them buried inside raw JSON previews
- recommend the most likely remediation workflow and workflow pack for each queue item
- show whether a queue item is still untracked or already related to a local case
- load a selected queue item directly into the Agents planner or capture it as a new local case file

The shape is intentional and tracks how current exposure-management tools
differentiate:

- [Wiz Exposure Management](https://www.wiz.io/solutions/exposure-management)
  emphasizes unifying findings across scanners, removing alert silos,
  enriching with context, and turning ownership into action
- [Wiz Security Graph](https://www.wiz.io/lp/wiz-security-graph)
  frames risk prioritization around connected code, cloud, runtime,
  identity, and blast-radius context rather than isolated findings
- [Elastic Security Cases](https://www.elastic.co/docs/solutions/security/investigate/security-cases)
  and [Microsoft Sentinel incident investigation](https://learn.microsoft.com/en-us/azure/sentinel/incident-investigation)
  both position the analyst workflow as queue, investigation, case, and
  escalation in one surface

SecurityRecipes keeps the same direction, but stays honest to the
browser-first model:

- the queue is built only from bounded summaries already present in browser storage
- nothing is fetched or sent unless the operator explicitly enabled that source
- loading a queue item into Agents or Caseboard does not imply that any external system was modified

## Local Caseboard

The browser workbench now also includes a **Local Caseboard**.

It closes another gap between "useful AI helper" and "complete security
application":

- capture the latest reviewed agent run as a reusable browser-local case file
- keep the scope, selected inputs, normalized report bundle, output contract, and generated response together
- preserve the captured launch-readiness packet alongside the case timeline so reviewers can see what setup, freshness, or route blockers existed at save time
- retain a small timeline of key events such as capture, status change, and delivery outcome
- replay the saved planner state back into the Agents tab without re-entering context by hand
- copy or download the full case JSON for downstream review, evidence retention, or customer-specific routing
- validate a selected case file against the published case schema before it leaves the browser
- export or import the full local Caseboard library on a stable schema-backed contract so saved investigations can move between browser profiles

This is consistent with how current SecOps products keep investigations
grounded:

- [Elastic Security Cases](https://www.elastic.co/docs/solutions/security/investigate/security-cases)
  centers investigation context, metrics, attachments, timelines, and
  connector-based escalation in one place
- [Microsoft Sentinel incident investigation](https://learn.microsoft.com/en-us/azure/sentinel/incident-investigation)
  frames the incident page as a complete case-management surface with an
  always-updated chronology of evidence and actions
- [Cortex XSOAR's War Room](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-SaaS-Documentation/Use-the-War-Room-in-an-investigation)
  still emphasizes the audit trail of manual and automated actions inside
  each incident

SecurityRecipes keeps the same product shape, but remains honest to the
browser-first runtime:

- the case file stays in browser storage until the operator deletes or exports it
- the portable library stays in browser storage until the operator explicitly copies, downloads, or imports it
- there is no hidden server-side state or ticket database
- downstream delivery still happens only when the operator explicitly runs an output route
- replaying a case back into the planner does not claim that any external system was modified

## Report Desk

The browser workbench now also includes a **Reports desk**.

It closes the gap between "we captured a useful artifact" and "we can hand it to another system in a consistent shape":

- seed a downstream-ready report from a saved Caseboard case, an Exposure Board queue item, or a grouped browser-local investigation session
- switch the report profile and output channel without redoing the underlying case capture or queue triage
- keep analyst notes, the selected report contract, and the selected output route together in one browser-local workspace
- carry the current launch-readiness packet, and any source-case readiness packet, into exported JSON so reviewers can compare capture-time and delivery-time posture
- copy or download the normalized JSON packet directly from the same surface
- reuse the existing browser delivery routes for case- and exposure-backed reports when the chosen route is live or live-or-copy

This mirrors current platform direction:

- [Cortex XDR report templates](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-5.x-Documentation/Run-or-schedule-reports) now treat report templates as first-class JSON artifacts that can be imported, exported, scheduled, and shared
- [Microsoft Security Copilot's Export Activity API](https://learn.microsoft.com/en-us/copilot/security/activity-export-api) now treats prompt and session export as an explicit contract instead of disposable UI state
- [Elastic Security cases](https://www.elastic.co/docs/solutions/security/investigate/security-cases) keep evidence, connectors, and escalation in one case surface, which supports generating the report from the same saved local artifact instead of from a separate reporting tool

SecurityRecipes keeps the same product shape, but remains honest to the
browser-first runtime:

- case- and exposure-backed reports can reuse the existing browser delivery path
- investigation-session packets stay export-first unless the operator promotes the work into a case or another explicit handoff artifact
- the selected report, analyst notes, and downloaded JSON stay local to the browser profile until the operator copies, downloads, or routes them downstream

## Runtime model

The browser workbench follows four operating modes:

- `live`: the browser can call the source or destination directly right now
- `live_or_copy`: the browser can write directly, or fall back to a local handoff
- `copy_only`: the browser generates the packet locally and does not write externally
- `config_only` / `planned`: the repo ships the JSON contract now, while live execution waits for an approved connector or relay

That keeps the product honest. A template can be present in the marketplace before the corresponding connector is promoted to live browser execution.

## Live local scanner intake

The browser workbench now promotes two scanner-oriented input channels from template-only contracts to live local runtime support:

- `sarif-manual-import`: upload a SARIF 2.1.0 JSON file in the browser and attach a bounded findings summary to chat prompts or agent runs
- `sbom-manual-import`: upload a CycloneDX or SPDX JSON SBOM and attach a bounded dependency and package inventory summary

This is still browser-first and BYO-token:

- the raw file stays local to the browser session
- the app stores only a bounded normalized summary in browser storage
- nothing is sent to a model unless the operator enables the channel and sends a prompt or agent run

The standards choice is deliberate:

- [GitHub documents SARIF](https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/code-scanning/sarif-files) as the interchange format for code scanning uploads
- [Harness STO documents SARIF 2.1.0 ingestion](https://developer.harness.io/docs/security-testing-orchestration/custom-scanning/ingest-sarif-data) as the generic path for many third-party scanners
- [CycloneDX JSON](https://cyclonedx.org/docs/1.7/json/) and [SPDX](https://spdx.github.io/spdx-spec/v2.3/) remain the two most practical JSON shapes for package and dependency inventory exchange

## Live SaaS and incident intake

The browser workbench now promotes four hosted sources from template-only
contracts to live runtime support:

- `snyk-issues-api`: pull a bounded first page of organization issues directly from the [Snyk REST Issues API](https://docs.snyk.io/snyk-api/reference/issues)
- `confluence-knowledge`: search [Confluence Cloud content](https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-search/) for runbooks and exception notes using browser-local credentials
- `microsoft-defender-xdr-incidents`: pull a bounded browser-side incident sample from the [Microsoft Defender XDR incidents API](https://learn.microsoft.com/en-us/defender-xdr/api-list-incidents)
- `microsoft-sentinel-incidents`: pull a bounded workspace-scoped incident sample from the [Microsoft Sentinel incidents REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list)

The intent is to keep the "all in one AppSec remediation surface" promise without breaking the BYO-token model:

- tokens remain in browser storage
- Microsoft workspace identifiers remain in browser storage alongside the token and are never relayed to a server component
- the fetch is explicit and operator-triggered
- only a bounded normalized summary is attached to prompts and agent runs
- the resulting report bundle stays inspectable and exportable

The capability choice is grounded in current vendor guidance:

- Snyk's REST API is versioned by date and supports org-level issue retrieval with severity and status filters, which makes it a good fit for bounded browser-side intake
- Atlassian documents both Confluence Cloud search scopes and API-token-based basic auth for script-style REST clients, which maps well to a user-operated browser workbench
- Microsoft documents Defender XDR incident listing through `GET /api/incidents` with delegated incident-read permissions, which fits the browser-local BYO-token fetch model when analysts already have a scoped bearer token
- Microsoft documents Sentinel incident listing through the Azure Resource Manager SecurityInsights incidents route, which fits a browser-local workspace pull so long as the operator supplies the workspace coordinates and bearer token explicitly

## Live GitLab intake

The browser workbench now also promotes two GitLab-centered input channels from starter contracts to live browser runtime support:

- `gitlab-project-context`: pull bounded project metadata plus selected repository files, open issues, and open merge requests through the [Projects API](https://docs.gitlab.com/api/projects/), [Issues API](https://docs.gitlab.com/api/issues/), and [Merge Requests API](https://docs.gitlab.com/api/merge_requests/)
- `gitlab-vulnerability-findings`: pull a bounded first page of project findings through the [Vulnerability Findings API](https://docs.gitlab.com/ee/api/vulnerability_findings.html)

The runtime stays honest to the current GitLab contract:

- public project metadata can load without auth where GitLab allows it, but private project context and all vulnerability-findings calls depend on a browser-local token
- GitLab explicitly documents the vulnerability-findings REST surface as unstable and recommends GraphQL longer-term, so SecurityRecipes keeps the browser result bounded, sampled, and reviewer-visible instead of pretending it is a durable bulk-export API
- project-level security access still matters: if the token cannot use the Project Security Dashboard, findings intake will fail fast and surface that state in the navigator recovery flow

## Live Azure DevOps repository intake

The browser workbench now also promotes `azure-devops-repository` from a starter contract to live browser runtime support:

- resolve the target repository through the [Git Repositories API](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/repositories/list?view=azure-devops-rest-7.1)
- load bounded repository files through the [Git Items API](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/items/get?view=azure-devops-rest-7.1)
- sample active pull requests through the [Pull Requests API](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.1)
- sample recent non-closed work items through [WIQL](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/wiql?view=azure-devops-rest-7.1) plus the [Work Items API](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/list?view=azure-devops-rest-7.1)

The runtime stays honest to the current Azure DevOps platform posture:

- organization, project, repository, and token values stay in browser storage until the operator clears them
- [Microsoft's current REST guidance](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/rest/samples?view=azure-devops) recommends Microsoft Entra tokens for production while still allowing PAT-backed script access, which fits the BYO-token browser model
- Microsoft's [public-project retirement guidance](https://learn.microsoft.com/en-us/azure/devops/organizations/projects/public-projects-retirement?view=azure-devops), last updated May 1, 2026, says public projects are retired and remaining public projects convert to private in 2027, so SecurityRecipes treats Azure DevOps as an authenticated enterprise source rather than an anonymous repository feed

## Live normalized scan bundle export

Imported scanner context is now useful beyond prompt stuffing.

When the operator selects the `scan-findings-bundle` report profile, the browser workbench can now generate a first-class JSON bundle that includes:

- report metadata and runtime details
- the selected input-channel contract
- normalized SARIF severity counts and sample findings
- SBOM component, package, dependency, and vulnerability summaries
- recommended remediation workflows inferred from the imported evidence
- the generated agent output that explains what to do next

That matters for the product shape:

- the browser stays the execution surface
- secrets still stay local
- the result becomes a reusable JSON artifact that can be copied, downloaded, or fed into downstream relays and integrations

This is the path from "AI chatbot" to "actual security application": every run should leave behind a bounded contract that another system or reviewer can consume.

## Live downstream delivery expanded

The browser workbench now treats several major output routes as `live_or_copy` instead of template-only:

- Microsoft Teams through a Workflows webhook
- ServiceNow incident or task records through the Table API
- Linear issues through the GraphQL API
- GitLab issues through the project Issues API with browser-local token storage
- Azure DevOps work items through the Work Item Tracking create endpoint with browser-local PAT or bearer token storage
- Splunk HEC events for SIEM and analytics
- Elastic Security cases through the Kibana Cases API
- generic webhooks for customer-specific relays

This keeps the product aligned with the BYO-token promise:

- operator secrets stay in browser storage
- delivery still happens only when the user explicitly configures the route
- copy/download remains available when CORS, auth scope, or target policy blocks direct browser delivery

If you want the public inventory instead of the narrative explanation, use the
[Marketplace and Workflow Gallery]({{< relref "/docs/marketplace-gallery" >}}).

## Example output channel contract

```json
{
  "id": "slack-webhook",
  "driver": "slack",
  "runtime_support": "live",
  "browser_delivery": true,
  "config": {
    "type": "slack_webhook",
    "webhook_url": "https://hooks.slack.com/services/...",
    "message_format": "mrkdwn"
  }
}
```

## Example input channel contract

```json
{
  "id": "github-repository",
  "runtime_support": "live",
  "auth_modes": ["public", "pat", "oauth"],
  "config": {
    "type": "github_repository",
    "repository": "owner/repo",
    "include": ["readme", "security", "manifests", "issues", "pull_requests"]
  }
}
```

## Example workflow template contract

```json
{
  "id": "github-dependency-pr-handoff",
  "workflow_value": "dependency",
  "default_report_profile_id": "remediation-pr-packet",
  "default_output_channel_id": "draft-pr-packet",
  "default_input_channel_ids": [
    "page-context",
    "recipe-index",
    "github-repository",
    "deps-dev-advisories"
  ]
}
```

## Product direction

This marketplace is intentionally opinionated:

- **Browser-first**: credentials stay local whenever possible.
- **Recipe-centered**: the marketplace wraps the remediation knowledge base instead of replacing it.
- **Report-driven**: every scan or remediation action should produce a reusable downstream contract.
- **Honest about maturity**: not every template is live; some are scaffolds for future connectors or customer-specific relays.
- **Private before public**: operators should be able to prove a workflow locally in the browser before turning it into contributed marketplace content.
- **Portable local draft state**: private packs should be exportable and importable between browsers before they are promoted into public site data.

The near-term expansion path is straightforward:

- more scanner source templates
- more downstream ticketing and SIEM payloads
- more external consumers of the public marketplace JSON feeds
- direct SaaS scanner and incident API intake beyond Snyk, Defender XDR, Sentinel, and Confluence where browser-safe auth and CORS make it practical
- richer report packs for trust-center and governance uses
- user-submitted workflow templates that bundle the above into repeatable operating motions
