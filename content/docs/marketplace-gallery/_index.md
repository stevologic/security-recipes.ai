---
title: "Marketplace and Workflow Gallery"
description: "A public gallery of SecurityRecipes input channels, output routes, report contracts, and workflow bundles for the BYO-token browser workbench."
date: 2026-05-04
lastmod: 2026-05-05
tags:
  - marketplace
  - workflows
  - integrations
  - byot
  - browser
---

# Marketplace and Workflow Gallery

This is the public control-plane view of the SecurityRecipes browser workbench.

Use it to answer four questions before a team enables a pack:

1. What context enters the run?
2. What report contract leaves the run?
3. Which downstream system receives it?
4. Is the path live, live-or-copy, or still template-only?

{{< callout type="info" >}}
Everything on this page is driven by the Hugo data files under `data/marketplace/`. That means integration packs and workflow bundles can be reviewed, forked, and contributed like any other site content.
{{< /callout >}}

{{< marketplace-gallery >}}

The public gallery now exposes runtime readiness directly, but routing
decisions themselves remain tenant-local on purpose. The live site can
tell you which inputs and outputs are browser-ready; the in-app Router
and Agents views are where an operator inspects which routing policy
matched, which defaults were suggested, and whether the current planner
still diverges before a case or webhook leaves the browser.

The gallery now also includes a dedicated readiness matrix for input and
output packs plus a derived `/marketplace-readiness.json` feed. That
surface answers a more operational question than the normal catalog
cards do: what exactly must the operator configure, and what is still
blocking a starter contract from being considered honestly live in the
browser?

The browser workbench now derives one more layer on top of that public
readiness view: a tenant-local portfolio coverage snapshot. The Router
and Asset portfolio preview score each service portfolio by owner
metadata, case coverage, routing coverage, and route blockers, then ship
that JSON inside normalized report bundles for downstream review.

The in-app **Security navigator** now sits beside that gallery with a
source freshness watch. It can refresh browser-safe sources such as
GitHub, deps.dev, Snyk, and Confluence inline, while still routing
manual-upload channels like SARIF and SBOM back to the browser-local
upload flow instead of pretending those files can be silently reopened.
It also exposes a source recovery hub that turns failed browser fetches,
credential issues, missing setup, and file-format problems into
copyable operator diagnostics before the next run.

The same navigator now also keeps a browser-local **process log and
history** view. It records source syncs, chat sessions, agent runs,
case actions, and report exports so the workbench has a lightweight
operator chronology instead of leaving that context fragmented across
tabs. The latest layer on top of that ledger is a grouped
**investigation sessions** view that correlates source pulls, AI runs,
case captures, and handoff exports into one browser-local session pack
that can be inspected or exported as JSON.

## Feed contract

The gallery now also publishes root-level JSON feeds for the combined control-plane manifest plus the catalog, input-channel, output-channel, report-profile, workflow-template, and derived readiness inventories.

The derived readiness feed sits alongside those root contracts:

- `/marketplace-readiness.json`

It also publishes root-level schema files for browser-authored contribution packets, local marketplace-library exports, and portable Caseboard records:

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
- `/marketplace-schemas/portfolio-coverage.schema.json`
- `/marketplace-schemas/routing-policy.schema.json`
- `/marketplace-schemas/routing-library.schema.json`

That matters for two reasons:

- external systems can consume the marketplace as structured data instead of scraping embedded page state
- contributors still only edit the Hugo data files under `data/marketplace/`; the public feeds and schema files are generated or shipped from the same contribution model during the site build

## Contribution path

To add a new marketplace pack or workflow bundle:

- edit `data/marketplace/input_channels.json`, `output_channels.json`, `report_profiles.json`, or `workflow_templates.json`
- add or update a docs page that explains operator intent, auth shape, and review expectations
- open a pull request with example inputs, expected output shape, and the runtime maturity you are claiming

If the pack is not yet browser-safe, keep it honest:

- `live`: the browser can call it directly today
- `live_or_copy`: the browser can deliver directly when config and CORS allow it, but still has a safe local fallback
- `copy_only`: the browser produces the handoff contract but does not write externally
- `config_only` or `planned`: the JSON contract exists before the connector is promoted to a live runtime path

For workflow packs specifically, the browser workbench now includes a local **Workflow Pack Lab** that can clone marketplace packs, capture the current agent planner configuration, and copy a contribution-ready JSON packet before you open a pull request.

For report contracts, the same Control Plane tab now includes a local
**Report Profile Lab** that can author browser-local report profiles,
validate them, and copy contribution-ready JSON for
`data/marketplace/report_profiles.json`.

For integration packs, the same Control Plane tab now includes an
**Integration Pack Lab** that can clone input/output contracts, save
private local drafts, and export or import a full local marketplace
library JSON bundle before the contracts are contributed publicly.

Both labs now also expose browser-side validation so the operator can
check the draft against the published schema before copying the
submission packet or importing a portable local-library export.

The Caseboard follows the same pattern: exported case files and full
case-library backups now sit on published schema contracts, so portable
browser investigations can be validated before they are handed to
another tool, reviewer, or browser profile.

The new Asset and Ownership Board follows the same contract model:
portable browser-local asset libraries now validate against the
published asset-library schema before they are imported, copied, or
downloaded, including optional portfolio IDs, portfolio labels, and
related asset links for a lightweight local service map.

That service map is no longer just descriptive data. The browser now
derives a coverage score and coverage state for each portfolio so an
operator can see whether the linked service still has owner gaps,
unrouted exposure items, only copy-safe delivery routes, or starter
contracts that still need promotion before live browser use.

The latest layer on top of that local service map is dependency-aware
coverage. Linked assets now fan out into upstream and downstream
portfolio relationships so the Router and Asset preview can show whether
one partially covered service is still blocking or amplifying risk for
other services. The exported portfolio snapshot is now schema-backed as
`/marketplace-schemas/portfolio-coverage.schema.json`, which makes the
copy/download path usable as a stable contract for external consumers.

The Routing Policy Lab follows the same pattern: single-policy exports
and full routing-library exports now validate against published routing
schemas before the browser applies, copies, downloads, or imports them,
including portfolio-aware match logic when multiple assets roll up to
one business service.
