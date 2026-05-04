---
title: "Control Plane Marketplace"
description: "Input channels, output routes, report packs, and workflow templates for the client-side SecurityRecipes browser workbench."
date: 2026-05-03
lastmod: 2026-05-03
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

## Why this exists

Recent market signals point in the same direction:

- Integration breadth matters, but only when it is governed. Airia's February 26, 2026 MCP update emphasized change detection, version pinning, and audit logging across a large connector catalog.
- Security teams want AI outputs to fit existing pipelines. Command Zero's April 29, 2026 API and MCP release explicitly positioned AI investigations as something to embed into existing SecOps flows.
- The market has moved from experimentation to integration. Wiz's April 29, 2026 State of AI in the Cloud recap framed 2026 as "the year of integration" and called out agents plus MCP servers as a new control-plane attack surface.
- Security teams still lose too much time to manual handoffs. Tines' January 28, 2026 Voice of Security report highlighted persistent repetitive work, which is exactly the gap structured workflow templates and normalized report bundles should close.
- APIs, MCP servers, and data access now behave like one attack surface. Salt Security's April 8, 2026 report framed the agentic stack as LLMs, MCP servers, APIs, and data operating together.
- The browser is now a real AI operating surface. The March 6, 2026 browser security report highlighted widespread AI tool use, sensitive inputs, and extension risk inside the browser itself.

This marketplace is SecurityRecipes' answer: **keep the integration plane visible, typed, and client-owned**.

## Contribution model

Marketplace entries are designed to be submitted the same way recipes are:

- Add or edit JSON under `data/marketplace/`
- Add or update docs that explain the intended operator workflow
- Open a pull request for review

The marketplace is intentionally split into four catalogs:

- `catalog.json`: positioning, runtime model, and market signals
- `input_channels.json`: context and finding sources
- `output_channels.json`: downstream delivery routes
- `report_profiles.json`: report shapes and evidence contracts
- `workflow_templates.json`: opinionated bundles that stitch the other pieces together

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

The near-term expansion path is straightforward:

- more scanner source templates
- more downstream ticketing and SIEM payloads
- direct SaaS scanner API intake where browser-safe auth and CORS make it practical
- richer report packs for trust-center and governance uses
- user-submitted workflow templates that bundle the above into repeatable operating motions
