---
title: "Marketplace and Workflow Gallery"
description: "A public gallery of SecurityRecipes input channels, output routes, report contracts, and workflow bundles for the BYO-token browser workbench."
date: 2026-05-04
lastmod: 2026-05-04
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
