// Port of layouts/shortcodes/marketplace-gallery.html: the control-plane
// marketplace overview, readiness matrix, feed directory, and pack grids,
// rendered from data/marketplace/*.json.

const { marketplace } = require("../site-data");
const { escapeHtml } = require("../util");

const SCHEMA_FEEDS = [
  ["/marketplace-control-plane.json", "Control plane manifest", "Combined catalog, routes, reports, and workflow bundles."],
  ["/marketplace-catalog.json", "Catalog feed", "Positioning, browser runtime model, and market signals."],
  ["/marketplace-input-channels.json", "Input channels", "Scanner, repo, runbook, and browser context intake contracts."],
  ["/marketplace-output-channels.json", "Output channels", "Ticketing, collaboration, SIEM, and webhook route definitions."],
  ["/marketplace-report-profiles.json", "Report profiles", "Reusable report and evidence contracts."],
  ["/marketplace-workflow-templates.json", "Workflow templates", "Curated and community workflow packs built from the same data model."],
  ["/marketplace-readiness.json", "Readiness matrix", "Derived input and output readiness view with auth labels, requirements, and blocker summaries."],
  ["/marketplace-schemas/index.json", "Schema manifest", "Discovery list for contribution-packet plus case, asset, and routing schema URLs."],
  ["/marketplace-schemas/input-channel-contribution.schema.json", "Input contribution schema", "Validates browser-exported input-channel submission packets before a marketplace PR."],
  ["/marketplace-schemas/output-channel-contribution.schema.json", "Output contribution schema", "Validates browser-exported output-route submission packets before a marketplace PR."],
  ["/marketplace-schemas/report-profile-contribution.schema.json", "Report contribution schema", "Validates browser-exported report-profile submission packets before a marketplace PR."],
  ["/marketplace-schemas/workflow-template-contribution.schema.json", "Workflow contribution schema", "Validates reusable workflow-pack submission packets before they land in the public marketplace."],
  ["/marketplace-schemas/local-library.schema.json", "Local library schema", "Validates portable browser-local library export and import payloads for private input, output, report, and workflow packs."],
  ["/marketplace-schemas/case-file.schema.json", "Case file schema", "Validates exported Caseboard JSON before it is handed to another tool or reviewer."],
  ["/marketplace-schemas/case-library.schema.json", "Case library schema", "Validates portable browser-local Caseboard library export and import payloads."],
  ["/marketplace-schemas/asset-library.schema.json", "Asset library schema", "Validates browser-local asset criticality and ownership library exports and imports."],
  ["/marketplace-schemas/operations-history.schema.json", "Operations history schema", "Validates browser-local source sync, agent run, case action, and report-export history before handoff."],
  ["/marketplace-schemas/operations-session.schema.json", "Operations session schema", "Validates grouped browser-local investigation sessions before correlated run context is handed downstream."],
  ["/marketplace-schemas/routing-policy.schema.json", "Routing policy schema", "Validates one owner-aware routing policy before it is applied across exposures, cases, or delivery flows."],
  ["/marketplace-schemas/routing-library.schema.json", "Routing library schema", "Validates portable browser-local routing libraries for approval, ticket, and downstream route defaults."],
];

const sortByLabel = (arr) =>
  [...(arr || [])].sort((a, b) => (a.label || "").localeCompare(b.label || "", "en"));

const dd = (v) => escapeHtml(v ?? "");

function badgeRow(...vals) {
  return `<div class="sr-marketplace-badges">${vals.map((v) => `<span>${dd(v)}</span>`).join("")}</div>`;
}

function governanceRows(item, catalog) {
  const version = item.governance?.pack_version || "1.0.0";
  const review = item.governance?.reviewed_at || catalog.last_reviewed;
  return (
    `<div><dt>Version</dt><dd>${dd(version)}</dd></div>` +
    `<div><dt>Review</dt><dd>${dd(review)}</dd></div>`
  );
}

module.exports = function marketplaceGallery() {
  const data = marketplace();
  const catalog = data.catalog;
  const inputs = sortByLabel(data.input_channels.channels);
  const outputs = sortByLabel(data.output_channels.channels);
  const reports = sortByLabel(data.report_profiles.profiles);
  const workflows = sortByLabel(data.workflow_templates.templates);
  const readiness = data.readiness_profiles;

  let liveInputs = 0, templateInputs = 0, liveOutputs = 0, copyOnlyOutputs = 0, templateOutputs = 0;
  for (const ch of inputs) {
    const rt = ch.runtime_support || "copy_only";
    if (rt === "live") liveInputs += 1;
    if (rt === "planned" || rt === "config_only") templateInputs += 1;
  }
  for (const ch of outputs) {
    const rt = ch.runtime_support || "copy_only";
    if (rt === "live" || rt === "live_or_copy") liveOutputs += 1;
    if (rt === "copy_only") copyOnlyOutputs += 1;
    if (rt === "planned" || rt === "config_only") templateOutputs += 1;
  }

  const authLabel = (mode) => readiness.auth_mode_labels?.[mode] || mode;
  const authList = (modes) => modes.map(authLabel).join(", ");

  const readinessItem = (item, { isOutput }) => {
    const runtime = item.runtime_support || (isOutput ? "copy_only" : "live");
    const authModes = isOutput
      ? readiness.output_driver_auth_modes?.[item.driver] || ["none"]
      : item.auth_modes || ["none"];
    const runtimeLabel = readiness.runtime_labels?.[runtime] || runtime;
    const blockers = readiness.runtime_blockers?.[runtime] || [];
    const blockerItems = blockers.length
      ? blockers.map((b) => `<li>${dd(b)}</li>`).join("")
      : isOutput
        ? `<li>No catalog-level blocker is left in the current browser model; only operator configuration and reviewer judgment remain.</li>`
        : `<li>No catalog-level blocker is left; the remaining step is loading the selected page, repository, or file into the browser session.</li>`;
    const reqItems = [
      `<li>${dd(readiness.runtime_requirements?.[runtime])}</li>`,
      ...authModes.map((m) => `<li>${dd(readiness.auth_mode_details?.[m])}</li>`),
    ];
    if (isOutput && item.browser_delivery) {
      reqItems.push(`<li>Browser delivery is always operator-triggered and keeps provider secrets in browser storage instead of a SecurityRecipes backend.</li>`);
    }
    if (!isOutput) {
      if (item.config?.accepted_formats) {
        reqItems.push(`<li>Accepted formats: ${dd(item.config.accepted_formats.join(", "))}.</li>`);
      } else if (item.config?.base_url) {
        reqItems.push(`<li>Provider endpoint: <code>${dd(item.config.base_url)}</code>.</li>`);
      }
    }
    const dl = isOutput
      ? `<div><dt>Requirement</dt><dd>${dd(item.requirement)}</dd></div>` +
        `<div><dt>Auth</dt><dd>${dd(authList(authModes))}</dd></div>` +
        `<div><dt>Config</dt><dd><code>${dd(item.config?.type)}</code></dd></div>` +
        `<div><dt>Browser delivery</dt><dd>${item.browser_delivery ? "yes" : "no"}</dd></div>`
      : `<div><dt>Auth</dt><dd>${dd(authList(authModes))}</dd></div>` +
        `<div><dt>Config</dt><dd><code>${dd(item.config?.type)}</code></dd></div>` +
        (item.config?.source ? `<div><dt>Source</dt><dd><code>${dd(item.config.source)}</code></dd></div>` : "");

    return (
      `<details class="sr-marketplace-readiness-item" data-runtime="${dd(runtime)}">` +
      `<summary><div><strong>${dd(item.label)}</strong><span>${dd(item.category)}</span></div>` +
      badgeRow(runtimeLabel, item.status) +
      `</summary>` +
      `<div class="sr-marketplace-readiness-body">` +
      `<p>${dd(item.description)}</p>` +
      `<dl>${dl}</dl>` +
      `<div class="sr-marketplace-readiness-copy">` +
      `<div><h4>Readiness requirements</h4><ul>${reqItems.join("")}</ul></div>` +
      `<div><h4>Current blockers</h4><ul>${blockerItems}</ul></div>` +
      `</div></div></details>`
    );
  };

  const feedLinks = SCHEMA_FEEDS.map(
    ([href, label, desc]) =>
      `<a class="sr-marketplace-feed" href="${href}"><strong>${escapeHtml(label)}</strong><code>${href}</code><span>${escapeHtml(desc)}</span></a>`
  ).join("");

  const outputCards = outputs
    .map(
      (ch) =>
        `<article class="sr-marketplace-card"><header><div><h3>${dd(ch.label)}</h3><p>${dd(ch.description)}</p></div>` +
        badgeRow(ch.category, ch.status, ch.runtime_support) +
        `</header><dl>` +
        `<div><dt>Driver</dt><dd><code>${dd(ch.driver)}</code></dd></div>` +
        `<div><dt>Browser delivery</dt><dd>${ch.browser_delivery ? "yes" : "no"}</dd></div>` +
        `<div><dt>Config type</dt><dd><code>${dd(ch.config?.type)}</code></dd></div>` +
        governanceRows(ch, catalog) +
        `</dl><p class="sr-marketplace-requirement">${dd(ch.requirement)}</p></article>`
    )
    .join("");

  const inputCards = inputs
    .map(
      (ch) =>
        `<article class="sr-marketplace-card"><header><div><h3>${dd(ch.label)}</h3><p>${dd(ch.description)}</p></div>` +
        badgeRow(ch.category, ch.status, ch.runtime_support) +
        `</header><dl>` +
        `<div><dt>Auth</dt><dd>${dd(ch.auth_modes ? ch.auth_modes.join(", ") : "none")}</dd></div>` +
        `<div><dt>Config type</dt><dd><code>${dd(ch.config?.type)}</code></dd></div>` +
        (ch.config?.source ? `<div><dt>Source</dt><dd><code>${dd(ch.config.source)}</code></dd></div>` : "") +
        governanceRows(ch, catalog) +
        `</dl></article>`
    )
    .join("");

  const reportCards = reports
    .map(
      (r) =>
        `<article class="sr-marketplace-card"><header><div><h3>${dd(r.label)}</h3><p>${dd(r.description)}</p></div>` +
        badgeRow(r.status, r.format) +
        `</header><dl>` +
        `<div><dt>Sections</dt><dd>${dd(r.sections ? r.sections.join(", ") : "none")}</dd></div>` +
        `<div><dt>ID</dt><dd><code>${dd(r.id)}</code></dd></div>` +
        governanceRows(r, catalog) +
        `</dl></article>`
    )
    .join("");

  const workflowCards = workflows
    .map(
      (w) =>
        `<article class="sr-marketplace-card"><header><div><h3>${dd(w.label)}</h3><p>${dd(w.description)}</p></div>` +
        badgeRow(w.status, w.workflow_value) +
        `</header><dl>` +
        `<div><dt>Inputs</dt><dd>${dd(w.default_input_channel_ids ? w.default_input_channel_ids.join(", ") : "none")}</dd></div>` +
        `<div><dt>Report</dt><dd><code>${dd(w.default_report_profile_id)}</code></dd></div>` +
        `<div><dt>Output</dt><dd><code>${dd(w.default_output_channel_id)}</code></dd></div>` +
        `<div><dt>Cadence</dt><dd>${dd(w.default_cadence)}</dd></div>` +
        `<div><dt>Approval</dt><dd>${dd(w.default_approval_gate)}</dd></div>` +
        governanceRows(w, catalog) +
        `</dl></article>`
    )
    .join("");

  const stat = (value, label) => `<article><strong>${value}</strong><span>${label}</span></article>`;
  const section = (title, desc, body) =>
    `<section class="sr-marketplace-section"><div class="sr-marketplace-section-head"><h2>${title}</h2><p>${desc}</p></div>${body}</section>`;

  return (
    `<div class="sr-marketplace-gallery">` +
    `<section class="sr-marketplace-overview"><div>` +
    `<p class="sr-marketplace-kicker">Client-side security control plane</p>` +
    `<h2>Inspect every input, report, output, and workflow pack before you trust it.</h2>` +
    `<p>${dd(catalog.positioning?.summary)}</p></div>` +
    `<div class="sr-marketplace-stats">` +
    stat(inputs.length, "Input channels") +
    stat(outputs.length, "Output channels") +
    stat(reports.length, "Report profiles") +
    stat(workflows.length, "Workflow packs") +
    `</div></section>` +
    section(
      "Runtime readiness",
      "See what the browser can execute today versus what is still a reviewed starter contract for later promotion.",
      `<div class="sr-marketplace-stats">` +
        stat(liveInputs, "Browser-live inputs") +
        stat(liveOutputs, "Browser-live routes") +
        stat(copyOnlyOutputs, "Local-only handoffs") +
        stat(templateInputs + templateOutputs, "Template contracts") +
        `</div>`
    ) +
    `<section class="sr-marketplace-section" id="readiness-matrix">` +
    `<div class="sr-marketplace-section-head"><h2>Readiness matrix</h2>` +
    `<p>Drill into the auth pattern, operator prerequisites, and the blockers that still keep a pack in fallback or starter-contract mode.</p></div>` +
    `<div class="sr-marketplace-readiness-layout">` +
    `<div class="sr-marketplace-readiness-column">` +
    `<div class="sr-marketplace-readiness-head"><h3>Output routes</h3><p>Downstream destinations with the exact browser-side review model called out.</p></div>` +
    `<div class="sr-marketplace-readiness-list">${outputs.map((o) => readinessItem(o, { isOutput: true })).join("")}</div></div>` +
    `<div class="sr-marketplace-readiness-column">` +
    `<div class="sr-marketplace-readiness-head"><h3>Input sources</h3><p>Context and finding sources, including the auth pattern and the reason a source is live, local, or still only a starter contract.</p></div>` +
    `<div class="sr-marketplace-readiness-list">${inputs.map((i) => readinessItem(i, { isOutput: false })).join("")}</div></div>` +
    `</div></section>` +
    section(
      "Public JSON feeds and schemas",
      "Machine-readable control-plane contracts and browser-authored schemas generated by the site build so downstream systems can consume the marketplace and contributors can validate packets without scraping page state.",
      `<div class="sr-marketplace-feed-grid">${feedLinks}</div>`
    ) +
    section("Output channels", "Downstream delivery routes for tickets, collaboration, SIEM, and custom relays.", `<div class="sr-marketplace-grid">${outputCards}</div>`) +
    section("Input channels", "Context and scanner sources that the browser workbench can attach to chat and agent runs.", `<div class="sr-marketplace-grid">${inputCards}</div>`) +
    section("Report profiles", "Normalized report contracts that make browser runs reusable outside the prompt transcript.", `<div class="sr-marketplace-grid">${reportCards}</div>`) +
    section("Workflow templates", "Opinionated packs that bind inputs, recipes, reports, and outputs into repeatable operating motions.", `<div class="sr-marketplace-grid">${workflowCards}</div>`) +
    `</div>`
  );
};
