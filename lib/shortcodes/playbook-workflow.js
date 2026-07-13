// Static, accessible workflow visual for every security-remediation playbook.
// The same registry also drives the Python suite, so the browser view and the
// executable scenario stay in sync without shipping registry JSON or diagram
// JavaScript to each page.

const fs = require("node:fs");
const path = require("node:path");
const { escapeHtml } = require("../util");

const REGISTRY_PATH = path.join(
  __dirname,
  "..",
  "..",
  "data",
  "remediation_suite",
  "playbooks.json",
);

let registryCache = null;

function loadRegistry(registryPath = REGISTRY_PATH) {
  const resolvedPath = path.resolve(registryPath);
  const stat = fs.statSync(resolvedPath);
  const signature = `${stat.size}:${stat.mtimeMs}`;
  if (
    registryCache &&
    registryCache.path === resolvedPath &&
    registryCache.signature === signature
  ) {
    return registryCache.value;
  }

  const registry = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
  if (!Array.isArray(registry.playbooks)) {
    throw new Error(`[playbook-workflow] registry has no playbooks array: ${resolvedPath}`);
  }
  registryCache = { path: resolvedPath, signature, value: registry };
  return registryCache.value;
}

function playbookIdForSourcePath(sourcePath) {
  const normalized = String(sourcePath || "").replace(/\\/g, "/").replace(/^\.\/?content\//, "");
  const match = normalized.match(/^security-remediation\/([^/]+)\/_index\.md$/);
  if (!match) {
    throw new Error(`[playbook-workflow] unsupported source path: ${sourcePath || "(empty)"}`);
  }
  return match[1];
}

function domId(value) {
  return String(value || "playbook")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "playbook";
}

function renderList(items, className) {
  return `<ul class="${className}">${(items || [])
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("")}</ul>`;
}

function renderPlaybook(playbook) {
  const id = domId(playbook.id);
  const labelId = `sr-playbook-${id}-title`;
  const pythonId = `sr-playbook-${id}-python`;
  const phases = Array.isArray(playbook.phases) ? playbook.phases : [];
  const gate = playbook.gate || {};
  const python = playbook.python || {};

  const phaseItems = phases
    .map(
      (phase, index) =>
        `<li class="sr-playbook-workflow__phase">` +
        `<span class="sr-playbook-workflow__phase-number" aria-hidden="true">${String(index + 1).padStart(2, "0")}</span>` +
        `<div class="sr-playbook-workflow__phase-copy">` +
        `<p class="sr-playbook-workflow__phase-label">${escapeHtml(phase.label)}</p>` +
        `<p class="sr-playbook-workflow__phase-title"><strong>${escapeHtml(phase.title)}</strong></p>` +
        `<p class="sr-playbook-workflow__phase-detail">${escapeHtml(phase.detail)}</p>` +
        `</div></li>`,
    )
    .join("");

  return (
    `<section class="sr-playbook-workflow" data-playbook-workflow data-playbook-id="${escapeHtml(playbook.id)}" aria-labelledby="${labelId}">` +
    `<header class="sr-playbook-workflow__header">` +
    `<div><p class="sr-playbook-workflow__kicker">Workflow at a glance</p>` +
    `<h2 id="${labelId}">${escapeHtml(playbook.title)} workflow</h2>` +
    `<p class="sr-playbook-workflow__summary">${escapeHtml(playbook.summary)}</p></div>` +
    `<span class="sr-playbook-workflow__category">${escapeHtml(playbook.category)}</span>` +
    `</header>` +
    `<ol class="sr-playbook-workflow__phases" style="--phase-count:${phases.length}">${phaseItems}</ol>` +
    `<section class="sr-playbook-gate" aria-label="Decision gate">` +
    `<div class="sr-playbook-gate__question">` +
    `<p class="sr-playbook-workflow__kicker">Decision gate</p>` +
    `<p><strong>${escapeHtml(gate.question)}</strong></p></div>` +
    `<div class="sr-playbook-gate__paths">` +
    `<div class="sr-playbook-gate__path sr-playbook-gate__path--pass">` +
    `<span>Proceed</span><p>${escapeHtml(gate.pass)}</p></div>` +
    `<div class="sr-playbook-gate__path sr-playbook-gate__path--stop">` +
    `<span>Hold or stop</span><p>${escapeHtml(gate.stop)}</p></div>` +
    `</div></section>` +
    `<div class="sr-playbook-workflow__closeout">` +
    `<section aria-label="Evidence to retain"><p class="sr-playbook-workflow__list-title"><strong>Evidence to retain</strong></p>` +
    renderList(playbook.evidence, "sr-playbook-workflow__list") +
    `</section>` +
    `<section aria-label="Expected outputs"><p class="sr-playbook-workflow__list-title"><strong>Expected outputs</strong></p>` +
    renderList(playbook.outputs, "sr-playbook-workflow__list") +
    `</section></div>` +
    `<aside class="sr-playbook-python" aria-labelledby="${pythonId}">` +
    `<div class="sr-playbook-python__intro">` +
    `<p class="sr-playbook-python__kicker">Python companion</p>` +
    `<p id="${pythonId}" class="sr-playbook-python__title"><strong>Run this playbook as a checked scenario</strong></p>` +
    `<p>${escapeHtml(python.scenario)}</p></div>` +
    `<div class="sr-playbook-python__command"><span>Command</span>` +
    `<pre tabindex="0" aria-label="Python command"><code>${escapeHtml(python.command)}</code></pre></div>` +
    `<a class="sr-playbook-python__link" href="/security-remediation/remediation-suite/#tool-commands">Python suite guide <span aria-hidden="true">&rarr;</span></a>` +
    `</aside>` +
    `</section>`
  );
}

function playbookWorkflow(sourcePath) {
  const slug = playbookIdForSourcePath(sourcePath);
  const page = `/security-remediation/${slug}/`;
  const playbook = loadRegistry().playbooks.find(
    (entry) => entry && (entry.id === slug || entry.page === page),
  );
  if (!playbook) {
    throw new Error(`[playbook-workflow] no registry entry for ${sourcePath} (${slug})`);
  }
  return renderPlaybook(playbook);
}

playbookWorkflow.renderPlaybook = renderPlaybook;
playbookWorkflow.playbookIdForSourcePath = playbookIdForSourcePath;
playbookWorkflow.loadRegistry = loadRegistry;

module.exports = playbookWorkflow;
