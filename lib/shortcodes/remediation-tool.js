// Port of layouts/shortcodes/remediation-tool.html: per-domain summary
// block for the Python remediation suite, driven by
// data/remediation_suite/domains.json.

const fs = require("node:fs");
const path = require("node:path");
const { escapeHtml } = require("../util");

let domains = null;

function loadDomains() {
  if (!domains) {
    const file = path.join(__dirname, "..", "..", "data", "remediation_suite", "domains.json");
    domains = JSON.parse(fs.readFileSync(file, "utf8")).domains || [];
  }
  return domains;
}

function titleCase(s) {
  return s.replace(/\w\S*/g, (w) => w[0].toUpperCase() + w.slice(1));
}

module.exports = function remediationTool(id) {
  const domain = loadDomains().find((d) => d.id === id);
  if (!domain) {
    return `<p><strong>Remediation tool not found:</strong> ${escapeHtml(id || "")}</p>`;
  }

  const list = (items) =>
    (items || []).slice(0, 4).map((i) => `<li>${escapeHtml(i)}</li>`).join("");

  const adapters = Object.entries(domain.enterprise_tools || {})
    .map(
      ([category, tools]) =>
        `<div><strong>${escapeHtml(titleCase(category.replace(/_/g, " ")))}</strong>` +
        `<span>${escapeHtml((tools || []).join(", "))}</span></div>`
    )
    .join("");

  return (
    `<section class="sr-remediation-tool" aria-labelledby="sr-tool-${escapeHtml(domain.id)}-title">` +
    `<div class="sr-tool-head"><div>` +
    `<p class="sr-tool-kicker">Python remediation tool</p>` +
    `<h3 id="sr-tool-${escapeHtml(domain.id)}-title">${escapeHtml(domain.title)}</h3>` +
    `<p>${escapeHtml(domain.purpose)}</p>` +
    `</div>` +
    `<a class="sr-tool-doc-link" href="/security-remediation/remediation-suite/">Suite docs</a></div>` +
    `<div class="sr-tool-command"><span>Custom command</span>` +
    `<code>python scripts/security_recipes_remediation_suite.py ${escapeHtml(domain.command)}</code></div>` +
    `<div class="sr-tool-flow" role="img" aria-label="${escapeHtml(domain.title)} usage flow">` +
    `<span>Finding</span><i aria-hidden="true"></i><span>Domain tool</span><i aria-hidden="true"></i>` +
    `<span>Recipes + optional LLM</span><i aria-hidden="true"></i><span>PR handoff or TRIAGE.md</span></div>` +
    `<div class="sr-tool-grid">` +
    `<div><h4>Inputs</h4><ul>${list(domain.inputs)}</ul></div>` +
    `<div><h4>Allowed actions</h4><ul>${list(domain.allowed_actions)}</ul></div>` +
    `<div><h4>Stop conditions</h4><ul>${list(domain.stop_conditions)}</ul></div>` +
    `<div><h4>Evidence output</h4><ul>${list(domain.evidence)}</ul></div>` +
    `</div>` +
    `<details class="sr-tool-details"><summary>Enterprise adapters and example command</summary>` +
    `<div class="sr-tool-details-body">` +
    `<div class="sr-tool-adapters">${adapters}</div>` +
    `<pre><code>python scripts/security_recipes_remediation_suite.py ${escapeHtml(domain.command)} \\\n` +
    `  --finding finding.json \\\n` +
    `  --recipes-source public/api/recipes.json \\\n` +
    `  --tooling github,snyk,jira,servicenow \\\n` +
    `  --llm-mode prompt \\\n` +
    `  --output out/${escapeHtml(domain.command)}-packet.json</code></pre>` +
    `</div></details>` +
    `</section>`
  );
};
