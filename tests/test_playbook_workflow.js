'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const ELEVENTY_CONFIG = path.join(ROOT, 'eleventy.config.js');
const REGISTRY = path.join(ROOT, 'data', 'remediation_suite', 'playbooks.json');
const WORKFLOW_CSS = path.join(ROOT, 'assets', 'css', 'playbook-workflows.css');
const playbookWorkflow = require('../lib/shortcodes/playbook-workflow.js');
const { escapeHtml } = require('../lib/util.js');
const { renderPlaybook, playbookIdForSourcePath, loadRegistry } = playbookWorkflow;

function fixture() {
  return {
    id: 'dependency-review',
    title: 'Dependency <review>',
    page: '/security-remediation/dependency-review/',
    category: 'Supply chain & policy',
    summary: 'Turn a finding into a bounded plan without trusting <script>alert(1)</script>.',
    phases: [
      { label: 'Intake', title: 'Normalize finding', detail: 'Preserve source & identity.' },
      { label: 'Scope', title: 'Select recipe', detail: 'Choose the narrowest matching workflow.' },
      { label: 'Plan', title: 'Prepare change', detail: 'Keep the action inside the allowlist.' },
      { label: 'Verify', title: 'Retain proof', detail: 'Replay checks before handoff.' },
    ],
    gate: {
      question: 'Is the evidence complete?',
      pass: 'Continue to a reviewer-ready handoff.',
      stop: 'Write TRIAGE.md and request the missing owner decision.',
    },
    evidence: ['Scanner result', 'Changed paths'],
    outputs: ['Remediation packet', 'Reviewer handoff'],
    python: {
      scenario: 'Normalize and inspect the finding without changing the repository.',
      command: 'python scripts/security_recipes_remediation_suite.py run --finding "<finding>.json" --dry-run',
    },
  };
}

test('workflow renderer is semantic, static, and keeps Python secondary', () => {
  const html = renderPlaybook(fixture());
  const phases = html.match(/class="sr-playbook-workflow__phase"/g) || [];

  assert.match(html, /^<section class="sr-playbook-workflow"/);
  assert.match(html, /data-playbook-workflow/);
  assert.match(html, /aria-labelledby="sr-playbook-dependency-review-title"/);
  assert.match(html, /<ol class="sr-playbook-workflow__phases"/);
  assert.equal(phases.length, 4);
  assert.match(html, /<section class="sr-playbook-gate" aria-label="Decision gate">/);
  assert.match(html, /<section aria-label="Evidence to retain">/);
  assert.match(html, /<section aria-label="Expected outputs">/);
  assert.match(html, /<aside class="sr-playbook-python"/);
  assert.match(html, /href="\/security-remediation\/remediation-suite\/#tool-commands"/);

  assert.ok(
    html.indexOf('sr-playbook-workflow__phases') < html.indexOf('sr-playbook-gate'),
    'the decision gate follows the ordered workflow',
  );
  assert.ok(
    html.indexOf('sr-playbook-workflow__closeout') < html.indexOf('sr-playbook-python'),
    'the Python companion follows the workflow, gate, and evidence contract',
  );

  assert.doesNotMatch(html, /<script\b/i);
  assert.doesNotMatch(html, /<svg\b/i);
  assert.doesNotMatch(html, /\bmermaid\b/i);
  assert.doesNotMatch(html, /role="img"/i);
});

test('workflow renderer escapes every registry-controlled field', () => {
  const html = renderPlaybook(fixture());

  assert.doesNotMatch(html, /<review>/);
  assert.doesNotMatch(html, /<script>alert/);
  assert.doesNotMatch(html, /<finding>/);
  assert.match(html, /Dependency &lt;review&gt;/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /Supply chain &amp; policy/);
  assert.match(html, /source &amp; identity/);
  assert.match(html, /&quot;&lt;finding&gt;\.json&quot;/);
});

test('source-path lookup accepts Eleventy and Windows paths but rejects unrelated pages', () => {
  assert.equal(
    playbookIdForSourcePath('./content/security-remediation/dependency-review/_index.md'),
    'dependency-review',
  );
  assert.equal(
    playbookIdForSourcePath('security-remediation\\dependency-review\\_index.md'),
    'dependency-review',
  );
  assert.throws(
    () => playbookIdForSourcePath('recipes/dependency-review/_index.md'),
    /unsupported source path/,
  );
});

test('every registry entry resolves through its public playbook path', () => {
  const registry = JSON.parse(fs.readFileSync(REGISTRY, 'utf8'));
  assert.ok(Array.isArray(registry.playbooks));
  assert.ok(registry.playbooks.length > 0);

  for (const playbook of registry.playbooks) {
    const match = String(playbook.page || '').match(/^\/security-remediation\/([^/]+)\/$/);
    assert.ok(match, `${playbook.id} has a canonical security-remediation page`);
    const html = playbookWorkflow(`security-remediation/${match[1]}/_index.md`);
    assert.match(html, /data-playbook-workflow/);
    assert.ok(html.includes(`data-playbook-id="${escapeHtml(playbook.id)}"`));
    assert.ok(
      html.includes(escapeHtml(playbook.python.command)),
      `${playbook.id} renders its registered Python command`,
    );
  }
});

test('print styles force readable dark text on white workflow panels', () => {
  const css = fs.readFileSync(WORKFLOW_CSS, 'utf8');
  const printAt = css.indexOf('@media print');

  assert.notEqual(printAt, -1, 'workflow stylesheet has a print mode');
  const printCss = css.slice(printAt);
  assert.match(printCss, /\.sr-playbook-workflow\s*\{[^}]*background:\s*#fff;[^}]*color:\s*#111\s*!important;/s);
  assert.match(printCss, /\.sr-playbook-workflow__phase-detail,[\s\S]*color:\s*#111\s*!important;/);
  assert.match(printCss, /\.sr-playbook-python__command pre\s*\{[^}]*background:\s*#fff\s*!important;[^}]*color:\s*#111\s*!important;/s);
  assert.match(printCss, /\.sr-playbook-python__link[\s\S]*color:\s*#111\s*!important;/);
});

test('registry cache refreshes after a watched source file changes', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'playbook-workflow-'));
  const registryPath = path.join(directory, 'playbooks.json');
  const firstPayload = { playbooks: [{ id: 'first', title: 'First title' }] };
  const secondPayload = { playbooks: [{ id: 'first', title: 'A refreshed, longer title' }] };

  try {
    fs.writeFileSync(registryPath, JSON.stringify(firstPayload), 'utf8');
    const first = loadRegistry(registryPath);
    assert.equal(first.playbooks[0].title, 'First title');
    assert.strictEqual(loadRegistry(registryPath), first, 'unchanged registry reuses its parsed value');

    fs.writeFileSync(registryPath, JSON.stringify(secondPayload), 'utf8');
    const refreshed = loadRegistry(registryPath);
    assert.notStrictEqual(refreshed, first, 'changed registry invalidates the parsed value');
    assert.equal(refreshed.playbooks[0].title, 'A refreshed, longer title');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }

  const config = fs.readFileSync(ELEVENTY_CONFIG, 'utf8');
  assert.match(
    config,
    /addWatchTarget\(["']\.\/data\/remediation_suite\/playbooks\.json["']\)/,
    'Eleventy rebuilds when the workflow registry changes',
  );
});
