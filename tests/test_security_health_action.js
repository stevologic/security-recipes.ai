'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..');
const actionDir = path.join(repoRoot, 'actions', 'security-health');
const actionPath = path.join(actionDir, 'action.yml');
const workflowPath = path.join(repoRoot, '.github', 'workflows', 'security-health.yml');

function loadModule() {
  return import(pathToFileURL(path.join(actionDir, 'main.mjs')).href);
}

test('the action declares every advertised toggle with truthful defaults', () => {
  const action = yaml.load(fs.readFileSync(actionPath, 'utf8'));

  assert.equal(action.runs.using, 'node24');
  assert.equal(action.runs.main, 'main.mjs');
  assert.ok(fs.existsSync(path.join(actionDir, action.runs.main)));

  assert.equal(action.inputs.provider.default, 'openai');
  assert.equal(action.inputs.model.default, '');
  assert.equal(action.inputs['mcp-url'].default, 'https://security-recipes.ai/mcp');
  assert.equal(action.inputs['fail-on'].default, 'fail');

  const expectedToggles = {
    'check-dependencies': 'true',
    'check-secrets': 'true',
    'check-injection': 'true',
    'check-supply-chain': 'true',
    'check-authz': 'false',
    'check-containers': 'false',
    'check-owasp': 'false',
    'check-cve-exposure': 'false',
    'check-compliance': 'false',
  };
  for (const [name, fallback] of Object.entries(expectedToggles)) {
    assert.equal(action.inputs[name].default, fallback, `${name} default drifted`);
  }
  assert.ok(action.outputs.result);
});

test('the check registry matches the action toggles and cites site guidance', async () => {
  const { CHECKS } = await loadModule();
  const action = yaml.load(fs.readFileSync(actionPath, 'utf8'));

  assert.equal(CHECKS.length, 9);
  for (const check of CHECKS) {
    assert.ok(action.inputs[check.input], `${check.input} missing from action.yml`);
    assert.equal(
      action.inputs[check.input].default,
      String(check.defaultEnabled),
      `${check.input} default disagrees with the registry`,
    );
    assert.match(check.page, /^https:\/\/security-recipes\.ai\//u);
    assert.ok(action.outputs[check.key], `${check.key} output missing`);
  }
});

test('inputs read the runner env spelling where dashes are preserved', async () => {
  const { readInput, readBoolInput } = await loadModule();

  process.env['INPUT_API-KEY'] = 'runner-spelling';
  process.env['INPUT_CHECK-CONTAINERS'] = 'true';
  try {
    assert.equal(readInput('api-key', ''), 'runner-spelling');
    assert.equal(readBoolInput('check-containers', false), true);
  } finally {
    delete process.env['INPUT_API-KEY'];
    delete process.env['INPUT_CHECK-CONTAINERS'];
  }
});

test('lowest-model selection prefers small tiers and skips non-chat models', async () => {
  const { pickLowestModel } = await loadModule();

  assert.equal(
    pickLowestModel(['gpt-5.6-luna', 'gpt-5-mini', 'text-embedding-3-large', 'gpt-5-nano']),
    'gpt-5-nano',
  );
  assert.equal(
    pickLowestModel(['claude-opus-5', 'claude-haiku-4-5', 'claude-sonnet-5']),
    'claude-haiku-4-5',
  );
  assert.equal(pickLowestModel(['grok-4', 'grok-3-mini', 'grok-2-image']), 'grok-3-mini');
  assert.equal(pickLowestModel(['whisper-1', 'tts-1']), '');
  assert.equal(pickLowestModel([]), '');
});

test('verdict parsing is strict about status and resilient to prose', async () => {
  const { parseVerdict } = await loadModule();

  const clean = parseVerdict('{"status":"fail","summary":"bad","findings":[{"severity":"high","title":"Pinned token"}]}');
  assert.equal(clean.status, 'fail');
  assert.equal(clean.findings.length, 1);

  const fenced = parseVerdict('Here you go:\n```json\n{"status":"pass","summary":"ok","findings":[]}\n```');
  assert.equal(fenced.status, 'pass');

  const invalidStatus = parseVerdict('{"status":"catastrophic","summary":"?","findings":[]}');
  assert.equal(invalidStatus.status, 'warn');

  const garbage = parseVerdict('I could not decide.');
  assert.equal(garbage.status, 'warn');
  assert.match(garbage.summary, /not valid JSON/u);
});

test('the summary shows disabled checks with how to enable them', async () => {
  const { renderSummary } = await loadModule();
  const summary = renderSummary(
    [
      {
        key: 'secrets', label: 'Secrets', input: 'check-secrets',
        page: 'https://security-recipes.ai/x/', status: 'pass', summary: 'clean', findings: [],
      },
      {
        key: 'owasp', label: 'OWASP', input: 'check-owasp',
        page: 'https://security-recipes.ai/y/', status: 'skipped', summary: '', findings: [],
      },
    ],
    { provider: 'openai', model: 'gpt-5-nano', autoSelected: true, contextSource: 'mcp' },
  );

  assert.match(summary, /connected to the hosted \[security-recipes\.ai MCP server\]/u);
  assert.match(summary, /auto-selected lowest available/u);
  assert.match(summary, /Not enabled — set `check-owasp: true`/u);
  assert.match(summary, /1 check\(s\) are not enabled/u);
});

test('evidence collection finds this repository manifests deterministically', async () => {
  const { collectEvidence } = await loadModule();
  const manifests = collectEvidence('manifests', repoRoot);
  assert.match(manifests, /--- package\.json ---/u);
  const pipeline = collectEvidence('pipeline', repoRoot);
  assert.match(pipeline, /--- \.github\/workflows\//u);
});

test('this repository runs the action on the existing OpenAI key', () => {
  const workflow = yaml.load(fs.readFileSync(workflowPath, 'utf8'));
  const steps = workflow.jobs['security-health'].steps;
  const actionStep = steps.find((step) => step.uses === './actions/security-health');

  assert.ok(actionStep, 'the repo workflow must consume the local action');
  assert.equal(actionStep.with.provider, 'openai');
  assert.equal(actionStep.with['api-key'], '${{ secrets.OPENAI_API_KEY }}');
  assert.equal(actionStep.with.model, undefined, 'the model must default to the lowest available');
  const trigger = workflow.on || workflow.true;
  assert.ok(trigger.pull_request !== undefined);
  assert.ok(trigger.schedule);
});
