'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..');
const githubDir = path.join(repoRoot, '.github');
const workflowsDir = path.join(githubDir, 'workflows');
const autoMergePath = path.join(workflowsDir, 'dependabot-automerge.yml');

function loadYaml(filePath) {
  return yaml.load(fs.readFileSync(filePath, 'utf8'));
}

function expressionText(value) {
  return String(value).replace(/\s+/g, ' ').trim();
}

test('all remote GitHub Actions are pinned to immutable commits with version comments', () => {
  const workflowFiles = fs.readdirSync(workflowsDir)
    .filter((fileName) => /\.ya?ml$/u.test(fileName));

  assert.ok(workflowFiles.length > 0);

  for (const fileName of workflowFiles) {
    const filePath = path.join(workflowsDir, fileName);
    const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/u);

    lines.forEach((line, index) => {
      if (!/^\s*(?:-\s*)?uses:/u.test(line)) {
        return;
      }

      const match = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)(?:\s+#\s*(\S+))?\s*$/u);
      assert.ok(match, `${fileName}:${index + 1} must use the canonical action-pin format`);

      const [, reference, versionComment] = match;
      if (reference.startsWith('./') || reference.startsWith('docker://')) {
        return;
      }

      assert.match(
        reference,
        /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$/u,
        `${fileName}:${index + 1} must pin the action to a full commit SHA`,
      );
      assert.match(
        versionComment || '',
        /^v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/u,
        `${fileName}:${index + 1} must preserve a precise version comment`,
      );
    });
  }
});

test('Dependabot auto-merge cannot execute PR code and only admits patch/minor updates', () => {
  const workflow = loadYaml(autoMergePath);
  const trigger = workflow.on || workflow.true;
  const job = workflow.jobs['enable-auto-merge'];
  const jobGuard = expressionText(job.if);
  const metadataStep = job.steps.find((step) => step.id === 'dependabot');
  const mergeStep = job.steps.find((step) => step.name.includes('Enable auto-merge'));
  const mergeGuard = expressionText(mergeStep.if);

  assert.deepEqual(
    trigger.pull_request_target.types,
    ['opened', 'reopened', 'synchronize', 'ready_for_review'],
  );
  assert.equal(trigger.pull_request, undefined);
  assert.deepEqual(workflow.permissions, {});
  assert.deepEqual(job.permissions, {
    contents: 'write',
    'pull-requests': 'write',
  });
  assert.equal(
    workflow.concurrency.group,
    'dependabot-automerge-${{ github.event.pull_request.number }}',
  );
  assert.equal(workflow.concurrency['cancel-in-progress'], true);

  assert.match(jobGuard, /github\.actor == 'dependabot\[bot\]'/u);
  assert.match(jobGuard, /pull_request\.user\.login == 'dependabot\[bot\]'/u);
  assert.match(jobGuard, /pull_request\.base\.ref == 'main'/u);
  assert.match(jobGuard, /pull_request\.head\.repo\.full_name == github\.repository/u);
  assert.match(jobGuard, /!github\.event\.pull_request\.draft/u);
  assert.equal(job['timeout-minutes'], 5);

  assert.match(
    metadataStep.uses,
    /^dependabot\/fetch-metadata@[0-9a-f]{40}$/u,
  );
  assert.deepEqual(metadataStep.with, {
    'github-token': '${{ github.token }}',
  });
  assert.equal(
    job.steps.some((step) => typeof step.uses === 'string' && step.uses.includes('/checkout@')),
    false,
  );

  for (const requiredGuard of [
    "target-branch == 'main'",
    "maintainer-changes == 'false'",
    "package-ecosystem == 'npm_and_yarn'",
    "package-ecosystem == 'pip'",
    "package-ecosystem == 'docker'",
    "package-ecosystem == 'docker_compose'",
    "package-ecosystem == 'github_actions'",
    "update-type == 'version-update:semver-patch'",
    "update-type == 'version-update:semver-minor'",
  ]) {
    assert.ok(mergeGuard.includes(requiredGuard), `missing guard: ${requiredGuard}`);
  }
  assert.deepEqual(
    [...mergeGuard.matchAll(/package-ecosystem == '([^']+)'/gu)]
      .map((match) => match[1])
      .sort(),
    ['docker', 'docker_compose', 'github_actions', 'npm_and_yarn', 'pip'],
  );
  assert.deepEqual(
    [...mergeGuard.matchAll(/update-type == '([^']+)'/gu)]
      .map((match) => match[1])
      .sort(),
    ['version-update:semver-minor', 'version-update:semver-patch'],
  );

  assert.equal(mergeStep.env.GH_TOKEN, '${{ github.token }}');
  assert.equal(mergeStep.env.PR_URL, '${{ github.event.pull_request.html_url }}');
  assert.equal(mergeStep.run, 'gh pr merge --auto --squash "$PR_URL"');
});

test('security disclosures are directed away from public issue forms', () => {
  const issueTemplateDir = path.join(githubDir, 'ISSUE_TEMPLATE');
  const config = loadYaml(path.join(issueTemplateDir, 'config.yml'));
  const securityFormPath = path.join(issueTemplateDir, 'security_report.yml');
  const privateContact = config.contact_links.find(
    (link) => link.name === 'Private Security Disclosure',
  );

  assert.equal(fs.existsSync(securityFormPath), false);
  assert.equal(config.blank_issues_enabled, false);
  assert.ok(privateContact);
  assert.equal(
    privateContact.url,
    'https://github.com/stevologic/security-recipes.ai/security/advisories/new',
  );
  assert.match(privateContact.about, /Do not open a public issue/u);

  const securityPolicy = fs.readFileSync(path.join(repoRoot, 'SECURITY.md'), 'utf8');
  assert.match(securityPolicy, /security\/advisories\/new/u);
  assert.match(securityPolicy, /security@security-recipes\.ai/u);
});
