'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const yaml = require('js-yaml');

const configPath = path.join(__dirname, '..', '.github', 'dependabot.yml');
const config = yaml.load(fs.readFileSync(configPath, 'utf8'));

test('Dependabot sends grouped version updates for every repository ecosystem to main', () => {
  const expectedEcosystems = [
    'docker',
    'docker-compose',
    'github-actions',
    'npm',
    'pip',
  ];

  assert.equal(config.version, 2);
  assert.ok(Array.isArray(config.updates));
  assert.deepEqual(
    config.updates.map((update) => update['package-ecosystem']).sort(),
    expectedEcosystems,
  );

  for (const update of config.updates) {
    const ecosystem = update['package-ecosystem'];
    const groups = Object.values(update.groups || {});

    assert.equal(update.directory, '/', `${ecosystem} should scan the repository root`);
    assert.equal(update['target-branch'], 'main', `${ecosystem} should target main`);
    assert.deepEqual(
      update.schedule,
      {
        interval: 'weekly',
        day: 'monday',
        time: '06:00',
        timezone: 'America/Phoenix',
      },
      `${ecosystem} should use the shared weekly schedule`,
    );
    assert.equal(groups.length, 1, `${ecosystem} should define one low-noise update group`);
    assert.deepEqual(groups[0].patterns, ['*']);
    assert.deepEqual(groups[0]['update-types'], ['minor', 'patch']);
  }
});
