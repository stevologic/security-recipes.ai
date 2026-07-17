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
    const routineGroup = groups.find((group) =>
      group['update-types']?.join(',') === 'minor,patch');

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
    assert.ok(routineGroup, `${ecosystem} should define a routine update group`);
    assert.deepEqual(routineGroup.patterns, ['*']);

    if (ecosystem === 'github-actions') {
      const cacheMajorGroup = groups.find((group) =>
        group['update-types']?.join(',') === 'major');
      assert.equal(groups.length, 2);
      assert.deepEqual(
        cacheMajorGroup?.patterns,
        ['actions/cache/restore', 'actions/cache/save'],
        'cache restore/save major updates must stay paired',
      );
    } else {
      assert.equal(groups.length, 1, `${ecosystem} should define one low-noise update group`);
    }
  }
});
