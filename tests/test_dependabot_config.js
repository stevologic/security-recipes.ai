'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const yaml = require('js-yaml');

const configPath = path.join(__dirname, '..', '.github', 'dependabot.yml');
const config = yaml.load(fs.readFileSync(configPath, 'utf8'));
const lockPath = path.join(__dirname, '..', 'package-lock.json');
const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));

function compareVersions(left, right) {
  const leftParts = left.split('.').map(Number);
  const rightParts = right.split('.').map(Number);

  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const difference = (leftParts[index] || 0) - (rightParts[index] || 0);
    if (difference !== 0) {
      return difference;
    }
  }

  return 0;
}

test('brace-expansion is pinned to the patched 1.x release', () => {
  assert.equal(
    lock.packages?.['node_modules/brace-expansion']?.version,
    '1.1.18',
    'GHSA-mh99-v99m-4gvg and GHSA-rgw5-rvv9-x895 affect older brace-expansion 1.x releases',
  );
});

test('every js-yaml dependency line meets the patched advisory floor', () => {
  const patchedFloors = new Map([
    [3, '3.15.1'],
    [4, '4.3.1'],
    [5, '5.2.1'],
  ]);

  for (const [packagePath, packageMetadata] of Object.entries(lock.packages || {})) {
    if (packagePath !== 'node_modules/js-yaml' && !packagePath.endsWith('/node_modules/js-yaml')) {
      continue;
    }

    const version = packageMetadata.version;
    const patchedFloor = patchedFloors.get(Number(version.split('.')[0]));
    assert.ok(patchedFloor, `unexpected js-yaml major version at ${packagePath}: ${version}`);
    assert.ok(
      compareVersions(version, patchedFloor) >= 0,
      `GHSA-5p4m-2wfm-xmqj affects ${packagePath} at ${version}; require ${patchedFloor} or newer`,
    );
  }
});

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
