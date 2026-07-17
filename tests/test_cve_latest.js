'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const zlib = require('node:zlib');

const {
  MAX_ITEMS,
  compareLatestCves,
  latestCves,
} = require('../lib/cve-latest.js');

function writePartition(root, year, records) {
  const relative = `indexes/${year}.json.gz`;
  const compressed = zlib.gzipSync(Buffer.from(JSON.stringify({
    schema_version: 2,
    year,
    records,
  })));
  fs.mkdirSync(path.join(root, 'indexes'), { recursive: true });
  fs.writeFileSync(path.join(root, ...relative.split('/')), compressed);
  return {
    path: relative,
    year,
    sha256: crypto.createHash('sha256').update(compressed).digest('hex'),
  };
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-recipes-latest-cves-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test('latest CVEs use the newest publication partition and catalog browse ordering', (t) => {
  const root = fixture(t);
  const older = writePartition(root, '2025', [{
    cve: 'CVE-2025-9999', title: 'Older partition', severity: 'critical', score: 10,
    published: '2025-12-31', kev: false,
  }]);
  const current = writePartition(root, '2026', [
    { cve: 'CVE-2026-4000', title: 'Critical B', severity: 'critical', score: 9.8, published: '2026-07-14', kev: true },
    { cve: 'CVE-2026-1000', title: 'Critical A', severity: 'critical', score: 9.8, published: '2026-07-14', kev: false },
    { cve: 'CVE-2026-2000', title: 'High', severity: 'high', score: 7.1, published: '2026-07-14', kev: false },
    { cve: 'CVE-2026-3000', title: 'Medium', severity: 'medium', score: 9.9, published: '2026-07-14', kev: false },
    { cve: 'CVE-2026-9000', title: 'Previous day', severity: 'critical', score: 10, published: '2026-07-13', kev: false },
    { cve: 'not-a-cve', title: 'Invalid', severity: 'critical', score: 10, published: '2026-07-15', kev: false },
  ]);
  fs.writeFileSync(path.join(root, 'index.json'), JSON.stringify({
    schema_version: 2,
    partitions: [older, current],
  }));

  const result = latestCves(5, { catalogRoot: root });
  assert.deepEqual(
    result.map((entry) => entry.cve),
    ['CVE-2026-1000', 'CVE-2026-4000', 'CVE-2026-2000', 'CVE-2026-3000', 'CVE-2026-9000']
  );
  assert.equal(result[0].href, '/cve/CVE-2026-1000/');
  assert.equal(result[0].publishedLabel, 'Jul 14');
  assert.equal(result[1].kev, true);
  for (let index = 1; index < result.length; index += 1) {
    assert.ok(compareLatestCves(result[index - 1], result[index]) <= 0);
  }
});

test('latest CVEs fail soft on an unverified partition and cap rendered items', (t) => {
  const root = fixture(t);
  const records = Array.from({ length: MAX_ITEMS + 5 }, (_, index) => ({
    cve: `CVE-2026-${String(1000 + index)}`,
    title: `Record ${index}`,
    severity: 'high',
    score: 8,
    published: '2026-07-14',
    kev: false,
  }));
  const partition = writePartition(root, '2026', records);
  fs.writeFileSync(path.join(root, 'index.json'), JSON.stringify({
    schema_version: 2,
    partitions: [{ ...partition, sha256: '0'.repeat(64) }],
  }));
  assert.deepEqual(latestCves(10, { catalogRoot: root }), []);

  fs.writeFileSync(path.join(root, 'index.json'), JSON.stringify({
    schema_version: 2,
    partitions: [partition],
  }));
  assert.equal(latestCves(100, { catalogRoot: root }).length, MAX_ITEMS);
});

test('homepage data exposes ten sorted records from the real generated catalog', () => {
  const data = require('../content/_index.11tydata.js');
  assert.equal(data.latestCves.length, 10);
  for (let index = 1; index < data.latestCves.length; index += 1) {
    assert.ok(compareLatestCves(data.latestCves[index - 1], data.latestCves[index]) <= 0);
  }
});
