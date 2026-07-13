'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const schemaIndex = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'static', 'marketplace-schemas', 'index.json'), 'utf8')
);

const snakeCase = (value) =>
  String(value)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();

test('control-plane schema inventory is derived exactly from the public index', () => {
  const controlPlane = JSON.parse(require('../lib/feeds.js').marketplaceControlPlane());
  const expected = Object.fromEntries([
    ['index', '/marketplace-schemas/index.json'],
    ...schemaIndex.schemas.map((schema) => [snakeCase(schema.key), schema.href]),
  ]);

  assert.deepEqual(controlPlane.schemas, expected);
  assert.equal(
    controlPlane.schemas.portfolio_coverage,
    '/marketplace-schemas/portfolio-coverage.schema.json'
  );
});

test('marketplace gallery publishes every indexed schema link', () => {
  const html = require('../lib/shortcodes/marketplace-gallery.js')();
  const hrefs = [
    '/marketplace-schemas/index.json',
    ...schemaIndex.schemas.map((schema) => schema.href),
  ];

  for (const href of hrefs) {
    assert.ok(html.includes(`href="${href}"`), `gallery is missing ${href}`);
  }
  assert.ok(html.includes('Portfolio coverage snapshot'));
});
