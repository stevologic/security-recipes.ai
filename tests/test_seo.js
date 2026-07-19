const assert = require('node:assert/strict');
const test = require('node:test');

const { seoHead } = require('../lib/seo');

test('JSON-LD serialization cannot break out of its script element', () => {
  const description = 'risk </script><script>globalThis.PWNED=1</script>\u2028next\u2029line';
  const output = seoHead({
    url: '/security-test/',
    title: 'Security\u2028test\u2029',
    description,
    isSection: true,
  });
  const match = output.match(/<script type="application\/ld\+json">(.*?)<\/script>/s);

  assert.ok(match, 'expected a JSON-LD script element');
  assert.equal(match[1].includes('<'), false);
  assert.match(match[1], /\\u003c\/script>/);
  assert.match(match[1], /\\u2028/);
  assert.match(match[1], /\\u2029/);
  const parsed = JSON.parse(match[1]);
  assert.equal(parsed.description, description.replace(/\s+/g, ' '));
  assert.equal(parsed.name, 'Security\u2028test\u2029');
});

test('deep CVE records identify the standalone database as their structured-data parent', () => {
  const url = '/recipes/cve/cve-2014-0160-heartbleed/';
  const output = seoHead({
    url,
    title: 'CVE-2014-0160 — Heartbleed',
    description: 'Heartbleed remediation record.',
    isSection: false,
  });
  const structuredData = [...output.matchAll(
    /<script type="application\/ld\+json">(.*?)<\/script>/gs
  )].map((match) => JSON.parse(match[1]));
  const breadcrumbs = structuredData.find((entry) => entry['@type'] === 'BreadcrumbList');

  assert.ok(breadcrumbs, 'expected a BreadcrumbList for the CVE record');
  assert.deepEqual(
    breadcrumbs.itemListElement.map((entry) => new URL(entry.item).pathname),
    ['/', '/cve-database/', url]
  );
  assert.equal(breadcrumbs.itemListElement[1].name, 'CVE Database');
  assert.ok(
    breadcrumbs.itemListElement.every(
      (entry) => !['/recipes/', '/recipes/cve/'].includes(new URL(entry.item).pathname)
    )
  );
});
