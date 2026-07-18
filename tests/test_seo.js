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

test('reviewed CVE pages consolidate on the clean canonical CVE route', () => {
  const output = seoHead({
    url: '/recipes/cve/cve-2024-3400-reviewed-title/',
    title: 'CVE-2024-3400 reviewed recipe',
    description: 'Reviewed product-specific guidance.',
    cve: 'cve-2024-3400',
    isSection: false,
  });

  assert.match(
    output,
    /<link rel="canonical" href="https:\/\/security-recipes\.ai\/cve\/CVE-2024-3400\/">/
  );
  assert.match(
    output,
    /<meta property="og:url" content="https:\/\/security-recipes\.ai\/cve\/CVE-2024-3400\/">/
  );
  const structured = output.match(/<script type="application\/ld\+json">(.*?)<\/script>/s);
  assert.ok(structured);
  assert.equal(JSON.parse(structured[1]).url, 'https://security-recipes.ai/cve/CVE-2024-3400/');
});

test('historical reviewed CVEs outside the dynamic catalog remain self-canonical', () => {
  const output = seoHead({
    url: '/recipes/cve/cve-2014-0160-heartbleed/',
    title: 'CVE-2014-0160 — Heartbleed',
    description: 'Reviewed Heartbleed remediation guidance.',
    cve: 'CVE-2014-0160',
    canonicalCveRoute: false,
    isSection: false,
  });

  assert.match(
    output,
    /<link rel="canonical" href="https:\/\/security-recipes\.ai\/recipes\/cve\/cve-2014-0160-heartbleed\/">/
  );
  assert.doesNotMatch(output, /rel="canonical" href="[^"]*\/cve\/CVE-2014-0160\/"/);
});
