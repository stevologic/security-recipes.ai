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

test('homepage structured search targets the working recipe catalog', () => {
  const output = seoHead({
    url: '/',
    title: 'Security Recipes',
    description: 'Open security intelligence.',
    isHome: true,
  });
  const match = output.match(/<script type="application\/ld\+json">(.*?)<\/script>/s);

  assert.ok(match, 'expected homepage JSON-LD');
  const parsed = JSON.parse(match[1]);
  const website = parsed['@graph'].find((entry) => entry['@type'] === 'WebSite');

  assert.equal(
    website.potentialAction.target,
    'https://security-recipes.ai/recipes/?q={search_term_string}',
  );
});
