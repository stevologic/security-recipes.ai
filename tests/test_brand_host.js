'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const site = require('../lib/site-config');
const {
  CANONICAL_HOST,
  MIRROR_HOSTS,
  applyBrand,
  displayBrandForHost,
  rewriteHostText,
} = require('../assets/js/brand-host.js');

const ROOT = path.resolve(__dirname, '..');
const read = (...parts) => fs.readFileSync(path.join(ROOT, ...parts), 'utf8');

class FakeNode {
  constructor(text, attributes = {}) {
    this.childNodes = [{ nodeType: 3, nodeValue: text }];
    this.attributes = new Map(Object.entries(attributes));
  }

  get textContent() {
    return this.childNodes.map((child) => child.nodeValue).join('');
  }

  set textContent(value) {
    this.childNodes = [{ nodeType: 3, nodeValue: String(value) }];
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }
}

class FakeDocument {
  constructor(nodes) {
    this.nodes = nodes;
  }

  querySelectorAll(selector) {
    return selector === '[data-brand-host]' ? this.nodes : [];
  }
}

test('site-config keeps the .ai build brand and lists the .si mirror', () => {
  assert.equal(site.canonicalHost, 'security-recipes.ai');
  assert.equal(site.title, 'security-recipes.ai');
  assert.equal(site.mcpPublicUrl, 'https://security-recipes.ai/mcp');
  assert.deepEqual(site.mirrorHosts, ['security-recipes.si']);
  assert.match(site.footer.copyright, /Copyright 2026 security-recipes\.ai -/);
  assert.equal(site.canonicalHost, CANONICAL_HOST);
  assert.deepEqual(site.mirrorHosts, MIRROR_HOSTS);
  assert.equal(site.repoURL, 'https://github.com/stevologic/security-recipes.ai');
});

test('display brand follows Host, including www, and defaults to .ai', () => {
  assert.equal(displayBrandForHost('security-recipes.ai'), 'security-recipes.ai');
  assert.equal(displayBrandForHost('www.security-recipes.ai'), 'security-recipes.ai');
  assert.equal(displayBrandForHost('security-recipes.si'), 'security-recipes.si');
  assert.equal(displayBrandForHost('www.security-recipes.si'), 'security-recipes.si');
  assert.equal(displayBrandForHost('SECURITY-RECIPES.SI.'), 'security-recipes.si');
  assert.equal(displayBrandForHost('localhost'), 'security-recipes.ai');
  assert.equal(displayBrandForHost(''), 'security-recipes.ai');
});

test('host rewrite leaves GitHub repo paths on the .ai repository name', () => {
  assert.equal(
    rewriteHostText('security-recipes.ai is open', 'security-recipes.si'),
    'security-recipes.si is open',
  );
  assert.equal(
    rewriteHostText(
      'https://github.com/stevologic/security-recipes.ai and security-recipes.ai',
      'security-recipes.si',
    ),
    'https://github.com/stevologic/security-recipes.ai and security-recipes.si',
  );
  assert.equal(
    rewriteHostText('https://security-recipes.ai/mcp', 'security-recipes.si'),
    'https://security-recipes.si/mcp',
  );
});

test('applyBrand rewrites marked chrome on .si and leaves .ai Host unchanged', () => {
  const navText = new FakeNode('security-recipes.ai', { 'data-brand-host': 'text' });
  const navAria = new FakeNode('', {
    'data-brand-host': 'aria',
    'aria-label': 'security-recipes.ai home',
  });
  const copyright = new FakeNode(
    'Copyright 2026 security-recipes.ai - bounded recipes for agent-assisted security remediation',
    { 'data-brand-host': 'text' },
  );
  const mcp = new FakeNode('https://security-recipes.ai/mcp', { 'data-brand-host': 'text' });
  const document = new FakeDocument([navText, navAria, copyright, mcp]);

  const unchanged = applyBrand(document, { hostname: 'security-recipes.ai' });
  assert.equal(unchanged.rewritten, false);
  assert.equal(navText.textContent, 'security-recipes.ai');
  assert.equal(navAria.getAttribute('aria-label'), 'security-recipes.ai home');

  const mirrored = applyBrand(document, { hostname: 'www.security-recipes.si' });
  assert.equal(mirrored.rewritten, true);
  assert.equal(mirrored.brand, 'security-recipes.si');
  assert.equal(navText.textContent, 'security-recipes.si');
  assert.equal(navAria.getAttribute('aria-label'), 'security-recipes.si home');
  assert.match(copyright.textContent, /Copyright 2026 security-recipes\.si -/);
  assert.equal(mcp.textContent, 'https://security-recipes.si/mcp');
});

test('homepage and docs mark visible brand strings without touching GitHub links', () => {
  const home = read('_includes', 'layouts', 'home-static.html');
  const navbar = read('_includes', 'partials', 'navbar.njk');
  const docs = read('_includes', 'layouts', 'docs.njk');

  assert.match(home, /aria-label="\{\{ site\.title \}\} home" data-brand-host="aria"/);
  assert.match(home, /<span data-brand-host>\{\{ site\.title \}\}<\/span>/);
  assert.match(home, /data-home-mcp-source="url" data-brand-host>\{\{ site\.mcpPublicUrl \}\}</);
  assert.match(home, /"url": "\{\{ site\.mcpPublicUrl \}\}"/);
  assert.match(home, /<span data-brand-host>\{\{ site\.title \}\}<\/span> is an open/);
  assert.match(home, /findings\. <span data-brand-host>\{\{ site\.title \}\}<\/span> helps/);
  assert.match(home, /src="\/js\/brand-host\.js\?v=20261006"/);
  assert.match(home, /https:\/\/github.com\/stevologic\/security-recipes\.ai/);
  assert.doesNotMatch(home, /aria-label="security-recipes\.ai home"/);
  assert.doesNotMatch(home, />security-recipes\.ai<\/span>/);

  assert.match(navbar, /aria-label="\{\{ site\.title \}\} home" data-brand-host="aria"/);
  assert.match(navbar, /<span data-brand-host>\{\{ site\.title \}\}<\/span>/);
  assert.match(navbar, /\{\{ site\.repoURL \}\}/);

  assert.match(docs, /src="\/js\/brand-host\.js\?v=20261006"/);
  assert.match(docs, /<span data-brand-host>\{\{ site\.footer\.copyright \}\}<\/span>/);
});
