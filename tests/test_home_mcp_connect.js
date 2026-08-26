'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { mountConnect } = require('../assets/js/home-mcp-connect.js');

const ROOT = path.resolve(__dirname, '..');
const HOSTED_URL = 'https://security-recipes.ai/mcp';
const CLIENT_JSON = [
  '{',
  '  "mcpServers": {',
  '    "security-recipes": {',
  '      "transport": "streamable-http",',
  '      "url": "https://security-recipes.ai/mcp"',
  '    }',
  '  }',
  '}',
].join('\n');

class FakeNode {
  constructor(text) {
    this.textContent = text;
    this.listeners = new Map();
    this.attributes = new Map();
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  removeEventListener(type) {
    this.listeners.delete(type);
  }

  click() {
    return this.listeners.get('click')?.();
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }
}

class FakeRoot {
  constructor() {
    this.url = new FakeNode(HOSTED_URL);
    this.json = new FakeNode(CLIENT_JSON);
    this.status = new FakeNode('');
    this.urlButton = new FakeNode('');
    this.jsonButton = new FakeNode('');
    this.urlButton.setAttribute('data-home-mcp-copy', 'url');
    this.jsonButton.setAttribute('data-home-mcp-copy', 'json');
    this.attributes = new Map();
    this.ownerDocument = {};
  }

  querySelector(selector) {
    if (selector === '[data-home-mcp-source="url"]') return this.url;
    if (selector === '[data-home-mcp-source="json"]') return this.json;
    if (selector === '[data-home-mcp-status]') return this.status;
    return null;
  }

  querySelectorAll(selector) {
    return selector === '[data-home-mcp-copy]'
      ? [this.urlButton, this.jsonButton]
      : [];
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }
}

function clipboardWindow(writeText) {
  return {
    navigator: {
      clipboard: { writeText },
    },
    document: {},
  };
}

test('homepage copy helper copies the printed URL and client JSON', async () => {
  const root = new FakeRoot();
  const writes = [];
  const controller = mountConnect(root, clipboardWindow(async (text) => {
    writes.push(text);
  }));

  assert.ok(controller);
  assert.equal(controller.sourceText('url'), HOSTED_URL);
  assert.equal(controller.sourceText('json'), CLIENT_JSON);

  await root.urlButton.click();
  assert.deepEqual(writes, [HOSTED_URL]);
  assert.equal(root.status.textContent, 'Copied URL.');

  await root.jsonButton.click();
  assert.deepEqual(writes, [HOSTED_URL, CLIENT_JSON]);
  assert.equal(root.status.textContent, 'Copied JSON.');

  controller.destroy();
  assert.equal(root.getAttribute('data-home-mcp-mounted'), null);
  assert.equal(root.urlButton.listeners.size, 0);
});

test('homepage copy helper falls back when the clipboard API rejects', async () => {
  const root = new FakeRoot();
  const execs = [];
  const field = {
    value: '',
    style: {},
    focus() {},
    select() {},
    setSelectionRange() {},
    setAttribute() {},
  };
  const doc = {
    body: {
      appendChild() {},
      removeChild() {},
    },
    createElement() {
      return field;
    },
    execCommand(name) {
      execs.push(name);
      return true;
    },
  };
  root.ownerDocument = doc;

  const controller = mountConnect(root, {
    navigator: {
      clipboard: {
        writeText() {
          return Promise.reject(new Error('denied'));
        },
      },
    },
    document: doc,
  });

  await root.urlButton.click();
  assert.equal(field.value, HOSTED_URL);
  assert.deepEqual(execs, ['copy']);
  assert.equal(root.status.textContent, 'Copied URL.');
  controller.destroy();
});

test('homepage template prints the hosted streamable-http client snippet', () => {
  const template = fs.readFileSync(
    path.join(ROOT, '_includes', 'layouts', 'home-static.html'),
    'utf8',
  );

  assert.match(template, /data-home-mcp-connect/);
  assert.match(template, /data-home-mcp-source="url">https:\/\/security-recipes\.ai\/mcp</);
  assert.match(template, /"mcpServers"/);
  assert.match(template, /"security-recipes"/);
  assert.match(template, /"transport": "streamable-http"/);
  assert.match(template, /"url": "https:\/\/security-recipes\.ai\/mcp"/);
  assert.doesNotMatch(template, /RECIPES_MCP_TRANSPORT/);
  assert.doesNotMatch(template, /mcp-server\.toml/);
});
