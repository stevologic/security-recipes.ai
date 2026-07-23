'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const catalogController = require('../assets/js/cve-catalog.js');
const { createCveRecordLoader } = require('../assets/js/cve-record-loader.js');

class FakeElement {
  constructor(tagName, attributes = {}) {
    this.tagName = String(tagName || '').toUpperCase();
    this.attributes = new Map(Object.entries(attributes));
    this.listeners = new Map();
    this.queries = new Map();
    this.disabled = false;
    this.hidden = false;
    this.textContent = '';
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  addEventListener(type, callback) {
    this.listeners.set(type, callback);
  }

  focus() {
    this.focused = true;
  }

  querySelector(selector) {
    return this.queries.get(selector) || null;
  }

  click() {
    const callback = this.listeners.get('click');
    return callback ? callback({ type: 'click' }) : undefined;
  }
}

function createHarness() {
  const assets = [];
  const exactShardFetches = [];
  const section = new FakeElement('section', {
    'data-cve-record-loader': '',
    'data-cve-catalog-script': '/js/cve-catalog.js',
  });
  const button = new FakeElement('button', {
    'data-cve-record-activate': '',
    'aria-expanded': 'false',
  });
  const status = new FakeElement('p', { 'data-cve-record-status': '' });
  const catalog = new FakeElement('div', {
    'data-cve-catalog': '',
    'data-cve-catalog-deferred': '',
    'data-cve-initial-id': 'CVE-2024-3400',
  });
  catalog.hidden = true;
  section.queries.set('[data-cve-record-activate]', button);
  section.queries.set(
    '[data-cve-catalog][data-cve-initial-id]',
    catalog,
  );
  section.queries.set('[data-cve-record-status]', status);

  const document = {
    head: {
      appendChild(element) {
        assets.push(element);
      },
    },
    createElement(tagName) {
      return new FakeElement(tagName);
    },
    querySelectorAll(selector) {
      assert.equal(selector, '[data-cve-record-loader]');
      return [section];
    },
  };

  class FakeEvent {
    constructor(type, options = {}) {
      this.type = type;
      this.bubbles = Boolean(options.bubbles);
      this.cancelable = Boolean(options.cancelable);
    }
  }

  const window = {
    Promise,
    Event: FakeEvent,
    console: { error() {} },
  };

  return {
    assets,
    button,
    catalog,
    document,
    exactShardFetches,
    section,
    status,
    window,
  };
}

test('canonical CVE catalog script and exact shard stay idle until explicit activation', async () => {
  const harness = createHarness();
  const loader = createCveRecordLoader({
    document: harness.document,
    window: harness.window,
  });
  const [instance] = loader.mountAll();

  assert.ok(instance);
  assert.equal(harness.assets.length, 0, 'catalog JavaScript is absent before activation');
  assert.deepEqual(harness.exactShardFetches, [], 'the exact shard is not fetched eagerly');
  assert.equal(harness.catalog.hidden, true);

  harness.button.click();
  assert.equal(harness.assets.length, 1);
  assert.equal(harness.button.disabled, false, 'the focused trigger remains focusable');
  assert.equal(harness.button.getAttribute('aria-disabled'), 'true');
  const script = harness.assets.find((asset) => asset.tagName === 'SCRIPT');
  assert.equal(script.src, '/js/cve-catalog.js');
  assert.equal(script.getAttribute('data-cve-record-catalog-script'), 'true');
  assert.equal(harness.exactShardFetches.length, 0, 'assets must load before hydration');

  let mountCalls = 0;
  harness.window.SecurityRecipesCveCatalog = {
    mount(target) {
      mountCalls += 1;
      assert.equal(
        target.getAttribute('data-cve-initial-id'),
        null,
        'the catalog automatic initial search is suppressed',
      );
      target.removeAttribute('data-cve-catalog-deferred');
      const form = new FakeElement('form');
      const input = new FakeElement('input', { 'data-cve-search': '' });
      input.value = '';
      input.closest = (selector) => selector === 'form' ? form : null;
      form.dispatchEvent = (event) => {
        assert.equal(event.type, 'submit');
        assert.equal(event.bubbles, true);
        assert.equal(event.cancelable, true);
        harness.exactShardFetches.push(
          '/api/cve-catalog/' + catalogController.shardPathForCve(input.value),
        );
        return true;
      };
      target.queries.set('[data-cve-search]', input);
    },
  };

  script.onload();
  await instance.whenIdle();

  assert.equal(mountCalls, 1);
  assert.deepEqual(harness.exactShardFetches, [
    '/api/cve-catalog/shards/2024/0003.jsonl.gz',
  ]);
  assert.equal(harness.catalog.getAttribute('data-cve-initial-id'), 'CVE-2024-3400');
  assert.equal(harness.catalog.hidden, false);
  assert.equal(harness.button.disabled, false);
  assert.equal(harness.button.getAttribute('aria-disabled'), null);
  assert.equal(harness.button.getAttribute('aria-expanded'), 'true');
  assert.equal(harness.section.getAttribute('data-cve-record-state'), 'loaded');
  assert.match(harness.status.textContent, /retrieving the normalized record/i);
  assert.match(harness.button.textContent, /focus complete machine-readable record controls/i);
  assert.equal(harness.catalog.querySelector('[data-cve-search]').focused, true);

  harness.catalog.querySelector('[data-cve-search]').focused = false;
  harness.button.click();
  await instance.whenIdle();
  assert.equal(harness.assets.length, 1, 'repeat activation reuses the same script');
  assert.equal(mountCalls, 1, 'repeat activation does not hydrate twice');
  assert.equal(harness.exactShardFetches.length, 1, 'repeat activation does not fetch twice');
  assert.equal(
    harness.catalog.querySelector('[data-cve-search]').focused,
    true,
    'repeat activation returns focus to the loaded controls',
  );
});
