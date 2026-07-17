'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { mountTicker } = require('../assets/js/cve-ticker.js');

const ROOT = path.resolve(__dirname, '..');

class FakeButton {
  constructor() {
    this.attributes = new Map();
    this.listeners = new Map();
    this.hidden = true;
  }

  addEventListener(type, listener) { this.listeners.set(type, listener); }
  removeEventListener(type) { this.listeners.delete(type); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  click() { this.listeners.get('click')?.(); }
}

class FakeTicker {
  constructor(button) {
    this.button = button;
    this.attributes = new Map();
  }

  querySelector(selector) {
    return selector === '[data-cve-ticker-toggle]' ? this.button : null;
  }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  removeAttribute(name) { this.attributes.delete(name); }
}

function fakeMotion() {
  return {
    matches: false,
    listener: null,
    addEventListener(type, listener) { if (type === 'change') this.listener = listener; },
    removeEventListener() { this.listener = null; },
    change(matches) { this.matches = matches; this.listener?.(); },
  };
}

test('ticker controller exposes pause, resume, and reduced-motion states', () => {
  const button = new FakeButton();
  const ticker = new FakeTicker(button);
  const motion = fakeMotion();
  const controller = mountTicker(ticker, { matchMedia: () => motion });

  assert.ok(controller);
  assert.equal(ticker.getAttribute('data-cve-ticker-ready'), 'true');
  assert.equal(button.hidden, false);
  assert.equal(button.getAttribute('aria-pressed'), 'false');
  assert.equal(button.getAttribute('aria-label'), 'Pause latest CVE ticker');

  button.click();
  assert.equal(ticker.getAttribute('data-cve-ticker-paused'), 'true');
  assert.equal(button.getAttribute('aria-pressed'), 'true');
  assert.equal(button.getAttribute('aria-label'), 'Resume latest CVE ticker');

  button.click();
  assert.equal(ticker.getAttribute('data-cve-ticker-paused'), null);
  motion.change(true);
  assert.equal(ticker.getAttribute('data-cve-ticker-ready'), null);
  assert.equal(button.hidden, true);

  controller.destroy();
  assert.equal(ticker.getAttribute('data-cve-ticker-mounted'), null);
});

test('homepage ticker is semantic, bounded, and explicitly motion-safe', () => {
  const source = fs.readFileSync(path.join(ROOT, '_includes', 'layouts', 'home-static.html'), 'utf8');
  assert.match(source, /<aside class="cve-ticker" aria-label="Latest published CVEs" data-cve-ticker>/);
  assert.match(source, /<ul class="cve-ticker__list">/);
  assert.match(source, /<ul class="cve-ticker__list" aria-hidden="true" inert>/);
  assert.match(source, /data-cve-ticker-toggle[^>]*aria-pressed="false"/);
  assert.doesNotMatch(source, /aria-live=/);
  assert.doesNotMatch(source, /browser-index\.json/);
  assert.match(source, /@media \(prefers-reduced-motion: reduce\)[\s\S]*?\.cve-ticker__track\s*\{[\s\S]*?animation: none !important;/);
  assert.match(source, /<script src="\/js\/cve-ticker\.js" defer><\/script>/);
});
