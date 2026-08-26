'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const chat = require('../assets/js/recipe-chat.js');

function fakeRoot(initialHidden) {
  const nodes = {
    quota: { textContent: '' },
    input: { disabled: false },
    send: { disabled: false },
    unlock: { hidden: initialHidden !== false },
  };
  return {
    querySelector(selector) {
      if (selector === '[data-recipe-chat-quota]') return nodes.quota;
      if (selector === '[data-recipe-chat-input]') return nodes.input;
      if (selector === '[data-recipe-chat-send]') return nodes.send;
      if (selector === '[data-recipe-chat-unlock]') return nodes.unlock;
      return null;
    },
    nodes,
  };
}

test('chat helpers hide the widget without XAI_API_KEY', () => {
  assert.equal(chat.isChatEnabled({ enabled: false }), false);
  assert.equal(chat.isChatEnabled(undefined), false);
  assert.equal(chat.isChatEnabled({ enabled: true }), true);
  assert.equal(chat.canSend({ quota: { can_send: false } }), false);
  assert.equal(chat.canSend({ quota: { can_send: true } }), true);
  assert.match(
    chat.quotaLabel({ quota: { paid_active: false, free_remaining: 2, free_limit: 6 } }),
    /2 of 6/
  );
});

test('composer is blocked after the free sample until checkout', () => {
  const root = fakeRoot(true);
  chat.applyQuota(root, {
    quota: { can_send: false, paid_active: false, free_remaining: 0, free_limit: 6 },
    stripe: { configured: true },
  });
  assert.equal(root.nodes.input.disabled, true);
  assert.equal(root.nodes.send.disabled, true);
  assert.equal(root.nodes.unlock.hidden, false);
  assert.match(root.nodes.quota.textContent, /0 of 6/);
});

test('homepage and collection pages include the Recipe chat entry', () => {
  const home = fs.readFileSync(path.join(ROOT, '_includes/layouts/home-static.html'), 'utf8');
  const docs = fs.readFileSync(path.join(ROOT, '_includes/layouts/docs.njk'), 'utf8');
  const head = fs.readFileSync(path.join(ROOT, '_includes/partials/head-common.njk'), 'utf8');
  const partial = fs.readFileSync(path.join(ROOT, '_includes/partials/recipe-chat.njk'), 'utf8');

  assert.match(home, /recipe-chat\.js/);
  assert.match(home, /recipe-chat\.njk/);
  assert.match(docs, /\/recipes\//);
  assert.match(docs, /recipe-chat\.njk/);
  assert.match(head, /recipe-chat\.js/);
  assert.match(partial, /Recipe chat/);
  assert.doesNotMatch(partial, /copilot/i);
  assert.doesNotMatch(partial, /your AI security/i);
});
