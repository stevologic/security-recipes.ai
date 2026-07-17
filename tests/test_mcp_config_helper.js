'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  healthChecks,
  shellQuote,
  standaloneToml,
  tomlArray,
  tomlString,
} = require('../assets/js/mcp-config-helper.js');

test('shell values are enclosed with POSIX-safe single-quote escaping', () => {
  const hostile = "https://example.test/a'b?x=$(touch /tmp/should-not-run);echo bad";
  assert.equal(
    shellQuote(hostile),
    "'https://example.test/a'\"'\"'b?x=$(touch /tmp/should-not-run);echo bad'"
  );

  const command = healthChecks({ feedUrl: hostile })
    .split('\n')
    .find((line) => line.startsWith('curl '));
  assert.equal(command, `curl -fsS ${shellQuote(hostile)} | head`);
});

test('TOML strings escape quotes, backslashes, newlines, and control characters', () => {
  const hostile = 'alpha"beta\\gamma\n\t\u0001';
  assert.equal(tomlString(hostile), '"alpha\\"beta\\\\gamma\\n\\t\\u0001"');
  assert.equal(
    tomlArray(['safe.example', hostile]),
    '["safe.example", "alpha\\"beta\\\\gamma\\n\\t\\u0001"]'
  );
});

test('standalone TOML uses the same encoder for every browser-derived value', () => {
  const config = {
    feedUrl: 'https://example.test/feed"\\\nnext',
    mcpUrl: 'https://example.test/mcp"\\\nnext',
    publicAllowedHosts: ['example.test', 'host"\\\nnext'],
  };
  const output = standaloneToml(config);

  assert.ok(output.includes(`source_index_url = ${tomlString(config.feedUrl)}`));
  assert.ok(output.includes(`server_public_base_url = ${tomlString(config.mcpUrl)}`));
  assert.ok(output.includes(`allowed_source_hosts = ${tomlArray(config.publicAllowedHosts)}`));
  assert.equal(output.split('\n').filter((line) => line === 'next').length, 0);
});
