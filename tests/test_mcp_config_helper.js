'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  healthChecks,
  mcpEndpointOverride,
  shellQuote,
  standaloneToml,
  tomlArray,
  tomlString,
} = require('../assets/js/mcp-config-helper.js');

const ROOT = path.resolve(__dirname, '..');

test('the MCP page leads with a copy-ready hosted connection', () => {
  const page = fs.readFileSync(
    path.join(ROOT, 'content', 'mcp-servers', '_index.md'),
    'utf8'
  );
  const quickConnect = page.indexOf('## Connect in 30 seconds');
  const protocolDocs = page.indexOf('## MCP in one minute');
  const fullConfiguration = page.indexOf('## Configure this Security Recipes MCP server');
  const frontMatterEnd = page.indexOf('\n---\n', 4);
  const body = page.slice(frontMatterEnd + '\n---\n'.length).trimStart();
  const quickConnectEnd = page.indexOf('\n---\n', quickConnect);
  const quickConnectBlock = page.slice(quickConnect, quickConnectEnd);

  assert.ok(quickConnect > -1, 'quick-connect section must exist');
  assert.ok(body.startsWith('## Connect in 30 seconds'), 'quick connect must be the first page content');
  assert.ok(quickConnect < protocolDocs, 'quick connect must precede protocol documentation');
  assert.ok(quickConnect < fullConfiguration, 'quick connect must precede full configuration');
  assert.match(quickConnectBlock, /data-mcp-config-copy="url"/u);
  assert.match(quickConnectBlock, /data-mcp-config-copy="client"/u);
  assert.match(
    quickConnectBlock,
    /data-mcp-config-endpoint="https:\/\/security-recipes\.ai\/mcp"/u
  );
  assert.match(quickConnectBlock, /https:\/\/security-recipes\.ai\/mcp/u);
  assert.match(quickConnectBlock, /"transport": "streamable-http"/u);
});

test('the hosted quick connect keeps its canonical endpoint on preview hosts', () => {
  const root = {
    getAttribute(name) {
      return name === 'data-mcp-config-endpoint'
        ? 'https://security-recipes.ai/mcp'
        : null;
    },
  };

  assert.equal(
    mcpEndpointOverride(root, 'http://localhost:8080/mcp'),
    'https://security-recipes.ai/mcp'
  );
});

test('endpoint overrides reject unsafe URLs and embedded credentials', () => {
  const rootFor = (value) => ({ getAttribute: () => value });
  const fallback = 'https://security-recipes.ai/mcp';

  assert.equal(mcpEndpointOverride(rootFor('javascript:alert(1)'), fallback), fallback);
  assert.equal(mcpEndpointOverride(rootFor('https://user:pass@example.test/mcp'), fallback), fallback);
  assert.equal(mcpEndpointOverride(rootFor('not a URL'), fallback), fallback);
});

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
