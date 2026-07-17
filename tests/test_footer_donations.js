'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const site = require('../lib/site-config');

const ROOT = path.resolve(__dirname, '..');
const read = (...parts) => fs.readFileSync(path.join(ROOT, ...parts), 'utf8');
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function decodeBase58Check(address) {
  let value = 0n;
  for (const character of address) {
    const digit = BASE58.indexOf(character);
    assert.notEqual(digit, -1, `invalid Base58 character in ${address}`);
    value = (value * 58n) + BigInt(digit);
  }

  const decoded = [];
  while (value > 0n) {
    decoded.unshift(Number(value & 0xffn));
    value >>= 8n;
  }
  const leadingZeroes = address.match(/^1*/)[0].length;
  const bytes = Buffer.concat([Buffer.alloc(leadingZeroes), Buffer.from(decoded)]);
  const payload = bytes.subarray(0, -4);
  const checksum = bytes.subarray(-4);
  const expected = crypto
    .createHash('sha256')
    .update(crypto.createHash('sha256').update(payload).digest())
    .digest()
    .subarray(0, 4);
  assert.deepEqual(checksum, expected, `invalid Base58Check checksum for ${address}`);
  return payload;
}

test('footer donation wallets preserve the exact public addresses and wallet schemes', () => {
  assert.deepEqual(site.donations, [
    {
      currency: 'BTC',
      name: 'Bitcoin',
      slug: 'btc',
      scheme: 'bitcoin',
      address: '3M9PTxL15b6c8REcHMZCVPbfMomXNZ5AGR',
    },
    {
      currency: 'DOGE',
      name: 'Dogecoin',
      slug: 'doge',
      scheme: 'dogecoin',
      address: 'DTW2M5oEW97WbmYJRM71qD7uE6xfJs1MUK',
    },
  ]);

  for (const wallet of site.donations) {
    assert.match(wallet.address, /^[1-9A-HJ-NP-Za-km-z]{26,40}$/);
    assert.equal(`${wallet.scheme}:${wallet.address}`.includes('?'), false);
  }
  assert.equal(decodeBase58Check(site.donations[0].address)[0], 0x05, 'BTC address must be P2SH');
  assert.equal(decodeBase58Check(site.donations[1].address)[0], 0x1e, 'DOGE address must be P2PKH');
});

test('home and documentation footers share accessible donation links', () => {
  const partial = read('_includes', 'partials', 'footer-donations.njk');
  const home = read('_includes', 'layouts', 'home-static.html');
  const docs = read('_includes', 'layouts', 'docs.njk');
  const head = read('_includes', 'partials', 'head-common.njk');

  assert.match(partial, /role="group" aria-label="Cryptocurrency donation wallets"/);
  assert.match(partial, /href="\{\{ wallet\.scheme \| escape \}\}:\{\{ wallet\.address \| escape \}\}"/);
  assert.match(partial, /<span class="crypto-donation__address">\{\{ wallet\.address \| escape \}\}<\/span>/);
  assert.doesNotMatch(partial, /target="_blank"/);

  for (const layout of [home, docs]) {
    assert.match(layout, /\{% include "partials\/footer-donations\.njk" %\}/);
  }
  assert.match(home, /<link rel="stylesheet" href="\/css\/footer-donations\.css">/);
  assert.match(head, /<link rel="stylesheet" href="\/css\/footer-donations\.css">/);
});

test('donation buttons keep complete addresses readable on narrow screens', () => {
  const css = read('assets', 'css', 'footer-donations.css');

  assert.match(css, /\.crypto-donations \.crypto-donation\s*\{[^}]*min-height:\s*44px;/);
  assert.match(css, /\.crypto-donations \.crypto-donation:focus-visible\s*\{[^}]*outline:\s*2px solid #2dd4bf;/);
  assert.match(css, /\.crypto-donation__address\s*\{[^}]*overflow-wrap:\s*anywhere;/);
  assert.match(css, /@media \(max-width: 720px\)[\s\S]*?\.crypto-donations \.crypto-donation\s*\{[^}]*width:\s*100%;/);
});
