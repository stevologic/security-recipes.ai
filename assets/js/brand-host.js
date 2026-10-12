'use strict';

(function bootstrap(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (!root || !root.document) return;

  const apply = function () {
    api.applyBrand(root.document, root.location);
  };
  apply();
  if (root.document.readyState === 'loading') {
    root.document.addEventListener('DOMContentLoaded', apply, { once: true });
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createBrandHost() {
  const CANONICAL_HOST = 'security-recipes.ai';
  const MIRROR_HOSTS = ['security-recipes.si'];
  const REPO_PATH_MARK = 'stevologic/';

  function normalizeHost(hostname) {
    return String(hostname || '')
      .trim()
      .toLowerCase()
      .replace(/\.$/u, '');
  }

  function apexHost(hostname) {
    const host = normalizeHost(hostname);
    return host.startsWith('www.') ? host.slice(4) : host;
  }

  function displayBrandForHost(hostname) {
    const host = apexHost(hostname);
    if (MIRROR_HOSTS.indexOf(host) !== -1) return host;
    return CANONICAL_HOST;
  }

  function rewriteHostText(value, brandHost) {
    const text = String(value == null ? '' : value);
    if (!text || brandHost === CANONICAL_HOST || text.indexOf(CANONICAL_HOST) === -1) {
      return text;
    }

    let result = '';
    let cursor = 0;
    let index = text.indexOf(CANONICAL_HOST);
    while (index !== -1) {
      const prefix = text.slice(Math.max(0, index - REPO_PATH_MARK.length), index);
      result += text.slice(cursor, index);
      result += prefix === REPO_PATH_MARK ? CANONICAL_HOST : brandHost;
      cursor = index + CANONICAL_HOST.length;
      index = text.indexOf(CANONICAL_HOST, cursor);
    }
    return result + text.slice(cursor);
  }

  function applyNode(node, brandHost) {
    if (!node) return;
    const mode = node.getAttribute('data-brand-host') || 'text';

    if (mode === 'aria') {
      const label = node.getAttribute('aria-label');
      if (label) node.setAttribute('aria-label', rewriteHostText(label, brandHost));
      return;
    }

    if (node.childNodes && node.childNodes.length) {
      Array.prototype.forEach.call(node.childNodes, function (child) {
        if (child.nodeType === 3) {
          child.nodeValue = rewriteHostText(child.nodeValue, brandHost);
        }
      });
      return;
    }

    if ('textContent' in node) {
      node.textContent = rewriteHostText(node.textContent, brandHost);
    }
  }

  function applyBrand(doc, location) {
    if (!doc || typeof doc.querySelectorAll !== 'function') {
      return { brand: CANONICAL_HOST, rewritten: false };
    }

    const brandHost = displayBrandForHost(location && location.hostname);
    if (brandHost === CANONICAL_HOST) {
      return { brand: brandHost, rewritten: false };
    }

    Array.prototype.forEach.call(doc.querySelectorAll('[data-brand-host]'), function (node) {
      applyNode(node, brandHost);
    });

    return { brand: brandHost, rewritten: true };
  }

  return {
    CANONICAL_HOST,
    MIRROR_HOSTS,
    applyBrand,
    displayBrandForHost,
    rewriteHostText,
  };
});
