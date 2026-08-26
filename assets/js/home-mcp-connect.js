'use strict';

(function bootstrap(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (!root || !root.document) return;

  const mount = function () { api.mountAll(root.document, root); };
  if (root.document.readyState === 'loading') {
    root.document.addEventListener('DOMContentLoaded', mount, { once: true });
  } else {
    mount();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createHomeMcpConnect() {
  const COPY_LABELS = {
    url: 'URL',
    json: 'JSON',
  };

  function sourceText(root, key) {
    const node = root.querySelector('[data-home-mcp-source="' + key + '"]');
    return node ? String(node.textContent || '').trim() : '';
  }

  function setStatus(root, message) {
    const status = root.querySelector('[data-home-mcp-status]');
    if (status) status.textContent = message;
  }

  function fallbackCopy(doc, text) {
    const field = doc.createElement('textarea');
    field.value = text;
    field.setAttribute('readonly', '');
    field.style.position = 'fixed';
    field.style.top = '0';
    field.style.left = '-9999px';
    doc.body.appendChild(field);
    field.focus();
    field.select();
    field.setSelectionRange(0, field.value.length);

    let copied = false;
    try {
      copied = doc.execCommand('copy');
    } catch (error) {
      copied = false;
    }

    doc.body.removeChild(field);
    if (!copied) throw new Error('Clipboard copy was unavailable.');
  }

  async function copyText(win, doc, text) {
    const clipboard = win && win.navigator && win.navigator.clipboard;
    if (clipboard && typeof clipboard.writeText === 'function') {
      try {
        await clipboard.writeText(text);
        return;
      } catch (error) {
        fallbackCopy(doc, text);
        return;
      }
    }

    fallbackCopy(doc, text);
  }

  function mountConnect(root, win) {
    if (!root || root.getAttribute('data-home-mcp-mounted') === 'true') return null;
    const doc = root.ownerDocument || (win && win.document);
    if (!doc) return null;

    const buttons = Array.from(root.querySelectorAll('[data-home-mcp-copy]'));
    if (!buttons.length) return null;

    const listeners = [];

    buttons.forEach(function (button) {
      const key = button.getAttribute('data-home-mcp-copy');
      const handler = function () {
        const text = sourceText(root, key);
        if (!text) {
          setStatus(root, 'Nothing to copy.');
          return Promise.resolve();
        }

        return copyText(win, doc, text).then(function () {
          setStatus(root, 'Copied ' + (COPY_LABELS[key] || key) + '.');
        }).catch(function () {
          setStatus(root, 'Copy unavailable. Select the text and copy it.');
        });
      };

      button.addEventListener('click', handler);
      listeners.push([button, handler]);
    });

    root.setAttribute('data-home-mcp-mounted', 'true');

    return {
      sourceText: function (key) { return sourceText(root, key); },
      destroy: function () {
        listeners.forEach(function (pair) {
          pair[0].removeEventListener('click', pair[1]);
        });
        root.removeAttribute('data-home-mcp-mounted');
      },
    };
  }

  function mountAll(doc, win) {
    if (!doc || typeof doc.querySelectorAll !== 'function') return [];
    return Array.from(doc.querySelectorAll('[data-home-mcp-connect]'))
      .map(function (root) { return mountConnect(root, win); })
      .filter(Boolean);
  }

  return { mountAll, mountConnect };
});
