(function () {
  'use strict';

  var STATUS_URL = '/api/chat/status';
  var MESSAGE_URL = '/api/chat';
  var CHECKOUT_URL = '/api/chat/checkout';
  var SESSION_URL = '/api/chat/checkout/session';

  function isChatEnabled(status) {
    return !!(status && status.enabled === true);
  }

  function canSend(status) {
    return !!(status && status.quota && status.quota.can_send);
  }

  function quotaLabel(status) {
    if (!status || !status.quota) return '';
    var quota = status.quota;
    if (quota.paid_active) {
      return quota.paid_remaining + ' paid messages left.';
    }
    return quota.free_remaining + ' of ' + quota.free_limit + ' free messages left today.';
  }

  function escapeHtml(value) {
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function linkify(text) {
    return escapeHtml(text).replace(
      /(https?:\/\/[^\s<]+)/g,
      '<a href="$1" rel="noopener noreferrer">$1</a>'
    );
  }

  function applyQuota(root, status) {
    var quota = root.querySelector('[data-recipe-chat-quota]');
    var input = root.querySelector('[data-recipe-chat-input]');
    var send = root.querySelector('[data-recipe-chat-send]');
    var unlock = root.querySelector('[data-recipe-chat-unlock]');
    var allowed = canSend(status);
    if (quota) quota.textContent = quotaLabel(status);
    if (input) input.disabled = !allowed;
    if (send) send.disabled = !allowed;
    if (unlock) unlock.hidden = allowed || !status || !status.stripe || !status.stripe.configured;
  }

  function appendBubble(log, role, text, sources) {
    if (!log) return;
    var article = document.createElement('article');
    article.className = 'recipe-chat__bubble recipe-chat__bubble--' + role;
    article.innerHTML = '<p>' + linkify(text) + '</p>';
    if (sources && sources.length) {
      var list = document.createElement('ul');
      list.className = 'recipe-chat__sources';
      sources.forEach(function (source) {
        var item = document.createElement('li');
        var anchor = document.createElement('a');
        anchor.href = source.url;
        anchor.textContent = source.title || source.url;
        item.appendChild(anchor);
        list.appendChild(item);
      });
      article.appendChild(list);
    }
    log.appendChild(article);
    log.scrollTop = log.scrollHeight;
  }

  function setStatus(root, message) {
    var node = root.querySelector('[data-recipe-chat-status]');
    if (node) node.textContent = message || '';
  }

  async function readJson(response) {
    try {
      return await response.json();
    } catch (_error) {
      return {};
    }
  }

  async function loadStatus() {
    var response = await fetch(STATUS_URL, { credentials: 'same-origin' });
    if (!response.ok) return { enabled: false };
    var payload = await readJson(response);
    return payload && typeof payload === 'object' ? payload : { enabled: false };
  }

  async function completeUnlock(status) {
    var params = new URLSearchParams(window.location.search);
    if (params.get('chat_unlock') !== '1') return status;
    var sessionId = params.get('session_id') || '';
    if (!sessionId) return status;
    var response = await fetch(SESSION_URL + '?session_id=' + encodeURIComponent(sessionId), {
      credentials: 'same-origin',
    });
    var payload = await readJson(response);
    if (response.ok && payload.quota) {
      status.quota = payload.quota;
    }
    return status;
  }

  function bind(root, status) {
    var form = root.querySelector('[data-recipe-chat-form]');
    var input = root.querySelector('[data-recipe-chat-input]');
    var log = root.querySelector('[data-recipe-chat-log]');
    var unlock = root.querySelector('[data-recipe-chat-unlock]');
    var current = status;

    applyQuota(root, current);

    if (form) {
      form.addEventListener('submit', async function (event) {
        event.preventDefault();
        if (!canSend(current) || !input || input.disabled) return;
        var message = input.value.trim();
        if (!message) return;
        appendBubble(log, 'user', message);
        input.value = '';
        setStatus(root, 'Looking up published pages…');
        form.setAttribute('aria-busy', 'true');
        try {
          var response = await fetch(MESSAGE_URL, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({
              message: message,
              page_url: window.location.pathname,
            }),
          });
          var payload = await readJson(response);
          if (payload.quota) current.quota = payload.quota;
          applyQuota(root, current);
          if (response.status === 402) {
            appendBubble(log, 'assistant', payload.message || 'Unlock to keep going.');
            setStatus(root, payload.message || '');
            return;
          }
          if (!response.ok) {
            appendBubble(log, 'assistant', payload.message || 'Recipe chat is unavailable.');
            setStatus(root, payload.message || '');
            return;
          }
          appendBubble(log, 'assistant', payload.reply || '', payload.sources || []);
          setStatus(root, '');
        } catch (_error) {
          appendBubble(log, 'assistant', 'Recipe chat is unavailable.');
          setStatus(root, 'Recipe chat is unavailable.');
        } finally {
          form.removeAttribute('aria-busy');
        }
      });
    }

    if (unlock) {
      unlock.addEventListener('click', async function () {
        setStatus(root, 'Opening checkout…');
        try {
          var response = await fetch(CHECKOUT_URL, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ return_path: window.location.pathname }),
          });
          var payload = await readJson(response);
          if (!response.ok || !payload.checkout_url) {
            setStatus(root, payload.message || 'Checkout is not configured.');
            return;
          }
          window.location.assign(payload.checkout_url);
        } catch (_error) {
          setStatus(root, 'Checkout is unavailable.');
        }
      });
    }
  }

  async function mount(root) {
    var status = await loadStatus();
    if (!isChatEnabled(status)) {
      root.hidden = true;
      return;
    }
    status = await completeUnlock(status);
    root.hidden = false;
    bind(root, status);
  }

  function start() {
    var roots = document.querySelectorAll('[data-recipe-chat]');
    for (var i = 0; i < roots.length; i++) {
      mount(roots[i]);
    }
  }

  var api = {
    isChatEnabled: isChatEnabled,
    canSend: canSend,
    quotaLabel: quotaLabel,
    applyQuota: applyQuota,
    mount: mount,
  };

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', start);
    } else {
      start();
    }
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})();
