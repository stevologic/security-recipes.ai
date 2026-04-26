/*
 * Global docs search for non-home Hugo/Hextra pages.
 * Reuses the same recipes-index.json data source and ranking model as
 * the landing page search so users can search from anywhere.
 */
(function () {
  'use strict';

  if (document.getElementById('home-search-input')) return;

  var docs = [];
  var loading = null;
  var activeIndex = -1;

  function escapeHtml(s) {
    return (s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function indexUrl() {
    return new URL('recipes-index.json', window.location.origin + (window.__SITE_BASE_PREFIX || '/')).toString();
  }

  function ensureIndexLoaded() {
    if (loading) return loading;
    loading = fetch(indexUrl(), { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error('index-unavailable')); })
      .then(function (data) {
        docs = Array.isArray(data) ? data : [];
        return docs;
      })
      .catch(function () {
        docs = [];
        return docs;
      });
    return loading;
  }

  function scoreDoc(doc, q) {
    var title = (doc.title || '').toLowerCase();
    var section = (doc.section || '').toLowerCase();
    var summary = (doc.summary || '').toLowerCase();
    var content = (doc.content || '').toLowerCase();

    var score = 0;
    if (title === q) score += 120;
    if (title.indexOf(q) === 0) score += 90;
    if (title.indexOf(q) !== -1) score += 60;
    if (section.indexOf(q) !== -1) score += 25;
    if (summary.indexOf(q) !== -1) score += 15;
    if (content.indexOf(q) !== -1) score += 10;
    return score;
  }

  function renderResults(items, query, resultsEl) {
    if (!query) {
      resultsEl.innerHTML = '';
      resultsEl.removeAttribute('data-open');
      activeIndex = -1;
      return;
    }
    if (!items.length) {
      resultsEl.innerHTML = '<div class="docs-search-empty">No matches found.</div>';
      resultsEl.setAttribute('data-open', '1');
      activeIndex = -1;
      return;
    }

    resultsEl.innerHTML = items.map(function (d, i) {
      return '<a class="docs-search-item" data-index="' + i + '" href="' + escapeHtml(d.path || d.url || '#') + '">' +
        '<div class="docs-search-item-title">' + escapeHtml(d.title || 'Untitled') + '</div>' +
        '<div class="docs-search-item-meta">' + escapeHtml(d.section || 'page') + '</div>' +
      '</a>';
    }).join('');

    resultsEl.setAttribute('data-open', '1');
    activeIndex = -1;
  }

  function setActive(index, resultsEl) {
    var nodes = resultsEl.querySelectorAll('.docs-search-item');
    Array.prototype.forEach.call(nodes, function (n) { n.removeAttribute('data-active'); });
    if (index < 0 || index >= nodes.length) return;
    nodes[index].setAttribute('data-active', '1');
    nodes[index].scrollIntoView({ block: 'nearest' });
    activeIndex = index;
  }

  function mount() {
    var shell = document.createElement('div');
    shell.className = 'docs-search-shell';
    shell.innerHTML =
      '<button class="docs-search-launch" type="button" aria-label="Open search">' +
        '<span class="docs-search-launch-icon">⌕</span>' +
        '<span class="docs-search-launch-text">Search docs</span>' +
        '<span class="docs-search-launch-kbd">/</span>' +
      '</button>' +
      '<div class="docs-search-modal" hidden>' +
        '<div class="docs-search-backdrop" data-close="1"></div>' +
        '<div class="docs-search-panel" role="dialog" aria-modal="true" aria-label="Search docs">' +
          '<label class="docs-search-label" for="docs-search-input">Search recipes</label>' +
          '<div class="docs-search-input-wrap">' +
            '<input id="docs-search-input" class="docs-search-input" type="search" placeholder="Find docs, agents, prompts, and remediation workflows…" autocomplete="off" />' +
            '<button type="button" class="docs-search-close" data-close="1" aria-label="Close search">✕</button>' +
          '</div>' +
          '<div id="docs-search-results" class="docs-search-results" role="listbox" aria-label="Search results"></div>' +
        '</div>' +
      '</div>';

    document.body.appendChild(shell);

    var launch = shell.querySelector('.docs-search-launch');
    var modal = shell.querySelector('.docs-search-modal');
    var input = shell.querySelector('#docs-search-input');
    var resultsEl = shell.querySelector('#docs-search-results');

    function openModal() {
      modal.hidden = false;
      setTimeout(function () { input.focus(); }, 0);
      if (input.value.trim()) runSearch();
    }

    function closeModal() {
      modal.hidden = true;
      resultsEl.removeAttribute('data-open');
    }

    async function runSearch() {
      var q = input.value.trim().toLowerCase();
      var index = await ensureIndexLoaded();
      if (!q) {
        renderResults([], '', resultsEl);
        return;
      }
      var matched = index
        .map(function (d) {
          var out = {};
          for (var k in d) out[k] = d[k];
          out._score = scoreDoc(d, q);
          return out;
        })
        .filter(function (d) { return d._score > 0; })
        .sort(function (a, b) { return b._score - a._score; })
        .slice(0, 8);
      renderResults(matched, q, resultsEl);
    }

    launch.addEventListener('click', openModal);
    shell.addEventListener('click', function (e) {
      if (e.target && e.target.getAttribute('data-close') === '1') closeModal();
    });

    input.addEventListener('input', runSearch);

    document.addEventListener('keydown', function (e) {
      if (e.key === '/' && document.activeElement !== input) {
        e.preventDefault();
        openModal();
        return;
      }
      if (e.key === 'Escape' && !modal.hidden) {
        closeModal();
        return;
      }
      if (modal.hidden || !resultsEl.hasAttribute('data-open')) return;
      var items = resultsEl.querySelectorAll('.docs-search-item');
      if (!items.length) return;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActive(Math.min(activeIndex + 1, items.length - 1), resultsEl);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActive(Math.max(activeIndex - 1, 0), resultsEl);
      } else if (e.key === 'Enter' && activeIndex >= 0 && items[activeIndex]) {
        items[activeIndex].click();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
  } else {
    mount();
  }
})();
