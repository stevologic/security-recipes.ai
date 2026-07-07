/*
 * Progressive enhancement for {{< tabs >}} content blocks. The build emits
 * each tab as a <section class="sr-tab" data-sr-tab-title="..."> inside a
 * .sr-tabs wrapper; this script builds the tablist and switches panels.
 * Without JS every panel stays visible in order, which remains readable.
 */
(function () {
  'use strict';

  function enhance(root) {
    var panels = Array.prototype.slice.call(root.querySelectorAll(':scope > .sr-tab'));
    if (!panels.length) return;

    var list = document.createElement('div');
    list.className = 'sr-tabs__list';
    list.setAttribute('role', 'tablist');

    panels.forEach(function (panel, i) {
      var button = document.createElement('button');
      button.type = 'button';
      button.className = 'sr-tabs__button';
      button.setAttribute('role', 'tab');
      button.setAttribute('aria-selected', i === 0 ? 'true' : 'false');
      button.textContent = panel.getAttribute('data-sr-tab-title') || 'Tab ' + (i + 1);
      button.addEventListener('click', function () {
        panels.forEach(function (p, j) {
          p.hidden = p !== panel;
          list.children[j].setAttribute('aria-selected', p === panel ? 'true' : 'false');
        });
      });
      list.appendChild(button);
      panel.setAttribute('role', 'tabpanel');
      panel.hidden = i !== 0;
    });

    root.insertBefore(list, root.firstChild);
  }

  function init() {
    document.querySelectorAll('[data-sr-tabs]').forEach(enhance);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
