(function () {
  'use strict';

  function init(root) {
    var drawer = root.querySelector('.recipe-library__facets');
    var toggle = root.querySelector('[data-recipe-filter-toggle]');
    if (!drawer || !toggle) return;

    function isMobile() {
      return window.matchMedia && window.matchMedia('(max-width: 900px)').matches;
    }

    function isOpen() {
      return isMobile() && drawer.classList.contains('is-open');
    }

    function closeDrawer() {
      if (!isOpen()) return;
      var close = drawer.querySelector('[data-recipe-filter-close]');
      if (close) close.click();
    }

    document.addEventListener('pointerdown', function (event) {
      if (!isOpen()) return;
      if (drawer.contains(event.target) || toggle.contains(event.target)) return;
      closeDrawer();
    }, true);

    document.addEventListener('keydown', function (event) {
      if (!isOpen() || event.key !== 'Tab') return;
      var focusable = Array.prototype.slice.call(drawer.querySelectorAll(
        'button:not([disabled]), select:not([disabled]), input:not([disabled]), a[href], summary, [tabindex]:not([tabindex="-1"])'
      )).filter(function (node) {
        return !node.hidden && node.offsetParent !== null;
      });
      if (!focusable.length) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
  }

  function boot() {
    document.querySelectorAll('[data-recipe-browser]').forEach(init);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
