/*
 * Navbar enhancement — security-recipes.ai.
 *
 * Hextra renders a top-level menu entry with children (`params.type: menu`)
 * as a <button> that toggles a dropdown but doesn't itself navigate. We
 * want three things that the default doesn't give us:
 *
 *   1. The label should be a real semantic link, so clicking, middle-click,
 *      cmd/ctrl-click, right-click "Open in new tab", and screen readers
 *      all work the way they would on any other nav link.
 *   2. The URL has to be whatever Hugo decided at build time — which on
 *      Docker-localhost is `/fundamentals/` (no port), and on GitHub Pages
 *      project hosting may be `/<repo>/fundamentals/`. Hard-coding baseURL
 *      in JS breaks when the browser port differs from the build port
 *      (e.g. `docker run -p 3000:80`), so we read URLs from a map emitted
 *      by `head-end.html` from Hugo's menu config.
 *   3. On pointer-fine devices, hovering the trigger should open the
 *      dropdown panel. We don't reuse Hextra's click-toggle for this —
 *      we locate the panel once and toggle it directly, which is
 *      resilient to Hextra version changes and doesn't fight a click
 *      handler that's been replaced.
 *
 * Touch / coarse-pointer devices fall through to default tap-to-navigate
 * behaviour; on Hextra, mobile navigation happens via the sidebar sheet
 * anyway, so nothing is lost.
 */
(function () {
  'use strict';

  // Populated by head-end.html from site.Menus.main. Shape:
  //   { "Agents": "/agents/", "Fundamentals": "/fundamentals/", ... }
  // When Hugo is built with --baseURL=http://localhost/, values are root-
  // relative like "/agents/". With a subpath baseURL, they come out as
  // "/<prefix>/agents/". Either way, they're port-agnostic.
  var ROUTES = window.__NAV_ROUTES || {};

  // Normalise a node's visible text: collapse whitespace, drop any non-
  // ASCII glyphs (Hextra's caret/chevron is an inline <svg>, but some
  // builds ship a unicode arrow) so text match works either way.
  function cleanText(el) {
    return (el.textContent || '')
      .replace(/[^\x20-\x7e\s]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  // Find the dropdown panel for a given trigger. Hextra's layout wraps the
  // trigger and panel in a common parent; the panel is a sibling (or close
  // descendant) containing the child anchor links. We accept <ul> or <div>
  // with at least one <a> inside, excluding the trigger itself.
  function findPanel(wrapper, trigger) {
    var candidates = wrapper.querySelectorAll('ul, div');
    for (var i = 0; i < candidates.length; i++) {
      var c = candidates[i];
      if (c === trigger || c.contains(trigger)) continue;
      if (c.querySelector('a')) return c;
    }
    return null;
  }

  // Build the replacement anchor, copying inner HTML (label + caret SVG)
  // and every useful attribute from the button so styling is preserved.
  function buildAnchor(trigger, href) {
    var a = document.createElement('a');
    a.href = href;
    a.innerHTML = trigger.innerHTML;
    if (trigger.className) a.className = trigger.className;
    // Copy attributes we care about (data-*, id, title). Deliberately
    // skip type, aria-expanded, aria-haspopup — those describe a button
    // toggle, not a link.
    Array.prototype.forEach.call(trigger.attributes, function (attr) {
      var n = attr.name;
      if (n === 'class' || n === 'type' || n === 'role' ||
          n === 'aria-expanded' || n === 'aria-haspopup' ||
          n === 'aria-controls') return;
      try { a.setAttribute(n, attr.value); } catch (e) { /* noop */ }
    });
    a.setAttribute('data-nav-dropdown', '1');
    return a;
  }

  function setup() {
    // Hextra's navbar container — scoped tight so we don't touch buttons
    // in the page body, mobile sheet, search widget, or footer.
    var nav = document.querySelector('.nextra-nav-container nav, header nav');
    if (!nav) return;

    var hoverCapable = !!(window.matchMedia &&
      window.matchMedia('(hover: hover) and (pointer: fine)').matches);

    Object.keys(ROUTES).forEach(function (name) {
      var href = ROUTES[name];
      if (!href) return;

      // Locate the trigger by visible text. Accept button / summary /
      // role=button (covers <details><summary> implementations too).
      var trigger = null;
      var candidates = nav.querySelectorAll('button, summary, [role="button"]');
      for (var i = 0; i < candidates.length; i++) {
        var t = cleanText(candidates[i]);
        // Exact or prefix match — prefix tolerates trailing caret glyphs
        // not stripped by cleanText.
        if (t === name || t === name.toLowerCase() ||
            t.indexOf(name) === 0) {
          trigger = candidates[i];
          break;
        }
      }
      if (!trigger) return;

      var wrapper = trigger.parentElement;
      if (!wrapper) return;

      // Find the panel BEFORE we replace the trigger, so the wrapper's
      // child collection is still the one Hextra built.
      var panel = findPanel(wrapper, trigger);

      // Replace the trigger element with a real anchor. This is what
      // makes it a proper link — clicks, middle-click, ctrl/cmd-click,
      // right-click context menu, prefetch hints, and a11y all behave
      // exactly as if Hugo had rendered it this way.
      var anchor = buildAnchor(trigger, href);
      trigger.parentNode.replaceChild(anchor, trigger);

      // Hover-to-open is desktop only. On touch, the link just navigates.
      if (!panel || !hoverCapable) return;

      // Remember the panel's initial "closed" state so we can restore it
      // cleanly on mouseleave even if Hextra's own toggle JS has also run.
      var hadHiddenAttr  = panel.hasAttribute('hidden');
      var hiddenClasses  = ['hidden', 'hx-hidden'].filter(function (c) {
        return panel.classList.contains(c);
      });

      var hideTimer = null;
      function clearHideTimer() {
        if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
      }

      function show() {
        clearHideTimer();
        panel.style.display = 'block';
        panel.removeAttribute('hidden');
        hiddenClasses.forEach(function (c) { panel.classList.remove(c); });
        anchor.setAttribute('data-nav-open', '1');
      }

      function scheduleHide() {
        clearHideTimer();
        // 180ms grace so diagonal cursor moves into the panel don't flash
        // the menu closed.
        hideTimer = setTimeout(function () {
          panel.style.display = 'none';
          if (hadHiddenAttr) panel.setAttribute('hidden', '');
          hiddenClasses.forEach(function (c) { panel.classList.add(c); });
          anchor.removeAttribute('data-nav-open');
        }, 180);
      }

      wrapper.addEventListener('mouseenter', show);
      wrapper.addEventListener('mouseleave', scheduleHide);
      // Hovering over the panel itself counts as "still inside" so the
      // dropdown stays open while the cursor reads its contents.
      panel.addEventListener('mouseenter', show);
      panel.addEventListener('mouseleave', scheduleHide);
      // Keyboard: focus-within the wrapper opens, blur closes.
      wrapper.addEventListener('focusin', show);
      wrapper.addEventListener('focusout', function (e) {
        // focusout fires before the new focus target is known; defer.
        setTimeout(function () {
          if (!wrapper.contains(document.activeElement)) scheduleHide();
        }, 0);
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setup);
  } else {
    setup();
  }
})();
