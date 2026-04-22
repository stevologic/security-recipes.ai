/*
 * Mermaid fullscreen viewer
 * -------------------------
 * Makes every rendered Mermaid diagram on the site clickable: tapping
 * a diagram opens it in a full-viewport lightbox where the SVG is
 * scaled to fit so dense flowcharts / sequence diagrams are actually
 * readable. Close via the × button, clicking the backdrop, or ESC.
 *
 * Uses event delegation + a MutationObserver so it picks up diagrams
 * that Mermaid renders asynchronously after initial page load (and
 * anything inside tabs / collapsed sections that get expanded later).
 */
(function () {
  "use strict";

  if (typeof document === "undefined") return;

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function init() {
    // --- build modal once ---
    var modal = document.createElement("div");
    modal.className = "mermaid-modal";
    modal.setAttribute("aria-hidden", "true");
    modal.innerHTML =
      '<div class="mermaid-modal__backdrop" data-mermaid-close="1"></div>' +
      '<div class="mermaid-modal__dialog" role="dialog" aria-modal="true" aria-label="Diagram viewer">' +
      '  <button type="button" class="mermaid-modal__close" aria-label="Close diagram viewer" data-mermaid-close="1">&times;</button>' +
      '  <div class="mermaid-modal__content"></div>' +
      "</div>";
    document.body.appendChild(modal);

    var content = modal.querySelector(".mermaid-modal__content");

    function openModal(svgEl) {
      // Clone so we don't detach the original from the page.
      var clone = svgEl.cloneNode(true);
      clone.removeAttribute("width");
      clone.removeAttribute("height");
      clone.style.width = "100%";
      clone.style.height = "auto";
      clone.style.maxWidth = "100%";
      clone.style.maxHeight = "100%";
      content.innerHTML = "";
      content.appendChild(clone);
      modal.classList.add("is-open");
      modal.setAttribute("aria-hidden", "false");
      document.documentElement.classList.add("mermaid-modal-open");
    }

    function closeModal() {
      modal.classList.remove("is-open");
      modal.setAttribute("aria-hidden", "true");
      content.innerHTML = "";
      document.documentElement.classList.remove("mermaid-modal-open");
    }

    modal.addEventListener("click", function (e) {
      if (e.target && e.target.getAttribute("data-mermaid-close") === "1") {
        closeModal();
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && modal.classList.contains("is-open")) {
        closeModal();
      }
    });

    // --- delegate clicks on any rendered mermaid diagram ---
    document.addEventListener("click", function (e) {
      // Ignore clicks that happen inside the modal itself.
      if (e.target.closest(".mermaid-modal")) return;
      var host = e.target.closest(".mermaid, pre.mermaid");
      if (!host) return;
      var svg = host.querySelector("svg");
      if (!svg) return; // not rendered yet — bail out silently
      e.preventDefault();
      openModal(svg);
    });

    // --- mark rendered diagrams as interactive (cursor + hover hint) ---
    function markInteractive() {
      var nodes = document.querySelectorAll(".mermaid, pre.mermaid");
      for (var i = 0; i < nodes.length; i++) {
        var el = nodes[i];
        if (!el.querySelector("svg")) continue;
        if (el.classList.contains("mermaid--interactive")) continue;
        el.classList.add("mermaid--interactive");
        el.setAttribute("role", "button");
        el.setAttribute("tabindex", "0");
        el.setAttribute("aria-label", "Open diagram in fullscreen viewer");
        var hint = document.createElement("span");
        hint.className = "mermaid__zoom-hint";
        hint.setAttribute("aria-hidden", "true");
        hint.innerHTML =
          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
          'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
          '<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>' +
          '<span>Click to expand</span>';
        el.appendChild(hint);
      }
    }

    // Keyboard activation: Enter / Space opens the viewer.
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" && e.key !== " ") return;
      var host = e.target.closest && e.target.closest(".mermaid--interactive");
      if (!host) return;
      var svg = host.querySelector("svg");
      if (!svg) return;
      e.preventDefault();
      openModal(svg);
    });

    // Mermaid renders async, and Hextra can lazy-mount tabs; a
    // MutationObserver keeps us in sync with whatever is on screen.
    if (typeof MutationObserver !== "undefined") {
      var observer = new MutationObserver(function () {
        markInteractive();
      });
      observer.observe(document.body, { childList: true, subtree: true });
    }

    // First pass, plus a couple of retries for slow mermaid renders.
    markInteractive();
    setTimeout(markInteractive, 250);
    setTimeout(markInteractive, 1000);
  });
})();
