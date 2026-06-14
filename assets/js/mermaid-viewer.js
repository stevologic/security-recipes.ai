/*
 * Shared fullscreen viewer
 * ------------------------
 * Reuses one lightbox for rendered Mermaid diagrams and dense figure
 * images that benefit from a closer look on smaller screens.
 */
(function () {
  "use strict";

  if (typeof document === "undefined") return;

  var MERMAID_SELECTOR = ".mermaid, pre.mermaid";
  var IMAGE_SELECTOR = ".sr-suite-figure img, .visual-guide-figure img";
  var HINT_ICON =
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>' +
    "<span>Click to expand</span>";

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  function setInteractiveHint(container) {
    if (!container || container.querySelector(".mermaid__zoom-hint")) return;
    var hint = document.createElement("span");
    hint.className = "mermaid__zoom-hint";
    hint.setAttribute("aria-hidden", "true");
    hint.innerHTML = HINT_ICON;
    container.appendChild(hint);
  }

  ready(function init() {
    var modal = document.createElement("div");
    modal.className = "mermaid-modal";
    modal.setAttribute("aria-hidden", "true");
    modal.innerHTML =
      '<div class="mermaid-modal__backdrop" data-mermaid-close="1"></div>' +
      '<div class="mermaid-modal__dialog" role="dialog" aria-modal="true" aria-label="Diagram viewer">' +
      '  <button type="button" class="mermaid-modal__close" aria-label="Close fullscreen viewer" data-mermaid-close="1">&times;</button>' +
      '  <div class="mermaid-modal__content"></div>' +
      "</div>";
    document.body.appendChild(modal);

    var dialog = modal.querySelector(".mermaid-modal__dialog");
    var content = modal.querySelector(".mermaid-modal__content");

    function openModal(viewEl, label) {
      var clone = viewEl.cloneNode(true);
      var tagName = clone.tagName ? clone.tagName.toLowerCase() : "";

      if (tagName === "svg") {
        clone.removeAttribute("width");
        clone.removeAttribute("height");
      }

      clone.style.width = "100%";
      clone.style.height = "auto";
      clone.style.maxWidth = "100%";
      clone.style.maxHeight = "100%";

      content.innerHTML = "";
      content.appendChild(clone);
      dialog.setAttribute("aria-label", label || "Diagram viewer");
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

    document.addEventListener("click", function (e) {
      if (e.target.closest(".mermaid-modal")) return;

      var mermaidHost = e.target.closest(MERMAID_SELECTOR);
      if (mermaidHost) {
        var svg = mermaidHost.querySelector("svg");
        if (!svg) return;
        e.preventDefault();
        openModal(svg, "Diagram viewer");
        return;
      }

      var image = e.target.closest(IMAGE_SELECTOR);
      if (!image) return;
      e.preventDefault();
      openModal(image, image.getAttribute("alt") || "Expanded figure image");
    });

    function markInteractive() {
      var nodes = document.querySelectorAll(MERMAID_SELECTOR);
      for (var i = 0; i < nodes.length; i++) {
        var el = nodes[i];
        if (!el.querySelector("svg")) continue;
        if (el.classList.contains("mermaid--interactive")) continue;
        el.classList.add("mermaid--interactive");
        el.setAttribute("role", "button");
        el.setAttribute("tabindex", "0");
        el.setAttribute("aria-label", "Open diagram in fullscreen viewer");
        setInteractiveHint(el);
      }

      var images = document.querySelectorAll(IMAGE_SELECTOR);
      for (var j = 0; j < images.length; j++) {
        var image = images[j];
        var figure = image.closest("figure");
        if (!figure || figure.classList.contains("figure--interactive")) continue;
        figure.classList.add("figure--interactive");
        image.setAttribute("role", "button");
        image.setAttribute("tabindex", "0");
        image.setAttribute("aria-label", image.getAttribute("alt") || "Open image in fullscreen viewer");
        setInteractiveHint(figure);
      }
    }

    document.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" && e.key !== " ") return;

      var mermaidHost = e.target.closest && e.target.closest(".mermaid--interactive");
      if (mermaidHost) {
        var svg = mermaidHost.querySelector("svg");
        if (!svg) return;
        e.preventDefault();
        openModal(svg, "Diagram viewer");
        return;
      }

      var image = e.target.closest && e.target.closest(IMAGE_SELECTOR);
      if (!image) return;
      e.preventDefault();
      openModal(image, image.getAttribute("alt") || "Expanded figure image");
    });

    if (typeof MutationObserver !== "undefined") {
      var observer = new MutationObserver(function () {
        markInteractive();
      });
      observer.observe(document.body, { childList: true, subtree: true });
    }

    markInteractive();
    setTimeout(markInteractive, 250);
    setTimeout(markInteractive, 1000);
  });
})();
