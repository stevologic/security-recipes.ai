/*
 * Lazy Mermaid renderer and shared fullscreen viewer
 * --------------------------------------------------
 * Loads the vendored Mermaid bundle as a diagram approaches the viewport,
 * then reuses one lightbox for diagrams and dense figure images.
 */
(function () {
  "use strict";

  var MERMAID_SELECTOR = ".mermaid, pre.mermaid";
  var MERMAID_SOURCE_SELECTOR = "pre.mermaid";
  var MERMAID_LIBRARY_SRC = "/js/mermaid.min.js";
  var IMAGE_SELECTOR = ".sr-suite-figure img, .visual-guide-figure img";
  var HINT_ICON =
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>' +
    "<span>Click to expand</span>";

  function createMermaidLazyLoader(options) {
    var win = options.window;
    var doc = options.document;
    var Observer = Object.prototype.hasOwnProperty.call(options, "IntersectionObserver")
      ? options.IntersectionObserver
      : win.IntersectionObserver;
    var PromiseConstructor = win.Promise || Promise;
    var librarySrc = options.librarySrc || MERMAID_LIBRARY_SRC;
    var preloadPixels = options.preloadPixels || 600;
    var rootMargin = preloadPixels + "px 0px";
    var onRendered = options.onRendered;
    var mermaidPromise = null;
    var mermaidInitialized = false;
    var renderQueue = PromiseConstructor.resolve();
    var intersectionObserver = null;
    var fallbackNodes = [];
    var fallbackScheduled = false;
    var fallbackListening = false;

    function state(node) {
      return node.getAttribute("data-mermaid-state");
    }

    function isPending(node) {
      var currentState = state(node);
      return node.getAttribute("data-processed") !== "true" &&
        currentState !== "loading" &&
        currentState !== "rendered";
    }

    function initializeMermaid(api) {
      if (!api || typeof api.initialize !== "function" || typeof api.run !== "function") {
        throw new Error("Mermaid loaded without the expected browser API");
      }
      if (!mermaidInitialized) {
        api.initialize({ startOnLoad: false, theme: "dark" });
        mermaidInitialized = true;
      }
      return api;
    }

    function loadMermaid() {
      if (win.mermaid) {
        return PromiseConstructor.resolve(initializeMermaid(win.mermaid));
      }
      if (mermaidPromise) return mermaidPromise;

      mermaidPromise = new PromiseConstructor(function (resolve, reject) {
        var script = doc.createElement("script");
        script.src = librarySrc;
        script.async = true;
        script.setAttribute("data-mermaid-library", "true");
        script.onload = function () {
          try {
            resolve(initializeMermaid(win.mermaid));
          } catch (error) {
            mermaidPromise = null;
            reject(error);
          }
        };
        script.onerror = function () {
          mermaidPromise = null;
          reject(new Error("Unable to load " + librarySrc));
        };
        (doc.head || doc.documentElement).appendChild(script);
      });

      return mermaidPromise;
    }

    function reportFailure(error) {
      if (win.console && typeof win.console.error === "function") {
        win.console.error("Unable to render Mermaid diagram", error);
      }
    }

    function render(nodes) {
      var pending = [];
      for (var i = 0; i < nodes.length; i++) {
        if (!isPending(nodes[i])) continue;
        nodes[i].setAttribute("data-mermaid-state", "loading");
        pending.push(nodes[i]);
      }
      if (!pending.length) return renderQueue;

      renderQueue = renderQueue
        .then(loadMermaid)
        .then(function (api) {
          return api.run({ nodes: pending });
        })
        .then(function () {
          for (var j = 0; j < pending.length; j++) {
            pending[j].setAttribute("data-mermaid-state", "rendered");
          }
          if (typeof onRendered === "function") onRendered(pending);
        })
        .catch(function (error) {
          for (var j = 0; j < pending.length; j++) {
            pending[j].setAttribute("data-mermaid-state", "error");
          }
          reportFailure(error);
        });

      return renderQueue;
    }

    function handleIntersections(entries) {
      var nearby = [];
      for (var i = 0; i < entries.length; i++) {
        if (!entries[i].isIntersecting && entries[i].intersectionRatio <= 0) continue;
        if (intersectionObserver && typeof intersectionObserver.unobserve === "function") {
          intersectionObserver.unobserve(entries[i].target);
        }
        nearby.push(entries[i].target);
      }
      if (nearby.length) render(nearby);
    }

    function stopFallback() {
      if (!fallbackListening || typeof win.removeEventListener !== "function") return;
      win.removeEventListener("scroll", scheduleFallbackCheck);
      win.removeEventListener("resize", scheduleFallbackCheck);
      fallbackListening = false;
    }

    function checkFallbackViewport() {
      var viewportHeight = win.innerHeight || doc.documentElement.clientHeight || 0;
      var nearby = [];
      var remaining = [];

      for (var i = 0; i < fallbackNodes.length; i++) {
        var node = fallbackNodes[i];
        if (!isPending(node)) continue;
        if (typeof node.getBoundingClientRect !== "function") {
          nearby.push(node);
          continue;
        }
        var bounds = node.getBoundingClientRect();
        if (bounds.top <= viewportHeight + preloadPixels && bounds.bottom >= -preloadPixels) {
          nearby.push(node);
        } else {
          remaining.push(node);
        }
      }

      fallbackNodes = remaining;
      if (nearby.length) render(nearby);
      if (!fallbackNodes.length) stopFallback();
    }

    function scheduleFallbackCheck() {
      if (fallbackScheduled) return;
      fallbackScheduled = true;
      var schedule = win.requestAnimationFrame || function (callback) {
        return win.setTimeout(callback, 16);
      };
      schedule(function () {
        fallbackScheduled = false;
        checkFallbackViewport();
      });
    }

    function observe() {
      var nodeList = doc.querySelectorAll(MERMAID_SOURCE_SELECTOR);
      var nodes = Array.prototype.slice.call(nodeList);
      if (!nodes.length) return;

      if (typeof Observer === "function") {
        intersectionObserver = new Observer(handleIntersections, {
          root: null,
          rootMargin: rootMargin,
          threshold: 0.01,
        });
        for (var i = 0; i < nodes.length; i++) {
          if (isPending(nodes[i])) intersectionObserver.observe(nodes[i]);
        }
        return;
      }

      fallbackNodes = nodes;
      if (typeof win.addEventListener === "function") {
        win.addEventListener("scroll", scheduleFallbackCheck, { passive: true });
        win.addEventListener("resize", scheduleFallbackCheck);
        fallbackListening = true;
      }
      checkFallbackViewport();
    }

    function destroy() {
      if (intersectionObserver && typeof intersectionObserver.disconnect === "function") {
        intersectionObserver.disconnect();
      }
      stopFallback();
    }

    return {
      destroy: destroy,
      observe: observe,
      render: render,
      whenIdle: function () { return renderQueue; },
    };
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { createMermaidLazyLoader: createMermaidLazyLoader };
  }

  if (typeof document === "undefined") return;

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

    var lazyMermaid = createMermaidLazyLoader({
      document: document,
      onRendered: markInteractive,
      window: window,
    });
    lazyMermaid.observe();

    markInteractive();
    setTimeout(markInteractive, 250);
    setTimeout(markInteractive, 1000);
  });
})();
