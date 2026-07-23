"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const nunjucks = require("nunjucks");
const path = require("node:path");
const test = require("node:test");

const { createMermaidLazyLoader } = require("../assets/js/mermaid-viewer.js");

const ROOT = path.resolve(__dirname, "..");

class FakeDiagram {
  constructor(top) {
    this.top = top;
    this.attributes = new Map();
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getBoundingClientRect() {
    return { top: this.top, bottom: this.top + 200 };
  }
}

function createHarness(diagrams, { withIntersectionObserver = true } = {}) {
  const scripts = [];
  const listeners = new Map();
  const observers = [];
  const document = {
    documentElement: { clientHeight: 800 },
    head: {
      appendChild(script) {
        scripts.push(script);
      },
    },
    createElement(tagName) {
      assert.equal(tagName, "script");
      return {
        attributes: new Map(),
        setAttribute(name, value) {
          this.attributes.set(name, String(value));
        },
      };
    },
    querySelectorAll(selector) {
      assert.equal(selector, "pre.mermaid");
      return diagrams;
    },
  };
  const window = {
    Promise,
    console: { error() {} },
    document,
    innerHeight: 800,
    addEventListener(type, callback) {
      listeners.set(type, callback);
    },
    removeEventListener(type, callback) {
      if (listeners.get(type) === callback) listeners.delete(type);
    },
    requestAnimationFrame(callback) {
      callback();
    },
    setTimeout,
  };

  class FakeIntersectionObserver {
    constructor(callback, options) {
      this.callback = callback;
      this.options = options;
      this.observed = [];
      this.unobserved = [];
      observers.push(this);
    }

    observe(node) {
      this.observed.push(node);
    }

    unobserve(node) {
      this.unobserved.push(node);
    }

    disconnect() {}
  }

  return {
    document,
    listeners,
    observers,
    scripts,
    window,
    IntersectionObserver: withIntersectionObserver ? FakeIntersectionObserver : null,
  };
}

async function flushPromises() {
  await new Promise((resolve) => setImmediate(resolve));
}

test("the shared head loads the deferred viewer only for relevant content", () => {
  const head = fs.readFileSync(
    path.join(ROOT, "_includes", "partials", "head-common.njk"),
    "utf8",
  );
  const environment = new nunjucks.Environment(
    new nunjucks.FileSystemLoader(path.join(ROOT, "_includes")),
  );
  const renderHead = (content) => environment.render("partials/head-common.njk", {
    content,
    page: { url: "/example/" },
  });

  assert.match(head, /<script src="\/js\/mermaid-viewer\.js" defer><\/script>/);
  assert.doesNotMatch(head, /<script[^>]+src="\/js\/mermaid\.min\.js"/);
  assert.doesNotMatch(head, /mermaid\.run\(\{ querySelector:/);
  assert.doesNotMatch(renderHead("<p>Documentation without a diagram.</p>"), /mermaid-viewer/);
  assert.match(renderHead('<pre class="mermaid">graph TD</pre>'), /mermaid-viewer/);
  assert.match(renderHead('<figure class="sr-suite-figure"></figure>'), /mermaid-viewer/);
  assert.match(renderHead('<figure class="visual-guide-figure"></figure>'), /mermaid-viewer/);
});

test("Mermaid loads once and renders only diagrams that approach the viewport", async () => {
  const first = new FakeDiagram(100);
  const second = new FakeDiagram(3000);
  const harness = createHarness([first, second]);
  const initializeCalls = [];
  const runCalls = [];
  const loader = createMermaidLazyLoader({
    document: harness.document,
    IntersectionObserver: harness.IntersectionObserver,
    window: harness.window,
  });

  loader.observe();

  assert.equal(harness.scripts.length, 0, "the 2.57 MB bundle stays off the network initially");
  assert.equal(harness.observers.length, 1);
  assert.deepEqual(harness.observers[0].observed, [first, second]);
  assert.equal(harness.observers[0].options.rootMargin, "600px 0px");

  harness.observers[0].callback([
    { target: first, isIntersecting: true, intersectionRatio: 0.1 },
    { target: second, isIntersecting: false, intersectionRatio: 0 },
  ]);
  await flushPromises();

  assert.equal(harness.scripts.length, 1);
  assert.equal(harness.scripts[0].src, "/js/mermaid.min.js");
  assert.equal(harness.scripts[0].attributes.get("data-mermaid-library"), "true");
  assert.equal(first.getAttribute("data-mermaid-state"), "loading");
  assert.equal(second.getAttribute("data-mermaid-state"), null);

  harness.window.mermaid = {
    initialize(options) {
      initializeCalls.push(options);
    },
    async run(options) {
      runCalls.push(options);
    },
  };
  harness.scripts[0].onload();
  await loader.whenIdle();

  assert.deepEqual(initializeCalls, [{ startOnLoad: false, theme: "dark" }]);
  assert.deepEqual(runCalls.map((call) => call.nodes), [[first]]);
  assert.equal(first.getAttribute("data-mermaid-state"), "rendered");
  assert.equal(second.getAttribute("data-mermaid-state"), null);

  harness.observers[0].callback([
    { target: second, isIntersecting: true, intersectionRatio: 0.25 },
  ]);
  await loader.whenIdle();

  assert.equal(harness.scripts.length, 1, "subsequent diagrams reuse the loaded bundle");
  assert.equal(initializeCalls.length, 1, "Mermaid is initialized once");
  assert.deepEqual(runCalls.map((call) => call.nodes), [[first], [second]]);
  assert.equal(second.getAttribute("data-mermaid-state"), "rendered");
});

test("the geometry fallback also leaves far-below-fold diagrams unloaded", async () => {
  const near = new FakeDiagram(1200);
  const far = new FakeDiagram(2400);
  const harness = createHarness([near, far], { withIntersectionObserver: false });
  const loader = createMermaidLazyLoader({
    document: harness.document,
    IntersectionObserver: harness.IntersectionObserver,
    window: harness.window,
  });

  loader.observe();
  await flushPromises();

  assert.equal(harness.scripts.length, 1, "a diagram inside the preload margin starts loading");
  assert.equal(near.getAttribute("data-mermaid-state"), "loading");
  assert.equal(far.getAttribute("data-mermaid-state"), null);

  harness.window.mermaid = { initialize() {}, async run() {} };
  harness.scripts[0].onload();
  await loader.whenIdle();

  far.top = 1300;
  harness.listeners.get("scroll")();
  await loader.whenIdle();

  assert.equal(harness.scripts.length, 1);
  assert.equal(far.getAttribute("data-mermaid-state"), "rendered");
});
