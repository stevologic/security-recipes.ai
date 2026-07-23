"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { extractTocEntries } = require("../eleventy.config").toc;

test("TOC entries decode rendered heading entities exactly once", () => {
  const entries = extractTocEntries([
    '<h2 id="metrics">Program Metrics &amp; KPIs</h2>',
    '<h3 id="bounds"><code>&gt;=8.0</code> &amp; &lt;9.0</h3>',
    '<h2 id="once">Already encoded &amp;amp; once</h2>',
  ].join("\n"));

  assert.deepEqual(entries, [
    { level: 2, id: "metrics", text: "Program Metrics & KPIs" },
    { level: 3, id: "bounds", text: ">=8.0 & <9.0" },
    { level: 2, id: "once", text: "Already encoded &amp; once" },
  ]);
});

test("TOC entries remain plain text after encoded markup is decoded", () => {
  assert.deepEqual(
    extractTocEntries('<h2 id="encoded">Review &lt;script&gt;alert(1)&lt;/script&gt;</h2>'),
    [{ level: 2, id: "encoded", text: "Review <script>alert(1)</script>" }],
  );
});
