"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const MarkdownIt = require("markdown-it");

const { createPreprocessor } = require("../lib/hugo-preprocess");

test("documented shortcodes survive inline code and fenced examples", () => {
  const preprocess = createPreprocessor(new MarkdownIt());
  const source = [
    "Use `{{</* callout */>}}`, `{{</* relref */>}}`, and `{{</* cards */>}}`.",
    "",
    "```markdown",
    '{{< callout type="info" >}}',
    "This is documentation, not an active shortcode.",
    "{{< /callout >}}",
    "```",
  ].join("\n");

  const preprocessed = preprocess(source, "contribute/_index.md");
  const rendered = new MarkdownIt().render(preprocessed);

  for (const expected of [
    "{{</* callout */>}}",
    "{{</* relref */>}}",
    "{{</* cards */>}}",
    '{{< callout type="info" >}}',
  ]) {
    assert.match(preprocessed, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.doesNotMatch(preprocessed, /SRFENCE|\uFFFD/u);
  assert.doesNotMatch(rendered, /SRFENCE|\uFFFD/u);
});
