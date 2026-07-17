'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const source = fs.readFileSync(
  path.join(ROOT, 'tools', 'security_recipes_remediation', 'ui', 'app.js'),
  'utf8'
);

test('saving non-secret dashboard configuration preserves the unsaved finding textarea', () => {
  const saveHandler = source.match(
    /byId\("saveConfig"\)\.addEventListener\("click", async \(\) => \{([\s\S]*?)\n\}\);/
  );
  assert.ok(saveHandler, 'save configuration handler is missing');

  const body = saveHandler[1];
  const request = body.indexOf('jsonRequest("/api/config"');
  const apply = body.indexOf('applyConfig(result.config, { preserveFindingInput: true });');

  assert.ok(request < apply, 'saved non-secret configuration should still be applied');
  assert.ok(
    !body.includes('const findingInput = byId("findingInput").value;'),
    'save must not snapshot an input value that can become stale while awaiting the request'
  );
  assert.match(
    source,
    /if \(!options\.preserveFindingInput\) \{\s*byId\("findingInput"\)\.value = config\.finding_input \|\| "";\s*\}/,
    'applyConfig must leave the current finding textarea untouched when requested'
  );
});
