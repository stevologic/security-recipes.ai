---
title: "Prototype pollution — `merge`, `assign`, and friends"
linkTitle: "Prototype pollution merges"
description: "Filter `__proto__` / `constructor` / `prototype` keys at parse boundaries; replace hand-rolled merges with vetted utilities."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["javascript", "prototype-pollution", "uplift", "mitigate"]
weight: 28
date: 2026-04-25
---

JavaScript objects inherit from `Object.prototype`. A function
that recursively merges a user-controlled JSON payload into an
internal object can — if it doesn't filter `__proto__`,
`constructor`, or `prototype` keys — *modify* the prototype,
which then leaks into every other object in the runtime. The
attack vector is decades old; the unsafe shape is still the
default in many homemade `merge` and `extend` utilities.

## Pattern

The vulnerable shape:

```javascript
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = target[key] || {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

merge({}, JSON.parse(userInput));
```

A `userInput` of `{"__proto__": {"isAdmin": true}}` makes
*every* object in the runtime suddenly have `isAdmin: true`.

Equivalent shapes appear in:

- Hand-rolled `merge` / `extend` / `assign` / `set` /
  `setProperty` utilities.
- Some old versions of `lodash.merge`, `lodash.set`,
  `lodash.defaultsDeep` (patched, but pinned-old versions
  still appear in repos).
- Express middleware that maps query strings or request bodies
  directly into options objects.
- Form-handling libraries that build nested objects from
  `nested[a][b]` form keys without filtering.
- React state-update reducers that spread user-controlled
  payloads.

## Why it matters

A polluted prototype changes the behaviour of code far away
from the call site. The classic exploit is making
authorization checks return true; subtler ones change
default-handling in libraries, set unexpected event handlers,
or break framework invariants. SAST scanners catch only the
most obvious shapes.

## Mitigation — key filter at the boundary

Add a global filter that strips `__proto__`, `constructor`,
and `prototype` keys from every parsed user payload before it
reaches application code:

```javascript
function stripDangerousKeys(value) {
  if (Array.isArray(value)) return value.map(stripDangerousKeys);
  if (value && typeof value === "object") {
    const out = Object.create(null);
    for (const key of Object.keys(value)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        continue;
      }
      out[key] = stripDangerousKeys(value[key]);
    }
    return out;
  }
  return value;
}
```

Wrap the application's body-parser, query-parser, and
JSON.parse boundary so every external object passes through
the filter once.

For Node, `Object.freeze(Object.prototype)` at startup is a
nuclear-grade defence — but it breaks libraries that
legitimately mutate the prototype. Test before deploying.

## Uplift — replace home-rolled merge with vetted utilities

- **Vetted merge libraries:** `deepmerge` (current versions
  filter), `merge-deep` (current versions), `lodash.merge`
  (post-4.17.20). Pin to the patched version and pin
  forward.
- **Null-prototype objects:** `Object.create(null)` for any
  object built from user input — it has no prototype to
  pollute.
- **`structuredClone`:** for cases where the merge can be
  replaced with "clone the user input and overlay it onto a
  fresh defaults object," `structuredClone` (Node 17+,
  modern browsers) is a safe primitive.
- **`Object.assign` is fine** — it doesn't recurse, so
  prototype-pollution payloads don't propagate. Many
  hand-rolled `merge` functions are used where `Object.assign`
  would be enough.

## Inputs

- **Call sites** — every hand-rolled merge / extend / set
  function and every entry-point that maps user input into
  nested objects.
- **Library versions** — for any merge utility, the pinned
  version.

## The prompt

~~~markdown
You are remediating prototype-pollution surface in this
JavaScript / TypeScript repo. Output a PR or a TRIAGE.md.

## Step 0 — Inventory

1. Grep for hand-rolled merge functions: `function merge(`,
   `function extend(`, `function deepMerge(`, recursive
   `for-in` loops that assign into nested objects.
2. Identify every entry-point that parses user input into
   nested objects: `body-parser`, `qs.parse` with
   `allowPrototypes`, form-data parsers, GraphQL resolvers
   that spread untyped variables.
3. Check pinned versions of `lodash`, `deepmerge`, `hoek`,
   `merge-deep`, `defaults-deep`. Anything pinned old is a
   suspect.

## Step 1 — Pick the strategy

- **Hand-rolled merge:** uplift to a vetted library, *and*
  install the boundary filter for defence-in-depth.
- **Old-pinned vetted library:** bump to the patched version,
  install the boundary filter.
- **Boundary parsers without filtering:** install the boundary
  filter.

## Step 2 — Install the boundary filter

1. Add the `stripDangerousKeys` utility (or import a
   maintained equivalent) at a stable module path.
2. Wrap every parsed-from-user-input boundary:
   - Express `body-parser`: replace
     `app.use(express.json())` with a wrapper that filters
     after parse.
   - Form parsers: filter after parse.
   - `JSON.parse(req.body)`: wrap with the filter.
3. Use `Object.create(null)` for any object built from user
   input where the application logic doesn't depend on
   `Object.prototype` methods being inherited.

## Step 3 — Replace hand-rolled merges

For each hand-rolled merge:

1. Identify the closest vetted equivalent
   (`Object.assign`, `lodash.merge`@latest, `deepmerge`,
   `structuredClone`).
2. Replace the hand-rolled function. Delete the old one if
   no callers remain.
3. If the hand-rolled merge had application-specific
   behaviour (e.g., array concatenation rules), encode that
   behaviour in the vetted library's options.

## Step 4 — Tests

Add tests:

- A `__proto__` payload: the merge does not set
  `Object.prototype.<key>`.
- A `constructor.prototype` payload: same assertion.
- A normal nested payload: the merge produces the expected
  object (behaviour preservation).
- After the request returns, `({}).polluted` is `undefined`
  (no leakage to other objects in the runtime).

## Step 5 — Open the PR

- Branch: `remediate/proto-pollution-<module-slug>`.
- Title: `[Security][prototype-pollution] filter dangerous keys at <module>`.
- Body: call-site inventory, library bumps, boundary filter
  installation, tests added.
- Label: `sec-auto-remediation`.

## Stop conditions

- The codebase legitimately uses `__proto__` as a property
  name (rare; if so, document and triage).
- A merge utility's behaviour-preservation test fails on a
  normal payload after the swap. Triage.
- `Object.freeze(Object.prototype)` would break
  load-bearing libraries; defer that mitigation.

## Scope

- Do not bundle unrelated refactors.
- Do not silently broaden the boundary filter to permit
  dangerous keys.
- Do not delete hand-rolled merges that are still called by
  code outside this PR's scope.
~~~

## Watch for

- **`Object.assign` mistaken for the unsafe pattern.** It
  isn't — `Object.assign` does shallow assignment and ignores
  `__proto__` as a key (it's a getter, not a writable
  property on plain objects). The audit should keep it.
- **`qs.parse` with `allowPrototypes: true`.** Some legacy
  Express apps set this. Remove.
- **`Object.create(null)` breaking libraries that expect
  `.hasOwnProperty`.** Use `Object.prototype.hasOwnProperty.call(obj, k)`
  instead.
- **GraphQL variables.** Mapping untyped GraphQL variables
  into nested option objects is a common entry-point.
- **TypeScript doesn't save you.** A type assertion on a
  parsed JSON payload is not a runtime check. The boundary
  filter is.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [eval and Function constructor]({{< relref "/prompt-library/general/classic-vulnerable-defaults/eval-and-function-constructor" >}})
  — companion JavaScript pattern.
