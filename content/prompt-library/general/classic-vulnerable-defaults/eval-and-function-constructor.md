---
title: "JavaScript `eval()` / `new Function()` on untrusted input"
linkTitle: "eval and Function constructor"
description: "Replace with parsers or restricted evaluators; add a CSP `script-src` ban on `unsafe-eval` for browser code."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["javascript", "eval", "uplift", "mitigate", "csp"]
weight: 26
date: 2026-04-25
---

`eval()`, `new Function()`, `setTimeout("...", n)` with a
string body, and `setInterval("...", n)` with a string body all
execute code parsed at runtime. When any of those strings
includes user input, the application is one cleverly-shaped
character away from arbitrary execution. The fix is rarely
"escape better" — it's "stop using a code parser as a data
parser."

## Pattern

- `eval(input)`, `eval("..." + input + "...")`,
  `new Function(input)`, `new Function("...", input)`.
- `setTimeout(input, n)`, `setInterval(input, n)` where the
  first argument is a string (passing a function reference is
  fine).
- `vm.runInNewContext(input)` (Node) without a sandbox or
  with a leaky one.
- Template engines that compile templates from user-supplied
  strings (`pug.compile`, `handlebars.compile` on user input,
  `lodash.template` on user input).

## Why it matters

A "math expression" feature, a "let users compute totals"
feature, a "let users write rules" feature — all classic
shapes where a developer reaches for `eval` because writing a
parser felt like overkill. It's not overkill; it's the safe
shape.

## Mitigation — restricted evaluator

When the codebase truly needs runtime expression evaluation
(business rules, formula fields, calculator features), replace
`eval` with a restricted evaluator that only supports the
operations the use case requires:

- **expr-eval** (npm) — arithmetic + a small set of named
  functions, no JavaScript globals.
- **mathjs** with an explicit function allowlist — strong
  scope-control, careful with `import`/`evaluate`.
- A purpose-built parser (Jison, Chevrotain, Nearley) that
  outputs an AST you walk yourself with no `eval` in sight.

## Uplift — replace with the right parser

The shape depends on what the input was actually for:

- **JSON-shaped data:** `JSON.parse`. Always.
- **A formula language:** a parser library, not `eval`.
- **A configuration DSL:** YAML (`safe_load`) or JSON, not
  JavaScript.
- **Dynamic UI rules:** a structured-rule object the
  client sends as JSON, evaluated by a typed interpreter.
- **Templates from user input:** *do not*. Compile templates
  from trusted source only. If users need to "customize," give
  them a typed schema with named placeholders.

## Mitigation — CSP `unsafe-eval` ban

For browser code, the page-level mitigation is the
Content-Security-Policy header. `script-src 'self'` (without
`'unsafe-eval'`) makes `eval`, `new Function`, and the
string-body `setTimeout`/`setInterval` *throw* at the browser
level, regardless of what the JavaScript code says.

This is a strong control — but it breaks any legitimate
`eval`-using library you ship. Audit before deploying.

## Inputs

- **Call sites** — every `eval`, `new Function`, string-body
  `setTimeout`/`setInterval`, `vm.runInNewContext`,
  template-compile-on-user-input.
- **Use-case classification** — what each call site was
  actually trying to do.

## The prompt

~~~markdown
You are remediating `eval`-shape call sites in this repository.
Output a PR or a TRIAGE.md.

## Step 0 — Inventory

1. Grep for `eval(`, `new Function(`,
   `setTimeout("`, `setInterval("`, `vm.runInNewContext`,
   `pug.compile`, `handlebars.compile`, `lodash.template`,
   `_.template`, `Function(`.
2. For each call, classify the use case: parsing JSON,
   evaluating a formula, dynamic configuration, template
   rendering, or "unknown / sketchy."

## Step 1 — Pick the replacement per call site

- **JSON-shaped:** `JSON.parse`.
- **Formula:** restricted evaluator (`expr-eval`, `mathjs`
  with allowlist) or a real parser.
- **Configuration:** load YAML/JSON instead.
- **Templates:** compile only trusted templates; for
  user-customization, switch to a typed-placeholder schema.
- **String-body `setTimeout`/`setInterval`:** pass a function
  reference instead.
- **Unknown / sketchy:** triage. Do not auto-replace.

## Step 2 — Apply the replacement

1. Replace each call site.
2. For formula evaluation, register the allowlist of
   functions the use case actually needs. Default deny.
3. For template rendering, the source of the template must be
   a static file or a constant — not a user-supplied string.

## Step 3 — Tests

For each replaced call, add tests:

- A representative legitimate input produces the same result
  as the old code (behaviour preservation).
- An input designed to escape (`'; require("child_process").exec("...")'`,
  `"constructor.constructor('return process')()"`)  is
  rejected by the new parser.

## Step 4 — Add the CSP header (browser code)

If the application has a browser front-end:

1. Add `script-src 'self'` (without `'unsafe-eval'`) to the
   `Content-Security-Policy` response header.
2. Add a CSP-violation reporting endpoint and watch for
   `unsafe-eval` violations from third-party scripts.
3. Roll out behind report-only mode first when uncertain about
   third-party usage.

## Step 5 — Open the PR

- Branch: `remediate/eval-uplift-<module-slug>`.
- Title: `[Security][eval] replace eval-shape calls in <module>`.
- Body: per-call-site classification, replacement chosen,
  tests added, CSP header changes (if any).
- Label: `sec-auto-remediation`.

## Stop conditions

- A call site classified as "unknown / sketchy" — triage,
  don't auto-replace.
- The replacement requires a parser library that's not
  available on the project's runtime version.
- The CSP header would break a third-party library the
  application depends on; defer the CSP change until that's
  resolved.

## Scope

- Do not bundle unrelated refactors.
- Do not silently broaden the allowlist of functions a
  restricted evaluator exposes.
- Do not commit the CSP change without report-only validation
  if there's third-party JS in the application.
~~~

## Watch for

- **`Function.prototype.constructor.constructor`.** A
  classic restricted-evaluator bypass. The replacement parser
  needs to reject access to `constructor`, `__proto__`, and
  `prototype`.
- **Template engines that read from a database.** If the
  template content is dynamic but stored in a "safe" place
  (database, S3), an attacker who can write there can
  compromise the page. Compiling templates from any
  user-controlled storage is the same shape as `eval` on user
  input.
- **`vm` module sandboxes leaking.** Node's `vm` module is
  not a security boundary. Use a real isolate (`isolated-vm`)
  if isolation is the goal.
- **Server-side `eval` in JSON-Schema validators.** Some
  schema-validation libraries compile schemas via `new
  Function`. Check the validator's release notes.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [Prototype pollution merges]({{< relref "/prompt-library/general/classic-vulnerable-defaults/prototype-pollution-merge" >}})
  — companion JS pattern.
