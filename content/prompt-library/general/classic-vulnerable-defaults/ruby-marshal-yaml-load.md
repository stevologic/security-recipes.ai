---
title: "Ruby unsafe deserialization — `Marshal.load` / `YAML.load`"
linkTitle: "Ruby Marshal/YAML.load"
description: "Replace `Marshal.load` and unsafe YAML loading with safe parsers, typed coercion, and strict migration tests."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["ruby", "deserialization", "yaml", "uplift", "mitigate"]
weight: 29
date: 2026-04-26
---

`Marshal.load` and permissive YAML loaders are durable Ruby
security traps. If untrusted bytes reach these APIs, attacker
payloads can instantiate arbitrary classes and trigger dangerous
code paths. This pattern appears in Rails jobs, cache/session
layers, signed-cookie migrations, and background workers.

## Pattern

- `Marshal.load(payload)` where payload crosses trust
  boundaries (HTTP params, Redis, MQ, DB rows editable by users).
- `YAML.load` / `Psych.load` on untrusted YAML.
- `YAML.unsafe_load` in modern Ruby/Psych.
- Indirect wrappers that decode serialized data before model/job
  processing.

## Why it matters

Unsafe Ruby deserialization can become RCE via gadget chains in
application or gem classes. Even without direct execution,
attackers can tamper with object state to bypass authz checks,
poison jobs, or trigger SSRF/file operations.

## Mitigation — safe loader with strict class policy

For YAML, switch to `safe_load` with explicit permitted classes:

```ruby
parsed = YAML.safe_load(payload, permitted_classes: [Date, Time], aliases: false)
```

For Marshal paths that cannot be removed immediately, enforce
trusted provenance and fail-closed guards at ingress. Treat as a
temporary bridge, not a steady state.

## Uplift — move to JSON + explicit coercion

Preferred uplift:

- Replace Marshal/YAML object payloads with JSON hashes/arrays.
- Perform explicit coercion into value objects/DTOs.
- Validate required fields and types before business logic.
- Keep temporary legacy decode only where required, with
  telemetry and a removal date.

## Inputs

- **Call sites** — every `Marshal.load`, `YAML.load`,
  `Psych.load`, and `unsafe_load` usage.
- **Data provenance** — where each payload originates.
- **Compatibility needs** — which historical payloads must
  continue to decode during migration.

## The prompt

~~~markdown
You are remediating unsafe Ruby deserialization call sites.
Output a PR or a TRIAGE.md.

## Step 0 — Inventory

1. Search for `Marshal.load`, `YAML.load`, `Psych.load`, and
   `unsafe_load`.
2. Classify each by trust boundary: trusted-only internal,
   external/untrusted, or unknown.
3. Map legacy payload producers/consumers.

## Step 1 — Choose remediation per site

- **Untrusted or unknown:** uplift to JSON + explicit coercion.
- **Trusted-only temporary compatibility path:** mitigate with
  strict guards and bounded lifespan.

## Step 2 — Implement

For YAML sites:
- Replace with `YAML.safe_load` and minimal
  `permitted_classes` list.
- Disable aliases unless explicitly required.

For Marshal sites:
- Replace with JSON decode + schema/type validation.
- Remove `Marshal.load` from runtime paths handling external
  input.

For temporary compat paths:
- Isolate in a clearly named legacy decoder module.
- Add telemetry counters for legacy decode usage.
- Add TODO with owner and removal date.

## Step 3 — Tests

Add behavior-preservation tests:

- Valid legacy payloads decode to equivalent domain values.
- Untrusted crafted payloads are rejected.
- Unknown class tags / alias abuse fails closed.

## Step 4 — Open the PR

- Branch: `remediate/ruby-deser-<module-slug>`.
- Title: `[Security][Ruby] remove unsafe deserialize in <module>`.
- Body: inventory, trust classification, uplift/mitigation
  decisions, compatibility plan, test evidence.
- Label: `sec-auto-remediation`.

## Stop conditions

- Trust boundary cannot be determined.
- Required migration spans multiple services with no staged
  rollout plan.
- Critical path lacks tests and cannot be safely instrumented.

## Scope

- Do not ship unrelated refactors.
- Do not introduce broad `permitted_classes` catch-alls.
- Do not retain legacy decode paths without explicit expiry.
~~~

## Watch for

- **Rails cookie/session migrations** where old serializers are
  still enabled.
- **Background job payload formats** shared across deploy waves.
- **`aliases: true`** in YAML parsers reopening gadget vectors.
- **Monkey patches in initializers** that re-enable unsafe
  loading globally.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [PyYAML `yaml.load`]({{< relref "/prompt-library/general/classic-vulnerable-defaults/pyyaml-load" >}})
  — analogous unsafe YAML default in Python.
