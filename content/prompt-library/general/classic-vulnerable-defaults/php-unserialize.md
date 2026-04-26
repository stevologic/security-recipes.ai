---
title: "PHP object deserialization — `unserialize` on untrusted data"
linkTitle: "PHP unserialize"
description: "Replace unsafe `unserialize` usage with JSON or strict allowed-class deserialization; add tests that preserve payload behavior."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["php", "deserialization", "uplift", "mitigate"]
weight: 28
date: 2026-04-26
---

`unserialize($_POST["data"])` is a long-lived PHP footgun.
When attacker-controlled bytes hit `unserialize`, PHP can
instantiate gadget objects and trigger magic methods such as
`__wakeup` / `__destruct`. That's object-injection territory,
with real-world RCE chains in common ecosystems.

## Pattern

- `unserialize($input)` where `$input` comes from HTTP,
  cookies, message queues, or user-editable DB fields.
- Session or cache adapters that deserialize values from
  shared stores without strict provenance checks.
- Framework wrappers that indirectly call `unserialize`
  (custom middleware, queue/job payload handling).

## Why it matters

Unsafe deserialization in PHP is frequently exploitable via POP
(property-oriented programming) chains. Even when no direct RCE
exists, object injection can corrupt authorization state,
overwrite files, or invoke network callbacks through gadget
classes.

## Mitigation — constrain classes immediately

If a full migration cannot ship in one PR, use strict class
allowlisting and fail closed:

```php
<?php
$decoded = unserialize($payload, ['allowed_classes' => false]);
```

Or, where specific DTO classes are required:

```php
<?php
$decoded = unserialize($payload, ['allowed_classes' => [OrderDTO::class]]);
```

Pair this with input provenance checks and rejection logging.

## Uplift — replace with JSON (or schema-validated format)

Preferred uplift:

- Replace serialized object payloads with JSON arrays/maps.
- Hydrate explicit DTOs from decoded arrays.
- Validate shape and types at boundaries before use.
- Keep a temporary legacy-read path only for migration windows,
  with telemetry and a removal date.

## Inputs

- **Call sites** — all `unserialize` invocations and wrappers.
- **Trust boundary** — where each payload originates.
- **Compat constraints** — which payload formats must continue
  to round-trip during migration.

## The prompt

~~~markdown
You are remediating unsafe PHP deserialization call sites.
Output a PR or a TRIAGE.md.

## Step 0 — Inventory

1. Search for `unserialize(` and wrappers around payload decode.
2. For each call site, record source of bytes and whether input
   can be attacker-controlled.
3. Identify classes currently instantiated by deserialize paths.

## Step 1 — Decide per call site

- **Untrusted / ambiguous input:** uplift to JSON + DTO hydrate.
- **Trusted-only legacy path with hard dependency:** mitigate
  with `allowed_classes` and explicit provenance checks.
- **Cannot classify trust boundary:** triage.

## Step 2 — Implement

For uplifted sites:

1. Replace `serialize`/`unserialize` with
   `json_encode`/`json_decode(..., true, flags)`.
2. Add boundary validation for required keys and value types.
3. Convert arrays into explicit DTO/value objects.

For mitigated sites:

1. Add `allowed_classes` with the narrowest possible list
   (`false` whenever feasible).
2. Reject and log payloads that require disallowed classes.

## Step 3 — Tests

Add behavior-preservation tests:

- Existing valid payloads still decode to expected domain
  values.
- A payload requiring a disallowed class is rejected.
- Malformed payloads fail closed.

## Step 4 — Open the PR

- Branch: `remediate/php-unserialize-<module-slug>`.
- Title: `[Security][PHP] remediate unserialize in <module>`.
- Body: inventory, trust-boundary classification, uplift vs
  mitigation, compatibility plan, tests.
- Label: `sec-auto-remediation`.

## Stop conditions

- You cannot identify payload provenance.
- Migration requires coordinated cross-service schema rollout
  not feasible in one PR.
- No test harness exists for the affected decode path.

## Scope

- Do not bundle unrelated refactors.
- Do not expand allowed class lists beyond what tests require.
- Do not silently keep legacy deserialize paths without a
  dated removal note.
~~~

## Watch for

- **Framework internals** that deserialize session/queue data;
  ensure your target call sites are truly app-controlled.
- **Base64 wrappers** around serialized bytes (easy to miss in
  grep).
- **“Trusted DB” assumptions** where user-controlled values are
  eventually written into that table.
- **Over-broad allowlists** that reintroduce gadget surfaces.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [Java ObjectInputStream]({{< relref "/prompt-library/general/classic-vulnerable-defaults/java-deserialization" >}})
  — analogous deserialization risk in JVM stacks.
