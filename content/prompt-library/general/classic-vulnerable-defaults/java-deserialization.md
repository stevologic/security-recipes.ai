---
title: "Java ObjectInputStream and friends"
linkTitle: "Java ObjectInputStream"
description: "Replace with JSON serializers; mitigate via JEP 290 deserialization filters with a strict class allowlist."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["java", "deserialization", "uplift", "mitigate", "jep-290"]
weight: 23
date: 2026-04-25
---

`ObjectInputStream.readObject()` is the Java equivalent of
pickle: a payload of class metadata that the runtime
*reconstructs*, including invoking constructors, setting
fields, and triggering `readObject` / `readResolve` /
`finalize` on every class in the graph. The "gadget chains"
that make this exploitable have been written and re-written
since 2015; the CVE shelf is full.

## Pattern

- `new ObjectInputStream(...).readObject()` on any
  network / file / DB-blob input.
- Frameworks that serialize via Java serialization under the
  hood: older RMI, JMS, JNDI lookup-with-RemoteObject paths,
  some session-replication backends.
- Legacy uses of `ObjectInputStream` for "convenient"
  same-VM persistence — still dangerous if the file ever
  reaches a different VM with different classpath assumptions.

## Why it matters

A malicious payload using a known gadget chain (commons-
collections, Spring, Groovy, the long-running Pwn-Twitter
list) can RCE on `readObject()` without the application code
ever being entered. There is no patch coming; the design
predates the threat model.

## Mitigation — JEP 290 deserialization filters

Java 9+ exposes
`ObjectInputFilter` / `ObjectInputFilter.Config` (and the
older `setObjectInputFilter` API). Set a strict allowlist
filter on every `ObjectInputStream` the application creates:

```java
ObjectInputFilter allowlist = ObjectInputFilter.Config.createFilter(
    "com.example.Order;com.example.OrderItem;java.lang.Number;" +
    "java.util.ArrayList;java.util.HashMap;" +
    "!*"  // reject everything else
);

try (ObjectInputStream in = new ObjectInputStream(input)) {
    in.setObjectInputFilter(allowlist);
    Object obj = in.readObject();
    // ...
}
```

Or set it globally at JVM start:
`-Djdk.serialFilter='com.example.*;java.lang.Number;!*'`. The
filter rejects every class outside the allowlist before the
class is loaded, before `readObject` is invoked, before any
gadget chain runs.

## Uplift — replace ObjectInputStream entirely

For any new-write path, switch to a JSON serializer with
explicit type handling:

- **Jackson** with default-typing **disabled** and
  `@JsonTypeInfo(use=Id.NAME)` plus
  `@JsonSubTypes({...})` enumerations on polymorphic fields,
  *or* a `BasicPolymorphicTypeValidator` allowlist if default
  typing genuinely cannot be removed.
- **Gson** with explicit `TypeAdapter` / `RuntimeTypeAdapterFactory`
  registrations.
- **Protobuf** when the data is structured enough to warrant a
  schema.

Read paths for legacy data: keep an `ObjectInputStream` reader
*with the JEP 290 filter installed* until the persisted data
has been migrated; then remove the reader.

## Inputs

- **Call sites** — every `new ObjectInputStream(...)` and
  every framework call known to deserialize Java objects
  internally.
- **Strategy** — mitigate / uplift / both.

## The prompt

~~~markdown
You are remediating Java deserialization call sites in this
repo. Output a PR or a TRIAGE.md.

## Step 0 — Inventory

1. List every `new ObjectInputStream(...)` in the repo.
2. List every framework usage that deserializes Java objects
   internally — check for `ObjectMapper.readValue` with
   `enableDefaultTyping`, RMI registrations, JMS message
   listeners that trust message bodies, session-replication
   bindings.
3. For each, record whether the input crosses a trust
   boundary.

## Step 1 — Pick the strategy

- **All call sites:** mitigate by adding a JEP 290 filter.
  This is required regardless of any uplift.
- **New-write paths:** also uplift to JSON with explicit
  typing.
- **Legacy read paths:** keep the filtered ObjectInputStream
  until data is migrated.

## Step 2 — Mitigate

1. Define a single allowlist filter as a constant in a
   security utility class.
2. Apply the filter to every ObjectInputStream creation. If
   the codebase has many call sites, factor a
   `safeObjectInputStream(InputStream)` helper and migrate to
   it.
3. Optionally, add the global JEP 290 filter to the
   application's JVM args / Dockerfile / launcher.
4. Add tests:
   - A payload containing an allowlisted class deserializes
     successfully.
   - A payload containing a non-allowlisted class
     (`org.apache.commons.collections.functors.InvokerTransformer`,
     `java.lang.Runtime`) is rejected.

## Step 3 — Uplift (when applicable)

1. Replace `ObjectOutputStream` writers with the chosen JSON
   serializer.
2. Add a behaviour-preservation test that round-trips a
   representative object through the old binary format and
   the new JSON format and asserts field-by-field equality.
3. If the codebase persists data: add a one-time migration job
   that reads old binary files via the filtered ObjectInputStream
   and writes them as JSON. Document a removal date for the
   legacy reader.

## Step 4 — Open the PR

- Branch: `remediate/java-deser-<module-slug>`.
- Title: `[Security][deserialization] add JEP 290 filter / uplift to JSON in <module>`.
- Body: call-site inventory, allowlist contents, test
  additions, migration plan if applicable, and the JVM-args
  change if global filter applied.
- Label: `sec-auto-remediation`.

## Stop conditions

- A framework is doing the deserialization and the agent
  cannot inject a filter. (E.g., a third-party library that
  exposes no filter hook — flag and triage.)
- Default typing in Jackson is load-bearing for a feature the
  agent cannot reshape without an API change.
- Test coverage on the call path is too thin to detect
  regressions safely.

## Scope

- Do not bundle in unrelated refactors.
- Do not silently broaden the allowlist.
- Do not remove the legacy reader without a documented
  migration.
~~~

## Watch for

- **Allowlist drift.** A reviewer who adds a class to the
  allowlist next quarter without re-reading the gadget-chain
  list defeats the mitigation. Guard with a comment that says
  so explicitly, and re-review the allowlist quarterly.
- **`enableDefaultTyping` re-enabled.** Jackson will resolve
  arbitrary classes if default typing is on. The Jackson
  recipe is a sibling pattern; if the codebase uses it, fix
  both at once.
- **JNDI lookups in deserialized payloads.** Even with a strict
  filter, some allowed classes can re-trigger lookups —
  validate the allowlist against the
  [log4j-style JNDI lookups]({{< relref "/prompt-library/cve" >}})
  threat surface.
- **Globally setting the JVM filter** can break other
  applications on the same JVM if any. Prefer per-stream
  filters when the JVM hosts multiple applications.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [Python pickle]({{< relref "/prompt-library/general/classic-vulnerable-defaults/python-pickle" >}})
  — same risk class in Python.
