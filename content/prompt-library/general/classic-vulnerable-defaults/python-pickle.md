---
title: "Python pickle / dill on untrusted input"
linkTitle: "Python pickle / dill"
description: "Replace pickle on untrusted input; mitigate via a restricted unpickler with an explicit class allowlist."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["python", "deserialization", "pickle", "uplift", "mitigate"]
weight: 21
date: 2026-04-25
---

`pickle.load`, `pickle.loads`, `cPickle.load`, `dill.load`, and
their friends are **arbitrary-code-execution primitives** when
fed untrusted input. The Python docs say so plainly. The CVE
trail is decades long. The unsafe behaviour is *the design* —
pickle is meant to reconstruct any Python object, including
ones whose `__reduce__` runs code.

## Pattern

Any of:

- `pickle.load(f)`, `pickle.loads(s)`,
  `cPickle.load(f)`, `cPickle.loads(s)`.
- `dill.load(f)`, `dill.loads(s)` (same problem, larger
  surface).
- `joblib.load(path)` when the path is user-controlled.
- `numpy.load(allow_pickle=True)` on user files (silent default
  before 1.16.3 was unsafe; current default is safe but the
  flag is often re-enabled in legacy code).
- `torch.load(path)` (Python 2.6+ pickling underneath; safer
  options now exist as of PyTorch 2.5+).

## Why it matters

A pickled payload can carry a `__reduce__` that returns
`(os.system, ("rm -rf /",))` — `pickle.load` happily executes
it. There is no patch coming. Reading attacker-controlled
pickles is RCE.

## Mitigation — restricted unpickler

When the call is on a backwards-compat read path (a legacy
checkpoint format, an old persistence file), wrap the
unpickler:

```python
import pickle, io

class SafeUnpickler(pickle.Unpickler):
    ALLOWED = {
        ("builtins", "dict"),
        ("builtins", "list"),
        ("builtins", "set"),
        ("builtins", "tuple"),
        # Add only the application-specific classes
        # that legitimately round-trip through pickle.
    }
    def find_class(self, module, name):
        if (module, name) in self.ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"forbidden: {module}.{name}")

def safe_loads(data: bytes):
    return SafeUnpickler(io.BytesIO(data)).load()
```

Every rejection logs at WARN. The allowlist is the policy; it is
narrow on purpose.

## Uplift — replace pickle entirely

Default replacement choices:

- **JSON** (`json.dumps` / `json.loads`) — when the data is
  already a tree of primitives.
- **msgpack** — when binary payload size matters.
- **protobuf** / **pydantic JSON** — when the data has a schema
  worth declaring.
- For ML-shaped state: **safetensors** for weights, JSON for
  metadata.

Behaviour preservation: round-trip a representative payload
through the old `pickle.dumps` and the new serializer; assert
the in-memory shape matches.

## Inputs

- **Call site** — file + line range.
- **Data path** — where the input comes from (file, network,
  user-uploaded, intra-process).
- **Replacement strategy** — uplift / mitigate / both.

## The prompt

~~~markdown
You are remediating one Python pickle call site. Output a PR
or a TRIAGE.md.

## Step 0 — Read the call site and trace input

1. Read the function containing the pickle call. Identify the
   input source (file handle, bytes, network payload).
2. If the input is provably trusted-only (e.g., a file written
   in the same process, never read across a trust boundary),
   stop and write a triage note documenting the trust
   boundary — do not auto-replace.

## Step 1 — Pick the strategy

- If the call is on a backwards-compat read path with active
  callers reading legacy data, do **mitigate**.
- Otherwise do **uplift**.
- For checkpoint loaders that take user-supplied paths, do
  **both** — mitigate the legacy path, uplift the write path.

## Step 2 — Mitigate (when applicable)

1. Add a `SafeUnpickler` subclass with an explicit class
   allowlist scoped to the classes that legitimately round-trip
   here. Log rejections at WARN.
2. Replace the `pickle.load(f)` call with the safe wrapper.
3. Add a unit test that loads a known-good payload (passes)
   and a payload referencing `os.system` (raises
   `UnpicklingError`).

## Step 3 — Uplift (when applicable)

1. Choose the replacement format from this list, in order:
   JSON if the payload is primitives, msgpack if binary size
   matters, protobuf/pydantic if schema is worth declaring,
   safetensors+JSON for ML weights.
2. Add a writer that emits the new format, and a reader that
   parses it.
3. If old data exists, add a one-time migration that reads the
   pickle (via the SafeUnpickler from Step 2) and writes the
   new format. The migration is its own commit.
4. Add a behaviour-preservation test that asserts the in-memory
   shape after uplift matches what the old pickle would have
   produced.

## Step 4 — Open the PR

- Branch: `remediate/pickle-<short-slug>`.
- Title: `[Security][pickle] replace untrusted-input pickle in <module>`.
- Body must include: input-source analysis, strategy chosen,
  test plan, legacy data migration plan if any, and a
  follow-up checklist for adjacent pickle call sites that this
  PR did not touch.
- Label: `sec-auto-remediation`.

## Stop conditions

- Input source cannot be classified as untrusted vs. trusted.
- Replacement requires a coordinated migration across repos.
- Test coverage on the call path is too thin to detect
  regressions.

## Scope

- Do not touch other pickle call sites in the repo. One per
  PR.
- Do not silently broaden the SafeUnpickler allowlist beyond
  the classes the local code actually uses.
- Do not remove the legacy read-path without a documented
  data migration.
~~~

## Watch for

- **`__reduce__` in tests.** Some test suites legitimately
  pickle and unpickle custom classes. Don't break those — add
  the classes to the allowlist explicitly.
- **`numpy.load(allow_pickle=True)` left enabled.** Often a
  copy-paste from a stack-overflow answer. The default is safe
  now; flip it back.
- **`torch.load` on a user-supplied path.** The mitigation
  shape depends on the PyTorch version; check the loader's
  `weights_only` parameter (PyTorch 2.5+ defaults it true).
- **Cross-version pickles.** A pickle written by Python 3.11
  may not round-trip cleanly on 3.9. The behaviour-preservation
  test catches this.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [PyYAML `yaml.load`]({{< relref "/prompt-library/general/classic-vulnerable-defaults/pyyaml-load" >}})
  — sibling pattern with a different fix.
- [Java ObjectInputStream]({{< relref "/prompt-library/general/classic-vulnerable-defaults/java-deserialization" >}})
  — same pattern in Java.
