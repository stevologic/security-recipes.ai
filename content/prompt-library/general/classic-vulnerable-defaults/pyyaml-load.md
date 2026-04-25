---
title: "PyYAML `yaml.load` without a safe Loader"
linkTitle: "PyYAML yaml.load"
description: "Default to `yaml.safe_load`; install an import-time shim that defaults the loader for legacy callers."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["python", "yaml", "deserialization", "uplift", "mitigate"]
weight: 22
date: 2026-04-25
---

`yaml.load(s)` — without an explicit `Loader=` — was unsafe by
default for over a decade. The default loader resolves
`!!python/object` tags, which is the YAML equivalent of pickle:
arbitrary code execution on untrusted input. PyYAML 5.1 added a
warning, 6.0 made the warning louder; the call shape is still
out there in repos by the thousands.

## Pattern

- `yaml.load(s)` — no `Loader=` argument.
- `yaml.load(s, Loader=yaml.Loader)` — explicit unsafe loader.
- `yaml.load(s, Loader=yaml.UnsafeLoader)` — same, named.
- `yaml.full_load(s)` — looser than `safe_load`; resolves
  arbitrary types, just not arbitrary Python.

The safe shapes:

- `yaml.safe_load(s)` — refuses every Python tag. Almost
  always the right answer.
- `yaml.load(s, Loader=yaml.SafeLoader)` — same thing, more
  verbose.

## Why it matters

```yaml
!!python/object/apply:os.system ["rm -rf /"]
```

…is a payload `yaml.load` will happily execute. There is no
patch coming; `safe_load` is the patch.

## Mitigation — monkey-patch at import

When the repo has dozens of call sites, replacing every one in
a single PR is risky. The mitigation is a one-line shim that
makes the unsafe loader behave like the safe one:

```python
# importable as e.g. `import myapp.yaml_safety_shim`
import yaml
import warnings

_orig_load = yaml.load

def _safe_load(stream, Loader=None, **kwargs):
    if Loader in (None, yaml.Loader, yaml.UnsafeLoader, yaml.FullLoader):
        warnings.warn(
            "yaml.load shimmed to SafeLoader",
            stacklevel=2,
        )
        return _orig_load(stream, Loader=yaml.SafeLoader, **kwargs)
    return _orig_load(stream, Loader=Loader, **kwargs)

yaml.load = _safe_load
```

Import this shim once at the application's entry point. Every
unsafe call now warns at runtime and decodes safely.

## Uplift — replace each call

The clean fix: replace every `yaml.load(s)` with
`yaml.safe_load(s)`. Mechanical change. A repo-wide search and
a sed-equivalent is enough for most cases — but the agent
inspects each call to confirm the data flow and adds a
behaviour-preservation test.

## Inputs

- **Call sites** — list of files / lines where `yaml.load`
  appears.
- **Strategy** — uplift each / install shim / both.

## The prompt

~~~markdown
You are remediating PyYAML `yaml.load` call sites that resolve
unsafe tags. Output a PR or a TRIAGE.md.

## Step 0 — Inventory

1. List every `yaml.load`, `yaml.full_load`,
   `yaml.load(..., Loader=yaml.Loader)`,
   `yaml.load(..., Loader=yaml.UnsafeLoader)`,
   `yaml.load(..., Loader=yaml.FullLoader)` call in the repo.
2. For each call, record whether the input is untrusted (file
   uploaded by a user, fetched from a URL, parsed from a
   request body) or trusted-only (a config file written by
   the same process).

## Step 1 — Pick the strategy

- **≤5 call sites or all in application code:** uplift each
  call site directly to `yaml.safe_load`.
- **Many call sites or the codebase imports through helpers:**
  install the import-time shim *and* still uplift the call
  sites that legitimately need a non-default loader.
- **Trusted-only call sites:** still uplift; the safe loader
  costs nothing on trusted input.

## Step 2 — Uplift

1. Replace `yaml.load(s)` with `yaml.safe_load(s)`.
2. Replace `yaml.load(s, Loader=yaml.Loader)` with
   `yaml.safe_load(s)`.
3. If the call truly needs a non-Safe loader (e.g., the YAML
   carries a custom tag this codebase legitimately registers),
   keep the explicit loader and document why in a comment with
   a `# noqa: yaml-load-policy` marker.
4. Add a unit test: a payload containing
   `!!python/object/apply:os.system ["echo pwned"]` must raise
   `yaml.constructor.ConstructorError` after the change.

## Step 3 — Install the shim (when chosen)

1. Add the shim module at a stable import path
   (`<package>/_yaml_safety_shim.py`).
2. Import the shim from the application's entry point(s).
3. Add a unit test that imports the shim, calls `yaml.load`
   without a Loader, and confirms the SafeLoader was used.

## Step 4 — Open the PR

- Branch: `remediate/yaml-safe-load-<short-slug>`.
- Title: `[Security][yaml] use safe_load on untrusted YAML`.
- Body: per-call-site analysis, strategy chosen, test
  additions, the `# noqa` exceptions if any.
- Label: `sec-auto-remediation`.

## Stop conditions

- The codebase relies on a custom YAML tag that requires
  `yaml.Loader` and the agent can't determine whether the
  custom tag's resolver is itself safe.
- Tests fail because of a legitimate behaviour change in
  unrelated code.

## Scope

- Do not change YAML files themselves.
- Do not add new YAML tags.
- Do not bundle in unrelated refactors.
~~~

## Watch for

- **`yaml.load(s, Loader=Loader)` where `Loader` is a custom
  subclass.** Custom loaders may already be safe. Read the
  subclass before swapping.
- **`yaml.load_all` and `yaml.full_load_all`.** Same problem,
  same fix — `yaml.safe_load_all`.
- **The shim breaking custom-tag YAML** in the repo's own
  config files. The shim opts out only when an explicit
  Loader is passed; verify all legitimate custom-tag callers
  pass an explicit Loader.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [Python pickle]({{< relref "/prompt-library/general/classic-vulnerable-defaults/python-pickle" >}})
  — same risk class, different syntax.
