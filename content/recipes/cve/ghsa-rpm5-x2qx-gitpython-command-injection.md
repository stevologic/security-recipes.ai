---
title: "CVE-2026-42215: GitPython command injection"
linkTitle: "CVE-2026-42215 GitPython"
description: "CVE-2026-42215 is GitPython upload_pack command injection. Upgrade to 3.1.47+ and reject user-controlled git kwargs."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["cve", "ghsa", "gitpython", "python", "pip", "git", "command-injection", "supply-chain", "high"]
weight: 57
date: 2026-05-02
lastmod: 2026-08-21
cve: "CVE-2026-42215"
ghsa: "GHSA-rpm5-65cw-6hj4"
known_as: ["GitPython command injection", "GHSA-x2qx-6953-8485"]
kev: false
severity: "high"
ecosystem: "python/pypi"
disclosed: "2026-04-25"
ai_enrichment_review_status: human-reviewed-development-draft
---

CVE-2026-42215 / GHSA-rpm5-65cw-6hj4 and GHSA-x2qx-6953-8485 cover GitPython
releases before `3.1.47` when untrusted input can shape Git operation options:

- **CVE-2026-42215 / GHSA-rpm5-65cw-6hj4**: unsafe Git option checks can be
  bypassed with Python kwargs such as `upload_pack` and `receive_pack`, which
  normalize into dangerous Git flags. Affected `>=3.1.30, <3.1.47`.
- **GHSA-x2qx-6953-8485**: `multi_options` validation happens before
  `shlex.split()`, allowing a seemingly safe option string to split into
  unsafe flags such as `--config core.hooksPath=...`.

GitHub names **`GitPython` 3.1.47**. Do not invent a later 3.1.48 floor. This
page stays a development draft. Do not prove exposure with helper-command
kwargs or custom Git options.

For agentic coding systems, CI workers, repository importers, and internal
automation bots, the practical risk is code execution on the worker handling
repo clone/fetch/pull/push operations.

## When to use it

Use this recipe when a repository uses GitPython in repo importers, agentic
coding systems, CI workers, mirror/sync jobs, internal automation bots, or
submodule helpers. It is especially relevant when users, tenants, webhooks,
workflow YAML, job definitions, repository metadata, or LLM/tool inputs can
influence Git operation options.

Use it to upgrade GitPython and remove raw Git option pass-through. Do not use
it to test exploit payloads, custom helper commands, hooks, or attacker-supplied
Git options.

## Inputs

- Python dependency manifests, constraints, lockfiles, base images, CI images,
  worker images, SBOMs, vendored code, deployment manifests, and repository
  import or mirror runbooks.
- GitPython operation paths such as clone, fetch, pull, push, submodule update,
  workspace preparation, repository sync, and agent checkout helpers.
- Option input sources: request bodies, webhook payloads, tenant settings,
  workflow YAML, job config, database records, environment variables,
  repository metadata, and LLM/tool arguments.
- Worker authority: SSH keys, deploy keys, package tokens, cloud credentials,
  source-code access, artifact access, internal network routes, and shared
  workspace state.
- Existing hardening controls for option validation, hook policy, environment
  scrubbing, per-job workspace isolation, credential scoping, and log review.

## Affected versions

- **Vulnerable:** `GitPython >=3.1.30, <3.1.47` for
  `GHSA-rpm5-65cw-6hj4`
- **Vulnerable:** `GitPython <3.1.47` for `GHSA-x2qx-6953-8485`
- **Fixed:** `GitPython 3.1.47+`

## Indicator-of-exposure

- The repository depends on GitPython directly or transitively.
- Application code calls `Repo.clone_from()`, `Repo.clone()`,
  `Remote.fetch()`, `Remote.pull()`, `Remote.push()`, or `Submodule.update()`.
- Users, tenants, webhooks, workflow YAML, job definitions, repository metadata,
  or LLM/tool inputs can influence `kwargs`, `multi_options`,
  `clone_multi_options`, or "extra git options."
- The process performing Git operations has access to SSH keys, cloud
  credentials, package publishing tokens, source code, build artifacts, or
  internal network routes.

Quick checks:

```bash
rg -n "GitPython|from git import Repo|import git|Repo\.clone_from|Repo\.clone\(|\.fetch\(|\.pull\(|\.push\(|multi_options|clone_multi_options|upload_pack|receive_pack|allow_unsafe" .
python -m pip show GitPython
pip freeze | rg '^GitPython=='
rg -n "extra.*git|git.*options|clone.*options|repo.*import|repository.*sync|webhook.*clone|workflow.*clone" .
```

## Remediation strategy

- Upgrade GitPython to `3.1.47+` everywhere this repository controls manifests,
  lockfiles, images, or runtime packaging.
- Remove user-controlled pass-through of Git kwargs and `multi_options`.
- Replace free-form Git option input with a strict allow-list of product
  features, represented as typed fields rather than raw flags.
- Block `upload_pack`, `receive_pack`, `exec`, `config`, `c`, `core.hooksPath`,
  and any option that can choose helper commands, hooks, config, protocol
  behavior, or SSH commands.
- Run repo-ingest workers with least privilege, isolated workspaces, disabled
  hooks where possible, and credentials scoped to the one repository operation.
- Review worker logs and credential access if untrusted users could control Git
  options during the exposure window.

## The prompt

~~~markdown
You are remediating GitPython command injection advisories
GHSA-rpm5-65cw-6hj4 and GHSA-x2qx-6953-8485. Produce exactly one output:

- A reviewer-ready PR/change request that upgrades GitPython, removes unsafe
  option pass-through, adds regression coverage, and documents operator cleanup,
  or
- TRIAGE.md if this repository does not own an affected GitPython runtime or
  safe patch path.

## Rules

- Scope only GHSA-rpm5-65cw-6hj4 and GHSA-x2qx-6953-8485.
- Treat SSH keys, deploy keys, package tokens, cloud credentials, source code,
  repo URLs, and worker environment values as sensitive.
- Do not execute exploit payloads, helper commands, custom hooks, reverse
  shells, or attacker-controlled Git options.
- Do not keep a free-form "extra Git options" feature for untrusted callers.
- Do not auto-merge.

## Steps

1. Inventory every GitPython dependency controlled by this repository:
   requirements files, pyproject files, lockfiles, constraints, Dockerfiles,
   base images, CI images, worker images, SBOMs, vendored code, and deployment
   manifests.
2. Determine every resolved GitPython version. A target is vulnerable if it
   resolves below `3.1.47`.
3. Search code paths that perform repository operations:
   - `Repo.clone_from()`;
   - `Repo.clone()`;
   - `Remote.fetch()`;
   - `Remote.pull()`;
   - `Remote.push()`;
   - `Submodule.update()`;
   - wrappers around repository import, mirror, sync, CI checkout, or agent
     workspace preparation.
4. Determine whether untrusted input can reach GitPython options:
   request bodies, webhook payloads, tenant settings, workflow YAML, job config,
   LLM/tool arguments, database records, environment variables, or "advanced
   options" fields.
5. If GitPython is absent or only used in non-deployable tooling, stop with
   `TRIAGE.md` explaining what was checked and why the runtime is not exposed.
6. Upgrade GitPython to `3.1.47+` on the smallest compatible release line.
   Regenerate lockfiles, constraints, images, SBOMs, and dependency reports.
7. Remove unsafe option pass-through:
   - do not pass user dictionaries directly as `**kwargs`;
   - do not pass user strings to `multi_options` or `clone_multi_options`;
   - reject `upload_pack`, `receive_pack`, `exec`, `config`, `c`,
     `core.hooksPath`, `GIT_SSH_COMMAND`, and equivalent normalized spellings;
   - represent supported behavior as typed fields, then map to a finite
     allow-list of safe GitPython arguments.
8. Add regression tests that do not execute commands:
   - `upload_pack` and `receive_pack` kwargs from untrusted input are rejected;
   - hyphen, underscore, and mixed-normalization forms are rejected;
   - `multi_options` strings containing embedded unsafe flags are rejected;
   - `clone_multi_options` for submodules uses the same validator;
   - validation happens after parsing/normalization, not only before it.
9. Harden repo-ingest execution where this repo controls it:
   - run workers as unprivileged users;
   - isolate workspaces per job;
   - scrub environment variables before Git operations;
   - scope SSH/deploy keys to the target repo and operation;
   - disable Git hooks or run with safe hook policy where supported.
10. Add a PR body section named `GitPython advisory operator actions` that
    states:
    - affected GitPython versions before and after the change;
    - which repo-operation paths were reachable by untrusted input;
    - whether free-form Git option features were removed or restricted;
    - which worker credentials should be rotated if exposure existed;
    - which logs should be reviewed for suspicious helper, hook, config, or SSH
      command options.
11. Run relevant validation: dependency install, unit tests, integration tests
    for repository import/sync, lint/typecheck, image build, SBOM refresh, and
    dependency/security scans available in this repository.
12. Use PR title:
    `fix(sec): remediate GitPython command injection advisories`.

## Stop conditions

- No deployable GitPython runtime is controlled by this repository.
- A fixed GitPython version cannot be consumed without a broader platform
  migration.
- Product requirements depend on arbitrary caller-controlled Git options;
  document the risk and require a product/security decision.
- Verification would require executing attacker-controlled hooks or helper
  commands.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled lockfile, image, SBOM, or deployment target resolves GitPython
  below `3.1.47`.
- User-controlled dictionaries, strings, workflow fields, or LLM/tool arguments
  cannot become raw GitPython kwargs, `multi_options`, or
  `clone_multi_options`.
- Regression tests cover normalized option names and post-parse validation.
- Repo-ingest workers do not run with broad credentials or reusable shared
  workspaces.
- The PR identifies whether credential rotation and log review are required.

## Watch for

- Updating application requirements while CI, worker, or agent images still
  carry an older GitPython version.
- Blocking only literal `--upload-pack` while allowing `upload_pack`.
- Validating `multi_options` before splitting or normalization.
- Treating repository URLs as the only untrusted input and missing workflow
  fields that configure clone/fetch behavior.

## Rollback and recovery

Prefer forward recovery to another GitHub-named `GitPython` 3.1.47+ release.
If an operational rollback restores a build before `3.1.47`, block
user-controlled `upload_pack`, `receive_pack`, and `multi_options` until the
named floor is restored.

## Output contract

Return one of:

- A reviewer-ready PR/change request that upgrades every controlled GitPython
  runtime to `3.1.47+`, removes raw `kwargs`, `multi_options`, and
  `clone_multi_options` pass-through, replaces free-form Git options with a
  typed allow-list, adds normalization-aware regression tests, hardens
  repo-ingest workers, and refreshes generated artifacts.
- `TRIAGE.md` when no controlled deployable GitPython runtime, repo-operation
  path, worker image, dependency graph, or generated artifact exists.

The output must list GitPython versions before and after, reachable
repo-operation paths, which free-form options were removed or restricted,
validation commands, worker credentials that need rotation or review, and logs
to inspect for helper, hook, config, or SSH command abuse. It must not execute
attacker-controlled hooks, helper commands, shell payloads, or custom Git
options.

## Related recipes

- [Source-code supply chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit" >}})
- [Source-code injection sink audit]({{< relref "/recipes/general/source-code-injection-sink-audit" >}})
- [Agent session kill rules]({{< relref "/recipes/general/agent-session-kill-rules" >}})

## References

- GitHub Advisory `GHSA-rpm5-65cw-6hj4`: <https://github.com/advisories/GHSA-rpm5-65cw-6hj4>
- NVD `CVE-2026-42215`: <https://nvd.nist.gov/vuln/detail/CVE-2026-42215>
- GitHub Advisory `GHSA-x2qx-6953-8485`: <https://github.com/advisories/GHSA-x2qx-6953-8485>
- GitPython 3.1.47 release: <https://github.com/gitpython-developers/GitPython/releases/tag/3.1.47>
- GitPython project: <https://github.com/gitpython-developers/GitPython>
