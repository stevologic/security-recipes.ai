---
title: "GHSA-vr7g-88fq-vhq3 - Paperclip workspace cleanup command injection"
linkTitle: "GHSA-vr7g Paperclip cleanupCommand"
description: "Critical Paperclip OS command injection through execution workspace cleanupCommand. Upgrade to 2026.416.0+, remove shell-backed cleanup strings, and add lifecycle-action allow-list tests."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "paperclip", "agentic-ai", "npm", "command-injection", "workspace", "critical"]
weight: 47
date: 2026-05-02
ghsa: "GHSA-vr7g-88fq-vhq3"
known_as: ["Paperclip cleanupCommand OS command injection"]
kev: false
severity: "critical"
ecosystem: "typescript/npm"
disclosed: "2026-04-16"
---

Paperclip versions before `2026.416.0` allowed OS command injection through the
execution workspace lifecycle. The vulnerable API accepted
`config.cleanupCommand` through `PATCH /api/execution-workspaces/:id`, stored
that value, and later executed it through a shell during workspace cleanup.

This is especially dangerous for agent workspaces because cleanup runs at a
privileged lifecycle boundary: the server may have source code, generated
artifacts, browser state, credentials, local files, and network access that the
agent used during execution.

## When to use it

Use this recipe when a repository, agent workspace service, or Paperclip
deployment allows users or agents to configure execution-workspace lifecycle
actions. It is designed for source-code remediation, command-injection review,
workspace cleanup hardening, and audit evidence that lifecycle hooks cannot
execute arbitrary shell strings.

## Inputs

- Paperclip version, deployment config, execution-workspace API routes, and
  all code paths that read or persist `cleanupCommand`.
- Source paths for workspace cleanup, lifecycle action dispatch, process
  execution, config validation, and authorization checks.
- Regression fixtures for shell metacharacters, command arrays, allow-listed
  cleanup actions, and denied custom commands.
- Runtime boundary evidence: workspace files, generated artifacts, browser
  state, credentials, network reach, and which users can patch workspace config.

## Affected versions

- **Vulnerable:** `@paperclipai/server <2026.416.0`
- **Fixed:** `@paperclipai/server 2026.416.0+`
- **Affected endpoint:** `PATCH /api/execution-workspaces/:id`
- **Affected field:** `config.cleanupCommand`
- **Affected sink:** shell execution during workspace archive/cleanup.

## Indicator-of-exposure

- The repository deploys or packages `@paperclipai/server <2026.416.0`.
- Execution workspace APIs are enabled.
- `local_trusted` mode, desktop mode, localhost APIs, or authenticated company
  users can patch workspace config.
- Workspace cleanup accepts arbitrary strings or shell snippets.
- The server runs with access to repositories, local files, browser profiles,
  package tokens, cloud credentials, SSH keys, or internal networks.

Quick checks:

```bash
rg -n "@paperclipai/server|paperclip|execution-workspaces|cleanupCommand|cleanupCommands|workspace-runtime|recordWorkspaceCommandOperation|spawn\\(|shell.*-c|resolveShell" .
npm ls @paperclipai/server
pnpm why @paperclipai/server
yarn why @paperclipai/server
rg -n "local_trusted|trusted.*local|execution workspace|archive.*workspace|cleanup.*command" Dockerfile* docker-compose*.yml charts deploy server src packages
```

## Remediation strategy

- Upgrade `@paperclipai/server` to `2026.416.0+` everywhere this repository
  controls package manifests, lockfiles, images, or deployment manifests.
- Remove shell-backed cleanup command strings from workspace configuration.
- Replace cleanup commands with a finite set of typed lifecycle actions such as
  deleting known workspace-owned directories, closing sessions, or revoking
  ephemeral credentials.
- If a command must be launched, use an argument-array API with a fixed
  executable, fixed arguments, no shell, and no tenant/user-controlled command
  text.
- Restrict workspace patch APIs by tenant, role, and workspace ownership.
- Review workspace audit logs and rotate credentials if untrusted users could
  patch cleanup commands.

## The prompt

~~~markdown
You are remediating GHSA-vr7g-88fq-vhq3 (Paperclip execution workspace
cleanupCommand OS command injection). Produce exactly one output:

- A reviewer-ready PR/change request that upgrades Paperclip or removes the
  shell-backed cleanup path, adds regression coverage, and documents operator
  cleanup, or
- TRIAGE.md if this repository does not own an affected Paperclip deployment or
  cannot make a safe change.

## Rules

- Scope only GHSA-vr7g-88fq-vhq3.
- Treat workspace files, repository contents, browser state, package tokens,
  cloud credentials, SSH keys, API keys, process output, and audit logs as
  sensitive.
- Do not run exploit payloads, shell commands, or cleanupCommand values against
  production, staging, shared dev, or real user workspaces.
- Do not replace `shell -c` with another shell wrapper or escaping-only fix.
- Do not auto-merge.

## Steps

1. Inventory every Paperclip runtime controlled by this repository:
   package manifests, lockfiles, Dockerfiles, compose files, Helm charts,
   Kubernetes manifests, Terraform, CI images, deployment docs, SBOMs, and
   vendored server code.
2. Determine every resolved `@paperclipai/server` version. A target is
   vulnerable if it resolves below `2026.416.0`.
3. Search workspace lifecycle code and config for `cleanupCommand`,
   `cleanupCommands`, `execution-workspaces`, `workspace-runtime`, `spawn`,
   `exec`, `shell -c`, and archive/cleanup hooks.
4. If this repository does not deploy Paperclip or only contains unrelated
   client code, stop with `TRIAGE.md` listing files checked and the runtime
   owner.
5. Prefer upgrading to `@paperclipai/server 2026.416.0+`. Regenerate lockfiles,
   image digests, SBOMs, and deployment render output.
6. If this repository owns a fork or vendored patch path, remove shell-backed
   cleanup:
   - delete `cleanupCommand` as a user-controlled string field;
   - define typed cleanup actions with fixed behavior;
   - reject unknown cleanup action types and legacy command strings;
   - avoid `child_process.exec`, `spawn(shell, ["-c", value])`, and equivalent
     shell invocation;
   - if launching a helper is unavoidable, use a fixed executable and fixed
     argument array with no shell.
7. Patch authorization around workspace mutation:
   - require workspace ownership/company access before patching config;
   - deny unauthenticated mutation in local or desktop modes unless protected by
     a local-only trust boundary and explicit user approval;
   - reject config updates for archived or foreign workspaces.
8. Add regression tests:
   - patching `cleanupCommand` is rejected or ignored;
   - cleanup lifecycle never calls a shell with tenant/user-controlled text;
   - only allowed typed cleanup actions execute;
   - cross-tenant workspace config patches are denied;
   - local trusted mode does not expose a remote unauthenticated mutation path.
9. Add operator hardening:
   - run workspace services as least-privilege users;
   - isolate workspaces per tenant/job;
   - scrub environment variables before workspace lifecycle operations;
   - revoke ephemeral credentials on archive through typed cleanup actions.
10. Add a PR body section named `GHSA-vr7g workspace operator actions` that
    states:
    - affected Paperclip versions before and after the change;
    - whether `local_trusted` or unauthenticated local APIs were enabled;
    - whether untrusted users could patch execution workspace config;
    - which workspace logs should be reviewed for suspicious cleanup commands;
    - which credentials or workspace artifacts require rotation or quarantine.
11. Run relevant validation: package install, lockfile checks, route tests,
    workspace lifecycle tests, authorization tests, lint/typecheck, image build,
    SBOM refresh, and dependency/security scans available in this repository.
12. Use PR title:
    `fix(sec): remove Paperclip cleanupCommand shell execution`.

## Stop conditions

- No affected Paperclip server deployment is controlled by this repository.
- A fixed Paperclip version cannot be consumed without a broader migration.
- Product requirements depend on arbitrary user-provided cleanup commands;
  document the risk and require a product/security decision.
- Verification would require executing attacker-controlled commands.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Output contract

- A reviewer-ready PR or change request that upgrades Paperclip, removes
  shell-backed cleanup strings, adds lifecycle-action allow-list tests, and
  documents cleanup/operator follow-up.
- Or a `TRIAGE.md` file that lists inspected files, owner, observed version,
  workspace API exposure, cleanup boundary, required fix, and residual risk.
- The output must include exact validation commands and must not execute shell
  payloads, delete real workspaces, or expose credentials from agent sessions.

## Verification - what the reviewer looks for

- No controlled package, lockfile, image, SBOM, or deployment target resolves
  `@paperclipai/server` below `2026.416.0`.
- Workspace cleanup no longer executes tenant/user-controlled strings through a
  shell.
- Patch routes enforce tenant/workspace ownership.
- Regression tests prove legacy `cleanupCommand` input fails closed.
- Operator actions cover workspace log review and credential rotation when
  exposure was possible.

## Watch for

- Escaping `cleanupCommand` instead of removing shell execution.
- Allowing cleanup hooks from templates, project files, or imported workspaces
  to bypass route-level validation.
- Treating localhost APIs as safe while browsers, extensions, or other local
  processes can reach them.
- Logging command strings that contain secrets or file paths.

## Related recipes

- [Source code injection sink audit]({{< relref "/prompt-library/general/source-code-injection-sink-audit" >}})
- [Source code attack surface map]({{< relref "/prompt-library/general/source-code-attack-surface-map" >}})
- [Source code authz tenant boundary audit]({{< relref "/prompt-library/general/source-code-authz-tenant-boundary-audit" >}})
- [SAST finding triage and fix]({{< relref "/prompt-library/general/sast-finding-triage-and-fix" >}})

## References

- GitHub Advisory: <https://github.com/advisories/GHSA-vr7g-88fq-vhq3>
- Paperclip project: <https://github.com/paperclipai/paperclip>

