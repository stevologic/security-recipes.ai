---
title: "GHSA-m99r-2hxc-cp3q - Flowise MCP security bypass RCE"
linkTitle: "GHSA-m99r Flowise MCP bypass"
description: "High-severity Flowise Custom MCP security bypass that reopens command execution through docker build, npx --yes, and node local-file path bypasses. Upgrade flowise and flowise-components to 3.1.2+ and replace deny-list MCP command validation with an approved registry."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "flowise", "mcp", "agentic-ai", "npm", "command-injection", "rce", "high"]
weight: 65
date: 2026-05-14
ghsa: "GHSA-m99r-2hxc-cp3q"
aliases: ["Flowise MCP security bypass", "Flowise Custom MCP incomplete fix"]
kev: false
severity: "high"
ecosystem: "typescript/npm"
disclosed: "2026-05-14"
---

Flowise and `flowise-components` versions `3.1.1` and earlier contain Custom
MCP security bypasses that can still lead to server-side command execution.
The important review lesson is that earlier Custom MCP command filtering was
deny-list based and incomplete: attackers could reach dangerous behavior
through `docker build`, the long `npx --yes` alias, or `node` arguments that
bypass local-file restrictions with alternate absolute-path spelling.

This is a follow-up hardening recipe for teams that already reacted to earlier
Flowise Custom MCP advisories. If Custom MCP stdio remains enabled, stopping at
`3.1.0` or `3.1.1` is not a mergeable fix; reviewers should require `3.1.2+`
plus authorization, import, and runtime containment checks.

## When to use it

Use this recipe when a repository deploys Flowise Custom MCP, embeds
`flowise-components`, or maintains MCP command validation policy. It is
designed for source-code remediation, MCP command-execution hardening,
deny-list replacement, and audit evidence that Custom MCP tools are limited to
an approved registry instead of shell-like command construction.

## Inputs

- Flowise and `flowise-components` versions, Custom MCP configuration,
  deployment manifests, command validation code, and allowed MCP tool registry.
- Source paths that invoke `docker`, `npx`, `node`, local file paths, package
  installers, or child processes for Custom MCP tools.
- Regression fixtures for bypass spellings, long-form aliases, absolute paths,
  package-manager command variants, and expected reject/allow decisions.
- Evidence of runtime reach: server filesystem, package tokens, Docker socket,
  network egress, environment variables, and workspace data.

## Affected versions

- **Vulnerable:** `flowise <=3.1.1`
- **Vulnerable:** `flowise-components <=3.1.1`
- **Fixed:** `flowise 3.1.2+` and `flowise-components 3.1.2+`
- **Affected surface:** Custom MCP stdio configuration saved through the UI,
  API, chatflow import/export, or workflow templates.
- **Bypass shapes:** dangerous Docker subcommands not covered by blocklists,
  package-manager long-option aliases, and local-file path validation bypasses
  for node-based MCP commands.

## Indicator-of-exposure

- The repository deploys, builds, vendors, or documents Flowise `<=3.1.1`.
- Authenticated users, workspace members, automation accounts, imported
  chatflows, or API clients can create, update, import, test, or execute Custom
  MCP server definitions.
- `docker`, `npx`, `node`, package managers, shells, or local interpreters are
  available in the Flowise runtime image.
- MCP server definitions can include raw `command`, `args`, `env`, file upload,
  or local path fields.
- Flowise runs with access to provider keys, workflow secrets, source
  repositories, cloud metadata, internal networks, writable storage, or mounted
  host paths.

Quick checks:

```bash
rg -n "flowise|flowise-components|Custom MCP|MCP|stdio|validateCommandFlags|validateArgsForLocalFileAccess|docker|npx|node|command.*args|chatflow|export-import|FLOWISE" .
npm ls flowise flowise-components
pnpm why flowise flowise-components
yarn why flowise flowise-components
rg -n "custom.*mcp|mcp.*custom|stdio|command|args|env|chatflow|FLOWISE_USERNAME|FLOWISE_PASSWORD" Dockerfile* docker-compose*.yml charts deploy k8s .github .
```

## Remediation strategy

- Upgrade `flowise` and `flowise-components` to `3.1.2+` everywhere this
  repository controls manifests, lockfiles, images, or deployment manifests.
- Disable Custom MCP stdio creation, update, import, and test paths until every
  runtime is patched and authorization is confirmed.
- Replace command deny-lists with an approved MCP server registry: pinned
  package or binary identity, finite server IDs, fixed launch arguments,
  environment redaction, and reviewer-approved runtime policy.
- Treat imported chatflows as executable supply-chain inputs. Reject or
  quarantine Custom MCP stdio definitions until reviewed.
- Remove `docker`, package managers, shells, and unnecessary interpreters from
  Flowise runtime images where possible; otherwise isolate workers with
  least-privilege users, read-only mounts, restricted egress, and no host socket
  access.
- Rotate Flowise, provider, MCP environment, and runtime credentials if
  untrusted users could save or import Custom MCP definitions while vulnerable.

## The prompt

~~~markdown
You are remediating GHSA-m99r-2hxc-cp3q, the Flowise Custom MCP security bypass
that can lead to command execution through incomplete stdio command filtering.
Produce exactly one output:

- A reviewer-ready PR/change request that upgrades Flowise to 3.1.2+, blocks or
  replaces unsafe Custom MCP stdio configuration, adds safe regression coverage,
  refreshes generated artifacts, and documents operator cleanup, or
- TRIAGE.md if this repository does not own an affected Flowise deployment or
  cannot make a safe change.

## Rules

- Scope only GHSA-m99r-2hxc-cp3q and directly related Custom MCP stdio
  hardening.
- Treat Flowise credentials, model provider keys, MCP `env` values, uploaded
  files, chatflow exports, tenant prompts, source code, application logs, and
  runtime environment variables as sensitive.
- Do not execute Custom MCP commands, run `docker build`, run `npx`, load local
  JavaScript files with `node`, trigger prediction endpoints, create reverse
  shells, beacon to external services, or print secrets to prove exposure.
- Do not rely on blocklists, prompt instructions, or UI-only validation as the
  sole security control for stdio MCP launch.
- Do not auto-merge.

## Steps

1. Inventory every Flowise runtime controlled by this repository:
   `package.json`, lockfiles, Dockerfiles, compose files, Helm charts,
   Kubernetes manifests, Terraform, Ansible, CI images, SBOMs, seed chatflows,
   exported chatflow JSON, environment templates, and runbooks.
2. Determine every resolved `flowise` and `flowise-components` version. A target
   is vulnerable if either package resolves to `<=3.1.1`.
3. Search for Custom MCP and stdio exposure:
   - Custom MCP node definitions;
   - exported or imported chatflows containing MCP server config;
   - API routes that create, update, import, test, or execute MCP definitions;
   - role checks for chatflow edit, workspace membership, API keys, and admin
     privileges;
   - config fields containing `command`, `args`, `env`, `stdio`, `docker`,
     `npx`, `node`, file uploads, or local executable references.
4. If this repository does not deploy Flowise or only contains unrelated client
   code, stop with `TRIAGE.md` listing files checked, runtime owner, and the
   required fixed version `Flowise 3.1.2+`.
5. Upgrade all controlled Flowise packages and images to `3.1.2+`. Regenerate
   lockfiles, image digests, SBOMs, deployment render output, and dependency
   reports.
6. Add containment for non-atomic rollouts:
   - disable Custom MCP stdio create, update, test, import, and execution paths;
   - block chatflow imports that contain stdio MCP config unless reviewed by an
     administrator;
   - fail closed when the Flowise version, node type, or transport type cannot
     be determined;
   - deny raw `command`, `args`, and `env` edits from non-admin callers.
7. Replace unsafe configuration patterns where this repo controls product code:
   - do not accept raw command strings from users;
   - map approved MCP server IDs to pinned binaries or packages;
   - use fixed argument templates rather than user-controlled args;
   - reject Docker, package-manager, shell, interpreter, and local-file launch
     paths unless explicitly approved for an isolated worker profile;
   - redact environment values from logs, reports, API responses, and browser
     errors.
8. Add safe tests or policy checks that do not execute commands:
   - dependency policy rejects `flowise` and `flowise-components <=3.1.1`;
   - non-admin roles cannot create, update, import, test, or enable stdio MCP
     servers;
   - imported chatflows containing stdio MCP config fail closed until reviewed;
   - blocklist bypass shapes such as Docker subcommands, package-manager long
     aliases, and alternate absolute paths are rejected by allow-list policy;
   - gateway render output contains any temporary deny or admin-only rules.
9. Harden the Flowise runtime where this repository controls deployment:
   - remove Docker socket access and package managers from runtime containers;
   - run with a least-privilege service identity;
   - remove cloud metadata and deployment-admin access;
   - restrict egress from Flowise workers;
   - mount only required paths read-only where possible;
   - ensure logs never contain provider keys, MCP env values, tenant prompts,
     uploaded-file contents, or full chatflow secrets.
10. Add a PR body section named `GHSA-m99r-2hxc-cp3q operator actions` that
    states:
    - Flowise versions before and after the change;
    - whether prior remediation stopped at `3.1.0` or `3.1.1`;
    - whether Custom MCP stdio was enabled;
    - which roles could create, update, import, test, or execute MCP server
      definitions before the patch;
    - whether runtime images included Docker, package managers, shells, or
      local interpreters;
    - whether Flowise, provider, MCP environment, and runtime credentials should
      be rotated;
    - which audit, application, gateway, and process logs should be reviewed for
      suspicious MCP server definitions or unexpected child processes.
11. Run relevant validation: package install, lockfile integrity, unit/API
    tests, role/authorization tests, chatflow import checks, gateway policy
    tests, image build, deployment diff, SBOM refresh, and dependency/security
    scans available in this repository.
12. Use PR title:
    `fix(sec): remediate GHSA-m99r Flowise MCP bypass`.

## Stop conditions

- No affected Flowise runtime is controlled by this repository.
- A fixed Flowise version cannot be consumed without a broader migration.
- Product requirements intentionally allow non-admin tenants to define local
  MCP stdio commands; document the risk and require a product/security
  decision.
- Verification would require executing attacker-controlled commands, package
  installers, Docker builds, local JavaScript, prediction requests, or MCP
  server definitions.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Output contract

- A reviewer-ready PR or change request that upgrades Flowise components,
  replaces deny-list command validation with an approved registry, adds bypass
  regression tests, and documents operator cleanup.
- Or a `TRIAGE.md` file that lists inspected files, owner, observed versions,
  Custom MCP exposure, command-execution boundary, required fix, and residual
  risk.
- The output must include exact validation commands and must not run Docker,
  package installers, arbitrary Node files, or payloads against production
  Flowise instances.

## Verification - what the reviewer looks for

- No controlled package, lockfile, image, SBOM, or deployment target resolves
  `flowise` or `flowise-components` to `<=3.1.1`.
- Custom MCP stdio create, update, import, test, and execution paths are
  admin-only or disabled until reviewed.
- Raw command entry has been replaced by an approved MCP server registry or
  equivalent allow-list policy.
- Tests cover bypass classes without executing subprocesses.
- Operator actions cover credential rotation and log review when exposure was
  possible.

## Watch for

- Treating `Flowise 3.1.0` or `3.1.1` as sufficient after earlier Custom MCP
  advisories.
- Blocking `docker run` but leaving `docker build`, `docker cp`, package
  manager aliases, shell wrappers, or interpreter paths reachable.
- Rejecting `/path` but accepting alternate absolute-path spellings or uploaded
  local files loaded by an interpreter.
- Blocking the UI while import, API, template, or prediction paths still save
  or execute stdio MCP definitions.
- Logging command arguments, MCP environment values, uploaded file contents,
  prompt content, or provider credentials while adding validation.

## Related recipes

- [Source code injection sink audit]({{< relref "/prompt-library/general/source-code-injection-sink-audit" >}})
- [Source code attack surface map]({{< relref "/prompt-library/general/source-code-attack-surface-map" >}})
- [Source code supply chain build integrity audit]({{< relref "/prompt-library/general/source-code-supply-chain-build-integrity-audit" >}})
- [SAST finding triage and fix]({{< relref "/prompt-library/general/sast-finding-triage-and-fix" >}})

## References

- GitHub Advisory: <https://github.com/advisories/GHSA-m99r-2hxc-cp3q>
- OSV: <https://osv.dev/vulnerability/GHSA-m99r-2hxc-cp3q>
- Flowise `flowise@3.1.2` release: <https://github.com/FlowiseAI/Flowise/releases/tag/flowise%403.1.2>
