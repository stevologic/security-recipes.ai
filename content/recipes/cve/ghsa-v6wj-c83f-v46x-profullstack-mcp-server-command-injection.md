---
title: "GHSA-v6wj-c83f-v46x - profullstack MCP server command injection"
linkTitle: "GHSA-v6wj profullstack MCP"
description: "Critical unauthenticated command injection in @profullstack/mcp-server domain_lookup. Remove exposed vulnerable servers, replace shell execution with argv-based process calls, and require MCP auth/bind controls."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "mcp", "npm", "command-injection", "critical", "agentic-ai"]
weight: 65
date: 2026-05-12
ghsa: "GHSA-v6wj-c83f-v46x"
known_as: ["profullstack MCP server domain_lookup command injection"]
kev: false
severity: "critical"
ecosystem: "npm"
disclosed: "2026-05-09"
---

`@profullstack/mcp-server` exposes a `domain_lookup` module where attacker
controlled `domains` or `keywords` are concatenated into a shell command and
passed to process execution. The vulnerable routes are HTTP reachable and the
reported default posture binds broadly without a global authentication layer,
making this a remote command execution issue rather than only a local plugin
bug.

For agentic AI deployments, the important boundary is simple: an MCP tool that
looks like passive DNS/domain enrichment is actually a command execution
surface. The fix must address the process call, the network exposure, and the
MCP server admission policy.

## When to use it

Use this recipe when a repository, MCP catalog, agent gateway, or developer
workbench installs `@profullstack/mcp-server` or exposes domain lookup tools.
It focuses on MCP command-injection remediation, unauthenticated HTTP exposure,
argv-based process execution, and audit evidence that network-supplied lookup
inputs cannot reach a shell.

## Inputs

- Package version, lockfile, MCP config, HTTP route exposure, bind address,
  authentication middleware, and enabled `domain_lookup` tools.
- Source paths that parse domains/keywords, construct lookup commands, call
  subprocess APIs, or render errors/logs.
- Regression fixtures for metacharacters, multiple domains, keyword lists,
  invalid hostnames, and expected reject/allow behavior.
- Runtime boundary evidence: server filesystem, credentials, DNS/network
  access, shell availability, logs, and who can reach the MCP HTTP server.

## Affected versions

| Package | Vulnerable versions | Fixed versions |
| --- | --- | --- |
| `@profullstack/mcp-server` | `<=1.4.12` | No patched version published in GHAD at intake |

## Indicator-of-exposure

- The repository installs, launches, documents, containers, or vendors
  `@profullstack/mcp-server <=1.4.12`.
- MCP or HTTP routes expose `/domain-lookup/check` or `/domain-lookup/bulk`.
- The server is reachable by browsers, local containers, internal users,
  agents, CI jobs, or untrusted tenants without strong authentication.
- Domain lookup code builds a command string for `tldx` instead of passing an
  executable plus an argument array.

Quick checks:

```bash
rg -n "@profullstack/mcp-server|domain-lookup|domain_lookup|tldx|execAsync|child_process\\.exec|/domain-lookup/(check|bulk)|0\\.0\\.0\\.0" .
npm ls @profullstack/mcp-server
pnpm why @profullstack/mcp-server
yarn why @profullstack/mcp-server
```

## Remediation strategy

- Remove or disable `@profullstack/mcp-server` wherever a patched release is
  not available.
- If the repository owns a fork or local module, replace shell-string execution
  with `execFile` or `spawn` using a fixed executable and validated argv.
- Validate domain names and keywords against strict hostname/token rules before
  invoking external tools.
- Require authentication for every HTTP-exposed MCP module and bind to
  `127.0.0.1` unless a reviewed deployment explicitly needs remote access.
- Add an MCP server intake check that rejects tools whose schemas eventually
  flow into shells, interpreters, package managers, or subprocess launchers.
- Rotate secrets if the vulnerable MCP server could access model provider keys,
  CI tokens, cloud credentials, SSH keys, or source workspaces.

## The prompt

~~~markdown
You are remediating GHSA-v6wj-c83f-v46x in `@profullstack/mcp-server`.
Produce exactly one output:

- A reviewer-ready PR/change request that removes or safely patches the
  vulnerable MCP domain lookup surface, hardens MCP server exposure, refreshes
  generated artifacts, and documents operator rotation actions, or
- TRIAGE.md if this repository does not control an affected deployment or no
  safe patch can be made.

## Rules

- Scope only GHSA-v6wj-c83f-v46x and directly related MCP command-execution
  hardening.
- Do not execute command-injection payloads, reverse shells, network callbacks,
  curl-pipe-shell commands, or proof commands that write files.
- Do not print or commit secrets, tokens, MCP client configs, environment
  variables, shell history, workspace archives, or package-manager credentials.
- Do not expose a patched MCP server remotely without authentication and an
  explicit bind-address decision.
- Do not auto-merge.

## Steps

1. Inventory package manifests, lockfiles, Dockerfiles, compose files, Helm
   charts, MCP client configs, runbooks, CI workflows, examples, and SBOMs for
   `@profullstack/mcp-server`, `domain_lookup`, `domain-lookup`, and `tldx`.
2. Determine whether any controlled target resolves `@profullstack/mcp-server`
   `<=1.4.12` or vendors equivalent vulnerable code.
3. Find all domain lookup handlers and subprocess calls. Flag any code that
   uses `exec`, `execSync`, `execAsync`, `shell: true`, or command-string
   concatenation with user-controlled `domains`, `keywords`, prefixes, suffixes,
   TLDs, or options.
4. Prefer removal or disabling of the vulnerable MCP module until a patched
   upstream release exists. If a local patch is required, replace the command
   string with a fixed executable and argv array using `execFile` or `spawn`.
5. Add validation that rejects shell metacharacters and only accepts expected
   domain/keyword shapes. Keep this validation as defense in depth, not as the
   only shell-safety control.
6. Add MCP exposure controls:
   - default bind address is loopback;
   - non-loopback bind requires authentication;
   - every HTTP route has global auth middleware;
   - tool schemas do not imply approval to launch arbitrary commands;
   - server environment excludes broad secrets by default.
7. Add regression tests that pass malicious-looking branch/domain/keyword input
   and assert argv is passed literally or rejected, without running a shell.
8. Refresh lockfiles, SBOMs, generated MCP manifests, deployment manifests, and
   documentation affected by the change.
9. Add a PR body section named `GHSA-v6wj-c83f-v46x operator actions` covering:
   affected MCP servers, before/after versions or removal, bind/auth posture,
   shell execution call sites, secrets reachable by the old process, and
   whether credentials should be rotated.
10. Run relevant validation: package install, unit tests, MCP tool tests,
    container build, lint/typecheck, SBOM refresh, dependency scan, and config
    policy checks.
11. Use PR title:
    `fix(sec): remove profullstack MCP command injection`.

## Stop conditions

- No affected MCP server, dependency, container, or runbook is controlled by
  this repository.
- No patched upstream exists and the repository cannot safely remove or fork
  the vulnerable server.
- Validation would require executing attacker-controlled shell syntax.
- The server must remain unauthenticated or remotely exposed for product
  reasons; document the owner decision required in TRIAGE.md.
- Validation fails for unrelated pre-existing reasons; document those failures
  without broadening scope.
~~~

## Output contract

- A reviewer-ready PR or change request that removes vulnerable exposure,
  replaces shell execution with validated argv calls, requires MCP auth/bind
  controls, adds regression tests, and documents operator cleanup.
- Or a `TRIAGE.md` file that lists inspected files, owner, observed version,
  exposed routes/tools, command-execution boundary, required fix, and residual
  risk.
- The output must include exact validation commands and must not run exploit
  payloads, shell commands, or tests against production MCP servers.

## Verification - what the reviewer looks for

- No controlled deployment resolves `@profullstack/mcp-server <=1.4.12`.
- No domain lookup handler passes user-controlled input through a shell command
  string.
- HTTP-exposed MCP routes require authentication or are loopback-only.
- Tests prove dangerous input is rejected or passed literally without shell
  interpretation.
- Operator notes address secret rotation and old MCP server shutdown.

## Watch for

- Example MCP configs or Docker images that keep the vulnerable server alive
  after application dependencies are fixed.
- "Internal only" MCP servers reachable from browsers through DNS rebinding,
  local containers, shared workstations, or agent runtimes.
- Patches that add regex escaping while still invoking a shell.

## Related recipes

- [Source code injection sink audit]({{< relref "/recipes/general/source-code-injection-sink-audit" >}})
- [Source code attack surface map]({{< relref "/recipes/general/source-code-attack-surface-map" >}})
- [Source code secrets and data exposure audit]({{< relref "/recipes/general/source-code-secrets-data-exposure-audit" >}})
- [SAST finding triage and fix]({{< relref "/recipes/general/sast-finding-triage-and-fix" >}})

## References

- GitHub Advisory: <https://github.com/advisories/GHSA-v6wj-c83f-v46x>
- Vendor advisory: <https://github.com/profullstack/mcp-server/security/advisories/GHSA-v6wj-c83f-v46x>
- Package source: <https://github.com/profullstack/mcp-server>
