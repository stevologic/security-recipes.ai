---
title: "CVE-2026-42271 - LiteLLM MCP stdio command execution"
linkTitle: "CVE-2026-42271 LiteLLM MCP"
description: "High-severity LiteLLM proxy command execution through MCP stdio test endpoints. Upgrade to 1.83.7+, restrict test endpoints to PROXY_ADMIN, and block stdio previews at the gateway until patched."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["cve", "ghsa", "litellm", "mcp", "python", "pip", "command-injection", "high"]
weight: 56
date: 2026-06-11
cve: "CVE-2026-42271"
ghsa: "GHSA-v4p8-mg3p-g94g"
known_as: ["LiteLLM MCP stdio command execution", "GHSA-v4p8-mg3p-g94g"]
kev: false
severity: "high"
ecosystem: "python/pypi"
disclosed: "2026-04-25"
---

CVE-2026-42271 / GHSA-v4p8-mg3p-g94g covers LiteLLM proxy versions `1.74.2`
through `1.83.6`, which allowed authenticated command execution through MCP
REST preview endpoints. The affected endpoints accepted a full MCP server
configuration, including stdio transport fields such as `command`, `args`, and
`env`, then attempted to connect to that server.

Because the endpoints only required a valid proxy API key and did not require
the `PROXY_ADMIN` role, a low-privilege authenticated user could submit a stdio
configuration that spawned an arbitrary subprocess on the LiteLLM proxy host.
GitHub now tracks this reviewed advisory under CVE-2026-42271, so reviewers
should key PR titles, ticket links, and scanner suppressions to the CVE while
keeping the GHSA alias for Dependabot and GitHub Advisory Database matches.

## When to use it

Use this recipe when a repository builds, deploys, configures, or operates a
LiteLLM proxy with MCP REST preview/test endpoints, MCP server management, stdio
transports, API keys, gateway rules, or admin UI actions that can submit MCP
server definitions. It is most important when low-privilege or tenant-scoped
keys can reach proxy endpoints.

Use it to upgrade LiteLLM and enforce admin-only MCP stdio preview behavior. Do
not use it to prove exposure by running arbitrary commands through the affected
endpoints.

## Inputs

- Python manifests, constraints, lockfiles, Dockerfiles, compose files, Helm
  charts, Kubernetes manifests, Terraform, Ansible, reverse proxy rules, API
  gateway policy, MCP registry config, generated SBOMs, and LiteLLM runbooks.
- Resolved LiteLLM versions across local, CI, image, hosted proxy, and
  deployment environments.
- Endpoint reachability for `/mcp-rest/test/connection`,
  `/mcp-rest/test/tools/list`, aliases, proxy rewrites, service-mesh routes,
  and admin UI actions that call those paths.
- Role and key mapping for `PROXY_ADMIN`, internal users, tenant keys,
  low-privilege API keys, seeded users, gateway claims, and MCP permissions.
- Stdio configuration policy, command allow-lists, environment redaction,
  subprocess audit logs, runtime identity, provider credentials, and proxy
  secrets that may need rotation.

## Affected versions

- **Vulnerable:** `litellm >=1.74.2, <1.83.7`
- **Fixed:** `litellm 1.83.7+`
- **Affected endpoints:**
  - `POST /mcp-rest/test/connection`
  - `POST /mcp-rest/test/tools/list`

## Indicator-of-exposure

- The repository builds or deploys a LiteLLM proxy on `>=1.74.2, <1.83.7`.
- MCP server management or preview functionality is enabled.
- Non-admin proxy API keys can reach either affected endpoint.
- The proxy process can spawn subprocesses and has access to model provider
  credentials, cloud credentials, internal network routes, or tenant data.
- Reverse proxy, API gateway, or ingress rules expose `/mcp-rest/test/*` beyond
  a tightly controlled admin network.

Quick checks:

```bash
rg -n "litellm|LiteLLM|mcp-rest|test/tools/list|test/connection|PROXY_ADMIN|proxy_server" .
python -m pip show litellm
pip freeze | rg '^litellm=='
rg -n "/mcp-rest/test/(connection|tools/list)|mcp.*stdio|\"command\".*\"args\"|PROXY_ADMIN" Dockerfile* docker-compose*.yml charts deploy k8s nginx* traefik* .
```

Windows:

```powershell
rg -n "litellm|LiteLLM|mcp-rest|test/tools/list|test/connection|PROXY_ADMIN|proxy_server" .
python -m pip show litellm
python -m pip freeze | rg '^litellm=='
rg -n "/mcp-rest/test/(connection|tools/list)|mcp.*stdio|\"command\".*\"args\"|PROXY_ADMIN" Dockerfile* docker-compose*.yml charts deploy k8s nginx* traefik* .
```

## Remediation strategy

- Upgrade LiteLLM to `1.83.7+` everywhere the repository controls dependencies,
  images, or deployment manifests.
- Until the patched version is deployed, block
  `POST /mcp-rest/test/connection` and `POST /mcp-rest/test/tools/list` at the
  reverse proxy, API gateway, WAF, or service mesh.
- Verify only `PROXY_ADMIN` users can preview or save MCP server
  configurations.
- Treat stdio MCP server definitions as code execution requests. Require admin
  approval, command allow-lists, environment redaction, and audit logging.
- Rotate LiteLLM proxy keys and provider credentials if low-privilege users
  could access the endpoints during the exposure window.

## The prompt

~~~markdown
Model context: this prompt was generated by GPT 5.5 Extra High reasoning.

You are remediating CVE-2026-42271 / GHSA-v4p8-mg3p-g94g (LiteLLM
authenticated command execution via MCP stdio test endpoints). Produce exactly
one output:

- A reviewer-ready PR/change request that upgrades LiteLLM, restricts MCP test
  endpoints, adds verification, and documents operator cleanup, or
- TRIAGE.md if this repository does not own an affected LiteLLM proxy or safe
  patch path.

## Rules

- Scope only CVE-2026-42271 / GHSA-v4p8-mg3p-g94g.
- Treat LiteLLM API keys, model provider keys, MCP server environment values,
  tenant data, subprocess output, and proxy logs as sensitive.
- Do not run arbitrary commands through the affected endpoints to prove
  exposure.
- Do not preserve low-privilege access to stdio MCP preview behavior.
- Do not auto-merge.

## Steps

1. Inventory every LiteLLM reference controlled by this repository:
   Python manifests, lockfiles, Dockerfiles, compose files, Helm charts,
   Kubernetes manifests, Terraform, Ansible, reverse proxy config, API gateway
   policy, MCP server registry config, generated SBOMs, and runbooks.
2. Determine every resolved `litellm` version. A target is vulnerable if it
   resolves to `>=1.74.2, <1.83.7`.
3. Determine whether the affected endpoints are reachable:
   - `POST /mcp-rest/test/connection`;
   - `POST /mcp-rest/test/tools/list`;
   - any route alias, proxy rewrite, or admin UI action that calls those paths.
4. Determine whether non-admin proxy API keys can reach the endpoints. Search
   auth policy, role mapping, seeded users, integration tests, and gateway
   rules for `PROXY_ADMIN`, internal-user keys, and MCP admin permissions.
5. If this repository does not deploy a LiteLLM proxy or only contains client
   code, stop with `TRIAGE.md` naming the owner, files checked, and required
   fixed version `litellm 1.83.7+`.
6. Upgrade all controlled LiteLLM deployments to `1.83.7+`. Regenerate
   lockfiles, image digests, SBOMs, deployment render output, and dependency
   reports.
7. Add temporary or permanent gateway containment where this repo controls it:
   - deny `POST /mcp-rest/test/connection` and
     `POST /mcp-rest/test/tools/list` unless the caller is admin;
   - require `PROXY_ADMIN` for MCP preview and save operations;
   - fail closed for stdio transport previews if role context is unavailable.
8. Add safe tests or policy checks:
   - low-privilege/internal-user keys receive 403 for both affected endpoints;
   - `PROXY_ADMIN` remains required for stdio MCP test and save paths;
   - stdio configs with `command`, `args`, or `env` are never executed during
     unauthorized tests;
   - gateway render output contains the deny or admin-only rule.
9. Add operator hardening for MCP stdio definitions:
   - command allow-list or approved MCP server registry;
   - environment variable redaction;
   - subprocess audit logs without secret values;
   - least-privilege runtime identity for the proxy process.
10. Add a PR body section named `CVE-2026-42271 operator actions` that
    states:
    - LiteLLM versions before and after the change;
    - whether affected endpoints were externally or tenant reachable;
    - which roles could call them before the patch;
    - whether proxy API keys, provider keys, or MCP environment secrets should
      be rotated;
    - which logs should be reviewed for stdio configs or unexpected child
      processes.
11. Run relevant validation: dependency install, unit/API tests, authz tests,
    gateway/ingress rendering, container build, deployment diff, SBOM refresh,
    and dependency/security scans available in this repository.
12. Use PR title:
    `fix(sec): remediate CVE-2026-42271 in LiteLLM MCP endpoints`.

## Stop conditions

- No affected LiteLLM proxy deployment is controlled by this repository.
- A fixed LiteLLM version cannot be consumed without a broader proxy migration.
- Endpoint reachability cannot be verified without executing attacker-supplied
  commands.
- Existing product requirements intentionally allow non-admin users to create
  stdio MCP command definitions; document the risk and require a
  product/security decision.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled dependency, lockfile, image, SBOM, or deployment target resolves
  `litellm >=1.74.2, <1.83.7`.
- Low-privilege/internal-user keys cannot access either affected MCP test
  endpoint.
- Gateway or service policy blocks the endpoints during rollout if the upgrade
  is not atomic.
- Tests prove stdio MCP configs are not executed for unauthorized callers.
- Operator actions cover key rotation and log review when exposure was possible.

## Watch for

- Updating Python lockfiles while a Docker image, Helm value, or hosted proxy
  still pins an older LiteLLM release.
- Treating a valid proxy key as sufficient authorization for subprocess-capable
  MCP actions.
- Logging MCP `env` fields or provider credentials while adding tests.
- Allowing preview endpoints to bypass stricter controls used by the save path.

## Output contract

Return one of:

- A reviewer-ready PR/change request that upgrades every controlled LiteLLM
  deployment to `1.83.7+`, restricts MCP preview/test endpoints to
  `PROXY_ADMIN`, adds gateway containment where needed, enforces stdio command
  allow-lists and environment redaction, adds low-privilege 403 tests, refreshes
  deployment artifacts, and documents operator cleanup.
- `TRIAGE.md` when no controlled LiteLLM proxy, MCP preview/test endpoint,
  gateway policy, deployment artifact, or generated SBOM can contain the
  affected behavior.

The output must list LiteLLM versions before and after, affected endpoint
reachability, roles and key classes that could call the endpoints before the
patch, validation commands, keys or provider secrets to rotate, logs to review,
and whether temporary gateway containment remains. It must not execute
attacker-controlled stdio commands, log MCP `env` values, expose provider
credentials, or preserve low-privilege access to subprocess-capable MCP
previews.

## Related recipes

- [Agent session kill rules]({{< relref "/prompt-library/general/agent-session-kill-rules" >}})
- [Critical infrastructure secure context]({{< relref "/security-remediation/critical-infrastructure-secure-context" >}})
- [Source-code injection sink audit]({{< relref "/prompt-library/general/source-code-injection-sink-audit" >}})

## References

- GitHub Advisory: <https://github.com/advisories/GHSA-v4p8-mg3p-g94g>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-42271>
- LiteLLM `v1.83.7-stable` release: <https://github.com/BerriAI/litellm/releases/tag/v1.83.7-stable>
