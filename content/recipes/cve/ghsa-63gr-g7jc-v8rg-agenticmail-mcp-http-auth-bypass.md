---
title: "GHSA-63gr-g7jc-v8rg - AgenticMail MCP HTTP auth bypass"
linkTitle: "GHSA-63gr AgenticMail MCP"
description: "High-severity @agenticmail/mcp HTTP transport authorization bypass. Upgrade to 0.9.27+, require auth on /mcp, bind locally by default, and disable master-key tools on unauthenticated transports."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "agenticmail", "mcp", "npm", "authentication", "authorization", "agent-tools", "high"]
weight: 80
date: 2026-06-07
ghsa: "GHSA-63gr-g7jc-v8rg"
known_as: ["AgenticMail MCP HTTP authorization bypass"]
kev: false
severity: "high"
ecosystem: "typescript/npm"
disclosed: "2026-05-29"
---

`@agenticmail/mcp` versions before `0.9.27` can expose a Streamable HTTP
transport with no HTTP authentication when started with `--http` or
`MCP_HTTP=1`. The `/mcp` endpoint can accept remote MCP sessions and tool calls
without requiring a bearer token, shared secret, or master key from the client.

The higher-impact issue is confused authorization: tools documented as requiring
`AGENTICMAIL_MASTER_KEY` are forwarded by the server using the server process's
own configured master key. Any network client that can reach the MCP HTTP port
can therefore become an indirect caller of master-key-only operations.

## When to use it

Use this recipe when a repository, AgenticMail deployment, MCP gateway, or
desktop profile starts `@agenticmail/mcp` with Streamable HTTP transport. It is
aimed at source-code remediation, MCP HTTP auth hardening, master-key
containment, and audit evidence that unauthenticated clients cannot invoke
mail tools through the server's configured credentials.

## Inputs

- `@agenticmail/mcp` version, HTTP transport flags, bind address, auth config,
  gateway/ingress rules, and enabled mail tools.
- Evidence of `AGENTICMAIL_MASTER_KEY` handling, per-tool authorization,
  missing/invalid auth behavior, error/log redaction, and session creation.
- Regression fixtures for unauthenticated `/mcp`, invalid bearer tokens, valid
  tokens, master-key-only tools, local binding, and remote transport denial.
- Boundary notes for reachable clients: loopback, LAN, shared workbench,
  internal gateway, internet, and any mailbox/account data reachable by tools.

## Affected versions

- **Vulnerable package:** `@agenticmail/mcp <0.9.27`
- **Fixed package:** `@agenticmail/mcp 0.9.27+`
- **Affected mode:** Streamable HTTP transport via `--http` or `MCP_HTTP=1`
- **Affected endpoint:** `/mcp`
- **Affected capability class:** administrative, gateway, and master-key-only
  MCP tools forwarded with server-side `AGENTICMAIL_MASTER_KEY`

## Indicator-of-exposure

- The repository installs, vendors, images, deploys, or documents
  `@agenticmail/mcp <0.9.27`.
- The MCP server starts in HTTP mode through `--http`, `MCP_HTTP=1`, npm
  scripts, Docker commands, process managers, devcontainers, or deployment
  manifests.
- The `/mcp` HTTP endpoint is reachable from anything other than a trusted local
  process.
- `AGENTICMAIL_MASTER_KEY` is present in the MCP server environment.
- Admin or gateway tools such as relay setup, domain setup, agent deletion,
  cleanup, or test email sending are exposed through the same MCP server.

Quick checks:

```bash
rg -n "@agenticmail/mcp|AGENTICMAIL_MASTER_KEY|MCP_HTTP|--http|/mcp|setup_email_relay|setup_email_domain|delete_agent|cleanup_agents|send_test_email" .
npm ls @agenticmail/mcp
pnpm why @agenticmail/mcp
yarn why @agenticmail/mcp
rg -n "@agenticmail/mcp|MCP_HTTP|AGENTICMAIL_MASTER_KEY|--http|/mcp|0\\.0\\.0\\.0|ports:" package.json package-lock.json pnpm-lock.yaml yarn.lock Dockerfile* docker-compose*.yml compose*.yaml charts deploy k8s .devcontainer . 2>/dev/null
```

Windows:

```powershell
rg -n "@agenticmail/mcp|AGENTICMAIL_MASTER_KEY|MCP_HTTP|--http|/mcp|setup_email_relay|setup_email_domain|delete_agent|cleanup_agents|send_test_email" .
npm ls @agenticmail/mcp
pnpm why @agenticmail/mcp
yarn why @agenticmail/mcp
rg -n "@agenticmail/mcp|MCP_HTTP|AGENTICMAIL_MASTER_KEY|--http|/mcp|0\\.0\\.0\\.0|ports:" package.json package-lock.json pnpm-lock.yaml yarn.lock Dockerfile* docker-compose*.yml compose*.yaml charts deploy k8s .devcontainer .
```

Do not validate by invoking master-key tools, changing email domains, sending
test messages, deleting agents, printing master keys, or calling live
production AgenticMail endpoints.

## Remediation strategy

- Upgrade every controlled `@agenticmail/mcp` dependency, lockfile, image,
  generated dependency report, and SBOM to `0.9.27+`.
- Bind HTTP MCP mode to `127.0.0.1` by default. Remove accidental public, LAN,
  devcontainer, tunnel, or preview exposure unless a reviewed auth gateway is
  in front of `/mcp`.
- Require HTTP authentication for `/mcp` before accepting session initialize or
  tool calls. Use a bearer token, shared secret, mTLS, reverse-proxy auth, or a
  local-only transport boundary appropriate to the deployment.
- Disable master-key-only tools when the HTTP transport lacks an authenticated
  caller identity with explicit admin authorization.
- Split user-level MCP tools from administrative/gateway setup tools where
  possible, and keep `AGENTICMAIL_MASTER_KEY` out of user-facing MCP runtime
  environments.
- Rotate `AGENTICMAIL_MASTER_KEY`, API keys, mail relay credentials, and agent
  credentials if the affected HTTP endpoint was reachable by untrusted clients.

## The prompt

~~~markdown
You are remediating GHSA-63gr-g7jc-v8rg, a high-severity
`@agenticmail/mcp` HTTP authorization bypass where unauthenticated clients can
call MCP tools and indirectly use the server-side `AGENTICMAIL_MASTER_KEY`.
Produce exactly one output:

- A reviewer-ready PR/change request that upgrades `@agenticmail/mcp`, requires
  authentication for `/mcp`, contains master-key tools, refreshes generated
  artifacts, and documents operator cleanup, or
- TRIAGE.md if this repository does not control an affected AgenticMail MCP
  runtime, package, image, or deployment.

## Rules

- Scope only GHSA-63gr-g7jc-v8rg and directly related AgenticMail MCP HTTP
  authentication, authorization, transport exposure, and secret cleanup.
- Treat `AGENTICMAIL_MASTER_KEY`, API keys, SMTP/IMAP credentials, SMS/phone
  credentials, email contents, agent inboxes, logs, MCP session IDs, and
  customer/tenant data as sensitive.
- Do not invoke live master-key tools, delete agents, alter email domains,
  send test messages, print secrets, or call production `/mcp` endpoints to
  prove exposure.
- Do not leave unauthenticated HTTP MCP mode with administrative tools enabled.
- Do not auto-merge.

## Steps

1. Inventory every `@agenticmail/mcp` reference controlled by this repository:
   package manifests, lockfiles, Dockerfiles, compose files, devcontainers,
   process managers, Helm/Kubernetes manifests, MCP client/server config,
   reverse proxy config, generated SBOMs, dependency reports, and docs.
2. Determine every resolved package version. A target is vulnerable if it
   resolves to `@agenticmail/mcp <0.9.27`.
3. Search for HTTP MCP launch paths:
   `--http`, `MCP_HTTP=1`, `/mcp`, published ports, `0.0.0.0`, tunnels,
   preview URLs, devcontainer forwarding, Codespaces, process manager commands,
   and reverse proxy routes.
4. Search for privileged runtime context:
   `AGENTICMAIL_MASTER_KEY`, relay/domain setup tools, agent deletion/cleanup
   tools, test email sending, gateway/admin actions, seeded admin credentials,
   and MCP clients reachable by untrusted users or agents.
5. If this repository only contains unrelated docs or client code, stop with
   `TRIAGE.md` naming the runtime owner, files checked, and required fixed
   version `0.9.27+`.
6. Upgrade all controlled package references to `@agenticmail/mcp 0.9.27+`.
   Regenerate lockfiles, package-manager metadata, image digests, deployment
   render output, generated dependency reports, and SBOMs.
7. Harden `/mcp` exposure:
   - bind HTTP MCP mode to `127.0.0.1` by default;
   - remove accidental `0.0.0.0`, LAN, public, tunnel, and forwarded-port
     defaults;
   - require a validated Authorization header, shared secret, mTLS identity,
     reverse-proxy auth, or equivalent local-only boundary before accepting
     MCP initialize or tool calls;
   - fail closed if auth context is missing or ambiguous.
8. Contain master-key behavior:
   - remove `AGENTICMAIL_MASTER_KEY` from user-facing MCP HTTP runtimes where
     possible;
   - disable or split master-key-only tools from normal MCP toolsets;
   - require explicit admin authorization for relay setup, domain setup, agent
     deletion, cleanup, and outbound test-message tools;
   - avoid logging master keys, session IDs, email contents, or tool arguments
     containing tenant data.
9. Add safe tests or policy checks:
   - resolved package version is `0.9.27+`;
   - unauthenticated `/mcp` initialize and `tools/call` requests fail;
   - non-admin callers cannot invoke master-key-only tools;
   - admin callers retain intended access through the authenticated path;
   - gateway/reverse-proxy render output contains the required auth rule;
   - logs and snapshots redact secrets and email content.
10. Add a PR body section named `GHSA-63gr-g7jc-v8rg operator actions` that
    states:
    - `@agenticmail/mcp` versions before and after;
    - whether HTTP mode was enabled;
    - effective bind address, published ports, and auth boundary;
    - whether `AGENTICMAIL_MASTER_KEY` was present in the MCP process;
    - which admin/gateway tools were reachable;
    - which keys, relay credentials, agent credentials, or logs need review or
      rotation;
    - which validation commands passed.
11. Run available validation: package install, lockfile integrity, unit/API
    auth tests, MCP config validation, gateway/ingress rendering, container
    build, SBOM refresh, dependency/security scans, and safe HTTP auth tests
    against local fixtures only.
12. Use PR title:
    `fix(sec): remediate GHSA-63gr in AgenticMail MCP`.

## Stop conditions

- No affected AgenticMail MCP runtime, dependency, image, or MCP registration
  is controlled by this repository.
- A fixed version cannot be consumed without a broader AgenticMail migration.
- Exposure can only be verified by invoking live master-key tools, sending
  messages, altering domains, deleting agents, or touching production data.
- Product requirements intentionally expose HTTP MCP to untrusted users without
  authentication; document the security-owner decision required in `TRIAGE.md`.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Output contract

- A reviewer-ready PR or change request that upgrades AgenticMail MCP, requires
  HTTP auth on `/mcp`, binds locally by default, disables master-key forwarding
  on unauthenticated transports, adds tests, and documents key cleanup.
- Or a `TRIAGE.md` file that lists inspected files, owner, observed version,
  endpoint exposure, master-key reach, required fix, and rotation
  recommendation.
- The output must include exact validation commands and must not expose real
  mail content, master keys, bearer headers, mailbox metadata, or production
  logs.

## Verification - what the reviewer looks for

- No controlled manifest, lockfile, image, SBOM, or dependency report resolves
  `@agenticmail/mcp <0.9.27`.
- `/mcp` rejects unauthenticated initialize and tool-call requests before any
  master-key-only action can run.
- Master-key-only tools require an authenticated admin caller or are absent
  from user-facing HTTP MCP deployments.
- HTTP mode is loopback-only by default or protected by a reviewed gateway.
- Operator actions cover rotation and log review when the affected endpoint was
  reachable by untrusted clients.

## Watch for

- Upgrading the npm dependency while a global install, Docker image,
  devcontainer, process manager command, or MCP registration still runs the
  affected package.
- Adding auth to API routes but forgetting MCP session initialize and
  `tools/call` requests on `/mcp`.
- Leaving `AGENTICMAIL_MASTER_KEY` in a network-facing MCP process that serves
  normal user or agent tool calls.
- Treating MCP session IDs as authentication. They are session state, not proof
  of caller identity.
- Tests or logs that expose email content, phone numbers, master keys, agent
  credentials, or tenant data.

## Related recipes

- [Source code authz tenant boundary audit]({{< relref "/recipes/general/source-code-authz-tenant-boundary-audit" >}})
- [Source code secrets and data exposure audit]({{< relref "/recipes/general/source-code-secrets-data-exposure-audit" >}})
- [Source code attack surface map]({{< relref "/recipes/general/source-code-attack-surface-map" >}})
- [NIST SSDF repository evidence check]({{< relref "/recipes/general/compliance-standards/nist-ssdf-repo-evidence-check" >}})

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-63gr-g7jc-v8rg>
- AgenticMail repository: <https://github.com/agenticmail/agenticmail>
