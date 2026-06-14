---
title: "Source code audit - attack surface map"
linkTitle: "Source code attack surface map"
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["source-code", "audit", "attack-surface", "threat-model", "read-only"]
weight: 13
date: 2026-06-06
---

A tool-agnostic source-code audit recipe that asks an agent to map
where untrusted input enters a repository, where privileged actions
happen, and which trust boundaries deserve deeper review.

Use this before focused audits like authz, injection, secrets, or
supply-chain review. The output is an inventory and prioritised audit
plan, not a vulnerability report and not a code change.

## What this prompt does

1. Enumerates entry points, identities, storage systems, external
   integrations, and privileged operations.
2. Draws trust boundaries from code evidence instead of architecture
   guesses.
3. Flags high-value paths that should receive deeper audit attention.
4. Produces a compact `SECURITY_ATTACK_SURFACE.md` report that can be
   handed to another agent or a reviewer.

## When to use it

- Before the first security pass on a new service.
- Before deciding which security audit prompt should run next.
- After a large refactor, framework migration, or new integration.
- During diligence when you need code-backed orientation fast.

Do not use it as a substitute for SAST, dependency scanning, runtime
testing, or a full threat model. It is the map, not the expedition.

## Inputs

Infer from the session where possible:

- Repo root and scope. If no scope is given, inspect the whole repo.
- Primary deployment target, inferred from Docker, Kubernetes, CI, or
  infrastructure files.
- Any product-critical flows named by the operator.
- Any files or directories that are out of scope.

## The prompt

~~~markdown
You are performing a read-only source-code attack-surface mapping pass
for this repository. Do not edit files. Do not open a pull request.

Your job is to map the system well enough that a security reviewer can
choose the next focused audit. Prefer code evidence over guesses.

## Step 0 - Repository orientation

Identify and record:

- Primary languages and frameworks.
- Main entry points:
  - HTTP routes, controllers, middleware, and API handlers.
  - GraphQL, gRPC, WebSocket, webhook, queue, cron, CLI, or background
    job entry points.
  - Browser/client entry points when they call privileged APIs.
- Authn and authz modules.
- Datastores and persistence layers.
- External network calls and third-party SDKs.
- Secret, credential, key, and token handling paths.
- Build, CI, release, and deployment entry points.

Use file paths and short notes. If something is unknown after a
reasonable look, mark it unknown instead of guessing.

## Step 1 - Identify trust boundaries

For each boundary, write:

- Boundary name.
- Incoming trust level.
- Outgoing trust level.
- Code locations that cross the boundary.
- Why the boundary matters.

Cover at minimum:

- Internet or user-controlled input entering server code.
- Authenticated user input crossing into tenant-owned resources.
- Internal service calls crossing service or account boundaries.
- Model, agent, or tool input crossing into code execution,
  filesystem, network, ticketing, or cloud APIs.
- Build-time inputs crossing into release artifacts.
- Secrets crossing into logs, telemetry, model prompts, or browser
  state.

## Step 2 - Find privileged operations

List code paths that can:

- Read, write, delete, export, or share user/customer data.
- Change roles, permissions, billing state, ownership, or tenant
  membership.
- Execute commands, evaluate code, render templates, deserialize data,
  or load plugins.
- Make outbound network requests from user-provided values.
- Create, rotate, display, persist, or transmit secrets.
- Publish artifacts, deploy code, or mutate CI/CD state.

For each operation, include:

- File path and function/class/route name.
- Required identity or permission if the code makes it clear.
- Missing context if the permission model is unclear.

## Step 3 - Prioritise deeper audit paths

Pick the top 10 paths for focused security review. Prioritise by:

- Untrusted input reaches privileged operation.
- Tenant or role boundary is involved.
- Secrets or regulated data are involved.
- Runtime side effects are hard to reverse.
- Code path is internet-facing, webhook-facing, or reachable by an
  integration token.
- Existing tests do not cover the boundary.

For each path, recommend the next audit recipe:

- Auth and tenant-boundary audit.
- Injection and unsafe-sink audit.
- Secrets and sensitive-data exposure audit.
- Dependency and build-integrity audit.
- Manual design review.

## Step 4 - Write the report

Write `SECURITY_ATTACK_SURFACE.md` at the repository root. If the
session is read-only, print the same content to stdout.

Use this structure:

```markdown
# Source code attack-surface map - <repo name>

Generated on <date>. Scope: <scope>.

## Context
- Languages/frameworks:
- Entry points:
- Auth model:
- Datastores:
- External integrations:
- Build/deploy surface:
- Unknowns:

## Trust Boundaries

### <Boundary name>
- **Code:** `path/to/file.ext:line`
- **Incoming trust:** ...
- **Outgoing trust:** ...
- **Why it matters:** ...
- **Notes:** ...

## Privileged Operations

### <Operation name>
- **Code:** `path/to/file.ext:line`
- **Capability:** ...
- **Required identity/permission:** ...
- **Missing context:** ...

## Recommended Follow-Up Audits

### P1 - <path name>
- **Why this first:** ...
- **Recipe:** ...
- **Files to inspect:** ...
- **Question to answer:** ...

## Gaps
- ...
```

## Stop conditions

Stop and report the reason if:

- The repository is too large for one pass. Split by service or top-level
  module and recommend the split.
- Secrets, private keys, or live credentials are discovered. Do not print
  values. Put the file path and redacted line reference at the top of the
  report.
- The requested scope would require reading private data, production logs,
  or customer content outside the source tree.
~~~

## Output contract

- `SECURITY_ATTACK_SURFACE.md` or equivalent stdout report.
- No source-code edits.
- File and function pointers for every material claim.
- A ranked list of follow-up audit paths.

## Guardrails

- Read-only. Do not run commands that mutate the repo, package cache, cloud
  state, CI state, or databases.
- Do not include secret values in the report.
- Treat generated, vendored, and minified code as out of scope unless the
  operator explicitly says otherwise.
- Prefer "unknown" over inferred certainty when auth, deployment, or data
  classification is not visible in the repo.

## Related

- [Source code audit - auth and tenant boundaries]({{< relref "/prompt-library/general/source-code-authz-tenant-boundary-audit" >}})
- [Source code audit - injection and unsafe sinks]({{< relref "/prompt-library/general/source-code-injection-sink-audit" >}})
- [Source code audit - secrets and data exposure]({{< relref "/prompt-library/general/source-code-secrets-data-exposure-audit" >}})
- [Source code audit - dependency and build integrity]({{< relref "/prompt-library/general/source-code-supply-chain-build-integrity-audit" >}})
