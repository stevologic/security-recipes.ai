---
title: "GHSA-3xx2/GHSA-47wq - Paperclip agent key tenant-boundary bypass"
linkTitle: "GHSA Paperclip agent keys"
description: "Critical Paperclip cross-tenant authorization bypass in agent API key routes. Upgrade to 2026.416.0+, require company access on key list/create/revoke, and rotate agent tokens if exposed."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "paperclip", "agentic-ai", "npm", "idor", "authorization", "multi-tenant", "critical"]
weight: 46
date: 2026-05-02
ghsa: "GHSA-3xx2-mqjm-hg9x"
known_as: ["Paperclip agent API key IDOR", "GHSA-47wq-cj9q-wpmp"]
kev: false
severity: "critical"
ecosystem: "typescript/npm"
disclosed: "2026-04-16"
---

Two critical Paperclip advisories describe the same tenant-boundary failure in
agent API key routes. The `GET`, `POST`, and `DELETE` handlers for
`/agents/:id/keys` accepted a board-type session but did not verify that the
caller belonged to the company owning the target agent.

An authenticated board user could supply another company's agent UUID, list or
revoke that agent's keys, and mint a new plaintext agent token bound to the
victim tenant. For an agent platform, that is a full cross-tenant control-plane
compromise.

## When to use it

Use this recipe when a repository, agent platform, or Paperclip deployment
manages agent API keys across companies, workspaces, or tenants. It is built
for source-code remediation, authorization boundary review, secret rotation
planning, and audit evidence that agent key routes enforce company ownership
before list, create, or revoke operations.

## Inputs

- Paperclip version, agent key API routes, session/tenant model, company
  membership checks, and deployment boundary.
- Source paths for `/agents/:id/keys`, key creation, key listing, key revocation,
  board sessions, company ownership lookup, and token storage.
- Regression fixtures for same-company, cross-company, revoked-agent, missing
  session, and low-privilege caller cases.
- Evidence of token exposure: plaintext key response paths, logs, audit events,
  existing keys, rotation owner, and impacted tenants.

## Affected versions

- **Vulnerable:** `@paperclipai/server <2026.416.0`
- **Fixed:** `@paperclipai/server 2026.416.0+`
- **Affected routes:**
  - `GET /agents/:id/keys`
  - `POST /agents/:id/keys`
  - `DELETE /agents/:id/keys/:keyId`
  - equivalent `/api/agents/:id/keys` deployments or reverse-proxy prefixes.

## Indicator-of-exposure

- The repository deploys or packages `@paperclipai/server <2026.416.0`.
- The Paperclip deployment is multi-tenant or has more than one company,
  workspace, board, customer, or organization.
- Board users can authenticate without being instance administrators.
- Agent IDs are visible in URLs, logs, exported data, webhooks, frontend state,
  or predictable test fixtures.
- Agent API tokens can call downstream endpoints that rely on token-bound
  `companyId` for authorization.

Quick checks:

```bash
rg -n "@paperclipai/server|paperclip|/agents/:id/keys|agents/.*/keys|assertBoard|assertCompanyAccess|createApiKey|listKeys|revokeKey" .
npm ls @paperclipai/server
pnpm why @paperclipai/server
yarn why @paperclipai/server
rg -n "agentApiKeys|companyId|instance_admin|board|agent token|pcp_" server src packages Dockerfile* docker-compose*.yml charts deploy
```

## Remediation strategy

- Upgrade `@paperclipai/server` to `2026.416.0+` everywhere this repository
  controls package manifests, lockfiles, images, or deployment manifests.
- Require company access for all agent-key list, create, and revoke paths:
  fetch the target agent first, then call the product's company-access helper
  using the agent's company ID.
- Enforce tenant checks in the service layer as well as route handlers so future
  routes cannot bypass the boundary by calling `createApiKey`, `listKeys`, or
  `revokeKey` directly.
- Make revocation scoped to both key ID and agent/company, not key ID alone.
- Rotate agent API tokens and review audit logs if unauthorized board users
  could access the key routes.

## The prompt

~~~markdown
You are remediating Paperclip agent API key tenant-boundary advisories
GHSA-3xx2-mqjm-hg9x and GHSA-47wq-cj9q-wpmp. Produce exactly one output:

- A reviewer-ready PR/change request that upgrades Paperclip or patches the
  tenant authorization boundary, adds regression coverage, and documents
  operator cleanup, or
- TRIAGE.md if this repository does not own an affected Paperclip deployment or
  cannot make a safe change.

## Rules

- Scope only GHSA-3xx2-mqjm-hg9x and GHSA-47wq-cj9q-wpmp.
- Treat agent API tokens, key hashes, tenant IDs, company IDs, session cookies,
  audit logs, and customer data as sensitive.
- Do not mint, print, commit, or attach real agent API tokens.
- Do not fix only the frontend. The server-side route and service boundary must
  enforce tenant ownership.
- Do not auto-merge.

## Steps

1. Inventory every Paperclip runtime controlled by this repository:
   package manifests, lockfiles, Dockerfiles, compose files, Helm charts,
   Kubernetes manifests, Terraform, CI images, deployment docs, SBOMs, and
   vendored server code.
2. Determine every resolved `@paperclipai/server` version. A target is
   vulnerable if it resolves below `2026.416.0`.
3. Search route and service code for agent-key operations:
   - `GET /agents/:id/keys`;
   - `POST /agents/:id/keys`;
   - `DELETE /agents/:id/keys/:keyId`;
   - `/api/agents/:id/keys` aliases;
   - `assertBoard`, `assertCompanyAccess`, `createApiKey`, `listKeys`,
     `revokeKey`, and `agentApiKeys`.
4. If this repository only deploys a fixed hosted Paperclip service or does not
   own Paperclip, stop with `TRIAGE.md` listing files checked and the runtime
   owner.
5. Prefer upgrading to `@paperclipai/server 2026.416.0+`. Regenerate lockfiles,
   image digests, SBOMs, and deployment render output.
6. If the repository owns a fork or vendored patch path, patch authorization:
   - fetch the target agent before key list/create/revoke;
   - call `assertCompanyAccess(req, agent.companyId)` or equivalent before any
     key operation;
   - allow instance-admin override only through the existing reviewed helper;
   - pass actor/company context into service-layer key functions;
   - scope revoke by key ID plus agent ID/company ID;
   - never return plaintext tokens except immediately after an authorized
     create operation in the caller's own tenant.
7. Add regression tests:
   - Company A board user gets 403 for Company B key list/create/revoke;
   - zero-membership board user gets 403;
   - instance admin behavior matches the intended product policy;
   - authorized same-company users can still create and revoke keys;
   - service-layer calls cannot create or revoke cross-tenant keys without
     actor/company context.
8. Add audit and operator hardening:
   - log key-management actor, target agent, company, and decision without
     plaintext tokens;
   - rate-limit key creation;
   - alert on cross-company key-management denials;
   - document token rotation for the exposure window.
9. Add a PR body section named `Paperclip agent key operator actions` that
   states:
   - affected Paperclip versions before and after the change;
   - whether multiple companies or self-service board accounts existed;
   - whether agent IDs were discoverable by non-member users;
   - whether agent API keys were listed, minted, or revoked by suspicious
     actors;
   - which agent tokens must be rotated and which audit logs must be reviewed.
10. Run relevant validation: package install, lockfile checks, route tests,
    service tests, authorization integration tests, lint/typecheck, image build,
    SBOM refresh, and dependency/security scans available in this repository.
11. Use PR title:
    `fix(sec): enforce tenant access on Paperclip agent keys`.

## Stop conditions

- No affected Paperclip server deployment is controlled by this repository.
- A fixed Paperclip version cannot be consumed without a broader migration.
- The tenant ownership model is unclear or intentionally allows cross-company
  board administration; document the risk and require a product/security
  decision.
- Verification would require exposing real agent tokens or customer data.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Output contract

- A reviewer-ready PR or change request that upgrades Paperclip, enforces
  company access on key routes, adds negative RBAC tests, and documents agent
  token rotation.
- Or a `TRIAGE.md` file that lists inspected files, owner, observed version,
  tenant boundary, key exposure, required fix, and rotation recommendation.
- The output must include exact validation commands and must not print real
  agent tokens, tenant data, bearer headers, or production audit logs.

## Verification - what the reviewer looks for

- No controlled package, lockfile, image, SBOM, or deployment target resolves
  `@paperclipai/server` below `2026.416.0`.
- Every agent-key route checks access to the company that owns the target agent.
- Service functions cannot list, create, or revoke keys without actor/company
  context.
- Cross-tenant regression tests cover list, create, and revoke.
- Operator actions cover token rotation and audit-log review without exposing
  plaintext tokens.

## Watch for

- Adding `assertCompanyAccess` only to `POST` while `GET` or `DELETE` remains
  tenant-blind.
- Fetching the agent after creating or revoking the key.
- Revoking by key ID alone when key IDs are globally unique and guessable from
  logs or frontend state.
- Logging plaintext `pcp_*` tokens in tests, audit events, or PR comments.

## Related recipes

- [Source code authz tenant boundary audit]({{< relref "/prompt-library/general/source-code-authz-tenant-boundary-audit" >}})
- [Source code secrets and data exposure audit]({{< relref "/prompt-library/general/source-code-secrets-data-exposure-audit" >}})
- [Source code attack surface map]({{< relref "/prompt-library/general/source-code-attack-surface-map" >}})
- [SOC 2 change management evidence check]({{< relref "/prompt-library/general/compliance-standards/soc2-change-management-evidence-check" >}})

## References

- GitHub Advisory `GHSA-3xx2-mqjm-hg9x`: <https://github.com/advisories/GHSA-3xx2-mqjm-hg9x>
- GitHub Advisory `GHSA-47wq-cj9q-wpmp`: <https://github.com/advisories/GHSA-47wq-cj9q-wpmp>
- Paperclip project: <https://github.com/paperclipai/paperclip>

