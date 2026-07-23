---
title: "Source code audit - auth and tenant boundaries"
linkTitle: "Source code auth boundary audit"
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["source-code", "audit", "authorization", "tenant-boundary", "idor"]
cve_archetypes:
  - "authentication_bypass"
  - "authorization_idor"
  - "privilege_escalation"
cve_workflow_role: "audit"
weight: 14
date: 2026-06-06
---

A focused source-code audit recipe for authorization, tenant isolation,
object ownership, and privilege-boundary mistakes. It is designed for
code review sessions where the question is not "is there login?" but
"can the wrong authenticated principal reach the wrong object?"

The output is a finding report. The agent should not patch code during
this run.

## What this prompt does

1. Builds a map of identities, roles, permissions, tenants, and owned
   resources from the code.
2. Reviews routes and service methods that read or mutate protected
   objects.
3. Looks for IDOR, confused-deputy, role escalation, missing policy
   checks, and client-trusted tenant IDs.
4. Emits file-level findings with reproduction ideas and recommended
   fixes.

## When to use it

- Reviewing an app with multi-tenant accounts or customer-owned data.
- Auditing admin routes, support tooling, billing flows, user invites,
  API keys, or organization membership.
- After adding a new authorization framework or policy layer.
- After an incident or bug report involving object access.

Do not use it for authentication protocol review alone. Session cookies,
OAuth, SSO, MFA, and password flows can be noted here, but the core job is
authorization and isolation after identity is established.

## Inputs

Infer where possible:

- Repo scope.
- Identity providers and auth middleware.
- Tenant or organization concept names.
- Admin, support, service-account, or integration-token roles.
- High-value resource types if the operator names any.

## The prompt

~~~markdown
You are performing a read-only authorization and tenant-boundary source
audit. Do not edit files. Do not open a pull request.

Focus on whether authenticated principals can access only the resources
and actions they are allowed to access.

## Step 0 - Build the auth map

Find and record:

- Authentication middleware and session/token parsing.
- Authorization middleware, policy objects, permission checks, guards, or
  decorators.
- Role names, permission names, tenant/org/account identifiers, and
  resource ownership fields.
- Admin/support/service-account bypasses.
- Places where the current user, tenant, org, account, or workspace is
  read from request parameters, headers, cookies, JWT claims, body fields,
  path params, or database state.

Create a short glossary:

- Principal types.
- Resource types.
- Privileged operations.
- Trustworthy sources of tenant/resource ownership.
- Untrustworthy sources that must be validated.

## Step 1 - Enumerate protected routes and methods

Review every route, resolver, controller action, command, queue handler,
or service method that:

- Reads a resource by ID.
- Lists resources.
- Creates, updates, deletes, exports, shares, transfers, or imports data.
- Changes role, ownership, membership, billing, plan, API key, webhook,
  integration, or admin state.
- Acts on behalf of another user, tenant, or organization.

For each, answer:

- Is authentication required?
- Where does authorization happen?
- Is object ownership or tenant membership checked server-side?
- Is the tenant/resource ID trusted from the client?
- Is the policy enforced before side effects happen?
- Do all branches, retries, fallbacks, and error paths pass through the
  same check?

## Step 2 - Look for failure patterns

Search for these concrete patterns:

- Object lookup by user-controlled ID without joining through tenant,
  owner, or policy scope.
- Tenant ID, org ID, workspace ID, role, or account ID accepted from the
  client and used directly in a query or command.
- Admin/support bypasses without explicit role checks and audit logging.
- List endpoints filtered by request parameters instead of policy-scoped
  query builders.
- Bulk operations that check the parent object but not every child object.
- Export, share, invite, webhook, and API-key endpoints with weaker checks
  than normal CRUD.
- Authorization checks after mutation.
- Cached permission decisions that do not include tenant, role, resource,
  or token version in the cache key.
- Background jobs that trust the enqueuer instead of re-checking
  authority when the job runs.
- Service-account or integration-token flows that can act outside their
  intended tenant.
- Test fixtures that use only admin users and therefore miss normal-user
  denial cases.

## Step 3 - Validate likely findings

For every candidate issue:

1. Trace the route from entry point to data access or side effect.
2. Identify the source of the principal and the source of the resource
   identifier.
3. Identify the exact policy check or confirm it is missing.
4. Check whether an upstream middleware guarantees the missing property.
5. Look for tests that prove denial for another tenant, lower role, or
   unrelated owner.

Only report a finding when you can point to a concrete path. If evidence
is incomplete, put it in "Needs human confirmation" instead of inflating
severity.

## Step 4 - Score findings

Assign:

- Severity: critical, high, medium, low.
- Boundary: tenant, role, object ownership, admin/support, service
  account, or background job.
- Blast radius: one object, one tenant, cross-tenant, admin, platform.
- Confidence: high, medium, low.

Use higher severity when exploitation crosses tenants, changes
privileges, exports sensitive data, or affects admin/support tools.

## Step 5 - Write the report

Write `SECURITY_AUTHZ_AUDIT.md` at the repo root. If the session is
read-only, print the same content to stdout.

Use this structure:

```markdown
# Authorization and tenant-boundary audit - <repo name>

Generated on <date>. Scope: <scope>.

## Auth Map
- Principals:
- Roles/permissions:
- Tenant/resource model:
- Trusted identity sources:
- Unknowns:

## Findings

### <Severity> - <Boundary> - <short title>
- **File:** `path/to/file.ext:line`
- **Entry point:** ...
- **Path:** ...
- **Why it is flagged:** ...
- **Exploit sketch:** ...
- **Blast radius:** ...
- **Confidence:** ...
- **Recommended fix:** ...
- **Tests to add:** ...

## Needs Human Confirmation
- ...

## Routes Reviewed With No Finding
- `path` - authorization evidence found.

## Gaps
- ...
```

## Stop conditions

Stop and report rather than guessing if:

- The auth or policy layer lives in another repo you cannot inspect.
- The repository lacks enough routing context to connect entry points to
  data access.
- You find live credentials or private keys while auditing.
- A suspected issue depends entirely on production IAM, feature flags, or
  runtime config not present in the repo.
~~~

## Output contract

- `SECURITY_AUTHZ_AUDIT.md` or equivalent stdout report.
- Findings include file paths, boundary type, blast radius, confidence,
  and test ideas.
- No code edits.

## Guardrails

- Do not exploit live systems or call production APIs.
- Do not use customer data to validate access control.
- Do not assume a missing inline check is a bug until middleware,
  framework guards, and policy wrappers have been checked.
- Default uncertain issues to "Needs Human Confirmation" instead of
  dressing them up as proven vulnerabilities.

## Related

- [Source code audit - attack surface map]({{< relref "/recipes/general/source-code-attack-surface-map" >}})
- [OWASP Top 10:2025 repository audit]({{< relref "/recipes/general/owasp-top-10-2025-audit" >}})
- [Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}})
