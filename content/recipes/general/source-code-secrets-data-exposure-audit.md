---
title: "Source code audit - secrets and data exposure"
linkTitle: "Source code secrets audit"
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["source-code", "audit", "secrets", "sensitive-data", "logging", "privacy"]
cve_archetypes:
  - "crypto_certificate_validation"
  - "information_disclosure"
cve_workflow_role: "audit"
weight: 16
date: 2026-06-06
---

A source-code audit recipe for finding places where secrets, tokens,
credentials, regulated data, or customer content can leak through code,
logs, telemetry, prompts, artifacts, exports, caches, or browser state.

This recipe is read-only. It reports exposure paths and containment
recommendations; it does not rotate secrets or patch code during the
audit pass.

## What this prompt does

1. Maps secret and sensitive-data sources.
2. Reviews storage, logging, telemetry, export, prompt, cache, and
   artifact paths.
3. Flags hard-coded secrets, unsafe redaction, over-broad data release,
   and missing classification boundaries.
4. Produces a report that separates incident candidates from normal
   engineering findings.

## When to use it

- Before launching an AI assistant, export feature, audit-log pipeline, or
  customer evidence portal.
- After adding observability, analytics, tracing, support tooling, or
  report generation.
- When reviewing code that handles API keys, OAuth tokens, session
  cookies, private keys, PII, PHI, payment data, customer source code, or
  internal prompts.
- After a secrets scanner finds a pattern and you need context.

Do not use this prompt to print, copy, validate, or test live secrets.

## Inputs

Infer where possible:

- Repo scope.
- Data classes the application handles.
- Secret managers, environment variable names, config paths, and logging
  systems.
- Known scanner findings, if any.

## The prompt

~~~markdown
You are performing a read-only source-code audit for secrets and
sensitive-data exposure. Do not edit files. Do not rotate credentials.
Do not call external services to validate secrets.

If you find a live-looking secret, redact it immediately in your notes
and treat it as a potential incident.

## Step 0 - Define sensitive classes

From code evidence, identify sensitive classes such as:

- API keys, OAuth tokens, refresh tokens, session cookies, JWT signing
  keys, webhook secrets, SSH keys, private keys, database passwords, cloud
  credentials, package tokens, and model-provider keys.
- User PII, employee data, customer content, customer source code,
  regulated data, payment data, health data, secrets embedded in tickets,
  and security findings.
- Internal prompts, system instructions, agent transcripts, retrieved
  context, tool output, and model-generated evidence packs.

Create a table of classes and likely code locations.

## Step 1 - Map ingress and storage

Find where sensitive data enters:

- Environment variables and config files.
- Secret managers and cloud SDKs.
- HTTP requests, uploads, webhooks, and forms.
- OAuth, SSO, API-key, and session flows.
- Database reads and writes.
- Object storage, queues, caches, and local temp files.
- CI variables and deployment manifests.
- MCP tools, browser agents, model prompts, retrieval indexes, and memory.

For each class, record:

- Where it enters.
- Where it is stored.
- Whether it is encrypted, hashed, tokenized, redacted, or classified.
- Retention and deletion logic if visible.

## Step 2 - Review exposure paths

Inspect paths that can release data:

- Logs, traces, metrics, exceptions, debug output, screenshots, and crash
  dumps.
- Audit events and security telemetry.
- API responses, exports, reports, evidence packs, support bundles, and
  downloadable artifacts.
- Email, Slack, ticketing, webhook, or notification integrations.
- Browser local storage, session storage, cookies, query strings, and
  frontend error reporters.
- Prompt construction, retrieval augmentation, model-provider requests,
  model outputs, agent memory, tool calls, and MCP resources.
- Test fixtures, snapshots, golden files, generated docs, and sample
  payloads.
- Build artifacts, container layers, source maps, package tarballs, and CI
  logs.

For each exposure path, check:

- Is the sensitive value included at all?
- Is redaction applied at the boundary or only downstream?
- Is redaction structured and type-aware, or string-based and brittle?
- Can an error path bypass redaction?
- Is access to the released artifact scoped to the right tenant/role?
- Is retention visible and bounded?

## Step 3 - Review hard-coded and committed secrets safely

Search for likely secret material, but do not print values:

- Private key block headers.
- Token-like variable names with literal values.
- Cloud provider key patterns.
- `.env`, config, fixture, and test-data files.
- Build scripts and CI workflow files.
- Dockerfiles and container entrypoints.

For each candidate:

- Redact the value in your notes.
- Record file path, line, secret type, and confidence.
- Decide whether it looks live, test-only, dummy, or unknown.
- If live or unknown, elevate it to "Potential incident" and stop broad
  auditing until a human decides whether rotation is needed.

## Step 4 - Review controls

Look for:

- Centralized redaction helpers.
- Data classification labels or schemas.
- Secret wrappers that prevent accidental stringification.
- Encryption-at-rest or envelope-encryption paths for stored sensitive
  data.
- Hashing for passwords or one-way tokens.
- Token expiration, revocation, rotation, and audit trails.
- Export review gates and tenant-bound release checks.
- Tests for redaction, export scoping, and prompt/tool data boundaries.

Flag duplicated or ad-hoc redaction code when it creates likely bypasses.

## Step 5 - Write the report

Write `SECURITY_SECRETS_DATA_AUDIT.md` at the repo root. If the session
is read-only, print the same content to stdout.

Use this structure:

```markdown
# Secrets and sensitive-data exposure audit - <repo name>

Generated on <date>. Scope: <scope>.

## Sensitive Data Classes
- ...

## Potential Incidents

### <Secret/data class> - <short title>
- **File:** `path/to/file.ext:line`
- **Value:** redacted
- **Why this may be live:** ...
- **Immediate action:** ...
- **Confidence:** ...

## Findings

### <Severity> - <Exposure path> - <short title>
- **File:** `path/to/file.ext:line`
- **Data class:** ...
- **Exposure path:** ...
- **Existing controls:** ...
- **Why controls are insufficient:** ...
- **Blast radius:** ...
- **Confidence:** ...
- **Recommended fix:** ...
- **Tests to add:** ...

## Controls Reviewed
- ...

## Gaps
- ...
```

## Stop conditions

Stop and escalate to the top of the report if:

- A live-looking credential, private key, or signing secret is present.
- The code appears to exfiltrate customer data, source code, prompts, or
  tokens to an unapproved external service.
- Validating the issue would require using a secret, calling production,
  or reading customer data.
~~~

## Output contract

- `SECURITY_SECRETS_DATA_AUDIT.md` or equivalent stdout report.
- Secret values are always redacted.
- Potential incidents are separated from ordinary findings.
- No code edits or credential validation.

## Guardrails

- Never print raw secret values.
- Never call external services to test whether a token works.
- Do not paste customer data, source code, logs, or private prompts into
  external tools while auditing.
- Treat source maps, CI logs, prompt transcripts, evidence exports, and
  support bundles as release artifacts that can leak data.

## Related

- [Source code audit - attack surface map]({{< relref "/recipes/general/source-code-attack-surface-map" >}})
- [Sensitive Data Exposure Remediation]({{< relref "/security-remediation/sensitive-data" >}})
- [Context Egress Boundary]({{< relref "/security-remediation/context-egress-boundary" >}})
