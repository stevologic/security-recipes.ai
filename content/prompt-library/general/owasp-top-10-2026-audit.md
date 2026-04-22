---
title: "OWASP Top 10 (2026) — repo audit"
linkTitle: "OWASP Top 10 2026 audit"
tool: "general"
author: "Stephen M Abbott"
team: "InfoSec"
maturity: "development"
model: "Opus 4.7"
tags: ["owasp", "top-10", "audit", "hunt", "sast", "security-posture"]
weight: 10
date: 2026-04-22
---

A tool-agnostic **hunt prompt** that walks an agent through a structured
audit of a repository against every category in the OWASP Top 10 (2026
iteration). The output is a prioritised report with file-level pointers
and concrete remediation recommendations — not a fix.

Pair this with the companion remediate prompt,
[OWASP Top 10 (2026) — remediate]({{< relref "/prompt-library/general/owasp-top-10-2026-remediate" >}}),
to take a single finding from the report to an open PR.

## What this prompt does

It asks the agent to:

1. **Enumerate the repo** — language, framework, entry points, auth
   mechanism, data stores, external calls, secret-handling paths.
2. **Walk each OWASP Top 10 2026 category** and look for concrete
   instances, not theoretical risk.
3. **Score and group findings** by category, severity, and blast
   radius.
4. **Emit a structured report** a reviewer can hand to product teams
   or feed into the remediate prompt.

Runs read-only. Does not edit files. No PRs.

## When to use it

- Quarterly posture review of a service you own.
- Diligence pass before a new service moves to production.
- Follow-on after a pen-test report that only listed categories, not
  file paths.

**Don't use it for:**

- Real-time exploit triage — too slow and too broad.
- Replacing SAST/DAST — this is a structured LLM pass, not a
  vulnerability scanner. It catches design-level issues scanners miss
  and misses pattern-level issues scanners catch. Run both.

## Inputs

The agent should **infer** as much as it can from the working session
and prompt only when genuinely ambiguous:

- **Repo** — the working directory the agent is running in.
- **Scope** — if the user mentions a specific directory or service,
  restrict to that. Otherwise, audit the whole repo.
- **Deployment target** — infer from `Dockerfile` / `k8s/` /
  `terraform/` / CI config. If unknown, note it in the report.
- **Auth / authz model** — infer from routing + middleware + any
  `auth/` module. If unclear, note it.

Do not refuse to run because an input is missing; produce the best
report you can and flag the gaps.

## The prompt

~~~markdown
You are performing a security posture audit of this repository against
the OWASP Top 10 (2026). Run read-only. Do not edit files or run
destructive commands.

## Step 0 — Repo orientation

Before auditing, infer and record:

- Primary language and framework.
- Entry points (HTTP routes, gRPC services, queue consumers, CLI
  commands, scheduled jobs).
- Authentication mechanism.
- Data stores touched (databases, caches, object storage, message
  queues).
- External services called.
- Secret handling (env vars, secret managers, config files).
- CI / deployment pipeline — where is this run, how is it built.

Record these in a short "Context" section at the top of the report.
If any are unknown after a reasonable look, say so — do not guess.

## Step 1 — Walk each OWASP Top 10 2026 category

For each category, answer three questions:

1. **What would this look like in this codebase?** (The concrete
   shape the weakness would take, given the framework and entry
   points.)
2. **Did you find any instances?** (File paths, line numbers, and a
   one-line excerpt for each.)
3. **What would fix or mitigate it?** (Specific, actionable —
   "add authz check to route X" beats "improve access control".)

### Categories to cover

Use the current OWASP Top 10 2026 naming. If the release is still
draft, note the version you are auditing against at the top of the
report. Cover at minimum:

- **A01 — Broken Access Control.** Missing authz checks on routes,
  IDOR patterns, tenant-id trust from client, over-broad admin
  endpoints.
- **A02 — Cryptographic Failures.** Weak/old ciphers, hard-coded
  keys, TLS verification disabled, plaintext-at-rest for sensitive
  fields, bad password hashing (MD5/SHA1/unsalted).
- **A03 — Injection.** SQL/NoSQL/command/LDAP/XPath injection,
  unsafe template rendering, prompt injection paths for LLM
  features (untrusted text pasted into a system prompt or tool
  call).
- **A04 — Insecure Design.** Missing rate limits on auth-adjacent
  endpoints, enumeration oracles (login, password-reset,
  invite-by-email), trust boundaries crossed without validation,
  features shipped without a threat model.
- **A05 — Security Misconfiguration.** Debug mode in production
  paths, permissive CORS, default credentials, verbose error
  pages, cloud resources without least-privilege IAM, missing
  security headers.
- **A06 — Vulnerable and Outdated Components.** Lockfile entries
  with known CVEs, unpinned or wildcard deps, abandoned upstreams,
  vendored code without a clear origin.
- **A07 — Identification and Authentication Failures.** Weak
  session handling, no MFA for sensitive ops, no account lockout
  or rate limiting on login, password policy gaps, tokens in URLs.
- **A08 — Software and Data Integrity Failures.** Unsigned release
  artifacts, CI pipelines that trust unverified third-party
  actions, deserialization of untrusted data, auto-update paths
  without signature checks.
- **A09 — Security Logging and Monitoring Failures.** Sensitive
  operations that emit no audit record, PII/secrets in logs,
  missing correlation IDs, no alerting on auth anomalies.
- **A10 — Server-Side Request Forgery (SSRF).** Outbound HTTP
  built from user input without allowlisting, webhook fetchers,
  URL preview services, metadata-endpoint (169.254.169.254) not
  blocked.

If the published 2026 list adds or renames a category (for example,
a standalone entry for LLM/agent-supply-chain risks), include it
using the current OWASP wording and drop any category that was
merged or retired.

## Step 2 — Score and prioritise

For each finding, assign:

- **Severity** — critical / high / medium / low. Use CVSS-style
  reasoning; err low when exploitation requires already-privileged
  access.
- **Blast radius** — scope of impact if exploited (one tenant, all
  tenants, infra, etc.).
- **Confidence** — high / medium / low. Low confidence is fine;
  flag it so a reviewer can verify.

Sort the report by (severity, blast radius, confidence).

## Step 3 — Emit the report

Write the report to `SECURITY_AUDIT.md` at the repo root (or print
to stdout if the session is read-only). Use this structure:

```markdown
# OWASP Top 10 (2026) audit — <repo name>

_Generated by <agent name> on <date>. OWASP version: <draft/final, date>._

## Context
- Language / framework: ...
- Entry points: ...
- Auth model: ...
- Data stores: ...
- Deploy target: ...
- Gaps in context: ...

## Findings

### <Severity> — <A0X category> — <short title>
- **File:** `path/to/file.py:42`
- **Excerpt:** `...one line of code...`
- **Why it's flagged:** ...
- **Blast radius:** ...
- **Confidence:** ...
- **Recommended fix:** ...

(repeat for each finding, sorted)

## Categories with no findings
- A0X — reasoning for why no instance was found (searched patterns,
  areas covered).

## Gaps
- Things the audit could not reach (e.g., "no access to the IAM
  config for the deployed environment").
```

## Stop conditions

Stop and write a note rather than guessing if:

- The repo is larger than you can meaningfully audit in one pass.
  Suggest splitting by module and re-running.
- A category requires runtime context you do not have (for
  example, deploy configuration lives in another repo).
- You find credentials, private keys, or unmistakable exploit
  artifacts — flag these to the top of the report immediately and
  stop; they are an incident, not an audit finding.
~~~

## Output contract

- A single `SECURITY_AUDIT.md` file with the structure above, or
  the same content on stdout if write access is not available.
- No source file edits.
- No PRs.

## Guardrails

- Read-only. The agent should not use any write tool.
- Do not exfiltrate repo contents to external services. If the
  agent has web-search / fetch tools, restrict them to looking up
  CVE advisories and OWASP documentation.
- Redact any credentials, tokens, or private keys the agent
  stumbles on while reading code — the report references them by
  file/line, never by value.

## How to hand off to remediation

- Pick the top finding.
- Feed its file, line, category, and recommended fix into the
  companion prompt:
  [OWASP Top 10 (2026) — remediate]({{< relref "/prompt-library/general/owasp-top-10-2026-remediate" >}}).
- Review the PR it opens.

## Related

- [Fundamentals]({{< relref "/fundamentals" >}}) — vocabulary used in
  the report (SAST, SSRF, blast radius).
- [MCP Server Access]({{< relref "/mcp-servers" >}}) — wiring an
  agent to scanners so audits can cross-reference existing findings.
- [OWASP Top 10 (2026) — remediate]({{< relref "/prompt-library/general/owasp-top-10-2026-remediate" >}})
