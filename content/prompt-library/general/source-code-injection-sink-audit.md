---
title: "Source code audit - injection and unsafe sinks"
linkTitle: "Source code injection sink audit"
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["source-code", "audit", "injection", "ssrf", "unsafe-sinks", "dataflow"]
weight: 15
date: 2026-06-06
---

A source-code audit recipe for tracing untrusted input into dangerous
sinks: SQL, shell, template rendering, SSRF, deserialization, file paths,
regular expressions, dynamic evaluation, and LLM/tool-call boundaries.

This is a read-only hunt prompt. It produces evidence-backed findings and
safe remediation recommendations, but it does not patch code.

## What this prompt does

1. Identifies untrusted input sources in the scoped code.
2. Builds a sink catalogue for the language and framework in use.
3. Traces source-to-sink data flow with sanitizer and validator checks.
4. Reports exploitable or suspicious flows with confidence and test ideas.

## When to use it

- After the attack-surface map identifies user input reaching privileged
  operations.
- Before or after SAST results for injection-heavy code.
- When reviewing importers, webhook processors, URL fetchers, search
  endpoints, report builders, template systems, plugin systems, or agent
  tool adapters.

Do not use it for dependency CVEs unless the vulnerable dependency creates
one of these source-to-sink paths in your code.

## Inputs

Infer where possible:

- Repo or directory scope.
- Framework and routing layer.
- User-controlled input sources if the operator has a specific flow in
  mind.
- Any SAST rule IDs or findings that should be checked first.

## The prompt

~~~markdown
You are performing a read-only source-code audit for injection and unsafe
sink paths. Do not edit files. Do not open a pull request.

Your output should distinguish proven findings from suspicious flows that
need human confirmation.

## Step 0 - Identify untrusted input sources

Map inputs from:

- HTTP path, query, body, headers, cookies, file uploads, and multipart
  fields.
- GraphQL variables and resolver args.
- WebSocket messages.
- Webhook payloads.
- Queue messages and scheduled-job payloads.
- CLI args and environment variables.
- Database fields previously written by users.
- Object storage files, archives, uploaded documents, and generated
  artifacts.
- Third-party API responses.
- Model output, agent memory, retrieved context, and tool-call arguments.

Record file paths and handler/function names.

## Step 1 - Build the sink catalogue

Search for dangerous or policy-sensitive sinks in the scoped code:

- SQL/NoSQL query construction.
- Shell command execution and process spawning.
- Template rendering and HTML/JS/CSS interpolation.
- Filesystem path construction, archive extraction, symlink handling, and
  file writes.
- Outbound HTTP requests, webhook fetchers, URL previews, proxying, and
  cloud metadata access.
- XML parsing, YAML loading, pickle/marshal/deserialization, dynamic module
  loading, plugin loading, and reflection.
- `eval`, function constructors, dynamic import, expression languages,
  sandbox escapes, and generated code execution.
- Regular expressions built from input or run against unbounded input.
- LLM prompts, system/developer instructions, tool arguments, browser
  automation commands, and MCP tool calls that include untrusted content.

For each sink, record:

- File path and function/class.
- Sink type.
- Inputs reaching the sink.
- Existing sanitizers, validators, parameter binding, escaping, allowlists,
  or policy checks.

## Step 2 - Trace source-to-sink flows

For each promising flow:

1. Start at the source and follow variable transformations to the sink.
2. Note validators, normalizers, encoders, escaping, type checks, length
   limits, allowlists, and permission checks.
3. Decide whether the control is sufficient for the sink:
   - SQL: parameter binding or ORM-safe query APIs.
   - Shell: argument array plus command and argument allowlists; no shell.
   - Template: contextual escaping at render time.
   - SSRF: scheme/host allowlist, DNS/IP checks, link-local and metadata
     blocking, redirect handling.
   - File path: canonicalization, base-directory containment, symlink
     policy, extension/type checks.
   - Deserialization: safe format or trusted signed payload only.
   - Regex: length caps, anchored intent, no user-controlled catastrophic
     patterns.
   - LLM/tool calls: untrusted text kept out of system instructions and
     privileged arguments; tool output treated as untrusted.
4. If the path crosses modules and cannot be fully traced, mark it
   "partial flow" and explain what is missing.

## Step 3 - Check tests and exploitability

For each candidate finding:

- Look for tests that would catch the payload class.
- Sketch a safe local reproduction payload without hitting production
  systems or destructive operations.
- Identify the minimum assertion a regression test should make.
- Identify whether exploitation requires authentication, a special role,
  internal network access, or prior data seeding.

Do not execute exploit payloads against live services. Keep any payloads
local, harmless, and illustrative.

## Step 4 - Score findings

Assign:

- Severity: critical, high, medium, low.
- Sink class.
- Exploit preconditions.
- Blast radius.
- Confidence: high, medium, low.

Raise severity for unauthenticated reachability, remote code execution,
credential exposure, cross-tenant impact, metadata-service access, and
server-side write primitives.

## Step 5 - Write the report

Write `SECURITY_INJECTION_SINK_AUDIT.md` at the repo root. If the
session is read-only, print the same content to stdout.

Use this structure:

```markdown
# Injection and unsafe-sink audit - <repo name>

Generated on <date>. Scope: <scope>.

## Source Map
- ...

## Sink Catalogue
- ...

## Findings

### <Severity> - <Sink class> - <short title>
- **File:** `path/to/file.ext:line`
- **Source:** ...
- **Sink:** ...
- **Data flow:** ...
- **Existing controls:** ...
- **Why controls are insufficient:** ...
- **Exploit sketch:** ...
- **Blast radius:** ...
- **Confidence:** ...
- **Recommended fix:** ...
- **Tests to add:** ...

## Partial Flows / Needs Human Confirmation
- ...

## Sinks Reviewed With No Finding
- ...

## Gaps
- ...
```

## Stop conditions

Stop and report rather than pushing through if:

- A candidate issue would require running a destructive payload to
  validate.
- A key flow depends on production-only routing, secrets, network
  topology, or policy code outside the repo.
- Live credentials, private keys, or unmistakable exploit artifacts are
  discovered.
~~~

## Output contract

- `SECURITY_INJECTION_SINK_AUDIT.md` or equivalent stdout report.
- Findings must include source, sink, data flow, existing controls, and
  why the controls fail.
- No code edits.

## Guardrails

- Read-only and local-only validation.
- Do not include credential values, tokens, or private keys.
- Do not label a flow exploitable solely because a dangerous function is
  present; prove or explain the source-to-sink path.
- Treat model output, retrieved context, and tool output as untrusted data
  when auditing AI-assisted code paths.

## Related

- [Source code audit - attack surface map]({{< relref "/prompt-library/general/source-code-attack-surface-map" >}})
- [SAST finding - triage and fix]({{< relref "/prompt-library/general/sast-finding-triage-and-fix" >}})
- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
