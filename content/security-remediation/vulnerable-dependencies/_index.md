---
title: Vulnerable Dependency Remediation
linkTitle: Vulnerable Dependency Remediation
weight: 2
sidebar:
  open: true
description: >
  Turn CVE and Dependabot advisories into lockfile bumps that pass
  tests — or a structured triage note explaining why a human needs
  to take it from here.
---

{{< callout type="info" >}}
**Scope.** Third-party dependencies only (SCA findings). First-party
code vulnerabilities (SAST) go through a separate workflow because
the fix shape is wildly different.
{{< /callout >}}

## What problem this solves

A typical mid-sized repo sees 5–20 new dependency advisories per
month. Most of them are routine version bumps — the advisory
reports the affected range, there's a patched version, and the
lockfile just needs updating. Historically this work piled up and
lost its urgency; by the time someone got to it, three more had
landed. This workflow drains the easy cases automatically so the
humans only see the hard ones.

{{< playbook-workflow >}}

## High-level flow

```mermaid
flowchart LR
    A[CVE feed / Dependabot] -->|advisory| B[Orchestrator]
    B --> C{Classifier}
    C -->|direct, patch in range| D[Agent: bump]
    C -->|transitive| E{Policy engine}
    E -->|auto-ok| D
    E -->|needs human| F[Triage queue]
    C -->|major bump required| F
    D --> G[Sandbox: apply bump]
    G --> H[Run tests]
    H -->|pass| I[PR: auto-remediation label]
    H -->|fail| J[Revert + TRIAGE.md]
    I --> K[Human reviewer]
    K -->|approve| L[Merge]
```

## Intake paths

Most programs start with one intake path and grow into more.
Two shapes are worth naming explicitly because they have
different orchestration implications:

- **Orchestrator-pulled.** Your orchestrator polls the advisory
  feed (CVE / OSV / vendor SCA API), classifies, and dispatches
  the agent. You own the identity, the queue, the rate limits,
  and the audit trail end-to-end. This is the shape the rest of
  this workflow assumes.
- **Platform-assigned.** The code-hosting platform exposes an
  "assign to agent" action directly on the native alert UI —
  Dependabot alerts assignable to Copilot, Claude, or Codex
  (2026) is the representative example; expect equivalents on
  GitLab, Bitbucket, and the SCA vendors. The platform spawns
  the run, opens the draft PR, and ties it back to the alert.
  No orchestrator required.

**If you run both**, treat platform-assigned as the *fallback*
path — it catches anything that falls off the main queue and
stays useful as a manual-escalation lever for reviewers — and
make sure the two audit trails land in a shared stream. "Which
agent, on whose authority, touched this PR?" should have one
answer, not two.

## What 'eligible' means

The classifier hands a finding to the agent only when:

- The advisory specifies a fix version (not "no fix yet").
- The affected package is present in the repo's lockfile.
- The patched version does **not** cross a major-version boundary
  on a direct dependency. Major bumps require a human.
- The repo has a passing CI pipeline and a `make test` (or
  equivalent) target the agent can invoke.

Everything else routes to the triage queue.

## What the agent does

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant A as Agent
    participant S as Sandbox
    participant R as Registry

    O->>A: advisory + repo snapshot
    A->>R: look up patched range
    A->>S: locate package in lockfile
    A->>S: invoke package manager<br/>(npm / poetry / go)
    S-->>A: new lockfile
    A->>S: run tests
    alt tests pass
        A->>O: PR<br/>"bump pkg to X.Y.Z (CVE-...)"
    else tests fail
        A->>S: revert bump
        A->>O: TRIAGE.md<br/>+ failing test names
    end
```

## Per-ecosystem notes

- **Node.** Uses `npm`, `pnpm`, or `yarn` depending on the
  lockfile present. Never hand-edits `package-lock.json`.
- **Python.** Uses `poetry`, `uv`, or `pip-compile` depending on
  the project. Hand-editing `requirements.txt` is allowed only
  when no resolver is configured.
- **Go.** Uses `go get` then `go mod tidy`. Never edits
  `go.sum` directly.
- **Monorepos.** Each lockfile gets its own PR. No cross-lockfile
  bundling — reviewers need diffs they can reason about in
  isolation.

## Guardrails

- **One CVE, one PR.** Bundling multiple fixes masks which bump
  caused a regression. One is the rule, even if it creates more
  PRs. Tag each PR with an auto-remediation label — the site uses
  `sec-auto-remediation` as the illustrative example; rename to
  your org's convention.
- **No code edits outside the lockfile.** If a bump requires a
  code change, the agent stops — that's a human call.
- **No CI skip tokens.** The agent will never add `[skip ci]`,
  `[skip test]`, or similar. If CI fails, the change fails.
- **Quota per repo.** A per-repo cap on open agent PRs prevents
  the reviewer queue from becoming a firehose.
- **Yanked version guard.** The registry is re-queried just before
  PR open; if the patched version was yanked, the agent stops and
  writes a triage note.
- **Malicious-package downgrade path.** "Bump to the latest patched
  version" is the wrong default when the *advisory itself* is that
  the package was compromised (maintainer account takeover,
  poisoned release, self-propagating worm in the supply chain). In
  those cases the remediation is a **pin backwards** to a
  known-good version — or an eject to a fork — not a forward bump.
  The classifier should recognise the advisory shape ("malicious
  code in versions X and later") and route the agent to a
  downgrade workflow; if the affected version is the only published
  version, escalate to a human. See
  [Threat Model → Agent-infrastructure supply-chain compromise]({{< relref "/fundamentals/threat-model#observed-real-world-patterns" >}})
  for why this case is worth calling out separately.

## What it won't catch

- **Transitive deps behind a pin** — when a direct dep pins the
  vulnerable transitive by exact version, the bump requires the
  direct dep to update first. Routed to triage.
- **Private registries** the orchestrator hasn't been granted
  read access to.
- **Native modules** that build on the CI runner but fail in prod
  (different ABI, different glibc). Reviewer checklist flags
  these; the agent doesn't detect them.
- **Embargoed / pre-disclosure CVEs** — these go through an
  out-of-band process; the automated feed doesn't see them.

## How this workflow evolves

Same principle as the other workflows: orchestration is constant,
inputs evolve.

- **Prompt.** The triage heuristics (when to stop, how to format
  the PR body) get tuned from reviewer pushback.
- **Model.** Upgraded when a newer model measurably improves
  precision on the team's labelled CVE set.
- **Tools.** New ecosystem connectors (e.g. Rust `Cargo.lock`,
  PHP `composer.lock`) plug in as MCP servers without touching
  the orchestrator.

## Changelog

- 2026-04-21 — v1 reference workflow, covers Node, Python, and
  Go. Rust and PHP are typical next-quarter extensions for teams
  adopting this pattern.
