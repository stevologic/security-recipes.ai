---
title: "Compromised package — cache quarantine"
linkTitle: "Cache quarantine for compromised packages"
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["supply-chain", "registry", "cache", "quarantine", "incident"]
weight: 14
date: 2026-04-25
---

A tool-agnostic prompt that takes a "this package is malicious"
advisory and runs the eviction across the org's registries,
caches, and mirrors — quarantining the artifact, verifying the
purge worked, and drafting the developer-machine broadcast a
human will deliver.

Designed to slot into the
[Artifact Cache & Mirror Quarantine]({{< relref "/security-remediation/artifact-cache-purge" >}})
workflow.

## What this prompt does

1. **Reads the advisory** — the artifact coordinate, the
   versions, the registries to inspect.
2. **Inventories** — for each registry / proxy / cache the agent
   has a connector for, lists matching versions or digests.
3. **Quarantines** the matching versions (preferred) or
   deletes them where policy requires. Default action is
   reversible quarantine.
4. **Verifies** by re-fetching the purged artifact and
   confirming the registry refuses to serve it.
5. **Drafts the developer-machine broadcast** — paste-ready
   purge commands for `npm`, `pip`, `go`, `docker`, etc., plus
   verification commands.
6. **Records the audit entry** — registry actions, verification
   results, restore commands, and the broadcast text.

## When to use it

- An advisory says a published artifact (package, image, chart)
  is malicious — maintainer takeover, poisoned release,
  supply-chain compromise.
- The artifact is identifiable by a stable coordinate.
- The org's registries / proxies have agent-quarantine API
  access declared in policy.

**Don't use it for:**

- Routine vulnerable-version advisories (use the
  [vulnerable-dependency workflow]({{< relref "/security-remediation/vulnerable-dependencies" >}})).
- Range-based or fuzzy advisories without a stable coordinate.
- Air-gapped mirrors the agent has no network path to (the
  broadcast pattern applies).
- Reaching into developer machines (the agent drafts
  broadcasts; humans deliver them).

## Inputs

- **Advisory** — ID, ecosystem, package name(s), affected
  versions, type (compromise vs. vulnerable).
- **Registry list** — which registry / proxy / cache connectors
  to use for this ecosystem.
- **Policy** — quarantine vs. hard delete; whether the
  developer-machine broadcast is required.

## The prompt

~~~markdown
You are running a cache-quarantine action across this
organization's registries in response to a compromise advisory.
Your output is exactly one of:

- A complete audit record showing every registry purged, every
  verification passing, and a drafted developer-machine
  broadcast text.
- A `TRIAGE.md` note explaining what could not be completed and
  what a human needs to do next.

Do not act on advisories that are not labelled
`compromise`/`malicious`. Do not perform a hard delete unless
the policy explicitly requires it for this advisory.

## Step 0 — Validate the input

1. Confirm the advisory is labelled `compromise` or `malicious`.
   If it is a routine `vulnerable` advisory, stop and route to
   the vulnerable-dependency workflow.
2. Confirm the advisory provides a stable coordinate
   (`name@version` for packages, `image:tag` or `image@digest`
   for containers). If the coordinate is fuzzy (range,
   wildcard), stop and triage.

## Step 1 — Inventory

For each registry / proxy / cache connector you have access to:

1. List all versions / digests matching the advisory's
   coordinate.
2. Record the registry's URL, the matching coordinates, and
   the version timestamps.
3. If the connector returns an empty list, record "not present
   in this registry" — do not preemptively block versions the
   advisory does not name.

## Step 2 — Quarantine

For each matching version on each registry:

1. Use the registry's quarantine API to mark the version
   forbidden. Quarantine is the default; only hard-delete if
   the policy file flags this advisory as `delete-required`.
2. Capture the registry's response and the resulting state.
3. If a registry rejects the quarantine call (permission,
   API error, version not deletable), record the failure and
   continue with the rest — do not abort the whole run on one
   registry's failure. Failures show up in the audit and the
   triage note.

## Step 3 — Verify

For each version you quarantined:

1. Make a fresh fetch attempt against the registry as a normal
   client would (not the privileged quarantine endpoint).
2. Confirm the registry returns a 404 / forbidden / quarantine
   response.
3. If the registry still serves the artifact, **revert the
   quarantine** for that version, record the failure in the
   audit, and add the registry to the triage note.

## Step 4 — Draft the developer-machine broadcast

Write a paste-ready broadcast text containing:

- A one-paragraph summary of the advisory.
- The exact purge command(s) for each ecosystem in scope. For
  the most common cases:
  - npm/pnpm/yarn: `npm cache clean --force` and remove
    matching entries from `~/.npm/_cacache`.
  - pip: `pip cache remove '<package>'` (and
    `~/.cache/pip/wheels` removal if the wheel is matched).
  - Go: `go clean -modcache` (note: removes everything; for
    targeted, `rm -rf ~/go/pkg/mod/<module>@<version>`).
  - Maven: remove `~/.m2/repository/<group>/<artifact>/<version>`.
  - Docker / Podman: `docker rmi <image>:<tag>` and prune by
    digest.
- A verify-clean command per ecosystem.
- The contact channel for "I purged but the package still shows
  up" reports.

The broadcast is **drafted, not delivered**. The audit record
includes the text but the engineering team owns distribution.

## Step 5 — Audit record

Append a single audit entry containing:

- Advisory ID and link.
- Coordinates targeted.
- Per-registry results (success / failure / not present).
- Per-registry verification results.
- Restore commands (the inverse of each quarantine action).
- The drafted broadcast text.
- Run ID and timestamp.

## Stop conditions (write a TRIAGE.md and exit)

- Advisory is not a `compromise` / `malicious` shape.
- Coordinate is fuzzy.
- One or more registries refused quarantine and the advisory
  policy requires "all registries before declaring success."
- Verification failed on a registry that does not support a
  reliable revert path.
- A registry connector is missing entirely (do not silently
  skip).

## Scope

- Do not act on registries not in the input list.
- Do not delete unrelated versions of the same package.
- Do not publish, rotate upstream URLs, or change registry
  configuration beyond version-state.
- Do not SSH into developer machines, CI runners, or any
  laptop. The broadcast is the only output that targets dev
  machines.
- Do not silently downgrade a hard-delete policy to
  quarantine.
~~~

## Output contract

- A complete audit record with every registry's state recorded
  and the broadcast text drafted, OR a `TRIAGE.md` note.
- Out-of-band notification to the security incident channel
  fires whether the run succeeds or fails — quiet purges are
  the wrong default.

## Guardrails

- **Quarantine before delete.** Default action is reversible.
  Hard deletes require an extra approval and are not in the
  agent's default toolset.
- **Per-registry scoped credentials.** The agent's credential
  on each registry can manage version-state on packages
  matching the advisory namespace, and nothing else.
- **Coordinate match required.** No fuzzy matches.
- **Verification before success.** No "purged" claim without a
  verifying re-fetch.
- **Restore path documented.** Every quarantine action's audit
  record includes the inverse command.
- **Dev machines = broadcast, not action.** Always.

## Related

- [Artifact Cache & Mirror Quarantine]({{< relref "/security-remediation/artifact-cache-purge" >}})
  — the workflow this prompt slots into.
- [Vulnerable Dependency Remediation → Malicious-package
  downgrade path]({{< relref "/security-remediation/vulnerable-dependencies#guardrails" >}})
  — the lockfile-shaped sibling.
- [Threat Model → Agent-infrastructure supply-chain compromise]({{< relref "/fundamentals/threat-model#observed-real-world-patterns" >}})
  — why this pattern is treated separately from routine CVEs.
