---
title: "GHSA-hf2g-6j7h-98wg - Klever-Go direct-message goroutine DoS"
linkTitle: "GHSA-hf2g Klever-Go direct message DoS"
description: "High-severity Klever-Go libp2p direct-message denial of service. Upgrade to 1.7.18+, bound ingress goroutine creation before ProcessReceivedMessage, and test DirectSendID flood controls locally."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "klever-go", "go", "blockchain", "p2p", "libp2p", "direct-message", "goroutine", "denial-of-service", "resource-exhaustion", "high"]
weight: 87
date: 2026-06-07
ghsa: "GHSA-hf2g-6j7h-98wg"
known_as: ["Klever-Go direct-message goroutine DoS", "DirectSendID ingress throttling bypass"]
kev: false
severity: "high"
ecosystem: "go/gomod"
disclosed: "2026-06-02"
---

Klever-Go versions `1.7.14` through `1.7.17` can spawn an unbounded goroutine
for each inbound libp2p direct message before message-processor antiflood
logic makes an admission decision. A connected peer can send many well-formed
direct-message envelopes with different sequence numbers, causing the node to
allocate goroutines, stacks, and message references faster than processors can
drain them.

This is distinct from Klever-Go P2P decompression, throttler-slot, and nil
`RawData` advisories. The vulnerable surface is the direct-message ingress
wrapper itself: `directMessageHandler` creates asynchronous work before the
normal `ProcessReceivedMessage` path has a chance to reject or rate-limit it.
Repositories that fork, build, deploy, or wrap Klever-Go nodes need to
upgrade and prove inbound direct-message processing is bounded before any
goroutine spawn.

As of 2026-06-07, GitHub Advisory Database lists no CVE for this advisory.

## When to use it

- A repository depends on, forks, vendors, builds, or deploys Klever-Go
  `1.7.14` through `1.7.17`.
- Validator, sentry, observer, relay, indexer, testnet, or developer nodes
  accept libp2p direct messages from untrusted or semi-trusted peers.
- Forked direct-message code can spawn goroutines before ingress admission.
- You need a bounded PR or triage note that upgrades Klever-Go and proves
  direct-message work is bounded before goroutine creation.

## Inputs

- Go modules, vendored trees, forks, node images, release artifacts, Docker/
  Helm/K8s/systemd manifests, SBOMs, and generated dependency reports.
- Direct-message handler code, throttlers/semaphores/worker pools, peer budgets,
  processor antiflood logic, and node exposure inventory.
- Available Go tests, targeted P2P tests, race/stress tests, image build,
  deployment render, SBOM, and dependency/security scan commands.

## Affected versions

- **Vulnerable package:** `github.com/klever-io/klever-go >=1.7.14, <=1.7.17`
- **Fixed package:** `github.com/klever-io/klever-go 1.7.18+`
- **Advisory ID:** `GHSA-hf2g-6j7h-98wg`
- **Severity:** High, CVSS 3.1 score 7.5
- **Weaknesses:** CWE-400 Uncontrolled Resource Consumption and CWE-770
  Allocation of Resources Without Limits or Throttling
- **Affected surface:** libp2p direct-message ingress, especially
  `network/p2p/libp2p/netMessenger.go` and `directMessageHandler` paths that
  call `go func(...)` before a throttler, semaphore, processor admission
  check, or synchronous validation gate.

## Indicator-of-exposure

- The repository depends on, vendors, forks, builds, or deploys
  `github.com/klever-io/klever-go` in the vulnerable range.
- The repository owns node images, Helm charts, Compose files, systemd units,
  runner scripts, release artifacts, or operations runbooks for Klever-Go
  validator, sentry, observer, relay, indexer, or testnet nodes.
- P2P direct messaging is reachable from untrusted or semi-trusted peers.
- Code contains `directMessageHandler`, `DirectSendID`, `directStreamHandler`,
  `ProcessReceivedMessage`, `goRoutinesThrottler`, `broadcastGoRoutines`,
  `seenMessages`, or custom libp2p direct-message wrappers.
- Tests assert happy-path direct messages but do not prove inbound message
  bursts are bounded before goroutine creation.

Quick checks:

```bash
rg -n "klever-go|directMessageHandler|DirectSendID|directStreamHandler|ProcessReceivedMessage|goRoutinesThrottler|broadcastGoRoutines|seenMessages|libp2p|SendToConnectedPeer" .
go list -m all | rg "github.com/klever-io/klever-go"
go list -m -json github.com/klever-io/klever-go
rg -n "klever|validator|sentry|observer|libp2p|p2p|direct|peer" Dockerfile* docker-compose*.yml compose*.yml charts k8s deploy deployments systemd scripts .github . 2>/dev/null
```

Windows:

```powershell
rg -n "klever-go|directMessageHandler|DirectSendID|directStreamHandler|ProcessReceivedMessage|goRoutinesThrottler|broadcastGoRoutines|seenMessages|libp2p|SendToConnectedPeer" .
go list -m all | rg "github.com/klever-io/klever-go"
go list -m -json github.com/klever-io/klever-go
rg -n "klever|validator|sentry|observer|libp2p|p2p|direct|peer" Dockerfile* docker-compose*.yml compose*.yml charts k8s deploy deployments systemd scripts .github .
```

Do not send direct-message flood traffic to live nodes, public testnets,
hosted RPCs, validators, explorers, or third-party infrastructure.

## Remediation strategy

- Upgrade every controlled Klever-Go dependency, fork baseline, vendored tree,
  image, binary, generated dependency report, and SBOM to `1.7.18+`.
- If this repository owns a fork or wrapper, gate inbound direct messages
  before goroutine creation. Use an ingress semaphore, throttler, peer budget,
  or synchronous processing path that bounds concurrent work.
- Prefer making direct-message ingress symmetric with the pubsub path where
  possible: transform/check the message, find the processor, then call
  `ProcessReceivedMessage` under a bounded admission model.
- If asynchronous processing is required, acquire capacity before cloning or
  retaining message data and always release capacity when processing finishes.
- Treat processor-level antiflood as necessary but insufficient when it runs
  after goroutine creation. The resource allocation must be bounded before the
  goroutine, stack, and message references exist.
- Review dedupe assumptions. Do not rely on attacker-controlled sequence
  numbers or seen-message caches as the only direct-message flood control.
- Add local regression tests that send controlled in-process direct-message
  bursts and assert bounded goroutine growth, throttler engagement, normal
  message processing, and non-secret metrics.

## The prompt

~~~markdown
You are remediating GHSA-hf2g-6j7h-98wg, a high-severity Klever-Go libp2p
direct-message denial of service caused by spawning one goroutine per inbound
direct message before antiflood admission. Produce exactly one output:

- A reviewer-ready PR/change request that upgrades Klever-Go, bounds inbound
  direct-message goroutine creation, adds local burst-regression tests,
  refreshes generated artifacts, and documents node-operator rollout actions,
  or
- TRIAGE.md if this repository does not control an affected Klever-Go
  dependency, fork, node image, direct-message wrapper, deployment, or runbook.

## Rules

- Scope only GHSA-hf2g-6j7h-98wg and directly related Klever-Go libp2p
  direct-message ingress, goroutine throttling, peer admission, dependency,
  image, deployment, SBOM, and operator-exposure controls.
- Treat validator keys, node keys, peer lists, private node topology, network
  captures, logs, telemetry, crash dumps, release artifacts, and production
  node addresses as sensitive.
- Do not run direct-message flood traffic against production, public testnet,
  hosted RPC, explorer, validator, or third-party infrastructure.
- Do not remove P2P validation, disable antiflood controls, widen peer
  exposure, turn off monitoring, or rely only on auto-restart as the fix.
- Do not auto-merge.

## Steps

1. Inventory every Klever-Go reference controlled by this repository: Go
   manifests and locks, vendored or forked code, Dockerfiles, release scripts,
   CI images, Helm/Kubernetes manifests, Compose files, systemd units, node
   bootstrap scripts, generated dependency reports, SBOMs, and runbooks.
2. Determine every resolved `github.com/klever-io/klever-go` version. A target
   is vulnerable if it resolves to `>=1.7.14` and `<=1.7.17`.
3. Search for repository-owned direct-message ingress paths:
   `directMessageHandler`, `DirectSendID`, `directStreamHandler`,
   `ProcessReceivedMessage`, `goRoutinesThrottler`, `broadcastGoRoutines`,
   `seenMessages`, `Seqno`, direct peer send helpers, and libp2p wrappers.
4. If the repository does not depend on, fork, vendor, build, deploy, or wrap
   Klever-Go direct-message behavior, stop with `TRIAGE.md` listing checked
   files, resolved ownership, and the required fixed version `1.7.18+`.
5. Upgrade every controlled Klever-Go dependency, fork baseline, image,
   release artifact, generated dependency report, and SBOM to `1.7.18+`.
6. Where this repository owns forked or wrapped direct-message code, enforce a
   bounded admission gate before goroutine creation:
   - acquire an ingress throttler, semaphore, peer budget, or worker-pool slot
     before spawning;
   - release capacity on every return path;
   - reject or backpressure excess messages with non-secret logging;
   - keep valid direct-message behavior compatible with existing processors;
   - do not allocate unbounded goroutines, message clones, or buffers before
     admission succeeds.
7. Consider removing the asynchronous wrapper and calling
   `ProcessReceivedMessage` synchronously if that matches the existing pubsub
   callback behavior and product latency requirements.
8. Review adjacent P2P resource controls:
   - seen-message caches and sequence-number handling;
   - per-peer budgets;
   - direct-stream frame limits;
   - processor-level antiflood;
   - panic recovery and metrics;
   - validator, sentry, observer, and relay node exposure.
9. Add safe local regression tests:
   - direct-message bursts do not increase goroutine count linearly;
   - the ingress throttler blocks or rejects excess work before spawn;
   - processor-level antiflood still runs for admitted messages;
   - valid direct messages still reach their registered processor;
   - logs and metrics omit peer secrets, node keys, topology, payload bytes,
     and production addresses.
10. Add a PR body section named `GHSA-hf2g Klever-Go operator actions` that
    states:
    - Klever-Go versions before and after;
    - which direct-message paths changed;
    - which bounded admission model is now used;
    - whether validator, sentry, observer, relay, indexer, testnet, or
      developer nodes are affected;
    - what burst and goroutine-growth tests were added;
    - what deployment artifacts and SBOMs were refreshed;
    - which rollout, health-check, crash-loop, and monitoring actions remain
      for operators;
    - which validation commands passed.
11. Run available validation: `go test`, targeted libp2p direct-message tests,
    race or stress tests where practical, dependency scan, lock/vendor
    integrity, image build, deployment manifest lint, SBOM refresh, and
    non-secret node startup smoke checks.
12. Use PR title:
    `fix(sec): remediate GHSA-hf2g in Klever-Go direct messages`.

## Stop conditions

- No affected Klever-Go dependency, fork, vendored tree, direct-message
  wrapper, node image, deployment, runbook, or SBOM is controlled by this
  repository.
- The vulnerable node runtime is supplied only by another platform, validator
  operator, vendor, or chain team; name the owner and required fixed version in
  `TRIAGE.md`.
- A fixed Klever-Go version cannot be consumed without a broader chain,
  protocol, or maintenance-window migration.
- Verification would require flood traffic against live nodes, exposing node
  topology, using validator credentials, or degrading shared services.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled Go module, vendored tree, image, SBOM, or generated dependency
  report resolves `github.com/klever-io/klever-go` to `1.7.14` through
  `1.7.17`.
- Inbound direct-message processing cannot spawn unbounded goroutines before
  an ingress throttler, semaphore, worker-pool slot, or synchronous processing
  gate admits the message.
- Local tests prove direct-message bursts are bounded and valid messages still
  reach registered processors.
- Operator notes cover validator/sentry/observer rollout, crash-loop alerting,
  peer exposure, and unmanaged node ownership.

## Output contract

- Reviewer-ready PR upgrading Klever-Go to `1.7.18+` across modules, forks,
  images, binaries, SBOMs, and generated reports.
- Bounded direct-message admission before goroutine creation in owned wrappers
  or forked code.
- Local regression tests proving burst handling is bounded without flooding
  live nodes.
- `TRIAGE.md` when node runtime, fork, deployment, or rollout ownership is
  outside this repository.

## Watch for

- Updating `go.mod` while release images, vendored code, generated binaries,
  Docker tags, or SBOMs still ship `1.7.14` through `1.7.17`.
- Reusing the outgoing broadcast throttler incorrectly while leaving inbound
  direct-message paths able to allocate work first.
- Treating `ProcessReceivedMessage` antiflood as sufficient when it still runs
  after goroutine creation.
- Depending on seen-message caches keyed by attacker-influenced sequence
  numbers as the only flood control.
- Running stress tests against shared nodes or logging peer topology, node
  keys, private chain configuration, production addresses, or raw payloads.

## Related recipes

- [Klever-Go P2P nil RawData DoS]({{< relref "/prompt-library/cve/ghsa-rm5c-5x2p-48wr-klever-go-p2p-nil-rawdata-dos" >}})
- [Klever-Go REST API slow-header DoS]({{< relref "/prompt-library/cve/ghsa-w4c6-7r69-w7j9-klever-go-rest-api-slow-header-dos" >}})
- [CVE intelligence intake gate]({{< relref "/prompt-library/general/cve-intelligence-intake-gate" >}})

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-hf2g-6j7h-98wg>
- Klever-Go 1.7.18 release: <https://github.com/klever-io/klever-go/releases/tag/v1.7.18>
