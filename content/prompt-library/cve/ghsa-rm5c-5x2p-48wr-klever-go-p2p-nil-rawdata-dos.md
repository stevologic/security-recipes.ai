---
title: "GHSA-rm5c-5x2p-48wr - Klever-Go P2P nil RawData DoS"
linkTitle: "GHSA-rm5c Klever-Go P2P DoS"
description: "High-severity Klever-Go P2P transaction-interceptor denial of service. Upgrade to 1.7.18+, reject nil transaction RawData before version checks, and add panic-free P2P validation tests."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "klever-go", "go", "blockchain", "p2p", "libp2p", "denial-of-service", "nil-pointer", "high"]
weight: 85
date: 2026-06-07
ghsa: "GHSA-rm5c-5x2p-48wr"
aliases: ["Klever-Go P2P nil RawData DoS", "KVM txVersionChecker nil dereference"]
kev: false
severity: "high"
ecosystem: "go/gomod"
disclosed: "2026-06-02"
---

Klever-Go versions `1.7.14` through `1.7.17` can crash while validating
transactions received over the P2P gossip path. The vulnerable validation flow
reaches the transaction version checker before proving that the decoded
transaction has a `RawData` message. A peer-supplied transaction with omitted
`RawData` can therefore trigger a nil-pointer panic in the synchronous pubsub
validation path and terminate the node process.

This is a code-path-specific availability issue, not just a dependency row.
Repositories that vendor, fork, deploy, or configure Klever-Go nodes need to
upgrade to the fixed release and prove that malformed or incomplete P2P
transaction messages return validation errors instead of panicking. Validator,
sentry, observer, and relay deployments should also review restart loops and
network exposure because repeated delivery can keep nodes unavailable.

As of 2026-06-07, GitHub Advisory Database lists no CVE for this advisory.

## Affected versions

- **Vulnerable package:** `github.com/klever-io/klever-go >=1.7.14, <=1.7.17`
- **Fixed package:** `github.com/klever-io/klever-go 1.7.18+`
- **Advisory ID:** `GHSA-rm5c-5x2p-48wr`
- **Severity:** High, CVSS 3.1 score 7.5
- **Weakness:** CWE-476, NULL Pointer Dereference
- **Affected surface:** libp2p transaction gossip validation, especially
  transaction interceptors that invoke the version checker before rejecting nil
  transaction fields.
- **Unaffected-by-itself surface:** ordinary REST transaction submission should
  still be reviewed, but the advisory's crash path is the P2P interceptor.

## Indicator-of-exposure

- The repository depends on, vendors, forks, builds, or deploys
  `github.com/klever-io/klever-go` in the vulnerable range.
- The repository owns node images, Helm charts, Compose files, systemd units,
  runner scripts, release artifacts, or operations runbooks for Klever-Go
  validator, sentry, observer, relay, indexer, or testnet nodes.
- P2P transaction gossip is enabled and reachable from untrusted or
  semi-trusted peers.
- The code contains transaction validators, interceptors, marshalizers, pubsub
  callbacks, or direct `RawData` field dereferences that can process decoded
  network messages.
- Tests assert valid transaction handling but do not cover missing `RawData`,
  nil transaction objects, malformed batches, or panic recovery on the P2P
  message path.

Quick checks:

```bash
rg -n "klever-go|txVersionChecker|CheckTxVersion|RawData|ProcessReceivedMessage|pubsubCallback|libp2p|transactions" .
go list -m all | rg "github.com/klever-io/klever-go"
go list -m -json github.com/klever-io/klever-go
rg -n "klever|validator|sentry|observer|libp2p|p2p|transactions" Dockerfile* docker-compose*.yml compose*.yml charts k8s deploy deployments systemd scripts .github . 2>/dev/null
```

Windows:

```powershell
rg -n "klever-go|txVersionChecker|CheckTxVersion|RawData|ProcessReceivedMessage|pubsubCallback|libp2p|transactions" .
go list -m all | rg "github.com/klever-io/klever-go"
go list -m -json github.com/klever-io/klever-go
rg -n "klever|validator|sentry|observer|libp2p|p2p|transactions" Dockerfile* docker-compose*.yml compose*.yml charts k8s deploy deployments systemd scripts .github .
```

Do not broadcast crafted P2P messages, run public-network crash tests, publish
payload bytes, or disable node validation to make the advisory disappear.

## Remediation strategy

- Upgrade every controlled Klever-Go dependency, fork, vendored tree, image,
  binary, chart, generated dependency report, and SBOM to `1.7.18+`.
- If this repository owns a fork or patch layer, reject nil transaction and
  nil `RawData` inputs before reading `RawData.Version` or any other nested
  `RawData` field.
- Convert missing or incomplete transaction fields into normal validation
  errors that the interceptor path already handles. Do not allow a peer message
  to panic the process.
- Add a defensive panic boundary around synchronous P2P message validation
  where this repository owns the callback or wrapper, but treat recovery as
  defense-in-depth; the root fix is fail-closed validation before dereference.
- Audit adjacent `RawData` dereferences in transaction validity, sender,
  chain-ID, fee, nonce, contract, and getter paths for the same nil-input
  class.
- Add regression coverage that drives the real interceptor or the closest
  repository-owned wrapper with missing-`RawData` fixture data and asserts an
  error or rejection, not a panic.
- Review node deployment controls: P2P exposure, peer admission, restart
  throttling, alerting on crash loops, and rollout order for validator/sentry
  fleets.

## The prompt

~~~markdown
You are remediating GHSA-rm5c-5x2p-48wr, a high-severity Klever-Go P2P
transaction-interceptor denial of service caused by dereferencing missing
transaction RawData during version validation. Produce exactly one output:

- A reviewer-ready PR/change request that upgrades Klever-Go, rejects nil
  transaction RawData before nested field access, adds panic-free P2P
  validation tests, refreshes generated artifacts, and documents node-operator
  rollout actions, or
- TRIAGE.md if this repository does not control an affected Klever-Go
  dependency, fork, node image, deployment, or P2P transaction-validation path.

## Rules

- Scope only GHSA-rm5c-5x2p-48wr and directly related Klever-Go transaction
  validation, P2P interceptor, nil-input, panic-recovery, dependency, image,
  and node-deployment controls.
- Treat validator keys, node keys, peer lists, RPC credentials, private network
  topology, chain configuration, telemetry, logs, crash dumps, release
  artifacts, and production node addresses as sensitive.
- Do not broadcast crafted P2P payloads, connect to production or public nodes
  for exploit testing, publish payload bytes, crash live services, disable
  transaction validation, or print sensitive node configuration.
- Do not remove P2P validation, downgrade peer controls, turn off monitoring,
  or rely only on auto-restart as the fix.
- Do not auto-merge.

## Steps

1. Inventory every Klever-Go reference controlled by this repository: Go
   manifests and locks, vendored or forked code, Dockerfiles, release scripts,
   CI images, Helm/Kubernetes manifests, Compose files, systemd units, node
   bootstrap scripts, generated dependency reports, SBOMs, and runbooks.
2. Determine every resolved `github.com/klever-io/klever-go` version. A target
   is vulnerable if it resolves to `>=1.7.14` and `<=1.7.17`.
3. Search for repository-owned P2P transaction validation code:
   `txVersionChecker`, `CheckTxVersion`, `RawData`, `ProcessReceivedMessage`,
   transaction interceptors, batch decoding, pubsub callbacks, libp2p message
   handlers, panic recovery, peer blacklisting, and validator/sentry/observer
   wrappers.
4. If the repository does not depend on, fork, vendor, build, deploy, or wrap
   Klever-Go, stop with `TRIAGE.md` listing checked files, resolved ownership,
   and the required fixed version `1.7.18+`.
5. Upgrade every controlled Klever-Go dependency, fork baseline, image,
   release artifact, generated dependency report, and SBOM to `1.7.18+`.
6. If this repository owns a fork or local patch, fix the root class:
   - reject a nil transaction before any nested field access;
   - reject nil `RawData` before reading `RawData.Version`;
   - return an existing invalid-transaction sentinel where available;
   - keep peer scoring, rejection, or blacklisting behavior consistent with
     other invalid transaction versions;
   - audit every adjacent `RawData` dereference reached from network input.
7. Add defense-in-depth where this repository owns the message callback:
   - wrap synchronous pubsub or direct-message validation bodies with recovery
     that converts panics into rejected messages and observable non-secret
     metrics;
   - avoid swallowing programmer errors silently in tests;
   - ensure a single peer message cannot terminate the process.
8. Add safe regression coverage:
   - dependency policy rejects Klever-Go `1.7.14` through `1.7.17`;
   - nil transaction and nil `RawData` fixtures return validation errors;
   - malformed transaction batches do not panic the real interceptor or wrapper
     path;
   - recovery paths emit non-secret metrics/logs;
   - tests run only in-process with local fixtures and do not connect to live
     P2P networks or publish payload bytes.
9. Harden deployment and operations:
   - roll fixed images to sentry and observer nodes before broad validator
     fleet rollout where possible;
   - verify crash-loop alerts, restart throttling, and health checks;
   - review whether public P2P exposure, peer admission, or bootstrap peers can
     be narrowed during rollout;
   - document any unmanaged nodes that must be upgraded by another owner.
10. Add a PR body section named `GHSA-rm5c Klever-Go operator actions` that
    states:
    - Klever-Go versions before and after;
    - whether this repo owns dependency, fork, image, deployment, or runbook
      changes;
    - which node roles are affected: validator, sentry, observer, relay,
      indexer, testnet, or developer node;
    - what nil-input and panic-free tests were added;
    - what deployment artifacts and SBOMs were refreshed;
    - which live rollout, health-check, crash-loop, and monitoring actions
      remain for operators;
    - which validation commands passed.
11. Run available validation: `go test`, targeted interceptor tests, race or
    panic tests where practical, dependency scan, lock/vendor integrity, image
    build, deployment manifest lint, SBOM refresh, and non-secret node startup
    smoke checks.
12. Use PR title:
    `fix(sec): remediate GHSA-rm5c in Klever-Go P2P validation`.

## Stop conditions

- No affected Klever-Go dependency, fork, vendored tree, node image,
  deployment, runbook, or P2P validation wrapper is controlled by this
  repository.
- The vulnerable node runtime is supplied only by another platform, validator
  operator, vendor, or chain team; name the owner and required fixed version in
  `TRIAGE.md`.
- A fixed Klever-Go version cannot be consumed without a broader chain,
  protocol, or maintenance-window migration.
- Validation would require connecting to live P2P networks, broadcasting crash
  payloads, exposing node topology, using validator credentials, or crashing
  production services.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled Go module, vendored tree, image, SBOM, or generated dependency
  report resolves `github.com/klever-io/klever-go` to `1.7.14` through
  `1.7.17`.
- Fork or wrapper code rejects nil transactions and nil `RawData` before
  accessing `RawData.Version` or adjacent nested fields.
- P2P transaction-interceptor tests prove malformed or incomplete transaction
  messages return errors without panicking.
- Any recovery boundary added around pubsub validation records non-secret
  telemetry and does not hide test failures.
- Operator notes cover validator/sentry/observer rollout, crash-loop alerting,
  peer exposure, and unmanaged node ownership.

## Watch for

- Updating `go.mod` while release images, vendored code, generated binaries, or
  deployment manifests still ship `1.7.14` through `1.7.17`.
- Testing only REST transaction submission and missing the P2P interceptor
  path named by the advisory.
- Adding `recover()` while leaving direct `RawData` dereferences reachable from
  network input.
- Treating testnet, observer, or sentry nodes as low priority even though they
  can relay operational pressure onto validators.
- Logging peer topology, node keys, validator identifiers, crash payloads, or
  private chain configuration in regression output.

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-rm5c-5x2p-48wr>
- Klever-Go 1.7.18 release: <https://github.com/klever-io/klever-go/releases/tag/v1.7.18>
