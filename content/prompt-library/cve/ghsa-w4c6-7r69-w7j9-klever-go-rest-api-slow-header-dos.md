---
title: "GHSA-w4c6-7r69-w7j9 - Klever-Go REST API slow-header DoS"
linkTitle: "GHSA-w4c6 Klever-Go REST DoS"
description: "High-severity Klever-Go REST API slow-header denial of service. Upgrade to 1.7.18+, replace Gin Engine.Run with explicit HTTP server limits, and add local slow-header regression tests."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "klever-go", "go", "gin", "rest-api", "slowloris", "denial-of-service", "resource-exhaustion", "high"]
weight: 86
date: 2026-06-07
ghsa: "GHSA-w4c6-7r69-w7j9"
aliases: ["Klever-Go REST API slow-header DoS", "Gin Engine.Run header timeout exhaustion"]
kev: false
severity: "high"
ecosystem: "go/gomod"
disclosed: "2026-06-02"
---

Klever-Go versions `1.7.14` through `1.7.17` start seednode and node REST
listeners through Gin's `Engine.Run`. That helper delegates to Go's default
HTTP server path without application-level header read deadlines, request
read deadlines, idle deadlines, or header-size limits. A client that can reach
an exposed REST listener can hold incomplete request headers open and consume
server-side sockets until legitimate REST traffic fails.

This is an operator-relevant availability issue. The default REST bind may be
localhost, but Klever-Go documents an all-interface `:8080` bind and common
Docker examples publish the REST port. Repositories that fork, build, deploy,
or wrap Klever-Go need to upgrade and prove that both REST startup paths are
served through explicit `http.Server` limits rather than relying on a reverse
proxy alone.

As of 2026-06-07, GitHub Advisory Database lists no CVE for this advisory.

## Affected versions

- **Vulnerable package:** `github.com/klever-io/klever-go >=1.7.14, <=1.7.17`
- **Fixed package:** `github.com/klever-io/klever-go 1.7.18+`
- **Advisory ID:** `GHSA-w4c6-7r69-w7j9`
- **Severity:** High, CVSS 3.1 score 7.5
- **Weaknesses:** CWE-400 Uncontrolled Resource Consumption and CWE-770
  Allocation of Resources Without Limits or Throttling
- **Affected surfaces:** `cmd/seednode/api.Start`, `network/api.Start`, and
  any forked or wrapped REST startup that calls `gin.Engine.Run`,
  `http.ListenAndServe`, or equivalent server creation without read-header
  limits.

## Indicator-of-exposure

- The repository depends on, vendors, forks, builds, or deploys
  `github.com/klever-io/klever-go` in the vulnerable range.
- Docker, Compose, Helm, Kubernetes, Terraform, systemd, or node runbook
  artifacts expose Klever REST API port `8080` or set
  `--rest-api-interface :8080`.
- REST startup code calls `ws.Run(...)`, `engine.Run(...)`, `gin.Engine.Run`,
  `http.ListenAndServe`, or a package helper that hides a default server.
- There is no application-owned `http.Server` with `ReadHeaderTimeout`,
  `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes` on the
  node and seednode REST API paths.
- Tests cover REST handlers with completed requests only and do not prove that
  slow or incomplete headers are closed quickly.

Quick checks:

```bash
rg -n "klever-go|rest-api-interface|:8080|gin\\.Default|\\.Run\\(|ListenAndServe|ReadHeaderTimeout|MaxHeaderBytes|cmd/seednode/api|network/api" .
go list -m all | rg "github.com/klever-io/klever-go"
go list -m -json github.com/klever-io/klever-go
rg -n "klever|seednode|validator|observer|rest-api|8080|hostPort|containerPort|ports:" Dockerfile* docker-compose*.yml compose*.yml charts k8s deploy deployments systemd scripts .github . 2>/dev/null
```

Windows:

```powershell
rg -n "klever-go|rest-api-interface|:8080|gin\\.Default|\\.Run\\(|ListenAndServe|ReadHeaderTimeout|MaxHeaderBytes|cmd/seednode/api|network/api" .
go list -m all | rg "github.com/klever-io/klever-go"
go list -m -json github.com/klever-io/klever-go
rg -n "klever|seednode|validator|observer|rest-api|8080|hostPort|containerPort|ports:" Dockerfile* docker-compose*.yml compose*.yml charts k8s deploy deployments systemd scripts .github .
```

Do not run slow-header tests against public nodes, hosted RPC endpoints,
production validators, shared testnets, or third-party infrastructure.

## Remediation strategy

- Upgrade every controlled Klever-Go dependency, fork baseline, vendored tree,
  image, binary, generated dependency report, and SBOM to `1.7.18+`.
- If this repository owns a fork or local REST wrapper, replace Gin
  `Engine.Run` and default `ListenAndServe` usage with explicit `http.Server`
  construction on every REST startup path.
- Set defensive server limits in application code: `ReadHeaderTimeout`,
  `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes`. Tune the
  values to production behavior, but make missing header deadlines a test
  failure.
- Apply the same server-limit helper to seednode and node REST API startup so
  future fixes do not drift between the two entry points.
- Keep reverse proxies, firewalls, and load balancers as defense-in-depth. Do
  not rely on them as the only fix for binaries that can bind directly to all
  interfaces.
- Review deployment defaults. Prefer localhost binding, private network
  exposure, authenticated gateways, or disabling the REST API where operators
  do not require it.
- Add local regression tests that open incomplete HTTP headers against a
  loopback-only server and assert that connections are closed by the configured
  deadline while normal probes continue to succeed.

## The prompt

~~~markdown
You are remediating GHSA-w4c6-7r69-w7j9, a high-severity Klever-Go REST API
slow-header denial of service caused by starting Gin routers through default
HTTP server paths without header deadlines. Produce exactly one output:

- A reviewer-ready PR/change request that upgrades Klever-Go, replaces unsafe
  REST startup with explicit HTTP server limits, adds local slow-header
  regression tests, refreshes generated artifacts, and documents node-operator
  rollout actions, or
- TRIAGE.md if this repository does not control an affected Klever-Go
  dependency, fork, node image, REST wrapper, deployment, or runbook.

## Rules

- Scope only GHSA-w4c6-7r69-w7j9 and directly related Klever-Go REST API
  startup, HTTP server limit, dependency, image, deployment, SBOM, and
  operator-exposure controls.
- Treat validator keys, node keys, API credentials, peer lists, private node
  topology, logs, telemetry, crash dumps, release artifacts, and production
  node addresses as sensitive.
- Do not run slow-header traffic against production, public testnet, hosted
  RPC, explorer, validator, or third-party infrastructure.
- Do not disable REST functionality, widen REST exposure, remove health
  checks, turn off monitoring, or rely only on auto-restart as the fix.
- Do not auto-merge.

## Steps

1. Inventory every Klever-Go reference controlled by this repository: Go
   manifests and locks, vendored or forked code, Dockerfiles, release scripts,
   CI images, Helm/Kubernetes manifests, Compose files, systemd units, node
   bootstrap scripts, generated dependency reports, SBOMs, and runbooks.
2. Determine every resolved `github.com/klever-io/klever-go` version. A target
   is vulnerable if it resolves to `>=1.7.14` and `<=1.7.17`.
3. Search for repository-owned REST startup paths and deployment exposure:
   `rest-api-interface`, `cmd/seednode/api`, `network/api`, `gin.Default`,
   `Engine.Run`, `ListenAndServe`, `ReadHeaderTimeout`, `MaxHeaderBytes`,
   Docker port `8080`, Kubernetes services, ingress rules, and node runbooks.
4. If the repository does not depend on, fork, vendor, build, deploy, or wrap
   Klever-Go REST APIs, stop with `TRIAGE.md` listing checked files, resolved
   ownership, and the required fixed version `1.7.18+`.
5. Upgrade every controlled Klever-Go dependency, fork baseline, image,
   release artifact, generated dependency report, and SBOM to `1.7.18+`.
6. Where this repository owns forked or wrapped REST startup code, replace
   `Engine.Run` or default `ListenAndServe` calls with an explicit
   `http.Server` helper that sets:
   - address from the configured REST bind;
   - handler from the Gin router;
   - `ReadHeaderTimeout`;
   - `ReadTimeout`;
   - `WriteTimeout`;
   - `IdleTimeout`;
   - `MaxHeaderBytes`.
7. Apply the same helper to both seednode and node REST APIs. Add a test or
   static assertion that neither path regresses to `Engine.Run`.
8. Add safe loopback-only regression tests:
   - incomplete headers are closed after the read-header deadline;
   - a batch of slow-header connections does not block normal `/log` or health
     probes;
   - default localhost binding remains private unless deployment artifacts
     intentionally expose the port;
   - timeout and max-header configuration is visible in non-secret test output.
9. Review deployment controls:
   - prefer localhost or private interface binding;
   - verify whether Docker, Compose, Helm, Kubernetes, or Terraform publishes
     `8080`;
   - place exposed REST APIs behind authenticated gateways or trusted networks;
   - document any unmanaged nodes that another operator must upgrade.
10. Add a PR body section named `GHSA-w4c6 Klever-Go operator actions` that
    states:
    - Klever-Go versions before and after;
    - which REST startup paths changed;
    - which timeout and header-size limits are now enforced;
    - whether Docker, Kubernetes, or node runbooks expose REST port `8080`;
    - what local slow-header and normal-probe tests were added;
    - what deployment artifacts and SBOMs were refreshed;
    - which rollout, health-check, and monitoring actions remain for operators;
    - which validation commands passed.
11. Run available validation: `go test`, targeted REST startup tests, local
    slow-header regression tests, dependency scan, lock/vendor integrity,
    image build, deployment manifest lint, SBOM refresh, and non-secret node
    startup smoke checks.
12. Use PR title:
    `fix(sec): remediate GHSA-w4c6 in Klever-Go REST API`.

## Stop conditions

- No affected Klever-Go dependency, fork, vendored tree, REST wrapper, node
  image, deployment, runbook, or SBOM is controlled by this repository.
- The vulnerable node runtime is supplied only by another platform, validator
  operator, vendor, or chain team; name the owner and required fixed version in
  `TRIAGE.md`.
- A fixed Klever-Go version cannot be consumed without a broader chain,
  protocol, or maintenance-window migration.
- Verification would require slow-header traffic against live nodes, exposing
  node topology, using validator credentials, or degrading shared services.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled Go module, vendored tree, image, SBOM, or generated dependency
  report resolves `github.com/klever-io/klever-go` to `1.7.14` through
  `1.7.17`.
- Seednode and node REST API startup use explicit HTTP server limits instead
  of Gin `Engine.Run` or default `ListenAndServe`.
- Local tests prove incomplete headers are closed and legitimate probes still
  succeed under slow-header pressure.
- Deployment notes identify whether REST port `8080` is exposed and who owns
  any remaining node upgrades.

## Watch for

- Updating `go.mod` while release images, vendored code, generated binaries,
  Docker tags, or SBOMs still ship `1.7.14` through `1.7.17`.
- Fixing only `cmd/seednode/api.Start` while `network/api.Start` keeps using
  `Engine.Run`.
- Assuming a reverse proxy always protects the binary even though documented
  node options can bind the REST API directly to all interfaces.
- Tests that use completed HTTP requests only and never hold headers open.
- Logging node topology, credentials, API tokens, private chain configuration,
  or production endpoint names in regression output.

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-w4c6-7r69-w7j9>
- Klever-Go 1.7.18 release: <https://github.com/klever-io/klever-go/releases/tag/v1.7.18>
