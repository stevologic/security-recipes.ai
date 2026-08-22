---
title: "GHSA-rh99-wc69-c255: Contrast CopyFile policy symlink bypass"
linkTitle: "GHSA-rh99 Contrast CopyFile"
description: "GHSA-rh99-wc69-c255 is Contrast CopyFile symlink policy bypass. Upgrade Contrast to 1.19.1+ and regenerate Kata agent policies."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "contrast", "kata-containers", "confidential-computing", "kubernetes", "symlink", "policy", "context-boundary", "high"]
weight: 58
date: 2026-05-03
lastmod: 2026-08-21
ghsa: "GHSA-rh99-wc69-c255"
known_as: ["Contrast CopyFile policy symlink subversion", "Kata Containers CopyFile symlink", "CVE-2026-41326"]
kev: false
severity: "high"
ecosystem: "go/gomod"
disclosed: "2026-04-30"
ai_enrichment_review_status: human-reviewed-development-draft
---

GHSA-rh99-wc69-c255 covers Contrast versions before `1.19.1`. Generated Kata
agent policies could let host-side `CopyFile` requests follow symlinks and
write inside the guest root. GitHub names **Contrast 1.19.1**. Do not invent
a later 1.19.2 floor.

The related upstream issue is **CVE-2026-41326 / GHSA-q49m-57vm-c8cc**. GHAD
names a Kata Go pseudo-version, not a 3.29.0 release. Do not invent a Kata
3.29.0 floor. This page stays a development draft. Do not prove exposure by
writing into guest paths.

## When to use it

- A repository builds, pins, deploys, or documents Contrast before `1.19.1`.
- Generated Kata agent policies, initdata, attestation manifests, or rendered
  Kubernetes artifacts are checked in or distributed from this repo.
- Confidential-container workloads rely on host-to-guest `CopyFile` policy
  enforcement while the host is outside the trusted computing base.
- You need a bounded PR or triage note that upgrades Contrast and regenerates
  policy artifacts, not only source dependencies.

## Inputs

- Contrast modules/CLI/images, generated policies, initdata, attestation
  manifests, runtime class/Kata config, Helm/K8s/Terraform artifacts, SBOMs,
  and deployment evidence.
- Kata Containers versions where directly managed, host VSOCK exposure, guest
  filesystem trust boundary, workload secrets, and attestation ownership.
- Available Go/Rego/policy tests, manifest rendering, attestation generation,
  container build, SBOM, and dependency/security scan commands.

## Affected versions

- **Vulnerable Contrast module:** `github.com/edgelesssys/contrast <1.19.1`
- **Fixed Contrast module:** `github.com/edgelesssys/contrast 1.19.1+`
- **Related upstream Kata issue:** `CVE-2026-41326` / `GHSA-q49m-57vm-c8cc`
- **GHAD-named Kata module:** `github.com/kata-containers/kata-containers`
  before `0.0.0-20260422180503-1b9e49eb2763`; do not invent a 3.29.0 floor
- **High-risk condition:** generated Kata agent policies permit `CopyFile`
  operations while a host-side process can reach the Kata agent VSOCK.

## Indicator-of-exposure

- The repository builds, vendors, pins, deploys, or documents Contrast before
  `1.19.1`.
- The repository runs `contrast generate`, commits generated policies, or
  distributes initdata/manifests produced by an older Contrast CLI.
- Kubernetes workloads use Contrast confidential containers, Kata Containers,
  CoCo, or host-to-guest policy enforcement where the host is untrusted.
- Generated policy, Rego, manifest, or runtime config references `CopyFile`,
  Kata agent policy, initdata, VSOCK, guest root filesystem paths, or
  host-provided content transfer.
- Workloads keep secrets, model provider credentials, service mesh keys, data
  processing artifacts, or privileged binaries inside the guest filesystem.
- Runtime ownership is split between platform, cluster, and application teams,
  making stale generated policies likely to survive a dependency-only upgrade.

Quick checks:

```bash
rg -n "edgelesssys/contrast|contrast generate|Contrast|kata-agent|Kata agent|CopyFile|VSOCK|vsock|initdata|agent policy|policy\\.rego" .
go list -m all | rg '^github.com/edgelesssys/contrast'
rg -n "kata-containers|io.containerd.kata|confidential|cvm|sev-snp|tdx|contrast.*policy|copy_file|copyfile" Dockerfile* docker-compose*.yml charts deploy k8s helm terraform .github .
find . -iname "*policy*.rego" -o -iname "*initdata*" -o -iname "*contrast*"
```

## Remediation strategy

- Upgrade every controlled Contrast CLI, module, container, deployment, and
  generated-policy toolchain to `1.19.1+`.
- Regenerate Kata agent policies, initdata, manifests, SBOMs, and deployment
  evidence with the fixed Contrast release. Do not assume upgrading the CLI
  protects workloads that still run old generated policy artifacts.
- If this repository directly manages Kata Containers outside Contrast, recheck
  GHAD-named Kata versions. Do not invent a 3.29.0 floor.
- If immediate Contrast upgrade is blocked, apply the upstream policy-only
  Rego workaround through `contrast generate --policy` and document it as
  temporary containment until `1.19.1+` is deployed.
- Restrict host access to the Kata agent VSOCK and treat host-provided
  `CopyFile` content as untrusted even after patching.
- Re-attest and redeploy affected confidential workloads so the running guest
  state proves it consumed the regenerated policy.
- Rotate secrets and rebuild affected workload images if host-side access to
  the agent was possible during the vulnerable window.

## The prompt

~~~markdown
You are remediating GHSA-rh99-wc69-c255 (Contrast-generated Kata agent
policies allow CopyFile policy subversion through symlinks). Produce exactly
one output:

- A reviewer-ready PR/change request that upgrades or contains affected
  Contrast/Kata policy generation, regenerates trusted artifacts, adds safe
  verification, and documents operator cleanup, or
- TRIAGE.md if this repository does not own an affected Contrast or Kata
  confidential-container deployment.

## Rules

- Scope only GHSA-rh99-wc69-c255 and the directly related upstream Kata
  CopyFile symlink issue (`CVE-2026-41326` / `GHSA-q49m-57vm-c8cc`).
- Treat guest filesystem contents, model/provider credentials, workload
  secrets, service mesh keys, attestation evidence, generated policy bundles,
  initdata, VSOCK endpoints, and host runtime logs as sensitive.
- Do not connect to a production or shared Kata agent VSOCK to prove exposure.
- Do not write test files into a real guest root filesystem, overwrite guest
  binaries, or exfiltrate workload data.
- Do not stop at updating `go.mod` if generated policies, initdata, manifests,
  images, or SBOMs remain stale.
- Do not auto-merge.

## Steps

1. Inventory every Contrast and Kata asset controlled by this repository:
   Go modules, lockfiles, vendored code, Contrast CLI download pins,
   Dockerfiles, Helm charts, Kubernetes manifests, Terraform, GitOps overlays,
   generated Kata agent policies, Rego files, initdata, attestation manifests,
   SBOMs, runbooks, and CI workflows.
2. Determine every resolved Contrast version. A target is vulnerable if it
   resolves to `github.com/edgelesssys/contrast <1.19.1` or uses a Contrast
   CLI/container/image before `1.19.1`.
3. Determine whether this repository directly manages Kata Containers. Recheck
   GHAD for `CVE-2026-41326`. Do not invent a 3.29.0 floor.
4. Identify generated artifacts that must be refreshed, including committed
   policy bundles, initdata, rendered manifests, attestation reference values,
   SBOMs, deployment evidence, and docs that tell operators how to generate
   policy.
5. Determine exposure without exploiting it:
   - Could a host-side process connect to the Kata agent VSOCK?
   - Do generated policies permit `CopyFile` requests?
   - Could `CopyFile` write into guest root paths that contain binaries,
     startup scripts, service config, credentials, or model/runtime data?
   - Are workloads running in confidential VMs where the host is explicitly
     untrusted?
   - Are old generated policies deployed after a dependency or CLI upgrade?
6. If the repository does not own Contrast/Kata deployment or generated policy
   artifacts, stop with `TRIAGE.md` naming the files checked, the likely
   runtime owner, the required Contrast fixed version `1.19.1+`, and a
   GHAD-rechecked Kata version instead of an invented 3.29.0 floor.
7. Upgrade controlled Contrast dependencies, CLIs, images, and deployment
   references to `1.19.1+`. Regenerate Go module state, binary checksums,
   container metadata, SBOMs, and dependency reports.
8. Regenerate every controlled Kata agent policy, initdata artifact,
   attestation manifest, rendered Kubernetes manifest, and deployment evidence
   with the fixed Contrast toolchain.
9. If direct Kata Containers are controlled here, upgrade only to a
   GHAD-named Kata version and regenerate runtime class, node image,
   operator, or containerd/Kata configuration artifacts.
10. If the Contrast upgrade cannot land immediately, add temporary containment
    using the upstream policy-only Rego fix through `contrast generate --policy`,
    block or restrict host access to the Kata agent VSOCK where this repository
    controls runtime policy, and mark the workaround as temporary.
11. Add safe verification:
    - version checks prove Contrast resolves to `1.19.1+`;
    - generated policy fixtures reject symlink-mediated `CopyFile` paths;
    - direct Kata targets resolve to a GHAD-named version when applicable;
    - rendered deployment artifacts no longer contain stale vulnerable policy;
    - tests use synthetic temporary fixtures and do not contact production
      agents, CVMs, or host VSOCK endpoints.
12. Add a PR body section named `GHSA-rh99-wc69-c255 operator actions` that
    states:
    - Contrast versions before and after the change;
    - whether direct Kata Containers are present and their versions;
    - which generated policies, initdata, attestation manifests, and deployment
      artifacts were regenerated;
    - whether any workload could have run with host-reachable Kata agent VSOCK;
    - which guest secrets, binaries, service configs, or model/runtime files
      could have been affected;
    - which node, runtime, VSOCK, workload, attestation, and deployment logs
      should be reviewed;
    - which secrets, service mesh credentials, images, or workloads require
      rotation, rebuild, or redeployment.
13. Run relevant validation: Go dependency resolution, unit tests, policy
    tests, Rego tests, manifest rendering, attestation/reference-value
    generation, container build, SBOM refresh, and dependency/security scans
    available in this repository.
14. Use PR title:
    `fix(sec): remediate Contrast CopyFile policy symlink subversion`.

## Stop conditions

- No Contrast, Kata Containers, confidential-container deployment, generated
  policy, initdata, or attestation artifact is controlled by this repository.
- The repository only consumes a platform-managed runtime and cannot safely
  upgrade or regenerate policy artifacts.
- A safe fix requires changing the confidential-container trust model or host
  runtime ownership boundaries; document the required product/security
  decision.
- Verification would require contacting a production Kata agent VSOCK,
  overwriting guest files, or reading real workload data.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled Contrast dependency, CLI, image, SBOM, or deployment artifact
  remains below `1.19.1`.
- Every controlled generated Kata agent policy, initdata artifact, attestation
  manifest, and rendered deployment artifact was regenerated after the upgrade.
- Direct Kata Containers targets, if present, resolve to a GHAD-named
  version rather than an invented 3.29.0 floor.
- Tests or policy checks reject symlink-mediated `CopyFile` writes using only
  synthetic local fixtures.
- Runtime containment addresses host access to the Kata agent VSOCK where this
  repository owns that boundary.
- Operator actions identify stale deployments, possible guest takeover impact,
  logs to review, and credentials or workloads that may need rotation or
  rebuild.

## Output contract

- Reviewer-ready PR upgrading Contrast to `1.19.1+` and regenerating every
  controlled Kata policy, initdata, attestation, manifest, SBOM, and deployment
  artifact.
- Policy tests proving symlink-mediated `CopyFile` writes are rejected using
  synthetic fixtures only.
- Operator notes for host VSOCK containment, guest impact, logs, secret
  rotation, image rebuilds, and stale deployment cleanup.
- `TRIAGE.md` when the runtime, generated policy, or confidential-computing
  trust boundary is platform-managed outside this repository.

## Watch for

- Updating Contrast source dependencies while committed policy/initdata
  artifacts remain generated by a vulnerable CLI.
- Regenerating policy locally but leaving GitOps, Helm, or rendered manifests
  pinned to older artifacts.
- Treating confidential computing attestation as sufficient when the measured
  policy itself permits unsafe host-to-guest file writes.
- Proving the issue by writing into real guest paths or collecting real
  workload data.
- Missing direct Kata Containers runtime pins because the repository uses
  RuntimeClass, node images, operator config, or containerd templates instead
  of Go modules.

## Rollback and recovery

Prefer forward recovery to another GitHub-named Contrast 1.19.1+ release and
regenerated policies. If an operational rollback restores Contrast before
`1.19.1`, isolate host VSOCK to the Kata agent until named Contrast policies
are restored. Recheck GHAD before treating any Kata 3.x tag as a floor.

## Related recipes

- [Critical infrastructure secure context]({{< relref "/security-remediation/critical-infrastructure-secure-context" >}})
- [Source code supply-chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit" >}})
- [CVE intelligence intake gate]({{< relref "/recipes/general/cve-intelligence-intake-gate" >}})

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-rh99-wc69-c255>
- Upstream Kata advisory: <https://github.com/kata-containers/kata-containers/security/advisories/GHSA-q49m-57vm-c8cc>
- NVD CVE: <https://nvd.nist.gov/vuln/detail/CVE-2026-41326>
- Contrast `v1.19.1` release: <https://github.com/edgelesssys/contrast/releases/tag/v1.19.1>
- Policy-only workaround: <https://gist.github.com/burgerdev/304dd0ab0fff1665b7c27e18a30cf96e>
