---
title: "LiteLLM 1.107.0 Backdoor: Check If You're Affected"
linkTitle: LiteLLM 1.107.0 compromise check
headline: Did the LiteLLM backdoor hit your agent stack?
weight: 4
date: 2026-10-21
lastmod: 2026-10-21
sidebar:
  open: true
description: >
  LiteLLM 1.107.0 wheels and Docker images shipped a startup credential stealer.
  Check versions, lockfiles, image digests and cook.pth; then pin, purge, rotate.
author: Stephen M Abbott
keywords:
  - litellm 1.107.0
  - cook.pth
  - supply chain
  - credential stealer
about:
  - type: SoftwareApplication
    name: LiteLLM
    softwareVersion: "1.107.0"
citation:
  - https://github.com/BerriAI/litellm/issues/47826
  - https://research.jfrog.com/post/litellm-hijacked-again/
faq:
  - name: Which LiteLLM versions are affected?
    acceptedAnswer: >-
      litellm 1.107.0: all seven PyPI wheels and the v1.107.0 Docker images
      (and latest/main-latest/main-stable while they pointed to it). PyPI has
      removed it.
  - name: Does it run if I never import litellm?
    acceptedAnswer: >-
      Yes. cook.pth contains 'import cook', which Python's site module executes
      at interpreter startup; sitecustomize.py also runs automatically.
  - name: What should I pin to?
    acceptedAnswer: >-
      litellm==1.106.2 (Docker v1.106.2 by digest), but only after removing the
      startup hooks without running Python, or in a freshly built environment.
      Then rotate every credential the host could reach.
---

{{< callout type="warning" >}}
**Status as of 2026-10-21 09:08 MST / 16:08 UTC.** PyPI removed 1.107.0
[S1, S2, S3]. Maintainers report the malicious Docker images were removed
[S1]. The publishing method is still under investigation [S1, S2]. Do not
run `pip` inside a suspect environment first [S1, S2].
{{< /callout >}}

This page is a check-and-containment workflow for hosts and images that may
have received `litellm` 1.107.0. The 1.107.0 wheels and the `v1.107.0` Docker
images shipped a startup credential stealer plus an hourly remote-code loader
[S1, S2]. Recheck S1–S4 before you act; this incident is still moving.

{{< playbook-workflow >}}

## Am I affected?

Any Python start in an affected environment runs `cook.pth` and
`sitecustomize.py`, and that includes `pip` [S1, S2]. Lead with filesystem
checks. Use `pip show` or `python -c` only on hosts you already know are
clean [S1, S2].

```bash
# A. Startup hooks present? (no interpreter started). Adjust roots to your venvs/conda/system paths.
find / -xdev \( -path '*/site-packages/cook.pth' -o -path '*/site-packages/cook.py' \
  -o -path '*/site-packages/sitecustomize.py' \) 2>/dev/null
# Note: a sitecustomize.py can be legitimate (some distros ship one); cook.pth / cook.py are not LiteLLM files.

# B. Installed litellm version, read from dist-info metadata (no interpreter)
find / -xdev -type d -name 'litellm-*.dist-info' 2>/dev/null
#   affected if any path is litellm-1.107.0.dist-info

# C. Lockfiles / pins
grep -rnE 'litellm[^a-z_-]*[=~<>!]*=?\s*"?1\.107\.0' --include='requirements*.txt' --include='*.in' --include='pyproject.toml' .
grep -n -A1 '^name = "litellm"$' uv.lock poetry.lock 2>/dev/null   # next line shows version = "..."
grep -n '^litellm==' requirements*.txt 2>/dev/null

# D. Host markers [S1, S2]
ls -la /tmp/.pc_once_72129118c59f5636c0bb /tmp/remote_code_loader.lock 2>/dev/null
ls -d /tmp/.pc_sq_* /tmp/.pc_e_* 2>/dev/null
command -v lsof >/dev/null && lsof /tmp/remote_code_loader.lock
grep -l 'PRIVCOLLECT_ACTIVE=1' /proc/[0-9]*/environ 2>/dev/null   # Linux, needs read access

# E. Docker images: which digests do you have?
docker image ls --digests | grep -Ei 'litellm'
docker image inspect --format '{{.RepoTags}} {{json .RepoDigests}}' $(docker image ls -q --filter=reference='*litellm*') 2>/dev/null
#   Affected index digest (litellm / Docker Hub): sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e
#   Affected platform manifests: amd64 sha256:bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5,
#                                arm64 sha256:56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf
# Image contents without running it:
cid=$(docker create <image>) && docker export "$cid" | tar -t | grep -E 'site-packages/(cook\.pth|cook\.py|sitecustomize\.py)$'; docker rm "$cid"
# Kubernetes: kubectl get pods -A -o jsonpath='{range .items[*]}{.status.containerStatuses[*].imageID}{"\n"}{end}' | grep -i litellm
```

{{< callout type="warning" >}}
**Clean host only.** `pip show` and `python -c` start an interpreter. Use
them only on hosts you already know are clean [S1, S2].
{{< /callout >}}

If 1.107.0 was ever installed on a host with outbound internet, assume the
exfiltration succeeded [S1]. The marker file confirms it; its absence proves
nothing [S1].

Any pull of `latest`, `main-latest`, or `main-stable` while they pointed at
1.107.0 (from about 11:48Z) counts as exposed [S1, S2]. That covers
`ghcr.io/berriai/litellm{,-database,-non_root}` and
`docker.io/litellm/litellm` [S1, S2]. The maintainers later removed the
malicious Docker images [S1, S2, S4]. Anyone who already pulled those
floating tags during the window should still be treated as exposed [S1, S2].

## What it does

Three files in `litellm-1.107.0.data/purelib/` land in the site-packages
root: `cook.pth` (`import cook`), `cook.py`, and `sitecustomize.py` [S1, S2].
`cook.pth` contains only `import cook` and runs during normal Python
startup, regardless of whether the application imports `litellm` [S2].
`sitecustomize.py` also runs automatically [S1, S2]. All seven PyPI wheels
for `litellm` 1.107.0 contain the payload [S1, S2]. The sdist has no payload
files but does carry the tampered `pyproject.toml` [S1, S2].

`cook.py` contains the `privcollect` credential stealer [S1, S2]. It runs
once, in a background thread, and needs no C2 [S1, S2]. It collects SSH,
cloud (AWS/Azure/GCP), k8s, Docker, git, package-manager, CI/CD, browser
and GPG/TLS secrets, AI tool configs (Claude, Codex, Gemini, Cursor,
Windsurf, Kiro, Copilot, HF and more), `/proc/*/environ`, cloud metadata
credentials (AWS creds are validated via STS `GetCallerIdentity`), and,
when `DATABASE_URL` is set, `LiteLLM_CredentialsTable` and
`LiteLLM_ProxyModelTable` [S1, S2].

Exfiltration is AES-256-CBC, with the key wrapped by RSA-4096-OAEP, sent
as a tar.gz POST to `hxxp[:]//www[.]litellm[.]dev/healthcheck` [S1, S2].
It cannot be decrypted from a packet capture [S1, S2]. `litellm.dev` was
registered 2026-10-13; the real project domain is `litellm.ai` [S1, S2].

`sitecustomize.py` forks a detached daemon (setsid, flock
`/tmp/remote_code_loader.lock`) [S1, S2]. Every hour it reads the GitHub
dead-drop; if a domain is present, it runs the stealer again and `exec()`s
`/codepy` [S1, S2]. It was dormant when observed: `domain.txt` was empty
(0 bytes) [S1, S2]. On Windows the fork fails silently, but `cook.py`
still runs [S1, S2].

LiteLLM proxies hold upstream provider keys, and the stealer specifically
targets AI coding-tool configs and MCP configs [S1, S2].

The build's provenance names the lookalike repo `Berri-AI/litellm` as its
source [S1]. How that happened is still unknown [S1, S2]. Do not treat
that lookalike as a confirmed root cause [S1, S2].

## What to do now

1. Isolate the affected host or container [S1, S2].
2. Purge **without Python**: delete `cook.pth`, `cook.py`,
   `sitecustomize.py` and `__pycache__/cook*.pyc` /
   `sitecustomize*.pyc` from every affected site-packages [S1, S2].
   Delete `/tmp/.pc_once_72129118c59f5636c0bb` and
   `/tmp/remote_code_loader.lock` (preserve copies first if you need
   forensics) [S1, S2].
3. Kill the detached python daemon (it holds the lock, runs under setsid,
   and has cwd `/`) [S1, S2].
4. Rebuild, preferably from scratch, pinned to `litellm==1.106.2` [S1, S2].
   Pin `litellm==1.106.2` only after removing the startup hooks or from a
   newly built clean environment [S1, S2]. For Docker, pin `v1.106.2` **by
   digest**:
   `ghcr.io/berriai/litellm@sha256:7294b90f868c5c38c99b83021c7ba46f9b439e95f8e32964c925c7d2563a03f7`
   [S1, S4]. Exclude 1.107.0 in your constraints, for example
   `litellm!=1.107.0` [S1, S2].
5. Rotate everything the host could reach: browser passwords, SSH and
   GPG/TLS keys, package-publishing and source-control tokens, k8s creds,
   `DATABASE_URL`, LiteLLM master and virtual keys, every provider key in
   `LiteLLM_CredentialsTable`, the instance/task IAM role, process env
   secrets, and the rest of the collection list in the previous section
   [S1, S2].
6. Check CloudTrail for `GetCallerIdentity` from the instance role, and
   for use of its credentials from outside your infrastructure [S1].
   Block and investigate `www[.]litellm[.]dev` and the dead-drop URL
   [S1, S2]. Investigate any `/codepy` fetch [S1, S2].
7. Purge caches and mirrors with
   [Artifact Cache Purge]({{< relref "/security-remediation/artifact-cache-purge/" >}}).

The maintainer reports that the enterprise private registry is unaffected
[S1].

## Indicators of compromise

Values below are verbatim from the sources. Truncated hashes stay
truncated. Network indicators are defanged.

### Wheels (sha256) [S1]

| File | sha256 |
| --- | --- |
| `litellm-1.107.0-cp310-abi3-macosx_10_12_x86_64.whl` | `7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d` |
| `litellm-1.107.0-cp310-abi3-macosx_11_0_arm64.whl` | `0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a` |
| `litellm-1.107.0-cp310-abi3-manylinux_2_28_aarch64.whl` | `668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6` |
| `litellm-1.107.0-cp310-abi3-manylinux_2_28_x86_64.whl` | `462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7` |
| `litellm-1.107.0-cp310-abi3-musllinux_1_2_aarch64.whl` | `c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054` |
| `litellm-1.107.0-cp310-abi3-musllinux_1_2_x86_64.whl` | `1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00` |
| `litellm-1.107.0-cp310-abi3-win_amd64.whl` | `12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484` |
| `litellm-1.107.0.tar.gz` (no payload; tampered pyproject) | `2befe2a79fb4fbbd9a543b5b40b530c8cffa8771bab22b8fb22b2e4ae3b1f819` |

### Payload files [S1]

| File | Size | RECORD sha256 | hex |
| --- | --- | --- | --- |
| `cook.pth` | 12 B | `fxkWMucyBwXRVLhSBPGuVGtUOsvX6IYSKbdvUEK5K9s` | `7f191632…2bdb` (truncated in source) |
| `cook.py` | 22252 B | `ndCjkm-Wo364bPHuIxDZvpMTnMTr7z754u_pUxOQviU` | `9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25` |
| `sitecustomize.py` | 25509 B | `NL7wT-iKydCq4EdWMLFzhoHRW5TyM6yKpG6s9ZaDBfo` | `34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa` |

Decoded stealer: cook.py variant
`6ea3d8ef6cf73a72d8df24f663b7a31ce67494eeb9b0d707b93484e66675d2df`;
sitecustomize variant
`20a59e5a285799e7cf7fa16cfba1c1414f1e84a8459e14207cfd4e998c2cd24b`
[S1]. Build-tree marker: `data = "cook"` under `[tool.maturin]` in
`pyproject.toml` [S1, S2].

### Network [S1, S2]

| Type | Value |
| --- | --- |
| Exfil | `POST hxxp[:]//www[.]litellm[.]dev/healthcheck` (`litellm.dev` registered 2026-10-13; the real project domain is `litellm.ai`) |
| Headers | `X-Token: XWiA8gZNa7NcX2XRoAEb`, `X-SHA256`, `Content-Type: application/octet-stream`, `User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)` |
| Dead-drop | `hxxps[:]//raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt` (GitHub user `letters9813`, id `341832141`, `letters9813@atomicmail.io`; commits `2c9dda9e`, `0495a8a1`, `b9d26fac`) |
| Stage 2 | `hxxp[:]//{domain}/codepy` |
| RSA-4096 key | SPKI sha256 `a898fd08ad220fed52488906eb45d196f332b972ad5d85214e7726545ecc4218` |

### Host [S1, S2]

`/tmp/.pc_once_72129118c59f5636c0bb`, `/tmp/remote_code_loader.lock`,
`/tmp/.pc_sq_*`, `/tmp/.pc_e_*`, env `PRIVCOLLECT_ACTIVE=1`, an orphaned
`python` process with cwd `/`.

### Images [S1, S2]

`ghcr.io/berriai/litellm{,-database,-non_root}:v1.107.0`,
`docker.io/litellm/litellm:v1.107.0`; index
`sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e`
(S2, full); amd64
`sha256:bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5`;
arm64
`sha256:56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf`;
`-database` index `sha256:c00f9d92c427…` and `-non_root` index
`sha256:7b00e91cd2fe…` (truncated in source).

### Git [S1]

Lookalike repo `github.com/Berri-AI/litellm` (now 404); author
`Berri-AI <ckdi82fkoos@proton.me>`; commits `9b98cd93`, `51020100`,
`7f7f9892`, `1a657baf`, `74983c8e`, `615e57ff`, `6a4390f1`, `91d6546f`,
`783c43bc`, `20535d8fa11f786a6c24df7488a0e449ed5f09ad`. Clean base commit
`a8113b0dd721804c752a6f1952367fb642205224`; v1.107.0 tag
`66c8f5b1a9cefaa7c55b758f86f4ab552f2e859e`.

### Tracking and clean versions

JFrog `XRAY-955589` [S2]; `ossf/malicious-packages#1655` [S1]. Clean
versions reported [S1]: 1.103.6, 1.103.7, 1.104.4, 1.104.5, 1.105.2,
1.105.3, 1.106.0, 1.106.1, 1.106.2, 1.107.0rc1, 1.107.0rc2.

## Timeline

All times are 2026, UTC [S1]; MST is UTC-7.

| UTC | MST | Event |
| --- | --- | --- |
| 10-13 00:45Z | 10-12 17:45 MST | `litellm.dev` registered [S1] |
| 10-13 06:43Z | 10-12 23:43 MST | GitHub user `letters9813` created [S1] |
| 10-20 09:15Z | 10-20 02:15 MST | dead-drop `domain.txt` emptied [S1] |
| 10-21 08:56–10:46Z | 01:56–03:46 MST | 10 attacker commits on the lookalike repo [S1] |
| 10-21 10:51Z | 03:51 MST | `project-releaser` run 39587059944 starts; images built around 11:00–11:06Z [S1] |
| 10-21 about 11:21Z | about 04:21 MST | wheels built (maturin 1.9.4) [S1] |
| 10-21 11:39:51–11:40:13Z | 04:40 MST | uploaded to PyPI [S1] |
| 10-21 11:48Z | 04:48 MST | Docker Hub push; floating tags point at 1.107.0 [S1] |
| 10-21 12:06Z | 05:06 MST | issue #47826 opened [S1] |
| 10-21 12:57Z | 05:57 MST | Docker/provenance update [S1] |
| 10-21 by 13:23Z | 06:23 MST | PyPI removed 1.107.0 [S1] |
| 10-21 13:50Z | 06:50 MST | maintainer declares SEV-0 [S1] |
| 10-21 14:32Z | 07:32 MST | maintainer: malicious Docker images removed; the publishing method is not yet identified [S1] |

## Common questions

### Which LiteLLM versions are affected?

`litellm` 1.107.0: all seven PyPI wheels and the `v1.107.0` Docker images
(and `latest` / `main-latest` / `main-stable` while they pointed to it)
[S1, S2]. PyPI has removed it [S1, S2, S3].

### Does it run if I never import litellm?

Yes. `cook.pth` contains `import cook`, which Python's site module
executes at interpreter startup; `sitecustomize.py` also runs
automatically [S1, S2].

### What should I pin to?

`litellm==1.106.2` (Docker `v1.106.2` by digest), but only after removing
the startup hooks without running Python, or in a freshly built
environment [S1, S2, S4]. Then rotate every credential the host could
reach [S1, S2].

## Related

- [Artifact Cache Purge]({{< relref "/security-remediation/artifact-cache-purge/" >}}) — purge caches and mirrors
- [Compromised package cache quarantine]({{< relref "/recipes/general/compromised-package-cache-quarantine/" >}})
- [Source-code supply-chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit/" >}})
- [Agentic Incident Response Pack]({{< relref "/security-remediation/agentic-incident-response-pack/" >}})
- [Agent Skill Supply Chain]({{< relref "/security-remediation/agent-skill-supply-chain/" >}})
- [AI Agent Security]({{< relref "/agentic-security/" >}})
- [CVE Database]({{< relref "/cve-database/" >}}) — search "litellm"

## Sources

- **S1**: [BerriAI/litellm#47826](https://github.com/BerriAI/litellm/issues/47826) (Upwind report, updates, and maintainer comments)
- **S2**: [JFrog Security Research, "LiteLLM Hijacked Again" (2026-10-21)](https://research.jfrog.com/post/litellm-hijacked-again/)
- **S3**: [PyPI `litellm` JSON](https://pypi.org/pypi/litellm/json) / [project page](https://pypi.org/project/litellm/). Observed on re-check: `info.version` = `1.106.2`, and there is no `1.107.0` key in `releases` (rc1, rc2 and dev1–3 are still there).
- **S4**: Registry check. `ghcr.io/berriai/litellm`: `latest`, `main-stable`, `main-latest` and `v1.107.0` → HTTP 404; `v1.106.2` → 200, digest `sha256:7294b90f868c5c38c99b83021c7ba46f9b439e95f8e32964c925c7d2563a03f7`. Docker Hub `litellm/litellm`: `v1.106.2` and `1.106.2` share that digest; `latest` / `v1.107.0` / `main-stable` / `main-latest` return 404.

Last checked 2026-10-21 09:08 MST / 16:08 UTC.
