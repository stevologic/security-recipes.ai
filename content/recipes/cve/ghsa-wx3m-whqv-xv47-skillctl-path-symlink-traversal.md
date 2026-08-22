---
title: "GHSA-wx3m-whqv-xv47: skillctl path and symlink traversal"
linkTitle: "GHSA-wx3m skillctl traversal"
description: "GHSA-wx3m-whqv-xv47 is skillctl path and symlink traversal. Upgrade to 0.1.2+ and reject unsafe skill paths and libraries."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: ["ghsa", "skillctl", "rust", "cargo", "path-traversal", "symlink", "skills", "supply-chain", "high"]
weight: 73
date: 2026-06-07
lastmod: 2026-08-21
ghsa: "GHSA-wx3m-whqv-xv47"
known_as: ["skillctl path traversal and symlink-follow", "skill supply-chain file disclosure"]
kev: false
severity: "high"
ecosystem: "rust/cargo"
disclosed: "2026-05-20"
ai_enrichment_review_status: human-reviewed-development-draft
---

GHSA-wx3m-whqv-xv47 covers `skillctl` versions before `0.1.2`. Affected
releases could follow skill-folder symlinks and trust unsafe `.skills.toml`
path fields. A malicious library or PR could copy symlink targets into a
project and publish them, or delete writable directories outside the intended
root through `destination`, `source_path`, `detect --target`, or fork-name
handling.

GitHub names **`skillctl` 0.1.2**. Do not invent a later 0.1.3 floor. This
page stays a development draft. Do not prove exposure by following untrusted
skill paths or publishing copied local files.

## When to use it

Use this recipe when a repository installs, wraps, documents, or automates
`skillctl`, skill libraries, `.skills.toml`, reusable agent skills, marketplace
sync jobs, or onboarding flows that copy skills into developer or CI projects.
It is most important when contributors, customers, plugins, forks, or external
marketplaces can provide skill folders or metadata.

Use it to upgrade `skillctl`, quarantine untrusted skill libraries, and harden
path handling around copy, pull, push, detect, fork, replacement, and publishing
flows. Do not use it to run untrusted skill operations on a host with secrets.

## Inputs

- Cargo manifests and locks, install scripts, CI images, Dockerfiles, release
  jobs, developer setup docs, agent onboarding docs, marketplace sync jobs,
  `.skills.toml` files, skill libraries, generated SBOMs, and runbooks.
- Skill-library metadata fields including `destination`, `source_path`,
  `detect --target`, custom target prompts, fork names, publish targets,
  symlinks, folder replacement behavior, and destructive copy/delete paths.
- Trust boundaries for skill sources: PR-submitted libraries, customer skill
  packs, plugins, marketplace content, forks, vendored skills, and internal
  curated libraries.
- Operator authority: home-directory secrets, SSH keys, cloud credentials,
  package tokens, source checkouts, private prompts, CI workspaces, writable
  project roots, and library roots.
- Existing path-safety controls, safe-join helpers, symlink policy, quarantine
  process, review gates, audit logs, and disposable-workspace setup.

## Affected versions

- **Vulnerable package:** `skillctl <0.1.2`
- **Fixed package:** `skillctl 0.1.2+`
- **Affected package manager:** Cargo
- **Affected inputs:** `.skills.toml` `destination` and `source_path`,
  symlinks inside skill folders, `detect --target`, custom target prompts, and
  fork names equal to `.` or `..`
- **Affected operations:** skill copy, pull, push, detect, folder replacement,
  publishing, and fork rename flows

## Indicator-of-exposure

- The repository installs, pins, vendors, or documents `skillctl <0.1.2`.
- CI, developer setup, release automation, or agent onboarding runs `skillctl`
  against skill libraries submitted by contributors, customers, plugins, forks,
  or external marketplaces.
- `.skills.toml` files are accepted through PRs or copied from untrusted skill
  libraries without review.
- Skill folders may contain symlinks, absolute paths, `..` traversal, Windows
  drive prefixes, UNC-style paths, or fork names that affect filesystem joins.
- The operator running `skillctl` has access to home-directory secrets, cloud
  credentials, SSH keys, source checkouts, private package tokens, CI workspaces,
  or writable project/library directories.

Quick checks:

```bash
rg -n "skillctl|\\.skills\\.toml|source_path|destination|detect --target|fork|skills library|skill library" .
cargo install --list | rg -i "skillctl"
cargo tree -i skillctl
rg -n "skillctl|\\.skills\\.toml|source_path|destination|detect --target" Cargo.toml Cargo.lock Dockerfile* .github scripts docs content . 2>/dev/null
```

Windows:

```powershell
rg -n "skillctl|\\.skills\\.toml|source_path|destination|detect --target|fork|skills library|skill library" .
cargo install --list | rg -i "skillctl"
cargo tree -i skillctl
rg -n "skillctl|\\.skills\\.toml|source_path|destination|detect --target" Cargo.toml Cargo.lock Dockerfile* .github scripts docs content .
```

Do not run `skillctl pull`, `push`, `detect`, or copy operations on untrusted
skill libraries from a workstation or CI runner that has secrets mounted.

## Remediation strategy

- Upgrade every controlled `skillctl` install, lockfile, bootstrap script, CI
  image, developer setup guide, release container, and SBOM entry to `0.1.2+`.
- Quarantine or re-review skill libraries imported while `skillctl <0.1.2` was
  in use. Look for unexpected symlinks, absolute paths, traversal components,
  unsafe `.skills.toml` path fields, and surprising published files.
- Reject symlinks inside skill folders before copying or publishing. Treat both
  top-level symlinks and descendant symlinks as unsafe for untrusted libraries.
- Validate all user-controlled relative paths lexically before filesystem
  operations. Reject absolute paths, `..`, Windows prefixes, UNC-style inputs,
  empty path components where unsafe, and fork names `.` or `..`.
- Use a safe-join helper at destructive call sites and keep delete/replace
  operations confined under the expected project or library root.
- Run skill tooling with least privilege: clean workspace, no home-directory
  secrets, no cloud metadata access, narrow write permissions, and read-only
  mounts where possible.

## The prompt

~~~markdown
You are remediating GHSA-wx3m-whqv-xv47, a `skillctl` path traversal and
symlink-follow issue that can disclose local files or delete writable
directories when untrusted skill libraries or `.skills.toml` metadata are
processed. Produce exactly one output:

- A reviewer-ready PR/change request that upgrades skillctl, rejects unsafe
  skill metadata and symlinks, adds path-safety regression coverage, refreshes
  generated artifacts, and documents operator cleanup, or
- TRIAGE.md if this repository does not control affected skillctl usage or
  cannot safely patch the skill-library workflow.

## Rules

- Scope only GHSA-wx3m-whqv-xv47 and directly related skillctl path, symlink,
  copy, pull, push, detect, fork, and publishing controls.
- Treat home directories, SSH keys, cloud credentials, package tokens, source
  checkouts, CI secrets, customer skill content, private prompts, and published
  skill packages as sensitive.
- Do not run untrusted `skillctl pull`, `push`, `detect`, copy, rename, or
  delete flows on a host or CI runner that has secrets mounted.
- Do not print secrets, symlink target contents, private skill bodies, token
  files, absolute home paths, or CI environment values into logs or commits.
- Do not remove skill provenance checks, review gates, quarantine, audit logs,
  or path validation to make the alert disappear.
- Do not auto-merge.

## Steps

1. Inventory all `skillctl` usage controlled by this repository: Cargo
   manifests and locks, install scripts, CI images, Dockerfiles, release jobs,
   developer setup docs, agent onboarding docs, marketplace sync jobs,
   `.skills.toml` files, skill libraries, generated SBOMs, and runbooks.
2. Determine every resolved `skillctl` version. A target is vulnerable if it
   resolves to `<0.1.2`.
3. Search for untrusted skill-library paths and metadata: `source_path`,
   `destination`, `detect --target`, custom target prompts, fork names, publish
   workflows, pull/push automation, symlink support, folder replacement, and
   destructive copy/delete operations.
4. If the repository does not install or run `skillctl`, stop with `TRIAGE.md`
   listing checked files, known owners, and the required fixed version
   `0.1.2+`.
5. Upgrade every controlled install, lockfile, setup script, CI image, and docs
   to `skillctl 0.1.2+`. Refresh lockfiles, image digests, generated reports,
   SBOMs, and developer instructions.
6. If this repository owns a fork, wrapper, or adjacent skill-library tooling,
   add or verify fail-closed path safety:
   - reject symlinks at every skill-copy boundary;
   - reject absolute paths and `..` components in `.skills.toml`;
   - reject Windows prefixes, UNC paths, empty unsafe components, and fork names
     `.` or `..`;
   - run every destructive path through a safe-join helper;
   - confine deletes, renames, copies, and replacements under the project or
     library root;
   - avoid canonicalization patterns that create time-of-check/time-of-use
     windows around attacker-controlled paths.
7. Add safe regression coverage:
   - dependency policy rejects `skillctl <0.1.2`;
   - symlinks inside skill folders are rejected before copy or publish;
   - `destination`, `source_path`, and `detect --target` reject absolute paths,
     traversal, and Windows-prefix paths;
   - fork names `.` and `..` are rejected;
   - destructive operations cannot escape a temporary test root;
   - logs and fixtures do not contain real secrets or private skill content.
8. Harden operational usage:
   - run imports in disposable workspaces;
   - mount only the skill library and project paths needed for the run;
   - keep home directories, SSH keys, cloud credentials, package tokens, and
     source-control credentials out of the skillctl process environment;
   - require review for `.skills.toml` changes and new symlinks;
   - quarantine external skill libraries before publishing.
9. Add a PR body section named `GHSA-wx3m skillctl operator actions` that
   states:
   - skillctl versions before and after;
   - where pull, push, detect, copy, publish, and fork flows run;
   - whether untrusted skill libraries or PR-submitted `.skills.toml` files were
     processed while vulnerable;
   - whether any published skill packages, local projects, or library roots need
     review for unexpected files or deletions;
   - whether tokens, SSH keys, cloud credentials, or private prompts require
     rotation because they were reachable by the operator process;
   - which validation commands passed.
10. Run available validation: Cargo checks, dependency scan, lockfile
    integrity, path-safety unit tests, fixture tests, CI image build, SBOM
    refresh, docs link checks, and non-secret smoke checks in a disposable
    workspace.
11. Use PR title:
    `fix(sec): remediate GHSA-wx3m in skillctl`

## Stop conditions

- No affected skillctl install, wrapper, fork, CI image, setup script, or skill
  workflow is controlled by this repository.
- Skill-library tooling is owned by another team or vendor; name the owner and
  required version in `TRIAGE.md`.
- A fixed skillctl version cannot be consumed without a broader skill workflow
  migration.
- Verification would require running untrusted skill operations on a secret-
  bearing host, deleting real directories, copying symlink targets, or
  publishing private skill content.
- Validation fails for unrelated pre-existing reasons; document those failures
  instead of broadening scope.
~~~

## Verification - what the reviewer looks for

- No controlled Cargo lock, setup script, CI image, docs page, SBOM, or
  generated report resolves `skillctl <0.1.2`.
- Skill copy/publish flows reject symlinks inside skill folders before reading
  target contents.
- `.skills.toml` path fields, `detect --target`, custom target prompts, and fork
  names reject absolute paths, traversal, Windows prefixes, and `.` / `..`
  escapes.
- Destructive copy, rename, delete, and replacement operations are confined to
  a temporary test root in regression tests.
- Operator notes cover quarantine, unexpected published files, local deletion
  review, and credential rotation criteria.

## Watch for

- Updating a local `cargo install` instruction while CI images or bootstrap
  scripts still install the affected version.
- Running `skillctl` from an operator home directory with SSH keys, cloud
  credentials, or package tokens mounted.
- Validating path safety with string-prefix checks that accept Windows prefixes,
  UNC paths, symlinks, or `..` after normalization.
- Reviewing only `.skills.toml` while symlinks inside skill folders remain
  allowed.
- Publishing skill libraries before checking whether vulnerable runs copied
  unexpected local files into the project.

## Rollback and recovery

Prefer forward recovery to another GitHub-named `skillctl` 0.1.2+ release. If
an operational rollback restores 0.1.0 or 0.1.1, quarantine untrusted skill
libraries and stop pull, push, detect, and publish jobs until the named floor
is restored.

## Output contract

Return one of:

- A reviewer-ready PR/change request that upgrades every controlled `skillctl`
  usage to `0.1.2+`, refreshes lockfiles/images/SBOMs, rejects unsafe skill
  paths and symlinks, quarantines external skill libraries, adds path-safety
  regression coverage, hardens disposable-workspace execution, and documents
  operator cleanup.
- `TRIAGE.md` when no controlled `skillctl` install, wrapper, CI image, setup
  script, skill workflow, generated artifact, or skill-library publishing path
  exists.

The output must list `skillctl` versions before and after, which pull, push,
detect, copy, publish, and fork flows run, whether untrusted skill libraries or
PR-submitted `.skills.toml` files were processed while vulnerable, validation
commands, quarantine owners, unexpected-file/deletion review steps, and any
tokens or private prompts that require rotation. It must not copy symlink target
contents, delete real directories, publish private skills, print secrets, or
execute untrusted skill workflows on a secret-bearing host.

## Related recipes

- [Source-code supply chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit" >}})
- [Compromised package cache quarantine]({{< relref "/recipes/general/compromised-package-cache-quarantine" >}})
- [Agent session kill rules]({{< relref "/recipes/general/agent-session-kill-rules" >}})

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-wx3m-whqv-xv47>
- skillctl 0.1.2 release: <https://github.com/umanio-agency/skillctl/releases/tag/v0.1.2>
- Patch commit: <https://github.com/umanio-agency/skillctl/commit/827fff5>
