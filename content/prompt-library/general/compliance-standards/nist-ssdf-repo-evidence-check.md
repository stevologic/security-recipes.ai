---
title: "NIST SSDF repository evidence check"
linkTitle: "NIST SSDF evidence"
description: "Read-only recipe for mapping repository evidence to NIST SSDF practices and producing a secure-development gap report."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["compliance", "nist", "ssdf", "sp-800-218", "secure-development", "audit"]
weight: 40
date: 2026-06-25
severity: "medium"
---

A read-only check for evidence that supports NIST SP 800-218 Secure Software
Development Framework (SSDF) practices. It maps repository artifacts to the
SSDF practice families and identifies gaps a security engineering owner can
close.

## When to use it

- Before a supplier security questionnaire or federal customer review.
- After adding new build, release, agent, model, or MCP components.
- As a preflight check before declaring a service "secure development ready."

## Inputs

- Repository path and service owner.
- Optional supplied SSDF control map, SDLC policy, or secure-development
  standard.
- Optional SBOM, SCA, SAST, DAST, CI, or release evidence.

## The prompt

~~~markdown
You are running a NIST SSDF repository evidence check. Run read-only. Do not
edit code, dependencies, CI configuration, or policy. Do not claim compliance.

Use NIST SP 800-218 SSDF Version 1.1 practice families:

- Prepare the Organization (PO)
- Protect the Software (PS)
- Produce Well-Secured Software (PW)
- Respond to Vulnerabilities (RV)

## Step 0 - Context and source inventory

Record:

- Repository, service, owner, and scope.
- Languages, frameworks, package managers, and build systems.
- CI, release, signing, publishing, deployment, and scanner surfaces.
- Agent, model, prompt, skill, MCP, or automation surfaces.
- Evidence sources reviewed and evidence sources missing.

## Step 1 - Map Prepare the Organization evidence

Look for:

- Secure development policy, standards, and training references.
- Defined security roles, CODEOWNERS, reviewer playbooks, and escalation paths.
- Threat model, architecture review, and risk acceptance records.
- Approved tools, model providers, MCP servers, and scanner configuration.
- Metrics or evidence retention expectations.

Record evidence and gaps.

## Step 2 - Map Protect the Software evidence

Look for:

- Source control protections, branch protection, review gates, and signed tags.
- Protected build/release artifacts, SBOMs, provenance, and checksums.
- Secret handling, key storage, token scopes, and credential rotation notes.
- Access controls around release, deploy, signing, and package publishing.
- Reproducibility or artifact retention expectations.

## Step 3 - Map Produce Well-Secured Software evidence

Look for:

- Secure coding guidance, linting, SAST, SCA, secret scanning, IaC scanning, and
  dependency review.
- Test strategy, security regression tests, abuse-case tests, and fuzzing where
  relevant.
- Dependency pinning, lockfiles, container base image policy, and generated-code
  process.
- Review of prompts, rules, skills, agent workflows, and MCP tool policies when
  the repo contains agentic code.

## Step 4 - Map Respond to Vulnerabilities evidence

Look for:

- Vulnerability intake, triage, ownership, patch SLA, and disclosure workflow.
- Scanner finding to PR linkage.
- CVE/advisory source verification.
- Patch, containment, suppression, and exception evidence.
- Post-release verification and rollback evidence.

## Step 5 - Score gaps

For each gap, assign:

- SSDF family: PO, PS, PW, or RV.
- Evidence status: observed, partial, missing, or out of repo.
- Risk: critical, high, medium, low.
- Owner: inferred or unknown.
- Smallest next action.

## Step 6 - Write the report

Write `NIST_SSDF_REPO_EVIDENCE_CHECK.md` at the repo root, or print to stdout
if write access is unavailable.

Use this structure:

```markdown
# NIST SSDF repository evidence check - <repo>

Generated on <date>. SSDF basis: NIST SP 800-218 Version 1.1.

## Repository Context
- ...

## Evidence Matrix
| SSDF family | Status | Evidence | Gap | Owner |
| ... |

## Findings and Gaps
### <Risk> - <Family> - <short title>
- **Evidence:** ...
- **Gap:** ...
- **Recommended next action:** ...
- **Verification:** ...

## Agentic or AI-Specific Surfaces
- ...

## Out-of-Repository Evidence Needed
- ...
```

## Stop conditions

Stop and write a partial report if:

- Required evidence is in another repository or restricted compliance system.
- The operator asks you to mutate policy or CI configuration.
- You find live secrets, private keys, or customer data.
~~~

## Output contract

- Evidence matrix and gap report only.
- No code or configuration changes.
- No final compliance statement.
- Clear distinction between observed evidence and inferred evidence.

## Guardrails

- Use SSDF as a practice framework, not a checklist that can be "passed" by one
  repository alone.
- Treat agent prompts, MCP config, and model routing as software-development
  artifacts when they affect builds, releases, or code changes.

## References

- [NIST SP 800-218 SSDF Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST SP 800-218A AI SSDF community profile](https://csrc.nist.gov/pubs/sp/800/218/a/final)

