---
title: "ISO 27001 secure-development evidence check"
linkTitle: "ISO 27001 secure dev"
description: "Read-only recipe for collecting ISO 27001 secure-development, configuration, supplier, and access-control evidence from a repository."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["compliance", "iso-27001", "isms", "secure-development", "configuration", "audit"]
weight: 20
date: 2026-06-25
severity: "medium"
---

A repository evidence check for ISO/IEC 27001:2022 secure-development and
information-security management expectations. It produces a control-owner review
packet; it does not interpret the certification scope or certify an ISMS.

## When to use it

- Before an ISO 27001 internal audit.
- When onboarding a new service into an ISMS scope.
- After adding agents, MCP servers, CI workflows, or third-party integrations
  to a repository.

## Inputs

- Repository path and service name.
- Optional ISMS scope, asset owner, risk register entry, or policy links.
- Any supplied control mapping from the compliance owner.

## The prompt

~~~markdown
You are running an ISO/IEC 27001 secure-development evidence check for this
repository. Run read-only. Do not edit code, policies, tickets, or control
mappings. Do not claim certification or compliance.

## Step 0 - Record context

Record:

- Repository, service, and owner.
- Whether the operator supplied the ISMS scope.
- Product data classifications visible in docs or config.
- Build and deployment targets.
- Third-party services, model providers, MCP servers, or vendor integrations.
- Policies, runbooks, or control files available in the repo.

If scope is unclear, state that the report is a repository evidence packet, not
an ISMS-scope conclusion.

## Step 1 - Collect secure-development evidence

Inspect source-controlled evidence for:

- Secure development policy or coding standards.
- Threat model, architecture decision records, or design review notes.
- Security review checklist or reviewer playbook.
- SAST, SCA, secret scanning, dependency review, or container scanning in CI.
- CODEOWNERS or approval rules for security-sensitive files.
- Test evidence for security fixes and regression coverage.
- Vulnerability intake and remediation workflow.
- Prompt, rule, skill, or agent workflow review ownership.

Record file paths and gaps.

## Step 2 - Collect configuration-management evidence

Inspect:

- Infrastructure-as-code, deployment manifests, Dockerfiles, compose files,
  Helm charts, Terraform, or cloud config.
- Environment variable examples and secret-management boundaries.
- Change history for CI, deployment, and runtime policy.
- Default configuration and hardening decisions.
- Rollback, release, and incident runbooks.

Flag unmanaged or undocumented configuration surfaces.

## Step 3 - Collect access and supplier evidence

Inspect:

- Repository permissions-as-code, CODEOWNERS, branch protection docs, or
  approval workflows.
- CI token permissions, deployment credentials, package tokens, signing keys,
  model-provider keys, and scanner credentials.
- Vendor, model-provider, MCP, package-registry, and SaaS dependencies.
- Data handling notes for source code, logs, tickets, prompts, and artifacts.

Record whether each evidence item has an owner and review cadence.

## Step 4 - Build candidate mapping

Create candidate mappings to ISO 27001 themes without asserting final control
IDs unless the operator supplied an approved control map:

- secure development lifecycle;
- configuration management;
- access control and least privilege;
- supplier and cloud-service management;
- logging, monitoring, and incident response;
- vulnerability management;
- information classification and handling.

For every mapping, label it `observed`, `partial`, `missing`, or `out of repo`.

## Step 5 - Write the report

Write `ISO27001_SECURE_DEVELOPMENT_EVIDENCE_CHECK.md` at the repo root, or
print to stdout if write access is unavailable.

Use this structure:

```markdown
# ISO 27001 secure-development evidence check - <repo>

Generated on <date>. Scope note: <scope note>.

## Evidence Sources Reviewed
- ...

## Candidate Control Evidence
| Theme | Status | Evidence | Gaps | Owner |
| ... |

## Findings and Gaps
### <Severity> - <theme> - <short title>
- **Evidence:** ...
- **Gap:** ...
- **Risk:** ...
- **Recommended next action:** ...

## Out-of-Repository Evidence Needed
- ...

## Reviewer Notes
- ...
```

## Stop conditions

Stop and write a partial report if:

- ISMS scope cannot be determined and the operator asked for a certification
  conclusion.
- Evidence requires access to confidential auditor workpapers.
- You find secrets, customer data, or private regulatory correspondence.
~~~

## Output contract

- Evidence packet only.
- Candidate mappings are clearly marked as candidate mappings.
- No final pass/fail control opinion.
- No code or policy edits.

## Guardrails

- Prefer "out of repo" over guessing about evidence in another system.
- Use current public ISO wording only at a high level; do not reproduce
  licensed standard text.
- Include a compliance-owner review step before any audit submission.

## References

- [ISO/IEC 27001:2022 overview](https://www.iso.org/standard/27001)
- [Security Remediation - Compliance & Audit]({{< relref "/security-remediation/compliance" >}})

