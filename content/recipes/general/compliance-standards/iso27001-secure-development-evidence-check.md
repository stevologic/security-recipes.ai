---
title: "ISO/IEC 27001:2022 ISMS Evidence Readiness Check"
linkTitle: "ISO/IEC 27001:2022"
description: "Assess ISO/IEC 27001:2022 evidence readiness: verify applicability, map official requirements to artifacts, record gaps, and plan remediation."
recipe_id: "compliance.iso-iec-27001-2022"
framework_id: "iso-27001"
framework: "ISO/IEC 27001:2022"
framework_version: "2022"
framework_status: "final"
source_reviewed: "2026-08-21"
jurisdiction: ["global"]
jurisdictions: ["global"]
industry: ["cross-sector"]
industries: ["cross-sector"]
facets: ["audit", "compliance", "risk", "governance"]
official_sources: ["https://www.iso.org/standard/27001"]
routing_positive: ["prepare ISO 27001 audit evidence", "review our ISMS readiness", "check ISO 27001:2022 governance artifacts"]
routing_hard_negative: ["verify ISO 42001 AI management controls", "run a SOC 2 change-management evidence check"]
license_boundary: "summary-only"
tool: "Compliance evidence review"
author: "Security Recipes"
team: "GRC and Security Engineering"
maturity: "stable"
noindex: true
noindex_follow: true
model: "gpt-5-codex"
tags: ["compliance", "iso-27001", "security-programs", "audit", "risk", "governance", "cross-sector"]
weight: 120
date: "2026-08-21"
severity: "info"
---

# ISO/IEC 27001:2022 ISMS Evidence Readiness Check

Use this recipe to produce a source-aware evidence-readiness assessment for **ISO/IEC 27001:2022**. It creates an auditable gap record; it does not certify compliance, provide legal advice, or replace an assessor, regulator, or certification body.

## Section index

- [Framework basis](#framework-basis)
- [When to use it](#when-to-use-it)
- [Inputs](#inputs)
- [The prompt](#the-prompt)
- [Output contract](#output-contract)
- [Verification](#verification)
- [Guardrails](#guardrails)
- [Routing examples](#routing-examples)
- [References](#references)

## Framework basis

- **Publisher:** ISO/IEC
- **Version:** 2022
- **Status:** `final`
- **Sources reviewed:** 2026-08-21
- **Jurisdictions:** global
- **Industries:** cross-sector
- **License boundary:** `summary-only`

Organizations operating or preparing to certify an information security management system against ISO/IEC 27001:2022.

The cataloged version is final; still verify scope and any later official updates.

This recipe intentionally summarizes domains and evidence needs. Do not reproduce licensed control text; use an organization-supplied licensed copy for requirement-level work.

## When to use it

Use this recipe when the organization has established that ISO/IEC 27001:2022 is applicable or wants a readiness assessment against it. Use the routing positives below to distinguish this recipe from adjacent frameworks. If applicability, the effective version, or the authoritative requirement set is unresolved, stop at a scoped intake and record the decision owner.

## Inputs

- The business purpose, legal entities, products, services, systems, and locations in scope.
- The organization's role, applicability decision, selected profile, level, baseline, or control set where the framework requires one.
- The official publication URLs above and, for licensed material, an authorized organization-supplied copy.
- Evidence from the complete review period, including populations—not only hand-picked examples.
- Named owners, inherited/shared responsibilities, exceptions, compensating measures, and accepted risks.
- Read-only access by default. Redacted exports are acceptable when provenance and coverage remain testable.

Evidence domains for this framework:

- ISMS scope and interested parties: begin with approved ISMS scope.
- risk assessment and treatment: begin with risk register and treatment decisions.
- statement of applicability and objectives: begin with current statement of applicability.
- internal audit, management review, and improvement: begin with audit findings and corrective-action records.

## The prompt

```markdown
You are a compliance evidence-readiness analyst. Evaluate the supplied scope against ISO/IEC 27001:2022 (2022). The catalog status is final and the source review date is 2026-08-21.

Never claim certification or legal compliance. Never invent applicability, evidence, control operation, sampling results, or requirement text. Separate observed facts, organization assertions, and analyst inferences. Treat missing or inaccessible evidence as unknown, not as failure, unless the authoritative assessment method says otherwise.

## Step 0 — Lock authority, version, and scope

1. Record the exact official source, version, publication/update identifier, and effective date used.
2. Record the organization, role, jurisdiction, industry, system/product boundary, review period, and decision owner.
3. Confirm any selected level, profile, baseline, overlay, assessment type, or licensed requirement set.
4. The cataloged version is final; still verify scope and any later official updates.
5. This recipe intentionally summarizes domains and evidence needs. Do not reproduce licensed control text; use an organization-supplied licensed copy for requirement-level work.
6. Stop and request a decision when applicability or the authoritative requirement set cannot be established.

## Step 1 — Build the applicability map

For every supplied requirement identifier or official outcome in scope, record: applicability, rationale, responsible owner, implementation location, inherited/shared responsibility, evidence expected, and any dependency. Use only identifiers present in the authoritative source supplied for this engagement. Do not reconstruct licensed text.

## Step 2 — Collect evidence by framework domain

Review these domains without treating the labels as substitutes for authoritative requirements:

1. ISMS scope and interested parties
2. risk assessment and treatment
3. statement of applicability and objectives
4. internal audit, management review, and improvement

Start with these likely artifacts, then validate provenance and coverage:

1. approved ISMS scope
2. risk register and treatment decisions
3. current statement of applicability
4. audit findings and corrective-action records

For every artifact record: artifact ID, source system, owner, collection time, review period, access path, integrity/provenance note, population covered, and requirement/outcome links. Prefer system exports and immutable records over screenshots or narrative attestations.

## Step 3 — Test design and operation

For each applicable item, evaluate design, implementation, and operating evidence separately. Check whether evidence is authentic, complete, current for the review period, population-representative, and directly linked to the scoped system. Where sampling is permitted, state the population, method, sample size, selections, exceptions, and limitations; do not imply statistical assurance without a justified method.

## Step 4 — Classify gaps without overstating them

Use only: supported, partially supported, unsupported, not applicable with rationale, or not assessed. Record gaps as evidence-readiness findings—not declarations of legal noncompliance. Each finding must include the affected requirement/outcome, observed fact, missing or weak evidence, risk, owner, corrective action, due date, dependencies, retest method, and confidence.

## Step 5 — Produce the evidence bundle

Return one Markdown file named ISO27001_SECURE_DEVELOPMENT_EVIDENCE_CHECK.md with:

1. Executive summary and explicit assurance limitations.
2. Authority/version/status and scope/applicability record.
3. Coverage totals by status and evidence domain.
4. Requirement/outcome-to-evidence matrix with artifact provenance.
5. Findings ordered by risk and evidence impact.
6. A 30/60/90-day remediation and evidence-collection plan.
7. Open questions, unavailable sources, conflicts, and decisions required.
8. Official references with access/review date.

Before finalizing, verify that every conclusion is traceable to an artifact or clearly labeled assertion/inference, all denominators reconcile, all unavailable evidence is visible, licensed text is not reproduced, and no sentence claims certification or legal approval.
```

## Output contract

The response must contain one evidence matrix row per scoped authoritative item or outcome. At minimum include `item_id`, `applicability`, `owner`, `implementation`, `artifact_ids`, `test_method`, `coverage_period`, `status`, `gap`, and `confidence`. Every artifact ID must resolve to the artifact register, and every total must reconcile to the matrix.

## Verification

- Confirm the official source, version, status, and review date in both the executive summary and matrix metadata.
- Reconcile applicable, not applicable, and not assessed counts to the complete supplied scope.
- Trace each supported assertion to provenance-bearing evidence covering the stated period and population.
- Independently reperform a risk-based sample of mappings and document all exceptions.
- Verify findings distinguish control/design weakness from missing evidence and unknown scope.
- Have the accountable owner and, where required, qualified counsel or an authorized assessor review conclusions.

## Guardrails

- This is an evidence-readiness workflow, not certification, attestation, audit opinion, or legal advice.
- Do not infer that a voluntary framework is mandatory or that one framework proves another.
- Do not paste, paraphrase at length, or reconstruct licensed controls. Use source summaries and organization-supplied licensed material.
- Do not expose secrets, personal data, regulated data, or full production exports in the report.
- Do not modify systems, close findings, accept risk, or submit regulatory reports without explicit owner authorization.
- If versions conflict, preserve both citations, label the conflict, and escalate rather than choosing silently.

## Routing examples

Route here:

- prepare ISO 27001 audit evidence
- review our ISMS readiness
- check ISO 27001:2022 governance artifacts

Hard negatives—route elsewhere or clarify:

- verify ISO 42001 AI management controls
- run a SOC 2 change-management evidence check

## Related recipes

- [CIS Controls v8.1](../cis-controls-safeguard-implementation-check/)
- [NIST CSF 2.0](../nist-csf-2-0-profile-evidence-check/)
- [NIST SSDF 1.1](../nist-ssdf-repo-evidence-check/)

## References

1. [ISO/IEC official source 1](https://www.iso.org/standard/27001)
