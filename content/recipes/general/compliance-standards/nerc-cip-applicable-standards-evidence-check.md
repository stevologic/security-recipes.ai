---
title: "NERC CIP Applicable Standards Evidence Check"
linkTitle: "NERC CIP"
description: "Assess NERC CIP evidence readiness: verify applicability, map official requirements to artifacts, record gaps, and plan remediation."
recipe_id: "compliance.nerc-cip-current-applicable-set"
framework_id: "nerc-cip"
framework: "NERC CIP"
framework_version: "Operator-supplied effective standards set; checked 2026-07-12"
framework_status: "revision-in-progress"
source_reviewed: "2026-07-12"
jurisdiction: ["north-america", "united-states", "canada"]
jurisdictions: ["north-america", "united-states", "canada"]
industry: ["bulk-electric-system", "energy"]
industries: ["bulk-electric-system", "energy"]
facets: ["audit", "compliance", "ot-security", "critical-infrastructure"]
official_sources: ["https://www.nerc.com/pa/Stand/Pages/ReliabilityStandards.aspx"]
routing_positive: ["assess NERC CIP evidence", "review BES Cyber System compliance artifacts", "verify the effective CIP standards set"]
routing_hard_negative: ["assess generic IEC 62443 product security", "apply an obsolete CIP version without checking effective dates"]
license_boundary: "official-text"
tool: "Compliance evidence review"
author: "Security Recipes"
team: "GRC and Security Engineering"
maturity: "stable"
noindex: true
noindex_follow: true
model: "gpt-5-codex"
tags: ["compliance", "nerc-cip", "critical-infrastructure", "audit", "ot-security", "bulk-electric-system", "energy"]
weight: 380
date: "2026-07-12"
severity: "info"
---

# NERC CIP Applicable Standards Evidence Check

Use this recipe to produce a source-aware evidence-readiness assessment for **NERC CIP**. It creates an auditable gap record; it does not certify compliance, provide legal advice, or replace an assessor, regulator, or certification body.

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

- **Publisher:** North American Electric Reliability Corporation
- **Version:** Operator-supplied effective standards set; checked 2026-07-12
- **Status:** `revision-in-progress`
- **Sources reviewed:** 2026-07-12
- **Jurisdictions:** north-america, united-states, canada
- **Industries:** bulk-electric-system, energy
- **License boundary:** `official-text`

Registered entities with Bulk Electric System Cyber Systems must establish applicable, effective NERC CIP standards from current standards and implementation plans.

The authority is revising or transitioning this framework. Confirm the effective source set and dates before making a current-state claim.

Use the linked official legal or regulatory text and current implementing guidance; do not replace applicability analysis with this summary.

## When to use it

Use this recipe when the organization has established that NERC CIP is applicable or wants a readiness assessment against it. Use the routing positives below to distinguish this recipe from adjacent frameworks. If applicability, the effective version, or the authoritative requirement set is unresolved, stop at a scoped intake and record the decision owner.

## Inputs

- The business purpose, legal entities, products, services, systems, and locations in scope.
- The organization's role, applicability decision, selected profile, level, baseline, or control set where the framework requires one.
- The official publication URLs above and, for licensed material, an authorized organization-supplied copy.
- Evidence from the complete review period, including populations—not only hand-picked examples.
- Named owners, inherited/shared responsibilities, exceptions, compensating measures, and accepted risks.
- Read-only access by default. Redacted exports are acceptable when provenance and coverage remain testable.

Evidence domains for this framework:

- registration, assets, and applicability: begin with applicability and impact-rating records.
- electronic and physical security perimeters: begin with BES Cyber System inventories and diagrams.
- system security, access, and change management: begin with access, patch, configuration, and monitoring evidence.
- incident response, recovery, and supply chain: begin with exercise, recovery, and vendor-risk records.

## The prompt

```markdown
You are a compliance evidence-readiness analyst. Evaluate the supplied scope against NERC CIP (Operator-supplied effective standards set; checked 2026-07-12). The catalog status is revision-in-progress and the source review date is 2026-07-12.

Never claim certification or legal compliance. Never invent applicability, evidence, control operation, sampling results, or requirement text. Separate observed facts, organization assertions, and analyst inferences. Treat missing or inaccessible evidence as unknown, not as failure, unless the authoritative assessment method says otherwise.

## Step 0 — Lock authority, version, and scope

1. Record the exact official source, version, publication/update identifier, and effective date used.
2. Record the organization, role, jurisdiction, industry, system/product boundary, review period, and decision owner.
3. Confirm any selected level, profile, baseline, overlay, assessment type, or licensed requirement set.
4. The authority is revising or transitioning this framework. Confirm the effective source set and dates before making a current-state claim.
5. Use the linked official legal or regulatory text and current implementing guidance; do not replace applicability analysis with this summary.
6. Stop and request a decision when applicability or the authoritative requirement set cannot be established.

## Step 1 — Build the applicability map

For every supplied requirement identifier or official outcome in scope, record: applicability, rationale, responsible owner, implementation location, inherited/shared responsibility, evidence expected, and any dependency. Use only identifiers present in the authoritative source supplied for this engagement. Do not reconstruct licensed text.

## Step 2 — Collect evidence by framework domain

Review these domains without treating the labels as substitutes for authoritative requirements:

1. registration, assets, and applicability
2. electronic and physical security perimeters
3. system security, access, and change management
4. incident response, recovery, and supply chain

Start with these likely artifacts, then validate provenance and coverage:

1. applicability and impact-rating records
2. BES Cyber System inventories and diagrams
3. access, patch, configuration, and monitoring evidence
4. exercise, recovery, and vendor-risk records

For every artifact record: artifact ID, source system, owner, collection time, review period, access path, integrity/provenance note, population covered, and requirement/outcome links. Prefer system exports and immutable records over screenshots or narrative attestations.

## Step 3 — Test design and operation

For each applicable item, evaluate design, implementation, and operating evidence separately. Check whether evidence is authentic, complete, current for the review period, population-representative, and directly linked to the scoped system. Where sampling is permitted, state the population, method, sample size, selections, exceptions, and limitations; do not imply statistical assurance without a justified method.

## Step 4 — Classify gaps without overstating them

Use only: supported, partially supported, unsupported, not applicable with rationale, or not assessed. Record gaps as evidence-readiness findings—not declarations of legal noncompliance. Each finding must include the affected requirement/outcome, observed fact, missing or weak evidence, risk, owner, corrective action, due date, dependencies, retest method, and confidence.

## Step 5 — Produce the evidence bundle

Return one Markdown file named NERC_CIP_APPLICABLE_STANDARDS_EVIDENCE_CHECK.md with:

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

- assess NERC CIP evidence
- review BES Cyber System compliance artifacts
- verify the effective CIP standards set

Hard negatives—route elsewhere or clarify:

- assess generic IEC 62443 product security
- apply an obsolete CIP version without checking effective dates

## Related recipes

- [IEC 62443](../iec-62443-industrial-security-evidence-check/)
- [CISA Cross-Sector CPGs](../cisa-cross-sector-cpg-evidence-check/)
- [EU NIS2](../eu-nis2-evidence-readiness-check/)

## References

1. [North American Electric Reliability Corporation official source 1](https://www.nerc.com/pa/Stand/Pages/ReliabilityStandards.aspx)
