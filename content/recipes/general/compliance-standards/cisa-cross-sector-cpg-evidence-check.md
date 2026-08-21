---
title: "CISA Cross-Sector Cybersecurity Performance Goals Evidence Check"
linkTitle: "CISA Cross-Sector CPGs"
description: "Assess CISA Cross-Sector CPGs evidence readiness: verify applicability, map official requirements to artifacts, record gaps, and plan remediation."
recipe_id: "compliance.cisa-cross-sector-cpg-2-0"
framework_id: "cisa-cross-sector-cpg"
framework: "CISA Cross-Sector CPGs"
framework_version: "2.0"
framework_status: "final"
source_reviewed: "2026-08-21"
jurisdiction: ["united-states"]
jurisdictions: ["united-states"]
industry: ["critical-infrastructure", "cross-sector"]
industries: ["critical-infrastructure", "cross-sector"]
facets: ["audit", "compliance", "critical-infrastructure", "secure-defaults"]
official_sources: ["https://www.cisa.gov/cybersecurity-performance-goals"]
routing_positive: ["assess CISA cybersecurity performance goals", "prioritize critical infrastructure safeguards", "collect Cross-Sector CPG evidence"]
routing_hard_negative: ["claim regulatory certification from voluntary CPGs", "perform a NERC CIP entity assessment"]
license_boundary: "public-domain"
tool: "Compliance evidence review"
author: "Security Recipes"
team: "GRC and Security Engineering"
maturity: "stable"
noindex: true
noindex_follow: true
model: "gpt-5-codex"
tags: ["compliance", "cisa-cross-sector-cpg", "critical-infrastructure", "audit", "secure-defaults", "cross-sector"]
weight: 450
date: "2026-08-21"
severity: "info"
---

# CISA Cross-Sector Cybersecurity Performance Goals Evidence Check

Use this recipe to produce a source-aware evidence-readiness assessment for **CISA Cross-Sector CPGs**. It creates an auditable gap record; it does not certify compliance, provide legal advice, or replace an assessor, regulator, or certification body.

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

- **Publisher:** Cybersecurity and Infrastructure Security Agency
- **Version:** 2.0
- **Status:** `final`
- **Sources reviewed:** 2026-08-21
- **Jurisdictions:** united-states
- **Industries:** critical-infrastructure, cross-sector
- **License boundary:** `public-domain`

Critical infrastructure owners and operators using the voluntary Cross-Sector CPG 2.0 baseline. CPG 2.0 is current and aligned to NIST CSF 2.0, including the GOVERN function. Keep 1.0.1 mappings only as a historical comparison. Sector-Specific Goals may add overlays and do not replace the cross-sector baseline.

The cataloged version is final; still verify scope and any later official updates.

Use the official publication as the authority and preserve its version and update identifiers in every finding.

## When to use it

Use this recipe when the organization has established that CISA Cross-Sector CPGs is applicable or wants a readiness assessment against it. Use the routing positives below to distinguish this recipe from adjacent frameworks. If applicability, the effective version, or the authoritative requirement set is unresolved, stop at a scoped intake and record the decision owner.

## Inputs

- The business purpose, legal entities, products, services, systems, and locations in scope.
- The organization's role, applicability decision, selected profile, level, baseline, or control set where the framework requires one.
- The official publication URLs above and, for licensed material, an authorized organization-supplied copy.
- Evidence from the complete review period, including populations—not only hand-picked examples.
- Named owners, inherited/shared responsibilities, exceptions, compensating measures, and accepted risks.
- Read-only access by default. Redacted exports are acceptable when provenance and coverage remain testable.

Evidence domains for this framework:

- governance, accountability, and risk oversight: begin with cybersecurity oversight and risk-acceptance records.
- asset, identity, and least-privilege priorities: begin with prioritized asset, account, and privilege inventories.
- vulnerability, configuration, architecture, and detection: begin with MFA, vulnerability, segmentation, and logging evidence.
- incident response, recovery, MSP, and supply-chain readiness: begin with exercise, backup, MSP, and supplier artifacts.

## The prompt

```markdown
You are a compliance evidence-readiness analyst. Evaluate the supplied scope against CISA Cross-Sector CPGs (2.0). The catalog status is final and the source review date is 2026-08-21.

Never claim certification or legal compliance. Never invent applicability, evidence, control operation, sampling results, or requirement text. Separate observed facts, organization assertions, and analyst inferences. Treat missing or inaccessible evidence as unknown, not as failure, unless the authoritative assessment method says otherwise.

## Step 0 — Lock authority, version, and scope

1. Record the exact official source, version, publication/update identifier, and effective date used.
2. Record the organization, role, jurisdiction, industry, system/product boundary, review period, and decision owner.
3. Confirm any selected level, profile, baseline, overlay, assessment type, or licensed requirement set.
4. The cataloged version is final; still verify scope and any later official updates.
5. Use the official publication as the authority and preserve its version and update identifiers in every finding.
6. Stop and request a decision when applicability or the authoritative requirement set cannot be established.

## Step 1 — Build the applicability map

For every supplied requirement identifier or official outcome in scope, record: applicability, rationale, responsible owner, implementation location, inherited/shared responsibility, evidence expected, and any dependency. Use only identifiers present in the authoritative source supplied for this engagement. Do not reconstruct licensed text.

## Step 2 — Collect evidence by framework domain

Review these domains without treating the labels as substitutes for authoritative requirements:

1. governance, accountability, and risk oversight
2. asset, identity, and least-privilege priorities
3. vulnerability, configuration, architecture, and detection
4. incident response, recovery, MSP, and supply-chain readiness

Start with these likely artifacts, then validate provenance and coverage:

1. cybersecurity oversight and risk-acceptance records
2. prioritized asset, account, and privilege inventories
3. MFA, vulnerability, segmentation, and logging evidence
4. exercise, backup, MSP, and supplier artifacts

For every artifact record: artifact ID, source system, owner, collection time, review period, access path, integrity/provenance note, population covered, and requirement/outcome links. Prefer system exports and immutable records over screenshots or narrative attestations.

## Step 3 — Test design and operation

For each applicable item, evaluate design, implementation, and operating evidence separately. Check whether evidence is authentic, complete, current for the review period, population-representative, and directly linked to the scoped system. Where sampling is permitted, state the population, method, sample size, selections, exceptions, and limitations; do not imply statistical assurance without a justified method.

## Step 4 — Classify gaps without overstating them

Use only: supported, partially supported, unsupported, not applicable with rationale, or not assessed. Record gaps as evidence-readiness findings—not declarations of legal noncompliance. Each finding must include the affected requirement/outcome, observed fact, missing or weak evidence, risk, owner, corrective action, due date, dependencies, retest method, and confidence.

## Step 5 — Produce the evidence bundle

Return one Markdown file named CISA_CROSS_SECTOR_CPG_EVIDENCE_CHECK.md with:

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

- assess CISA cybersecurity performance goals
- prioritize critical infrastructure safeguards
- collect Cross-Sector CPG evidence

Hard negatives—route elsewhere or clarify:

- claim regulatory certification from voluntary CPGs
- perform a NERC CIP entity assessment

## Related recipes

- [IEC 62443](../iec-62443-industrial-security-evidence-check/)
- [NERC CIP](../nerc-cip-applicable-standards-evidence-check/)
- [EU NIS2](../eu-nis2-evidence-readiness-check/)

## References

1. [Cybersecurity and Infrastructure Security Agency official source 1](https://www.cisa.gov/cybersecurity-performance-goals)
