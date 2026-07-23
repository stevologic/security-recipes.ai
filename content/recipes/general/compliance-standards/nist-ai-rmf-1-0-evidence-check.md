---
title: "NIST AI Risk Management Framework 1.0 Evidence Check"
linkTitle: "NIST AI RMF 1.0"
description: "Assess NIST AI RMF 1.0 evidence readiness: verify applicability, map official requirements to artifacts, record gaps, and plan remediation."
recipe_id: "compliance.nist-ai-rmf-1-0"
framework_id: "nist-ai-rmf"
framework: "NIST AI RMF 1.0"
framework_version: "1.0; revision in progress"
framework_status: "revision-in-progress"
source_reviewed: "2026-07-12"
jurisdiction: ["global", "united-states"]
jurisdictions: ["global", "united-states"]
industry: ["artificial-intelligence", "cross-sector"]
industries: ["artificial-intelligence", "cross-sector"]
facets: ["audit", "compliance", "ai-safety", "risk"]
official_sources: ["https://www.nist.gov/itl/ai-risk-management-framework", "https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10"]
routing_positive: ["assess AI governance against NIST AI RMF", "collect Govern Map Measure Manage evidence", "review AI risk management artifacts"]
routing_hard_negative: ["assess secure model development only with SP 800-218A", "certify an ISO 42001 management system"]
license_boundary: "public-domain"
tool: "Compliance evidence review"
author: "Security Recipes"
team: "GRC and Security Engineering"
maturity: "stable"
model: "gpt-5-codex"
tags: ["compliance", "nist-ai-rmf", "ai-governance", "audit", "ai-safety", "risk", "artificial-intelligence", "cross-sector"]
weight: 390
date: "2026-07-12"
severity: "info"
---

# NIST AI Risk Management Framework 1.0 Evidence Check

Use this recipe to produce a source-aware evidence-readiness assessment for **NIST AI RMF 1.0**. It creates an auditable gap record; it does not certify compliance, provide legal advice, or replace an assessor, regulator, or certification body.

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

- **Publisher:** NIST
- **Version:** 1.0; revision in progress
- **Status:** `revision-in-progress`
- **Sources reviewed:** 2026-07-12
- **Jurisdictions:** global, united-states
- **Industries:** artificial-intelligence, cross-sector
- **License boundary:** `public-domain`

Organizations governing, mapping, measuring, and managing AI risks using AI RMF 1.0 while NIST develops a revision.

The authority is revising or transitioning this framework. Confirm the effective source set and dates before making a current-state claim.

Use the official publication as the authority and preserve its version and update identifiers in every finding.

## When to use it

Use this recipe when the organization has established that NIST AI RMF 1.0 is applicable or wants a readiness assessment against it. Use the routing positives below to distinguish this recipe from adjacent frameworks. If applicability, the effective version, or the authoritative requirement set is unresolved, stop at a scoped intake and record the decision owner.

## Inputs

- The business purpose, legal entities, products, services, systems, and locations in scope.
- The organization's role, applicability decision, selected profile, level, baseline, or control set where the framework requires one.
- The official publication URLs above and, for licensed material, an authorized organization-supplied copy.
- Evidence from the complete review period, including populations—not only hand-picked examples.
- Named owners, inherited/shared responsibilities, exceptions, compensating measures, and accepted risks.
- Read-only access by default. Redacted exports are acceptable when provenance and coverage remain testable.

Evidence domains for this framework:

- AI governance and accountability: begin with AI system inventory and ownership.
- context and impact mapping: begin with impact and stakeholder analyses.
- measurement and evaluation: begin with evaluation metrics and limitations.
- risk treatment, monitoring, and incident learning: begin with risk acceptance, monitoring, and incident records.

## The prompt

```markdown
You are a compliance evidence-readiness analyst. Evaluate the supplied scope against NIST AI RMF 1.0 (1.0; revision in progress). The catalog status is revision-in-progress and the source review date is 2026-07-12.

Never claim certification or legal compliance. Never invent applicability, evidence, control operation, sampling results, or requirement text. Separate observed facts, organization assertions, and analyst inferences. Treat missing or inaccessible evidence as unknown, not as failure, unless the authoritative assessment method says otherwise.

## Step 0 — Lock authority, version, and scope

1. Record the exact official source, version, publication/update identifier, and effective date used.
2. Record the organization, role, jurisdiction, industry, system/product boundary, review period, and decision owner.
3. Confirm any selected level, profile, baseline, overlay, assessment type, or licensed requirement set.
4. The authority is revising or transitioning this framework. Confirm the effective source set and dates before making a current-state claim.
5. Use the official publication as the authority and preserve its version and update identifiers in every finding.
6. Stop and request a decision when applicability or the authoritative requirement set cannot be established.

## Step 1 — Build the applicability map

For every supplied requirement identifier or official outcome in scope, record: applicability, rationale, responsible owner, implementation location, inherited/shared responsibility, evidence expected, and any dependency. Use only identifiers present in the authoritative source supplied for this engagement. Do not reconstruct licensed text.

## Step 2 — Collect evidence by framework domain

Review these domains without treating the labels as substitutes for authoritative requirements:

1. AI governance and accountability
2. context and impact mapping
3. measurement and evaluation
4. risk treatment, monitoring, and incident learning

Start with these likely artifacts, then validate provenance and coverage:

1. AI system inventory and ownership
2. impact and stakeholder analyses
3. evaluation metrics and limitations
4. risk acceptance, monitoring, and incident records

For every artifact record: artifact ID, source system, owner, collection time, review period, access path, integrity/provenance note, population covered, and requirement/outcome links. Prefer system exports and immutable records over screenshots or narrative attestations.

## Step 3 — Test design and operation

For each applicable item, evaluate design, implementation, and operating evidence separately. Check whether evidence is authentic, complete, current for the review period, population-representative, and directly linked to the scoped system. Where sampling is permitted, state the population, method, sample size, selections, exceptions, and limitations; do not imply statistical assurance without a justified method.

## Step 4 — Classify gaps without overstating them

Use only: supported, partially supported, unsupported, not applicable with rationale, or not assessed. Record gaps as evidence-readiness findings—not declarations of legal noncompliance. Each finding must include the affected requirement/outcome, observed fact, missing or weak evidence, risk, owner, corrective action, due date, dependencies, retest method, and confidence.

## Step 5 — Produce the evidence bundle

Return one Markdown file named NIST_AI_RMF_1_0_EVIDENCE_CHECK.md with:

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

- assess AI governance against NIST AI RMF
- collect Govern Map Measure Manage evidence
- review AI risk management artifacts

Hard negatives—route elsewhere or clarify:

- assess secure model development only with SP 800-218A
- certify an ISO 42001 management system

## Related recipes

- [NIST AI SSDF](../ai-governance-oversight-evidence-check/)
- [ISO/IEC 42001:2023](../iso42001-ai-management-system-evidence-check/)
- [EU AI Act](../eu-ai-act-evidence-readiness-check/)

## References

1. [NIST official source 1](https://www.nist.gov/itl/ai-risk-management-framework)
2. [NIST official source 2](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)
