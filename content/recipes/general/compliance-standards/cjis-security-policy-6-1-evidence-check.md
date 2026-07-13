---
title: "CJIS Security Policy v6.1 Evidence Check"
linkTitle: "CJIS Security Policy v6.1"
description: "Criminal justice agencies, noncriminal justice agencies, and service providers handling Criminal Justice Information under applicable agreements."
recipe_id: "compliance.cjis-security-policy-6-1"
framework_id: "cjis-security-policy"
framework: "CJIS Security Policy v6.1"
framework_version: "6.1 (June 25, 2026)"
framework_status: "final"
source_reviewed: "2026-07-12"
jurisdiction: ["united-states"]
jurisdictions: ["united-states"]
industry: ["law-enforcement", "criminal-justice", "government-contractors"]
industries: ["law-enforcement", "criminal-justice", "government-contractors"]
facets: ["audit", "compliance", "data-protection", "government"]
official_sources: ["https://le.fbi.gov/file-repository/cjis_security_policy_v6-1_20260625.pdf/view"]
routing_positive: ["assess CJIS Security Policy 6.1 evidence", "review Criminal Justice Information safeguards", "prepare CJIS audit artifacts"]
routing_hard_negative: ["assess CUI under NIST 800-171", "apply an older CJIS policy without version validation"]
license_boundary: "public-domain"
tool: "Compliance evidence review"
author: "Security Recipes"
team: "GRC and Security Engineering"
maturity: "stable"
model: "gpt-5-codex"
tags: ["compliance", "cjis-security-policy", "government", "audit", "data-protection", "law-enforcement", "criminal-justice"]
weight: 440
date: "2026-07-12"
severity: "info"
---

# CJIS Security Policy v6.1 Evidence Check

Use this recipe to produce a source-aware evidence-readiness assessment for **CJIS Security Policy v6.1**. It creates an auditable gap record; it does not certify compliance, provide legal advice, or replace an assessor, regulator, or certification body.

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

- **Publisher:** Federal Bureau of Investigation
- **Version:** 6.1 (June 25, 2026)
- **Status:** `final`
- **Sources reviewed:** 2026-07-12
- **Jurisdictions:** united-states
- **Industries:** law-enforcement, criminal-justice, government-contractors
- **License boundary:** `public-domain`

Criminal justice agencies, noncriminal justice agencies, and service providers handling Criminal Justice Information under applicable agreements.

The cataloged version is final; still verify scope and any later official updates.

Use the official publication as the authority and preserve its version and update identifiers in every finding.

## When to use it

Use this recipe when the organization has established that CJIS Security Policy v6.1 is applicable or wants a readiness assessment against it. Use the routing positives below to distinguish this recipe from adjacent frameworks. If applicability, the effective version, or the authoritative requirement set is unresolved, stop at a scoped intake and record the decision owner.

## Inputs

- The business purpose, legal entities, products, services, systems, and locations in scope.
- The organization's role, applicability decision, selected profile, level, baseline, or control set where the framework requires one.
- The official publication URLs above and, for licensed material, an authorized organization-supplied copy.
- Evidence from the complete review period, including populations—not only hand-picked examples.
- Named owners, inherited/shared responsibilities, exceptions, compensating measures, and accepted risks.
- Read-only access by default. Redacted exports are acceptable when provenance and coverage remain testable.

Evidence domains for this framework:

- CJI scope, roles, and agreements: begin with CJI data-flow and agreement inventory.
- access, authentication, and personnel security: begin with personnel screening and access reviews.
- encryption, media, and physical protection: begin with encryption and media handling records.
- logging, incidents, audits, and service providers: begin with audit logs, incident exercises, and vendor evidence.

## The prompt

```markdown
You are a compliance evidence-readiness analyst. Evaluate the supplied scope against CJIS Security Policy v6.1 (6.1 (June 25, 2026)). The catalog status is final and the source review date is 2026-07-12.

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

1. CJI scope, roles, and agreements
2. access, authentication, and personnel security
3. encryption, media, and physical protection
4. logging, incidents, audits, and service providers

Start with these likely artifacts, then validate provenance and coverage:

1. CJI data-flow and agreement inventory
2. personnel screening and access reviews
3. encryption and media handling records
4. audit logs, incident exercises, and vendor evidence

For every artifact record: artifact ID, source system, owner, collection time, review period, access path, integrity/provenance note, population covered, and requirement/outcome links. Prefer system exports and immutable records over screenshots or narrative attestations.

## Step 3 — Test design and operation

For each applicable item, evaluate design, implementation, and operating evidence separately. Check whether evidence is authentic, complete, current for the review period, population-representative, and directly linked to the scoped system. Where sampling is permitted, state the population, method, sample size, selections, exceptions, and limitations; do not imply statistical assurance without a justified method.

## Step 4 — Classify gaps without overstating them

Use only: supported, partially supported, unsupported, not applicable with rationale, or not assessed. Record gaps as evidence-readiness findings—not declarations of legal noncompliance. Each finding must include the affected requirement/outcome, observed fact, missing or weak evidence, risk, owner, corrective action, due date, dependencies, retest method, and confidence.

## Step 5 — Produce the evidence bundle

Return one Markdown file named CJIS_SECURITY_POLICY_6_1_EVIDENCE_CHECK.md with:

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

- assess CJIS Security Policy 6.1 evidence
- review Criminal Justice Information safeguards
- prepare CJIS audit artifacts

Hard negatives—route elsewhere or clarify:

- assess CUI under NIST 800-171
- apply an older CJIS policy without version validation

## Related recipes

- [NIST SP 800-53 Rev. 5](../nist-sp-800-53-rev5-control-evidence-check/)
- [NIST SP 800-171 Rev. 3](../nist-sp-800-171-rev3-cui-evidence-check/)
- [FedRAMP 2026](../fedramp-2026-rev5-evidence-check/)

## References

1. [Federal Bureau of Investigation official source 1](https://le.fbi.gov/file-repository/cjis_security_policy_v6-1_20260625.pdf/view)
