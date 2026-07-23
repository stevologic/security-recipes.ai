---
title: "EU Cyber Resilience Act Evidence Readiness Check"
linkTitle: "EU Cyber Resilience Act"
description: "Assess EU Cyber Resilience Act evidence readiness: verify applicability, map official requirements to artifacts, record gaps, and plan remediation."
recipe_id: "compliance.eu-cra-2024-2847"
framework_id: "eu-cyber-resilience-act"
framework: "EU Cyber Resilience Act"
framework_version: "Regulation (EU) 2024/2847"
framework_status: "phased-implementation"
source_reviewed: "2026-07-12"
jurisdiction: ["european-union", "extraterritorial"]
jurisdictions: ["european-union", "extraterritorial"]
industry: ["products-with-digital-elements", "software", "hardware"]
industries: ["products-with-digital-elements", "software", "hardware"]
facets: ["audit", "compliance", "product-security", "vulnerability-management"]
official_sources: ["https://eur-lex.europa.eu/legal-content/en/ALL/?uri=CELEX%3A32024R2847"]
routing_positive: ["prepare EU CRA product evidence", "review Cyber Resilience Act readiness", "assess product vulnerability handling obligations"]
routing_hard_negative: ["assess NIS2 essential entity obligations", "review GDPR controller accountability"]
license_boundary: "official-text"
tool: "Compliance evidence review"
author: "Security Recipes"
team: "GRC and Security Engineering"
maturity: "stable"
noindex: true
noindex_follow: true
model: "gpt-5-codex"
tags: ["compliance", "eu-cyber-resilience-act", "product-security", "audit", "vulnerability-management", "products-with-digital-elements", "software"]
weight: 340
date: "2026-07-12"
severity: "info"
---

# EU Cyber Resilience Act Evidence Readiness Check

Use this recipe to produce a source-aware evidence-readiness assessment for **EU Cyber Resilience Act**. It creates an auditable gap record; it does not certify compliance, provide legal advice, or replace an assessor, regulator, or certification body.

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

- **Publisher:** European Union
- **Version:** Regulation (EU) 2024/2847
- **Status:** `phased-implementation`
- **Sources reviewed:** 2026-07-12
- **Jurisdictions:** european-union, extraterritorial
- **Industries:** products-with-digital-elements, software, hardware
- **License boundary:** `official-text`

Manufacturers, importers, and distributors of products with digital elements placed on the EU market, subject to role, product, and exception analysis.

Implementation is phased. Determine which duties and dates apply to the organization before evaluating evidence.

Use the linked official legal or regulatory text and current implementing guidance; do not replace applicability analysis with this summary.

## When to use it

Use this recipe when the organization has established that EU Cyber Resilience Act is applicable or wants a readiness assessment against it. Use the routing positives below to distinguish this recipe from adjacent frameworks. If applicability, the effective version, or the authoritative requirement set is unresolved, stop at a scoped intake and record the decision owner.

## Inputs

- The business purpose, legal entities, products, services, systems, and locations in scope.
- The organization's role, applicability decision, selected profile, level, baseline, or control set where the framework requires one.
- The official publication URLs above and, for licensed material, an authorized organization-supplied copy.
- Evidence from the complete review period, including populations—not only hand-picked examples.
- Named owners, inherited/shared responsibilities, exceptions, compensating measures, and accepted risks.
- Read-only access by default. Redacted exports are acceptable when provenance and coverage remain testable.

Evidence domains for this framework:

- product and economic-operator scope: begin with product classification and role analysis.
- cybersecurity risk assessment and secure development: begin with lifecycle risk assessment.
- technical documentation and conformity: begin with technical file and conformity records.
- vulnerability handling and regulatory reporting: begin with vulnerability intake, update, and reporting workflows.

## The prompt

```markdown
You are a compliance evidence-readiness analyst. Evaluate the supplied scope against EU Cyber Resilience Act (Regulation (EU) 2024/2847). The catalog status is phased-implementation and the source review date is 2026-07-12.

Never claim certification or legal compliance. Never invent applicability, evidence, control operation, sampling results, or requirement text. Separate observed facts, organization assertions, and analyst inferences. Treat missing or inaccessible evidence as unknown, not as failure, unless the authoritative assessment method says otherwise.

## Step 0 — Lock authority, version, and scope

1. Record the exact official source, version, publication/update identifier, and effective date used.
2. Record the organization, role, jurisdiction, industry, system/product boundary, review period, and decision owner.
3. Confirm any selected level, profile, baseline, overlay, assessment type, or licensed requirement set.
4. Implementation is phased. Determine which duties and dates apply to the organization before evaluating evidence.
5. Use the linked official legal or regulatory text and current implementing guidance; do not replace applicability analysis with this summary.
6. Stop and request a decision when applicability or the authoritative requirement set cannot be established.

## Step 1 — Build the applicability map

For every supplied requirement identifier or official outcome in scope, record: applicability, rationale, responsible owner, implementation location, inherited/shared responsibility, evidence expected, and any dependency. Use only identifiers present in the authoritative source supplied for this engagement. Do not reconstruct licensed text.

## Step 2 — Collect evidence by framework domain

Review these domains without treating the labels as substitutes for authoritative requirements:

1. product and economic-operator scope
2. cybersecurity risk assessment and secure development
3. technical documentation and conformity
4. vulnerability handling and regulatory reporting

Start with these likely artifacts, then validate provenance and coverage:

1. product classification and role analysis
2. lifecycle risk assessment
3. technical file and conformity records
4. vulnerability intake, update, and reporting workflows

For every artifact record: artifact ID, source system, owner, collection time, review period, access path, integrity/provenance note, population covered, and requirement/outcome links. Prefer system exports and immutable records over screenshots or narrative attestations.

## Step 3 — Test design and operation

For each applicable item, evaluate design, implementation, and operating evidence separately. Check whether evidence is authentic, complete, current for the review period, population-representative, and directly linked to the scoped system. Where sampling is permitted, state the population, method, sample size, selections, exceptions, and limitations; do not imply statistical assurance without a justified method.

## Step 4 — Classify gaps without overstating them

Use only: supported, partially supported, unsupported, not applicable with rationale, or not assessed. Record gaps as evidence-readiness findings—not declarations of legal noncompliance. Each finding must include the affected requirement/outcome, observed fact, missing or weak evidence, risk, owner, corrective action, due date, dependencies, retest method, and confidence.

## Step 5 — Produce the evidence bundle

Return one Markdown file named EU_CYBER_RESILIENCE_ACT_EVIDENCE_CHECK.md with:

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

- prepare EU CRA product evidence
- review Cyber Resilience Act readiness
- assess product vulnerability handling obligations

Hard negatives—route elsewhere or clarify:

- assess NIS2 essential entity obligations
- review GDPR controller accountability

## Related recipes

- [NIST SSDF 1.1](../nist-ssdf-repo-evidence-check/)
- [SLSA v1.2](../slsa-provenance-evidence-check/)
- [OWASP ASVS 5.0.0](../owasp-asvs-5-0-0-evidence-check/)

## References

1. [European Union official source 1](https://eur-lex.europa.eu/legal-content/en/ALL/?uri=CELEX%3A32024R2847)
