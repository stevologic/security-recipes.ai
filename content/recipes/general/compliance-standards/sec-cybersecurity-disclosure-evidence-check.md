---
title: "SEC Cybersecurity Disclosure Evidence Readiness Check"
linkTitle: "SEC Cyber Disclosure Rule"
description: "Assess SEC Cyber Disclosure Rule evidence readiness: verify applicability, map official requirements to artifacts, record gaps, and plan remediation."
recipe_id: "compliance.sec-cyber-disclosure-2023"
framework_id: "sec-cyber-disclosure"
framework: "SEC Cyber Disclosure Rule"
framework_version: "Release 33-11216 (2023)"
framework_status: "final"
source_reviewed: "2026-07-12"
jurisdiction: ["united-states"]
jurisdictions: ["united-states"]
industry: ["public-companies"]
industries: ["public-companies"]
facets: ["audit", "compliance", "governance", "incident-response"]
official_sources: ["https://www.sec.gov/rules-regulations/2023/07/s7-09-22"]
routing_positive: ["prepare SEC cybersecurity disclosure evidence", "review cyber incident materiality governance", "assess annual cyber risk disclosures"]
routing_hard_negative: ["perform a technical incident-response investigation", "test SOX ITGC operating effectiveness"]
license_boundary: "official-text"
tool: "Compliance evidence review"
author: "Security Recipes"
team: "GRC and Security Engineering"
maturity: "stable"
model: "gpt-5-codex"
tags: ["compliance", "sec-cyber-disclosure", "assurance", "audit", "governance", "incident-response", "public-companies"]
weight: 280
date: "2026-07-12"
severity: "info"
---

# SEC Cybersecurity Disclosure Evidence Readiness Check

Use this recipe to produce a source-aware evidence-readiness assessment for **SEC Cyber Disclosure Rule**. It creates an auditable gap record; it does not certify compliance, provide legal advice, or replace an assessor, regulator, or certification body.

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

- **Publisher:** U.S. Securities and Exchange Commission
- **Version:** Release 33-11216 (2023)
- **Status:** `final`
- **Sources reviewed:** 2026-07-12
- **Jurisdictions:** united-states
- **Industries:** public-companies
- **License boundary:** `official-text`

SEC reporting companies preparing evidence for material cybersecurity incident and annual risk-management, strategy, and governance disclosures.

The cataloged version is final; still verify scope and any later official updates.

Use the linked official legal or regulatory text and current implementing guidance; do not replace applicability analysis with this summary.

## When to use it

Use this recipe when the organization has established that SEC Cyber Disclosure Rule is applicable or wants a readiness assessment against it. Use the routing positives below to distinguish this recipe from adjacent frameworks. If applicability, the effective version, or the authoritative requirement set is unresolved, stop at a scoped intake and record the decision owner.

## Inputs

- The business purpose, legal entities, products, services, systems, and locations in scope.
- The organization's role, applicability decision, selected profile, level, baseline, or control set where the framework requires one.
- The official publication URLs above and, for licensed material, an authorized organization-supplied copy.
- Evidence from the complete review period, including populations—not only hand-picked examples.
- Named owners, inherited/shared responsibilities, exceptions, compensating measures, and accepted risks.
- Read-only access by default. Redacted exports are acceptable when provenance and coverage remain testable.

Evidence domains for this framework:

- materiality decision process: begin with materiality criteria and decision records.
- incident escalation and disclosure: begin with incident timeline and escalation artifacts.
- risk management and strategy: begin with disclosure committee minutes.
- board and management governance: begin with board oversight and management-role documentation.

## The prompt

```markdown
You are a compliance evidence-readiness analyst. Evaluate the supplied scope against SEC Cyber Disclosure Rule (Release 33-11216 (2023)). The catalog status is final and the source review date is 2026-07-12.

Never claim certification or legal compliance. Never invent applicability, evidence, control operation, sampling results, or requirement text. Separate observed facts, organization assertions, and analyst inferences. Treat missing or inaccessible evidence as unknown, not as failure, unless the authoritative assessment method says otherwise.

## Step 0 — Lock authority, version, and scope

1. Record the exact official source, version, publication/update identifier, and effective date used.
2. Record the organization, role, jurisdiction, industry, system/product boundary, review period, and decision owner.
3. Confirm any selected level, profile, baseline, overlay, assessment type, or licensed requirement set.
4. The cataloged version is final; still verify scope and any later official updates.
5. Use the linked official legal or regulatory text and current implementing guidance; do not replace applicability analysis with this summary.
6. Stop and request a decision when applicability or the authoritative requirement set cannot be established.

## Step 1 — Build the applicability map

For every supplied requirement identifier or official outcome in scope, record: applicability, rationale, responsible owner, implementation location, inherited/shared responsibility, evidence expected, and any dependency. Use only identifiers present in the authoritative source supplied for this engagement. Do not reconstruct licensed text.

## Step 2 — Collect evidence by framework domain

Review these domains without treating the labels as substitutes for authoritative requirements:

1. materiality decision process
2. incident escalation and disclosure
3. risk management and strategy
4. board and management governance

Start with these likely artifacts, then validate provenance and coverage:

1. materiality criteria and decision records
2. incident timeline and escalation artifacts
3. disclosure committee minutes
4. board oversight and management-role documentation

For every artifact record: artifact ID, source system, owner, collection time, review period, access path, integrity/provenance note, population covered, and requirement/outcome links. Prefer system exports and immutable records over screenshots or narrative attestations.

## Step 3 — Test design and operation

For each applicable item, evaluate design, implementation, and operating evidence separately. Check whether evidence is authentic, complete, current for the review period, population-representative, and directly linked to the scoped system. Where sampling is permitted, state the population, method, sample size, selections, exceptions, and limitations; do not imply statistical assurance without a justified method.

## Step 4 — Classify gaps without overstating them

Use only: supported, partially supported, unsupported, not applicable with rationale, or not assessed. Record gaps as evidence-readiness findings—not declarations of legal noncompliance. Each finding must include the affected requirement/outcome, observed fact, missing or weak evidence, risk, owner, corrective action, due date, dependencies, retest method, and confidence.

## Step 5 — Produce the evidence bundle

Return one Markdown file named SEC_CYBERSECURITY_DISCLOSURE_EVIDENCE_CHECK.md with:

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

- prepare SEC cybersecurity disclosure evidence
- review cyber incident materiality governance
- assess annual cyber risk disclosures

Hard negatives—route elsewhere or clarify:

- perform a technical incident-response investigation
- test SOX ITGC operating effectiveness

## Related recipes

- [SOC 2 TSC](../soc2-change-management-evidence-check/)
- [COBIT 2019](../cobit-2019-governance-evidence-check/)
- [SOX ITGC](../sox-itgc-financial-reporting-evidence-check/)

## References

1. [U.S. Securities and Exchange Commission official source 1](https://www.sec.gov/rules-regulations/2023/07/s7-09-22)
