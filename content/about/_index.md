---
title: About Security Recipes
linkTitle: About
page_kind: webpage
weight: 99
lastmod: 2026-07-21
toc: true
sidebar:
  open: false
  exclude: true
description: >
  How Security Recipes sources CVE facts, reviews remediation guidance,
  labels AI-assisted content, publishes corrections, and keeps security
  workflows accountable.
---

Security Recipes is an open-source knowledge base for people and AI coding
agents working on vulnerability remediation. It combines a synchronized CVE
catalog with practical, reviewable playbooks that require evidence, testing,
rollback, and a human decision before changes are merged or deployed.

The project is maintained in public at
[stevologic/security-recipes.ai](https://github.com/stevologic/security-recipes.ai).
Repository history, contributors, tests, generated-data contracts, and review
discussion are available there for inspection. Last reviewed: **July 21, 2026**.

## Stephen M Abbott

Stephen M Abbott maintains and edits Security Recipes. His
[GitHub profile](https://github.com/stevologic) and the repository's
[public commit history](https://github.com/stevologic/security-recipes.ai/commits/main)
provide the public source and review trail for his work on the project.

## Editorial principles

1. **Source facts and recommendations separately.** CVE identity, CVSS,
   affected-product data, CISA KEV status, and vendor statements retain their
   source and timestamp. A remediation workflow is presented as guidance, not
   as a source fact.
2. **Do not invent certainty.** Missing fixed versions, unclear ownership,
   incomplete affected ranges, and unverified deployment state remain unknown.
   A recipe must stop or route to triage instead of filling those gaps.
3. **Prefer primary evidence.** Vendor advisories, release notes, maintained
   security advisories, NVD records, CISA KEV entries, and official registries
   take precedence over secondary summaries.
4. **Make changes reviewable and reversible.** Guidance calls for narrow diffs,
   focused tests, explicit approval gates, rollback instructions, and residual
   risk that a reviewer can evaluate.
5. **Correct the record visibly.** Material source or remediation changes are
   committed through public history and reflected in page freshness metadata.

## CVE data and review levels

The [CVE Database](/cve-database/) synchronizes non-rejected NVD records in its
declared rolling window when at least one NVD-supplied CVSS observation is
medium or higher. CISA KEV data is joined independently. The
[catalog manifest](/api/cve-catalog/manifest.json) publishes scope, coverage,
and freshness; the [partition index](/api/cve-catalog/index.json) publishes the
machine-readable archive.

Each record is labeled by what supports it:

- **Metadata-backed** records preserve source facts and pair them with a
  deterministic remediation archetype. Teams must confirm product exposure and
  obtain an authoritative fixed version before changing a dependency or system.
- **AI-enriched** records may add evidence-backed context. The page identifies
  the model, status, citations, uncertainty, and evidence gaps. An enrichment
  with insufficient evidence is withheld rather than promoted into a claim.
- **Stable reviewed recipes** contain product-specific exposure, containment,
  remediation, verification, rollback, and source history reviewed through the
  repository workflow.

## How AI is used

Automation builds the catalog, validates integrity hashes, and composes bounded
plans from reviewed archetypes. AI may assist selected research and drafting,
but it is not represented as a human author or an authoritative vulnerability
source. Model-assisted material is labeled at the point of use and remains
subject to source verification, repository tests, and human review.

The reason for publishing any generated page is to help a reader investigate
and remediate a real finding. Pages that cannot add trustworthy source facts or
safe operational guidance should not be indexed merely to capture a search
query.

## Corrections

For an ordinary factual or editorial correction, open a
[GitHub issue](https://github.com/stevologic/security-recipes.ai/issues) or a
pull request with the affected URL, primary source, proposed correction, and
why it changes the remediation decision. Maintainers review the source trail,
update the relevant catalog or recipe input, run validation, and retain the
change in public history.

Do not disclose an unpatched vulnerability, credential, private customer data,
or exploit detail in a public issue. Use the repository's
[private security advisory channel](https://github.com/stevologic/security-recipes.ai/security/advisories/new)
for sensitive reports.

## Independence and scope

Security Recipes is a community project, not the CVE Program, NVD, CISA, or an
affected vendor. External names and identifiers are used to identify evidence.
The site does not grant an agent permission to edit a repository, access a
system, rotate credentials, open a pull request, or deploy a change. Those
authorizations remain with the user and the owning organization.

## License and reuse

Repository content and code are published under the
[Apache License 2.0](https://github.com/stevologic/security-recipes.ai/blob/main/LICENSE).
External source material remains subject to its original terms. When reusing a
recipe, retain its evidence links and update product-specific facts against the
current vendor guidance.
