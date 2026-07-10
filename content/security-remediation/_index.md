---
title: Remediation Playbooks
linkTitle: Playbooks
weight: 2
sidebar:
  open: false
toc: true
cascade:
  - _target:
      kind: page
    sidebar:
      exclude: true
description: >
  Practical remediation recipes that help AI agents produce narrow,
  reviewable security fixes.
---

Remediation playbooks are reusable, bounded recipes for one finding. Each one
should tell an AI agent:

- what kind of finding it can handle,
- what context it needs,
- what files it should avoid,
- what tests or checks matter,
- when to stop and write a triage note,
- what a reviewer should see in the output.

The goal is not to automate every security task. The goal is to make safe,
bounded fixes easier to delegate to an agent while keeping humans in the review
loop.

## Exact scope

Exact scope means a recipe is allowed to handle one concrete finding, not a
general backlog theme. The recipe should be narrow enough that a reviewer can
tell whether the agent stayed inside the boundary without reconstructing the
whole system.

A scoped recipe names:

- the finding identity, such as a CVE, scanner rule, SARIF alert, package,
  endpoint, or source/sink pair;
- the files, manifests, tests, and configuration the agent may inspect or
  change;
- the files and actions that are explicitly out of scope;
- the evidence that must be returned before review starts;
- the stop conditions that turn the run into a triage note instead of a patch.

The boundary is useful because it makes failure legible. If an agent needs to
touch unrelated ownership areas, change deployment topology, migrate data, edit
secrets, broaden permissions, or fix several findings at once, the recipe should
stop and ask for a human-owned plan. That is not a failed automation run; it is
the guardrail working.

Use [Recipe Recommender]({{< relref "/security-remediation/recipe-recommender" >}})
to choose the single safest recipe before work starts, and use
[Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}})
to reject PRs that drift outside the declared scope.

## Python remediation suite

{{< cards >}}
  {{< card link="/security-remediation/remediation-suite/" title="Python Remediation Suite" subtitle="Use domain-specific Python tools for SCA, SAST, sensitive data, containers, cache purge, gatekeeping, runtime controls, review, rollout, metrics, and audit." >}}
{{< /cards >}}

## Core remediation recipes

{{< cards >}}
  {{< card link="/security-remediation/vulnerable-dependencies/" title="Vulnerable Dependencies" subtitle="Bump direct and transitive dependencies, update lockfiles, and prove the affected package is no longer present." >}}
  {{< card link="/security-remediation/sast-findings/" title="SAST Findings" subtitle="Use for local, testable SAST fixes where the rule, source, sink, and safe pattern are clear." >}}
  {{< card link="/security-remediation/sensitive-data/" title="Sensitive Data" subtitle="Clean up exposed secrets, PII, or sensitive fields in logs, configs, fixtures, and schemas." >}}
  {{< card link="/security-remediation/base-images/" title="Base Images and Containers" subtitle="Update image tags, OS packages, and Dockerfile patterns without broad deployment changes." >}}
  {{< card link="/security-remediation/classic-vulnerable-defaults/" title="Classic Vulnerable Defaults" subtitle="Fix repeat offenders such as unsafe YAML, pickle, XXE, weak JWT settings, and dangerous defaults." >}}
  {{< card link="/security-remediation/artifact-cache-purge/" title="Artifact Cache Purge" subtitle="Quarantine compromised artifacts from mirrors, registries, and CI caches." >}}
{{< /cards >}}

## Specialized domains

{{< cards >}}
  {{< card link="/security-remediation/crypto-payments/" title="Crypto Payments" subtitle="Protect irreversible payment, wallet, address, and settlement workflows." >}}
  {{< card link="/security-remediation/defi-blockchain/" title="DeFi and Blockchain" subtitle="Remediation patterns for smart contracts, bridges, oracle usage, and governance workflows." >}}
{{< /cards >}}

## Operating the recipe loop

{{< cards >}}
  {{< card link="/security-remediation/recipe-recommender/" title="Recipe Recommender" subtitle="Classify one finding and pick the single safest downstream recipe before an agent starts remediation." >}}
  {{< card link="/security-remediation/reviewer-playbook/" title="Reviewer Playbook" subtitle="Questions reviewers should ask before merging an agent-authored security PR." >}}
  {{< card link="/security-remediation/gatekeeping/" title="Gatekeeping Patterns" subtitle="Admission, mid-run, pre-merge, and post-merge gates for agent-assisted work." >}}
  {{< card link="/security-remediation/runtime-controls/" title="Runtime Controls" subtitle="How to keep agent tool use scoped while a remediation run is active." >}}
  {{< card link="/security-remediation/maturity/" title="Rollout Model" subtitle="Crawl, walk, run adoption with promotion criteria and stop signals." >}}
  {{< card link="/security-remediation/metrics/" title="Metrics" subtitle="MTTR, reviewer burden, merge quality, false positives, and where automation is earning its keep." >}}
  {{< card link="/security-remediation/compliance/" title="Compliance and Audit" subtitle="Evidence patterns for SOC 2, ISO 27001, PCI DSS, NIST SSDF, and internal review." >}}
  {{< card link="/security-remediation/evidence-bundles/" title="Evidence Bundles" subtitle="Export run receipts as normalized events, manifests, control gaps, hashes, and readable audit reports." >}}
{{< /cards >}}

## Recipe run contract

```text
One finding.
One matching recipe.
One agent run.
One PR or triage note.
Human review before merge.
```

That contract keeps agentic remediation useful. If a finding requires broad
architecture work, production infrastructure changes, unclear ownership, or a
high-risk data migration, the correct output is a triage note rather than a
heroic patch.

## MCP context for recipes

Most recipes get better when the agent can read structured evidence:

- advisory and package data,
- code scanning alerts,
- SBOM or SARIF output,
- repository ownership,
- CI status,
- internal runbooks.

Use [MCP Integration]({{< relref "/mcp-servers" >}}) to connect those sources
as scoped context. Start read-only; add write access only after a separate
review.

## Add or improve a recipe

Good recipes are specific. They name what is in scope, what is out of scope,
what evidence is required, and what a safe stop looks like. See
[Contribute]({{< relref "/contribute" >}}) when you have a working recipe or
prompt to share.
