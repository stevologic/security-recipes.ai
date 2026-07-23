---
title: Visual Guide to Security Recipes
linkTitle: Visual Guide
weight: 3
date: 2026-05-02
lastmod: 2026-07-23
toc: true
sidebar:
  open: true
description: >
  Search the CVE database, inspect an evidence-qualified canonical record, run
  a bounded agent plan, and return proof for human review.
---

{{< callout type="info" >}}
Use this page when you have a CVE or vulnerability finding and want the
shortest path from source evidence to a reviewer-ready result. The complete
database is broad; search-indexable canonical CVE pages are deliberately
limited to records with reviewed Markdown or evidence-qualified remediation.
{{< /callout >}}

## The path at a glance

Security Recipes is meant to be used as a loop:

1. Search the CVE database or start from one named finding.
2. Open the canonical record and confirm the affected surface.
3. Select the smallest evidence-backed agent plan or remediation playbook.
4. Return tests, source evidence, rollback, and stop conditions for review.
5. Add read-only MCP context only when the agent needs runtime retrieval.

{{< cards >}}
  {{< card link="/cve-database/" title="CVE Database" subtitle="Search sourced vulnerability facts and evidence-qualified canonical records." >}}
  {{< card link="/security-remediation/" title="AI Remediation" subtitle="Move from one finding to a bounded patch or complete triage note." >}}
  {{< card link="/agents/" title="Compare AI Agents" subtitle="Choose an agent, then load its native instruction file for the task." >}}
  {{< card link="/recipes/" title="Recipes" subtitle="Use reviewed prompts, rules, skills, and verification contracts." >}}
  {{< card link="/mcp-servers/" title="Read-only MCP" subtitle="Retrieve approved CVE and recipe context without granting write authority." >}}
{{< /cards >}}

## 1. Search the CVE database

<figure class="visual-guide-figure">
  <img src="../images/how-to-use/cve-search-to-record.webp" alt="A compact CVE search flows from a selected record through affected, severity, and evidence panels into a canonical remediation record." width="2048" height="1152" loading="lazy" decoding="async">
  <figcaption>Search the complete catalog, then open an evidence-qualified canonical record when one is available.</figcaption>
</figure>

Start with the [CVE Database]({{< relref "/cve-database" >}}) when you have an
exact CVE ID, product, severity, ecosystem, or known-exploited status. The
database covers the complete tracked Medium, High, and Critical scope. A
canonical CVE page is narrower: it is published for search only after the
record passes the repository's remediation-evidence policy. The page initially
shows its server-rendered qualified records and downloads the full compressed
browser index only after you interact with search. Results link to a local
canonical page only when that evidence-qualified route exists; every record
still links to its official CVE.org source.

On a canonical record, the visible primary references and structured-data
citations come from the same conservative source set. Multi-branch fixes keep
all trusted fixed-release versions in the recommended action, so reviewing one
branch does not silently hide the others.

The [Recipes]({{< relref "/recipes" >}}) library uses the same data-first
pattern: its initial document contains 18 crawlable cards and loads the complete
curated feed only after you search, filter, sort, open a filtered URL, or ask for
more. The full JSON feed remains available for agents and offline consumers.

## 2. Turn evidence into a bounded plan

<figure class="visual-guide-figure">
  <img src="../images/how-to-use/cve-to-agent-plan.webp" alt="An affected surface and evidence packet flow through discover, assess, mitigate, remediate, verify, rollback, and triage inside a review gate." width="2048" height="1152" loading="lazy" decoding="async">
  <figcaption>The machine-readable plan preserves all seven lifecycle phases while keeping mutation behind review and approval boundaries.</figcaption>
</figure>

Confirm the affected asset, versions, exposure, and owner before asking an
agent to edit anything. Then choose the relevant [agent setup]({{< relref "/agents" >}})
and load its native instruction file: `AGENTS.md`, `CLAUDE.md`,
`.github/copilot-instructions.md`, or `.cursor/rules/*.mdc`. The plan is
context, not permission; repository scope and every approval gate still apply.

## 3. Return proof for human review

<figure class="visual-guide-figure">
  <img src="../images/how-to-use/proof-and-review.webp" alt="A scoped finding moves through a bounded change, tests, evidence, recorded rollback, and a distinct final human review gate." width="2048" height="1152" loading="lazy" decoding="async">
  <figcaption>A complete handoff names the scope, shows the change, records tests and sources, preserves rollback, and ends at human review.</figcaption>
</figure>

Use the [AI Vulnerability Remediation Playbooks]({{< relref "/security-remediation" >}})
to define the finding, allowed files, verification,
rollback, and stop conditions. The acceptable outcome is either a small,
reviewer-ready change with evidence or a triage note that names the blocker and
responsible owner. It is never an unreviewed production mutation.

## 4. Add read-only MCP context when needed

<figure class="visual-guide-figure">
  <img src="../images/how-to-use/read-only-mcp-context.webp" alt="An agent retrieves CVE context and recipes through a read-only MCP layer with audit, while write access remains blocked behind a separate approval-required gate." width="2048" height="1152" loading="lazy" decoding="async">
  <figcaption>The public MCP baseline retrieves context read-only; an approved host or gateway can add redacted audit logging while write authority remains a separate decision.</figcaption>
</figure>

Use MCP when an agent needs structured recipe or CVE retrieval at runtime.
Keep the baseline read-only. Connecting an organization-approved tool can add
context, but it does not authorize edits, ticket changes, secret rotation,
deployment, or any other external mutation.

## What to read next

- [CVE Database]({{< relref "/cve-database" >}}) to search sourced records by
  ID, product, severity, ecosystem, or KEV status.
- [Quick Start]({{< relref "/quickstart" >}}) for the shortest path from one
  finding to one reviewed output.
- [Agents]({{< relref "/agents" >}}) if you already know which AI tool
  your team uses.
- [Recipes]({{< relref "/recipes" >}}) if you need rules,
  skills, or prompts to copy into a repo.
- [MCP Servers]({{< relref "/mcp-servers" >}}) for read-only retrieval and
  separately approved enterprise connectors.
- [Security Remediation]({{< relref "/security-remediation" >}}) if you
  are designing the full security-operated workflow.
