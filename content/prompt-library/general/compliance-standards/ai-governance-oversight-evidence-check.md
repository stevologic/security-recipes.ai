---
title: "AI governance oversight evidence check"
linkTitle: "AI governance oversight"
description: "Read-only recipe for collecting human oversight, model-provider, logging, and risk-classification evidence for AI-enabled workflows."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "gpt-5-codex"
tags: ["compliance", "ai-governance", "eu-ai-act", "nist-ai", "human-oversight", "agentic-ai"]
weight: 70
date: 2026-06-25
severity: "medium"
---

A read-only evidence check for AI-enabled engineering workflows. It helps a
team document human oversight, model-provider contracts, data flows, logging,
and risk classification before legal or compliance teams map the workflow to a
specific AI governance regime.

## When to use it

- Before deploying agentic remediation into a regulated product environment.
- When an AI workflow can affect identity, employment, credit, safety, payment,
  healthcare, or other sensitive outcomes.
- When preparing documentation for EU AI Act, NIST AI SSDF, or internal AI
  governance review.

## Inputs

- Repository path and AI workflow name.
- Model providers, agent platforms, MCP servers, and data sources.
- Optional approved risk taxonomy or AI system inventory fields.
- Optional legal/compliance classification if already available.

## The prompt

~~~markdown
You are running an AI governance oversight evidence check. Run read-only. Do
not edit code, change policies, call external systems, upload data, or classify
the workflow as legally compliant.

## Step 0 - AI workflow inventory

Record:

- Workflow name and repository/service owner.
- Models, providers, agent platforms, MCP servers, plugins, skills, prompts,
  and tools involved.
- Inputs sent to models: source code, tickets, logs, scanner findings, customer
  data, personal data, secrets, payment data, healthcare data, or other
  regulated data.
- Outputs produced: PRs, triage notes, tickets, deployment changes, access
  decisions, user-impacting decisions, or reports.
- Whether the workflow is advisory, code-generating, autonomous, or
  decision-making.

## Step 1 - Risk-classification evidence

Collect evidence for:

- AI inventory record.
- Business purpose and intended use.
- Data classification for model inputs and outputs.
- Whether the workflow can materially affect people, access, eligibility,
  safety, financial outcomes, employment, education, law enforcement,
  healthcare, or critical infrastructure.
- Known limitations, misuse cases, and prohibited uses.
- Owner approval and review cadence.

If no classification exists, mark it missing. Do not invent a legal category.

## Step 2 - Human oversight evidence

Check whether the workflow requires human approval before:

- merging code;
- deploying;
- changing access;
- sending external messages;
- modifying tickets or incidents;
- rotating secrets;
- touching regulated data;
- making user-impacting decisions.

Record the reviewer role, evidence artifact, escalation path, and whether the
control is enforced by tooling or documented as process only.

## Step 3 - Data and provider evidence

Collect:

- model-provider contract or configuration references;
- retention, training-use, residency, and incident-notification settings;
- prompt/data redaction controls;
- secrets and regulated-data exclusion rules;
- MCP/tool allowlists and per-run credential boundaries;
- logs that show what the model and tools accessed.

Mark missing provider evidence as a gap for legal/compliance review.

## Step 4 - Logging and traceability evidence

Check for:

- run IDs;
- prompt and recipe version;
- model/provider/version;
- tool calls and MCP responses;
- input source links;
- output artifacts;
- reviewer decisions;
- error, refusal, rollback, and incident logs;
- retention period.

## Step 5 - Write the report

Write `AI_GOVERNANCE_OVERSIGHT_EVIDENCE_CHECK.md` at the repo root, or print
to stdout if write access is unavailable.

Use this structure:

```markdown
# AI governance oversight evidence check - <workflow>

Generated on <date>. Legal classification: not determined by this recipe.

## Workflow Inventory
- ...

## Evidence Matrix
| Area | Status | Evidence | Gap | Owner |
| ... |

## Human Oversight Controls
- ...

## Data and Provider Evidence
- ...

## Findings
### <Severity> - <short title>
- **Evidence:** ...
- **Gap:** ...
- **Why it matters:** ...
- **Recommended next action:** ...

## Legal/Compliance Review Questions
- ...
```

## Stop conditions

Stop and write a partial report if:

- the workflow touches regulated personal, payment, healthcare, employment, or
  safety data and no owner is identified;
- classification requires legal judgment;
- the operator asks you to upload data to a model provider to complete the
  check;
- secrets or private data are found in prompts, logs, fixtures, or run records.
~~~

## Output contract

- Evidence and gap report only.
- No final legal classification or compliance claim.
- No data upload or external tool write.
- Explicit questions for legal/compliance review.
- Clear separation between repository evidence, runtime/platform evidence,
  provider-contract evidence, and legal classification questions.

## Verification

Before handing the report to legal, compliance, or AI governance owners,
verify that:

- every workflow, model, provider, MCP server, prompt, skill, and tool claim is
  backed by a file path, configuration reference, run record, or `not found`
  note;
- the report does not assign a final EU AI Act, NIST AI RMF, sectoral, or
  internal-risk classification unless the operator supplied an approved
  classification;
- human oversight controls are marked as `enforced`, `documented only`,
  `missing`, or `out of repo`;
- provider-retention, training-use, residency, and incident-notification
  settings are listed as observed evidence or explicit gaps;
- secrets, personal data, regulated data, and proprietary prompts are redacted
  from examples and findings.

## Guardrails

- Treat human oversight as a control only when it is evidenced and enforceable.
- Separate "model generated a suggestion" from "AI made a decision."
- Keep regulated-data examples redacted.

## Related recipes

- [NIST SSDF repository evidence check]({{< relref "/prompt-library/general/compliance-standards/nist-ssdf-repo-evidence-check" >}})
- [Source code audit - secrets and data exposure]({{< relref "/prompt-library/general/source-code-secrets-data-exposure-audit" >}})
- [Source code audit - attack surface map]({{< relref "/prompt-library/general/source-code-attack-surface-map" >}})
- [Context egress boundary]({{< relref "/security-remediation/context-egress-boundary" >}})

## References

- [European Commission AI Act overview](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [NIST SP 800-218A AI SSDF community profile](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [Security Remediation - Compliance & Audit]({{< relref "/security-remediation/compliance" >}})
