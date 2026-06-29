---
title: "Bridge and multisig emergency response"
linkTitle: "Bridge/multisig emergency response"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "bridge", "multisig", "incident-response", "runbook"]
weight: 26
date: 2026-04-26
---

Use this prompt to codify emergency response for bridge and multisig
incidents where rapid containment is required.

## When to use it

- Bridge validator compromise is suspected.
- Multisig signer keys are lost or potentially exposed.
- Timelock bypass or unauthorized proposal execution is detected.

## Inputs

- Incident trigger, timestamp, affected bridge route, governance proposal,
  or signer identity.
- Current bridge pause controls, multisig threshold, signer roster,
  timelock delay, and emergency-role map.
- Read-only chain explorer, governance, validator, and deployment evidence.
- Existing incident-response, disclosure, reconciliation, and re-enable
  runbooks.

## Prompt

~~~markdown
You are a DeFi incident-remediation agent preparing bridge/multisig
containment actions.

Goal: produce auditable emergency runbook updates + automation checks,
without executing privileged on-chain actions. Output PR or TRIAGE.md.

Tasks:
1. Validate incident triggers and map them to containment playbooks:
   pause bridge, raise signer threshold, revoke compromised signer,
   freeze high-risk routes, and notify counterparties.
2. Add machine-checkable preconditions for each action so operators
   cannot run steps out of order.
3. Add tabletop simulation script/tests for at least two incident types.
4. Add post-incident checklist: fund reconciliation, signer rotation,
   governance disclosure, and re-enable criteria.

Constraints:
- Agent cannot submit governance votes or sign emergency txs.
- Every manual action must include approver role + evidence artifact.
- Stop with TRIAGE.md if playbook ownership is undefined.
~~~

## Output contract

- Containment runbook diff with preconditions, approver roles, evidence
  artifacts, and exact manual action owners.
- Simulation or tabletop test plan for at least two incident paths.
- Reconciliation checklist covering balances, counterparties, signer
  rotation, disclosure, and re-enable criteria.
- `TRIAGE.md` when ownership, authority, or evidence is insufficient.

## Verification

- Confirm no generated command signs, broadcasts, or submits governance
  transactions.
- Run tabletop or unit tests for pause, threshold raise, signer removal,
  and route freeze ordering.
- Attach explorer or governance read-only evidence for affected contracts,
  proposals, signers, and route state.

## Guardrails

- Do not execute privileged on-chain actions from the recipe run.
- Do not infer a compromised signer without evidence from wallet logs,
  governance activity, custody tooling, or chain observations.
- Stop if emergency authority is unclear, contested, or outside the
  operator's approved incident process.

## Related recipes

- [Hot-wallet policy enforcement]({{< relref "/prompt-library/general/crypto-defi/hot-wallet-transaction-policy-enforcement" >}})
- [Seed/key material purge]({{< relref "/prompt-library/general/crypto-defi/seed-phrase-and-key-material-purge" >}})
- [Contract upgrade diff review]({{< relref "/prompt-library/general/crypto-defi/smart-contract-upgrade-diff-risk-review" >}})
