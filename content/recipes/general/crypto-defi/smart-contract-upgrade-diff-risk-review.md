---
title: "Smart-contract upgrade diff risk review"
linkTitle: "Contract upgrade diff review"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "smart-contract", "upgrade", "proxy", "invariants"]
weight: 24
date: 2026-04-26
---

Use this prompt to review upgrade diffs and enforce invariant checks
before smart-contract changes are approved.

## When to use it

- Proxy implementation contracts are changing.
- Storage layout or access-control logic is modified.
- Emergency patches must still prove safety.

## Inputs

- Old and new implementation addresses, source commits, compiler versions,
  ABI files, storage-layout artifacts, and deployment chain id.
- Timelock, proxy admin, guardian, owner, and role-assignment evidence.
- Existing invariant, fork-test, simulation, and formal-check outputs.
- Approved upgrade proposal, reviewer policy, and emergency-change
  exception record when applicable.

## Prompt

~~~markdown
You are a DeFi security remediation agent reviewing contract upgrades.

Goal: produce a PR that adds upgrade-risk checks and test coverage,
or TRIAGE.md if upgrade safety cannot be established.

Required checks:
- Storage layout compatibility (no unsafe slot collisions).
- Access-control changes and role escalation diff.
- Pause/guardian semantics unchanged or explicitly approved.
- Solvency and collateral invariants across fork tests.

Tasks:
1. Generate a machine-readable diff of old vs new ABI, storage layout,
   events, and privileged functions.
2. Add/extend tests for invariants and permission boundaries.
3. Fail CI on unauthorized changes to timelock delay or signer threshold.
4. Produce reviewer checklist summarizing high-risk deltas.

Constraints:
- No mainnet execution from this run.
- No silent ignore of compiler warnings.
- Stop with TRIAGE.md if baseline artifacts are missing.
~~~

## Output contract

- Machine-readable upgrade diff covering ABI, storage layout, events,
  privileged functions, roles, and timelock-sensitive parameters.
- Added or updated tests for storage compatibility, authorization,
  pause/guardian behavior, solvency, and collateral invariants.
- Reviewer checklist that separates approved deltas from unresolved risks.
- `TRIAGE.md` when baseline artifacts, chain evidence, or test harnesses
  are missing.

## Verification

- Run compiler, storage-layout comparison, invariant tests, and fork tests
  required by the repository.
- Confirm unauthorized timelock, signer-threshold, proxy-admin, or guardian
  changes fail CI.
- Compare generated ABI and privileged-function diffs against the approved
  proposal.

## Guardrails

- Do not execute mainnet transactions, submit proposals, or sign upgrade
  payloads.
- Do not approve compiler warnings, storage-layout drift, or access-control
  expansion without explicit reviewer evidence.
- Stop if the old implementation artifact cannot be reproduced.

## Related recipes

- [Bridge/multisig emergency response]({{< relref "/recipes/general/crypto-defi/defi-bridge-and-multisig-emergency-response" >}})
- [DeFi admin key and role blast-radius review]({{< relref "/recipes/general/crypto-defi/defi-admin-key-and-role-blast-radius-review" >}})
- [DeFi reentrancy and callback hardening]({{< relref "/recipes/general/crypto-defi/defi-reentrancy-and-callback-hardening" >}})
