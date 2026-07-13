---
title: "DeFi admin-key and role blast-radius review"
linkTitle: "Admin-key blast-radius review"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "access-control", "admin-key", "timelock", "governance"]
weight: 28
date: 2026-06-14
---

Use this prompt to reduce the damage a compromised admin key, overbroad
role, or rushed governance action can cause in a DeFi protocol.

## When to use it

Use this recipe when smart contracts, deployment scripts, governance proposals,
or runbooks define privileged roles that can upgrade contracts, pause markets,
alter parameters, list assets, change oracles, move treasury funds, or trigger
emergency actions. It is especially useful before mainnet launches, governance
migrations, incident reviews, and audits of owner-only or role-gated code.

Use it to reduce privileged-action blast radius with least privilege,
timelocks, multisigs, bounded parameters, deployment checks, events, and
reviewable governance paths. Do not use it to remove emergency controls that
are genuinely required to stop active loss.

## Inputs

- Solidity/Vyper contracts, proxy/admin contracts, access-control libraries,
  modifiers, deployment scripts, governance proposals, timelock config,
  multisig config, role assignment manifests, Foundry/Hardhat scripts, and
  runbooks.
- Privileged functions that can upgrade implementations, pause/unpause,
  change fees, list assets, set caps, alter risk parameters, change oracles,
  move reserves, mint/burn, bridge, rescue tokens, or modify treasury routes.
- Current role holders: EOAs, multisigs, timelocks, governors, executors,
  guardians, emergency councils, deployment accounts, automation bots, and
  cross-chain message receivers.
- Tests, invariants, deployment checks, event coverage, monitoring rules, and
  audit findings related to access control and governance actions.
- Operational constraints for emergency response, routine governance cadence,
  timelock delays, signer availability, and off-chain approval processes.

## Research basis

- [OWASP Smart Contract Top 10 2026](https://scs.owasp.org/sctop10/) ranks access control and business logic issues among the top smart-contract risk categories.
- [Trail of Bits: Maturing your smart contracts beyond private key risk](https://blog.trailofbits.com/2025/06/25/maturing-your-smart-contracts-beyond-private-key-risk/) recommends least privilege, multisigs, timelocks, and design-stage access control maturity for privileged DeFi functions.

## Use when

- Any privileged function can list assets, alter risk parameters, pause
  markets, upgrade contracts, change oracles, or move reserves.
- Admin roles are held by EOAs, shared wallets, broad multisigs, or
  unclear governance executors.
- Emergency powers and routine governance powers are mixed together.
- Role assignments are not covered by tests or deployment checks.

## Prompt

~~~markdown
You are a DeFi governance and access-control remediation agent.

Goal: reduce privileged-role blast radius and make admin action paths
auditable, delayed where appropriate, and least-privileged. Output PR or
TRIAGE.md.

Controls to implement:
- Replace single-key privileged ownership with multisig or governance
  executors where the deployment model supports it.
- Split routine parameter roles, emergency pause roles, upgrade roles,
  treasury roles, and oracle roles.
- Add timelocks for non-emergency changes that can affect user funds.
- Add explicit allowlists and bounds for high-risk parameter changes.
- Emit events for every privileged action and role change.

Tasks:
1. Inventory all privileged functions, role holders, modifiers, and
   deployment-time role assignments.
2. Classify each privileged action by fund-loss impact, speed required,
   and whether it should be timelocked.
3. Narrow roles so each authority can perform only the actions required
   for its operational purpose.
4. Add tests proving unauthorized accounts cannot call privileged paths
   and authorized roles cannot exceed their intended scope.
5. Add deployment or configuration checks that fail on EOA ownership,
   missing timelocks, missing events, or unbounded critical parameters.

Constraints:
- Do not remove emergency pause capability from genuinely time-critical
  loss-prevention paths.
- Do not hide risk behind comments or documentation-only controls.
- Stop with TRIAGE.md if role ownership is controlled outside this
  repository and cannot be verified by code or deployment artifacts.
~~~

## Output contract

Return one of:

- A reviewer-ready PR/change request that narrows privileged roles, adds or
  verifies multisig/governor/timelock execution where appropriate, separates
  emergency and routine authorities, bounds high-risk parameters, emits events,
  adds tests and deployment checks, and refreshes governance documentation.
- `TRIAGE.md` when privileged ownership is entirely external to the repository
  and cannot be verified through code, deployment artifacts, governance config,
  or runbooks.

The output must list every privileged action reviewed, its current holder,
fund-loss impact, intended authority, delay/emergency classification, tests
added, deployment checks added, and residual roles that need human governance
approval. It must not remove emergency pause paths, transfer authority to an
unreviewed EOA, or rely only on comments for access-control risk reduction.

## Related recipes

- [Smart-contract upgrade diff risk review]({{< relref "/recipes/general/crypto-defi/smart-contract-upgrade-diff-risk-review" >}})
- [DeFi bridge and multisig emergency response]({{< relref "/recipes/general/crypto-defi/defi-bridge-and-multisig-emergency-response" >}})
- [Hot-wallet transaction policy enforcement]({{< relref "/recipes/general/crypto-defi/hot-wallet-transaction-policy-enforcement" >}})
