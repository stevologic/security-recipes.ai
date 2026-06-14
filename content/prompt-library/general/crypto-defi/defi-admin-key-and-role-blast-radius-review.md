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
