---
title: DeFi & Blockchain Protocol Security
linkTitle: DeFi & Blockchain Security
weight: 10
date: 2026-04-26
lastmod: 2026-07-13
sidebar:
  open: true
description: >
  Agentic workflows for defending smart contracts and protocol
  operations, including oracle controls, bridge response, and
  upgrade-risk review.
---

{{< callout type="info" >}}
**Protocol risk is system risk.** DeFi failures are often cross-component:
contract logic, oracle assumptions, bridge trust, and governance timing.
This workflow keeps agent actions narrow and auditable while humans own
final protocol decisions.
{{< /callout >}}

## What this workflow covers

- **Upgrade diff review** for proxy and immutable deployments.
- **Oracle and scope guardrails** for manipulation-resistant execution.
- **Bridge and multisig emergency runbooks** for containment.

{{< playbook-workflow >}}

## Eligibility profile

A finding is eligible when:

- The impacted contracts/configs are known and versioned.
- A fork-test or simulation harness can validate behavior.
- Emergency actions are pre-approved in runbook policy.
- Agent changes are reviewable as code/config, not ad-hoc operator chat.

## Recipe catalog

- [Smart-contract upgrade diff risk review]({{< relref "/recipes/general/crypto-defi/smart-contract-upgrade-diff-risk-review" >}})
- [DeFi oracle manipulation guardrails]({{< relref "/recipes/general/crypto-defi/defi-oracle-manipulation-guardrails" >}})
- [Bridge & multisig emergency response]({{< relref "/recipes/general/crypto-defi/defi-bridge-and-multisig-emergency-response" >}})

## Guardrails

- Chain-specific simulation required before merge.
- Invariant tests for solvency, collateralization, and pause logic.
- Timelock and signer-threshold constraints cannot be weakened by agent.
- Any unverifiable assumption triggers `TRIAGE.md` and stop.

## Not in scope

- Autonomous governance voting with production keys.
- New protocol feature design.
- Economic parameter tuning without risk committee sign-off.

## See also

- [Cryptocurrency & Crypto Payments Security]({{< relref "/security-remediation/crypto-payments" >}})
- [Prompt catalog: Crypto + DeFi]({{< relref "/recipes/general/crypto-defi" >}})
