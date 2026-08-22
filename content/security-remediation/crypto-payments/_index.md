---
title: Cryptocurrency & Crypto Payments Security
linkTitle: Crypto Payments Security
weight: 9
date: 2026-04-26
lastmod: 2026-08-21
sidebar:
  open: true
description: >
  Agentic workflows for wallet operations, payment address integrity,
  settlement controls, and key-material hygiene in cryptocurrency
  payment systems.
---

{{< callout type="warning" >}}
**Irreversibility changes everything.** In crypto payments, a single bad
transaction can settle in seconds with no clawback path. The goal of
this workflow is to stop high-blast-radius mistakes *before* signing,
then produce auditable triage when automation cannot prove safety.
Rechecked August 21, 2026: stop before signing when ownership, a
named floor, or rollback cannot be proved.
{{< /callout >}}

## What this workflow covers

- **Wallet-op hardening** for hot-wallet signing services.
- **Address integrity controls** to prevent substitution and poisoning.
- **Key-material cleanup** in code, logs, CI artifacts, and runbooks.
- **Settlement policy checks** before release and after chain events.

{{< playbook-workflow >}}

## Eligibility profile

A finding is agent-eligible when all are true:

1. The fix shape is bounded (policy/config, controlled code path, or
   deterministic runbook update).
2. A signed transaction is **not** emitted directly by the agent.
3. A dry-run or simulation path exists.
4. Human approval remains mandatory for production key use.

## Recipe catalog

Use the following prompt recipes for this workflow:

- [Hot-wallet transaction policy enforcement]({{< relref "/recipes/general/crypto-defi/hot-wallet-transaction-policy-enforcement" >}})
- [Crypto payment address integrity checks]({{< relref "/recipes/general/crypto-defi/crypto-payment-address-integrity-check" >}})
- [Seed phrase and key-material purge]({{< relref "/recipes/general/crypto-defi/seed-phrase-and-key-material-purge" >}})

## Guardrails

- Signer credentials are scoped to simulation-only in agent runs.
- Allowlists enforce destination, chain, token, amount, and cadence.
- Every fail-open branch is converted to fail-closed with triage.
- Incident evidence is written to immutable audit storage.

## Not in scope

- Autonomous treasury strategy decisions.
- Trading or market-making actions.
- On-chain signing from unreviewed prompts.

## See also

- [DeFi & Blockchain Protocol Security]({{< relref "/security-remediation/defi-blockchain" >}})
- [Prompt catalog: Crypto + DeFi]({{< relref "/recipes/general/crypto-defi" >}})
