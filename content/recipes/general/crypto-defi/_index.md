---
title: Crypto & DeFi Security Recipes
linkTitle: Crypto & DeFi Recipes
weight: 20
lastmod: 2026-08-21
sidebar:
  open: false
description: >
  Tool-agnostic prompts for securing cryptocurrency payment flows,
  wallet operations, and DeFi protocol controls.
---

This catalog groups reusable prompts for **crypto payments** and
**DeFi blockchain security**. The recipes are tool-agnostic and are
intended for bounded, auditable workflows with human approval.
Rechecked August 23, 2026: leftover CVE dumps stay **development /
noindex**. Do not invent a protocol upgrade target or a named
floor from leftover dump version text. Frontmatter `model` strings
such as `GPT-5.3-Codex` are recipe metadata, not prompt pins. Do
not emit a signed transaction from an agent run.

## Crypto payment recipes

- [Hot-wallet transaction policy enforcement]({{< relref "/recipes/general/crypto-defi/hot-wallet-transaction-policy-enforcement" >}})
- [Crypto payment address integrity checks]({{< relref "/recipes/general/crypto-defi/crypto-payment-address-integrity-check" >}})
- [Seed phrase and key-material purge]({{< relref "/recipes/general/crypto-defi/seed-phrase-and-key-material-purge" >}})

## DeFi blockchain recipes

- [Smart-contract upgrade diff risk review]({{< relref "/recipes/general/crypto-defi/smart-contract-upgrade-diff-risk-review" >}})
- [DeFi oracle manipulation guardrails]({{< relref "/recipes/general/crypto-defi/defi-oracle-manipulation-guardrails" >}})
- [Bridge & multisig emergency response]({{< relref "/recipes/general/crypto-defi/defi-bridge-and-multisig-emergency-response" >}})
- [DeFi reentrancy and callback hardening]({{< relref "/recipes/general/crypto-defi/defi-reentrancy-and-callback-hardening" >}})
- [DeFi admin-key and role blast-radius review]({{< relref "/recipes/general/crypto-defi/defi-admin-key-and-role-blast-radius-review" >}})
- [ERC-4626 vault inflation and rounding guardrails]({{< relref "/recipes/general/crypto-defi/erc4626-vault-inflation-and-rounding-guardrails" >}})
- [Permit and meta-transaction replay guardrails]({{< relref "/recipes/general/crypto-defi/permit-and-meta-transaction-replay-guardrails" >}})
- [Cross-chain message authenticity guardrails]({{< relref "/recipes/general/crypto-defi/cross-chain-message-authenticity-guardrails" >}})
- [DEX slippage and MEV guardrails]({{< relref "/recipes/general/crypto-defi/dex-slippage-and-mev-guardrails" >}})

{{< prompt-toc >}}
