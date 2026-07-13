---
title: "Permit and meta-transaction replay guardrails"
linkTitle: "Permit replay guardrails"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "signature", "permit", "replay", "eip712"]
weight: 30
date: 2026-06-14
---

Use this prompt to prevent signature replay across chains, contracts,
forks, functions, and repeated permit or meta-transaction execution.

## When to use it

- Contracts or services implement `permit`, delegated execution,
  meta-transactions, gasless approvals, off-chain orders, claims, or governance
  signatures.
- Signed payloads can authorize transfers, approvals, withdrawals, orders,
  claims, role changes, or other state-changing actions.
- Domain separators, nonces, deadlines, typed-data fields, upgrade behavior, or
  fork handling are custom or partially implemented.
- You need a bounded PR or triage note that binds every signature to one chain,
  contract, purpose, signer state, and expiration window.

## Inputs

- Signature verification code, EIP-712 domain construction, nonce storage,
  order books, relayer/meta-tx handlers, upgradeable proxy config, and permit
  adapters.
- Chain IDs, verifying contracts, domain names/versions, typed-data schemas,
  nonce namespaces, deadline rules, signer recovery logic, and migration notes.
- Available unit tests, fork tests, fuzz/property tests, signature fixtures,
  deployment scripts, audit reports, and security scan commands.

## Research basis

- [OWASP SCWE-105: Permit Signature Replay](https://scs.owasp.org/SCWE/SCSVS-AUTH/SCWE-105/) recommends EIP-712 domain separators with name, version, chain ID, and verifying contract plus nonce handling.
- [EIP-2612](https://eips.ethereum.org/EIPS/eip-2612) defines `permit`, `nonces`, deadlines, and domain separation requirements.
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712) uses domain separation to prevent collisions between otherwise identical signed structures.

## Use when

- Contracts implement `permit`, meta-transactions, delegated actions, or
  off-chain approvals.
- Signatures authorize transfers, approvals, withdrawals, orders,
  claims, or governance actions.
- Domain separators, nonces, deadlines, or typed-data fields are custom.
- Signatures may be replayed after forks, upgrades, or deployments to
  another chain.

## Prompt

~~~markdown
You are a DeFi signature replay remediation agent.

Goal: bind every signed action to one chain, one contract, one purpose,
one signer state, and one expiration window. Output PR or TRIAGE.md.

Controls to implement:
- Use EIP-712 typed data with domain fields for name, version, chainId,
  and verifyingContract.
- Include action-specific fields so signatures cannot authorize a
  different function or asset.
- Enforce per-signer nonces, order nonces, or nonce bitmaps before state
  changes complete.
- Enforce deadlines or validity windows.
- Reject zero address owners, mismatched signers, reused signatures, and
  malformed signatures.

Tasks:
1. Inventory all signature verification paths and the assets or actions
   they authorize.
2. Compare signed fields against the state changes they permit and add
   any missing chain, contract, nonce, deadline, spender, asset, amount,
   recipient, or function intent fields.
3. Ensure nonce consumption is atomic and cannot be skipped on success.
4. Add tests replaying signatures across chains, contracts, forks,
   functions, nonce states, and expired deadlines.
5. Add migration notes for any domain separator or version change that
   intentionally invalidates old signatures.

Constraints:
- Do not accept signatures without clear replay scope and expiration.
- Do not reuse one nonce namespace for unrelated actions unless that
  behavior is intentional and tested.
- Stop with TRIAGE.md if existing live signatures must remain valid and
  the safe migration path requires governance or user coordination.
~~~

## Output contract

- Reviewer-ready PR binding each signed action to explicit domain fields,
  action-specific typed data, signer identity, nonce state, and deadline before
  any state change.
- Tests for replay across chains, contracts, forks, function intents, nonce
  states, expired deadlines, malformed signatures, and zero-address owners.
- Operator/auditor notes describing domain/version changes, migration effects,
  nonce namespace choices, live-signature invalidation, and governance needs.
- `TRIAGE.md` when a safe signature migration or governance decision is outside
  this repository.

## Verification - what the reviewer looks for

- Signatures cannot be replayed across chain IDs, verifying contracts, proxy
  deployments, function intents, assets, recipients, or nonce states.
- Nonce consumption is atomic with successful execution and cannot be skipped
  or reused after partial failure.
- Deadlines or validity windows are enforced before state changes.
- Tests cover both canonical valid signatures and malicious reuse scenarios
  against the actual entry points.

## Related recipes

- [ERC-4626 vault inflation and rounding guardrails]({{< relref "/recipes/general/crypto-defi/erc4626-vault-inflation-and-rounding-guardrails" >}})
- [Crypto payment address integrity checks]({{< relref "/recipes/general/crypto-defi/crypto-payment-address-integrity-check" >}})
- [Source code supply-chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit" >}})
