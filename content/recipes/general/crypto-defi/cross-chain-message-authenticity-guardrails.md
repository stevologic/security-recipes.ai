---
title: "Cross-chain message authenticity guardrails"
linkTitle: "Cross-chain message guardrails"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "bridge", "cross-chain", "message-authenticity", "replay"]
weight: 31
date: 2026-06-14
lastmod: 2026-08-21
---

Use this prompt to harden cross-chain message handlers against forged
payloads, chain replay, untrusted relayers, and missing proof checks.

## When to use it

- Destination-chain code executes deposits, withdrawals, mints, burns,
  unlocks, governance actions, or configuration changes from cross-chain
  messages.
- Relayers, bridge adapters, oracle committees, light clients, or off-chain
  services submit payloads, receipts, proofs, signatures, or message IDs.
- Source chain, source sender, destination contract, payload hash, or nonce
  binding is unclear or split across multiple modules.
- You need a bounded PR or triage note that hardens message authenticity and
  replay protection without trusting relayer identity alone.

## Inputs

- Smart contracts, relayer services, bridge adapters, chain-domain registries,
  proof verifiers, message schemas, event processors, and governance configs.
- Source/destination chain IDs, trusted sender lists, nonce/message-ID storage,
  proof formats, quorum rules, payload hash construction, and emergency pause
  ownership.
- Available contract tests, fork/simulation tests, fuzz/property tests,
  deployment scripts, audit reports, and security scan commands.

## Research basis

- [OWASP SCWE-107: Missing Chain ID Validation in Cross-Chain Messages](https://scs.owasp.org/SCWE/SCSVS-COMM/SCWE-107/) recommends binding inbound messages to expected source chain, domain, sender, and nonce.
- [OWASP SCWE-108: Unverified Cross-Chain Message Proofs](https://scs.owasp.org/SCWE/SCSVS-COMM/SCWE-108/) recommends validating Merkle proofs, light-client headers, signatures, or quorum rules before executing payloads.

## Use when

- A destination contract executes deposits, withdrawals, mints, burns,
  unlocks, governance actions, or parameter changes from cross-chain
  messages.
- Relayers submit payloads, receipts, proofs, signatures, or message IDs.
- Message validation does not bind source chain, source sender, nonce,
  bridge adapter, and payload hash together.
- Tests cover the happy path but not forged or replayed messages.

## Prompt

~~~markdown
You are a cross-chain message authenticity remediation agent.

Goal: ensure destination-chain execution happens only for authentic,
authorized, non-replayed messages from expected source domains. Output PR
or TRIAGE.md.

Controls to implement:
- Validate source chain ID, source domain, source sender, destination
  chain, and destination contract.
- Verify inclusion proofs, light-client headers, validator signatures,
  quorum thresholds, or bridge-adapter attestations before execution.
- Track nonces or message IDs per source chain and source sender.
- Bind payload hash, asset, amount, recipient, and action type into the
  authenticated message.
- Fail closed on unknown relayers, unsupported source domains, stale
  roots, malformed proofs, or already-consumed messages.

Tasks:
1. Inventory all cross-chain receive, finalize, execute, mint, unlock,
   and governance message handlers.
2. Trace which component proves message authenticity and which component
   enforces replay protection.
3. Add missing source-domain, trusted-sender, proof, quorum, and nonce
   checks at the destination boundary.
4. Add negative tests for wrong chain, wrong sender, forged proof,
   replayed nonce, mismatched payload hash, and unauthorized relayer.
5. Document emergency pause behavior for bridge-adapter compromise or
   proof-system outage.

Constraints:
- Do not trust relayer identity as a substitute for message proof.
- Do not use a global nonce if multiple source chains or senders can
  collide.
- Stop with TRIAGE.md if authenticity depends on an off-chain service
  whose verification contract or trust assumptions are unavailable.
~~~

## Output contract

- Reviewer-ready PR binding each inbound message to source chain/domain,
  trusted sender, destination contract, payload hash, action type, and nonce or
  message ID before execution.
- Negative tests for wrong chain, wrong sender, forged proof, stale root,
  mismatched payload, replayed nonce, unauthorized relayer, and paused bridge
  behavior.
- Operator/auditor notes describing trust assumptions, proof/quorum ownership,
  emergency pause behavior, and any unsupported source domains.
- `TRIAGE.md` when the repository cannot verify the proof system, bridge
  adapter, trust model, or deployment owner.

## Verification - what the reviewer looks for

- Every destination execution path validates source domain, trusted sender,
  proof/quorum, payload binding, and replay protection before state changes.
- Nonces or message IDs are scoped by source chain and sender, not shared as a
  collision-prone global counter.
- Tests exercise forged, replayed, stale, malformed, and unauthorized messages
  against the real boundary that executes payloads.
- Emergency pause behavior is deterministic and documented for bridge-adapter
  compromise or proof-system outage.

## Related recipes

- [Crypto payment address integrity checks]({{< relref "/recipes/general/crypto-defi/crypto-payment-address-integrity-check" >}})
- [DeFi oracle manipulation guardrails]({{< relref "/recipes/general/crypto-defi/defi-oracle-manipulation-guardrails" >}})
- [Source code supply-chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit" >}})
