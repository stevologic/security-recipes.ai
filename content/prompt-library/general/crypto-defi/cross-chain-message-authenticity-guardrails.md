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
---

Use this prompt to harden cross-chain message handlers against forged
payloads, chain replay, untrusted relayers, and missing proof checks.

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
