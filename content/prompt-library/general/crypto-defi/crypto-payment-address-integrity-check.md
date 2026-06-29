---
title: "Crypto payment address integrity checks"
linkTitle: "Address integrity checks"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["crypto", "payments", "address", "poisoning", "validation"]
weight: 22
date: 2026-04-26
---

Use this prompt to prevent destination-address substitution and
address-poisoning mistakes in crypto payment systems.

## When to use it

- Users, operators, invoices, APIs, or import jobs supply crypto destination
  addresses manually.
- Address books, recent-recipient lists, QR flows, clipboard workflows, or
  withdrawal templates can be poisoned or confused by near-match addresses.
- Chain-specific memos, destination tags, checksums, network prefixes, or asset
  routing rules are required for safe settlement.
- You need a bounded PR or triage note that centralizes address validation and
  prevents silent destination substitution.

## Inputs

- Payment API handlers, withdrawal services, UI/backend validation paths,
  address-book storage, QR/deeplink parsers, import jobs, and notification
  templates.
- Chain metadata, address formats, checksum/network rules, memo/tag
  requirements, asset routing tables, trust tiers, and fraud telemetry.
- Available unit tests, API tests, UI/backend integration tests, chain metadata
  fixtures, telemetry checks, and security scan commands.

## Use when

- Users paste wallet addresses manually.
- Address books and recent-recipient UX can be poisoned.
- Memos/tags are required for some chains.

## Prompt

~~~markdown
You are a security remediation agent for crypto payment integrity.

Goal: implement and enforce destination address integrity controls.
Output either a PR with tests or TRIAGE.md.

Required controls:
- Chain-aware address format validation (checksum/network prefix).
- Canonicalization before storage and comparison.
- Address-book trust tiers (verified, user-added, untrusted).
- High-risk transfer interstitial requiring full-address confirmation.
- Required memo/tag validation for chains that need destination tags.

Tasks:
1. Add a shared address-validation module used by API + UI backend.
2. Reject mixed-chain mismatches (e.g., BTC address for EVM transfer).
3. Add duplicate/similar-address detection to flag poisoning patterns.
4. Add tests covering valid/invalid checksums, chain mismatch,
   missing memo/tag, and poisoning-like near-match cases.
5. Ensure telemetry emits structured security events for rejections.

Constraints:
- Do not auto-correct addresses silently.
- Do not downgrade strict validation to warning-only.
- Stop with TRIAGE.md if chain metadata is incomplete.
~~~

## Output contract

- Reviewer-ready PR adding a shared chain-aware validation path used by API,
  services, and UI backend before storing or submitting destinations.
- Tests for checksums, network mismatch, memo/tag requirements, canonicalized
  comparison, duplicate/near-match poisoning, and high-risk confirmation flows.
- Operator/auditor notes describing chain metadata ownership, address-book
  trust tiers, rejection telemetry, and any unsupported chains.
- `TRIAGE.md` when reliable chain metadata, memo/tag rules, or settlement
  ownership is outside this repository.

## Verification - what the reviewer looks for

- Invalid, mixed-chain, missing-tag, and near-match poisoned addresses are
  rejected before persistence or transfer execution.
- Address canonicalization is explicit and never silently autocorrects a user
  destination.
- API and UI backend paths call the same validation module or share the same
  authoritative policy.
- Security telemetry records rejection reasons without leaking private account
  or wallet metadata.

## Related recipes

- [Cross-chain message authenticity guardrails]({{< relref "/prompt-library/general/crypto-defi/cross-chain-message-authenticity-guardrails" >}})
- [Permit and meta-transaction replay guardrails]({{< relref "/prompt-library/general/crypto-defi/permit-and-meta-transaction-replay-guardrails" >}})
- [Source code supply-chain build integrity audit]({{< relref "/prompt-library/general/source-code-supply-chain-build-integrity-audit" >}})
