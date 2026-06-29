---
title: "Hot-wallet transaction policy enforcement"
linkTitle: "Hot-wallet policy enforcement"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["crypto", "wallet", "payments", "policy", "transaction-signing"]
weight: 21
date: 2026-04-26
---

Use this prompt to harden a hot-wallet signing pipeline so unsafe
transactions are blocked before they can be signed.

## When to use it

- Payment services sign transfers from online wallets.
- Destination and amount controls exist but are inconsistently enforced.
- You need reproducible policy checks in CI and runtime.

## Inputs

- Signing entrypoint names, wallet service paths, and transaction request
  schemas.
- Approved chains, assets, destination allowlists, per-transaction caps,
  rolling daily caps, and business-reason requirements.
- Existing policy store, logging, metrics, and alerting conventions.
- Test harness or simulation mode that can exercise signing flows without
  broadcasting transactions.

## Prompt

~~~markdown
You are a security remediation agent for a cryptocurrency payment system.

Goal: enforce a deterministic transaction-policy gate for hot-wallet
signing requests. Produce either:
1) a PR that adds policy enforcement + tests, or
2) TRIAGE.md if you cannot safely complete.

Policy checks must include: allowed chain, allowed asset, destination
allowlist, per-tx cap, rolling daily cap, and required business reason.

Constraints:
- Never sign or broadcast real transactions.
- Operate in dry-run/simulation mode only.
- Fail closed if policy data is unavailable.

Implementation tasks:
1. Locate signing entrypoints and insert a `validateTransactionPolicy`
   guard before any signer call.
2. Ensure every rejection is logged with reason code and request ID,
   without logging secrets.
3. Add tests for allow, reject-by-destination, reject-by-amount,
   reject-by-daily-cap, and reject-by-missing-policy-store.
4. Add a runbook note describing rollback and emergency deny-all mode.

Stop and write TRIAGE.md if signing paths are dynamic/reflection-based
and cannot be bounded confidently.
~~~

## Output contract

- PR that inserts fail-closed policy enforcement before every signer call.
- Tests for allowed requests, blocked destinations, blocked amounts,
  rolling-limit exhaustion, and missing policy data.
- Audit log fields for request id, rejection reason, policy version, and
  actor without secrets or private keys.
- `TRIAGE.md` when signing paths, policy ownership, or simulation coverage
  cannot be bounded safely.

## Verification

- Run unit and integration tests in dry-run mode only.
- Confirm no code path signs or broadcasts a real transaction during the
  recipe run.
- Verify missing policy data, policy-store outage, and malformed requests
  fail closed.

## Guardrails

- Do not sign, broadcast, sweep, or move funds.
- Do not log seed phrases, private keys, full wallet addresses beyond the
  approved audit format, or raw transaction secrets.
- Stop if a signing path cannot be located, policy limits conflict, or the
  runtime cannot enforce deny-all mode.

## Related recipes

- [Bridge/multisig emergency response]({{< relref "/prompt-library/general/crypto-defi/defi-bridge-and-multisig-emergency-response" >}})
- [Seed/key material purge]({{< relref "/prompt-library/general/crypto-defi/seed-phrase-and-key-material-purge" >}})
- [Crypto payment address integrity checks]({{< relref "/prompt-library/general/crypto-defi/crypto-payment-address-integrity-check" >}})
