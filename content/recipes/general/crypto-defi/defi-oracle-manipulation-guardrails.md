---
title: "DeFi oracle manipulation guardrails"
linkTitle: "Oracle manipulation guardrails"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "oracle", "plan documentation", "manipulation", "risk-controls"]
weight: 25
date: 2026-04-26
lastmod: 2026-08-21
---

Use this prompt to add and verify protections against oracle-based
price manipulation in DeFi execution paths.

## When to use it

- Borrowing, liquidation, swaps, minting, vault accounting, collateral limits,
  or settlement logic depends on oracle prices.
- Thin-liquidity assets, stale feeds, single-source spot prices, or
  governance-controlled parameters can create manipulation windows.
- Existing tests cover normal price movement but not flash spikes, stale data,
  feed outage, deviation limits, or fallback behavior.
- You need a bounded PR or triage note that adds deterministic oracle
  guardrails and proves risky actions fail closed.

## Inputs

- Contracts/modules that read oracle values, feed adapters, TWAP/median logic,
  collateral configs, liquidation paths, pause/circuit-breaker code, and
  governance parameter files.
- Feed freshness/deviation thresholds, fallback sources, emergency controls,
  asset liquidity assumptions, deployment configs, and prior audit findings.
- Available unit tests, fork/simulation tests, invariant/fuzz tests, oracle
  fixtures, deployment scripts, and security scan commands.

## Use when

- Liquidation and borrow limits rely on oracle prices.
- Thin-liquidity assets can be manipulated intra-block.
- Protocol needs bounded fallback behavior during oracle anomalies.

## Prompt

~~~markdown
You are a DeFi security remediation agent implementing oracle guardrails.

Goal: harden oracle consumption paths and add tests proving safe
behavior under manipulation scenarios. Output PR or TRIAGE.md.

Controls to implement:
- TWAP/medianized price checks where applicable.
- Maximum deviation and staleness thresholds.
- Secondary-source cross-check or safe pause mode.
- Circuit breaker for extreme price movement.

Tasks:
1. Identify every contract/module that reads oracle values.
2. Add validation wrapper enforcing staleness + deviation limits.
3. Add simulation tests for flash-spike, stale feed, and feed outage.
4. Ensure fail mode is deterministic (pause/reject) rather than
   partially executing risky actions.

Constraints:
- Do not relax collateral requirements to make tests pass.
- Keep guardrail constants in governance-controlled config.
- Stop with TRIAGE.md if no reliable fallback oracle exists.
~~~

## Output contract

- Reviewer-ready PR routing oracle reads through validated wrappers with
  staleness, deviation, fallback, and circuit-breaker behavior.
- Tests or simulations for flash spikes, stale feeds, feed outage, thin
  liquidity, fallback mismatch, and paused/rejected execution.
- Operator/auditor notes describing guardrail constants, governance ownership,
  fallback assumptions, monitored events, and any unsupported assets.
- `TRIAGE.md` when reliable fallback sources, governance authority, or oracle
  deployment ownership is outside this repository.

## Verification - what the reviewer looks for

- Risky execution paths cannot consume stale, missing, manipulated, or
  unsupported oracle values without deterministic rejection or pause.
- Guardrail thresholds live in reviewable configuration with clear governance
  ownership, not scattered magic numbers.
- Negative tests hit liquidation/borrow/swap/vault paths that actually consume
  oracle data, not only standalone helpers.
- Events or telemetry provide non-secret evidence when oracle guardrails reject
  execution.

## Related recipes

- [ERC-4626 vault inflation and rounding guardrails]({{< relref "/recipes/general/crypto-defi/erc4626-vault-inflation-and-rounding-guardrails" >}})
- [Cross-chain message authenticity guardrails]({{< relref "/recipes/general/crypto-defi/cross-chain-message-authenticity-guardrails" >}})
- [Source code supply-chain build integrity audit]({{< relref "/recipes/general/source-code-supply-chain-build-integrity-audit" >}})
