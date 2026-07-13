---
title: "DEX slippage and MEV guardrails"
linkTitle: "DEX slippage and MEV guardrails"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "dex", "slippage", "mev", "front-running"]
weight: 32
date: 2026-06-14
---

Use this prompt to harden swaps, liquidations, rebalances, and routing
flows against missing slippage checks and predictable-ordering risk.

## When to use it

Use this recipe when contracts, bots, keepers, or backend services execute DEX
swaps, AMM routes, aggregator calls, liquidations, rebalances, zaps, vault
deposits, or strategy trades. It is especially relevant when execution bounds
are zero, static, optional, UI-only, stale, or not enforced on-chain.

Use it to add slippage, deadline, quote-freshness, price-impact, and ordering
guardrails. Do not use it to paper over missing execution bounds with a
hardcoded `amountOutMin = 0` placeholder or frontend-only setting.

## Inputs

- Smart contracts, keeper code, bots, backend route builders, liquidation
  scripts, rebalance scripts, vault adapters, router integrations, aggregator
  calls, deployment config, and runbooks.
- Route parameters such as `amountOutMin`, `minShares`, `maxAmountIn`,
  deadlines, quote IDs, TWAP windows, oracle checks, path selection, partial
  fill behavior, and private-orderflow settings.
- On-chain and off-chain quote sources, oracle feeds, pre-trade simulations,
  mempool/orderflow assumptions, keeper permissions, and transaction submission
  paths.
- Existing tests, fuzz/invariant coverage, fork tests, slippage settings,
  sandwich/MEV findings, audit reports, and production incident notes.
- Monitoring and event data for quoted amount, bounded amount, executed route,
  realized output/input, deadline rejection, and price-impact rejection.

## Research basis

- [OWASP SCWE-090: Missing Slippage Protection](https://scs.owasp.org/SCWE/SCSVS-CODE/SCWE-090/) warns that zero or static `amountOutMin` values disable execution protection.
- [OWASP SCWE-142: MEV and Transaction Ordering Dependence](https://scs.owasp.org/SCWE/SCSVS-GOV/SCWE-142/) recommends private mempools, commit-reveal, slippage and deadline parameters, batch auctions, or fair-ordering mechanisms where appropriate.
- [Uniswap V3 swapping guide](https://developers.uniswap.org/docs/protocols/v3/guides/swapping/single-hop-swapping) calls out zero `amountOutMinimum` as a significant production risk.

## Use when

- Code calls DEX routers, aggregators, AMMs, or liquidation routes.
- `amountOutMin`, `minShares`, `maxAmountIn`, or deadlines are zero,
  static, optional, or controlled only by the UI.
- Trades can be sandwiched, backrun, or executed against stale quotes.
- Automated strategies rebalance or liquidate based on public mempool
  transactions.

## Prompt

~~~markdown
You are a DEX execution and MEV guardrail remediation agent.

Goal: prevent bad execution caused by missing slippage checks, stale
quotes, and predictable transaction ordering. Output PR or TRIAGE.md.

Controls to implement:
- Require caller-provided minimum output, maximum input, minimum shares,
  or equivalent execution bounds.
- Enforce deadlines or block-validity windows on user and automated
  trades.
- Derive default bounds from live quotes, TWAPs, oracle checks, or
  pre-trade simulation where the protocol owns execution.
- Use private orderflow, commit-reveal, batch execution, auctions, or
  fair-ordering design where public ordering creates material loss.
- Emit events for executed route, quoted amount, bounded amount, and
  realized amount.

Tasks:
1. Inventory every swap, route, liquidation, rebalance, zap, and
   aggregator call.
2. Replace zero or static slippage bounds with required parameters or
   protocol-computed limits.
3. Add stale-quote, deadline, and price-impact rejection checks.
4. Add tests for sandwich-style price movement, volatile pool reserves,
   stale quote reuse, and unfavorable partial fills.
5. Add runbook notes for routes that must use private mempools or batch
   settlement to reduce ordering exposure.

Constraints:
- Do not hardcode `amountOutMin = 0` or equivalent placeholders in
  production paths.
- Do not rely only on frontend slippage controls if contracts can be
  called directly.
- Stop with TRIAGE.md if the code cannot access a reliable quote,
  oracle, or user-supplied bound for a value-moving route.
~~~

## Output contract

Return one of:

- A reviewer-ready PR/change request that inventories every value-moving route,
  replaces zero/static bounds with required or protocol-computed limits,
  enforces deadlines and quote freshness, rejects excessive price impact, adds
  sandwich/stale-quote/unfavorable-fill tests, emits execution evidence events,
  and documents private-orderflow or batch-settlement requirements.
- `TRIAGE.md` when the repository does not own the execution path or cannot
  access a reliable quote, oracle, pre-trade simulation, or user-supplied bound
  for a value-moving route.

The output must list each route reviewed, old and new execution bounds,
deadline/freshness policy, quote or oracle source, tests added, monitoring
events added, and residual MEV/orderflow risk. It must not leave production
paths with zero bounds, rely only on frontend controls, or introduce stale
off-chain quotes without a rejection window.

## Related recipes

- [DeFi oracle manipulation guardrails]({{< relref "/recipes/general/crypto-defi/defi-oracle-manipulation-guardrails" >}})
- [DeFi reentrancy and callback hardening]({{< relref "/recipes/general/crypto-defi/defi-reentrancy-and-callback-hardening" >}})
- [ERC-4626 vault inflation and rounding guardrails]({{< relref "/recipes/general/crypto-defi/erc4626-vault-inflation-and-rounding-guardrails" >}})
