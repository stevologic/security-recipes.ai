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
