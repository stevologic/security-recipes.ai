---
title: "ERC-4626 vault inflation and rounding guardrails"
linkTitle: "ERC-4626 inflation guardrails"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "erc4626", "vault", "rounding", "invariants"]
weight: 29
date: 2026-06-14
---

Use this prompt to harden ERC-4626 vaults and vault-like share systems
against first-depositor inflation, donation attacks, and unsafe rounding.

## Research basis

- [OpenZeppelin ERC-4626 documentation](https://docs.openzeppelin.com/contracts/4.x/erc4626) explains how direct asset donations can shift the exchange rate and cause small deposits to mint zero or too few shares.
- [OpenZeppelin: A novel defense against ERC4626 inflation attacks](https://www.openzeppelin.com/news/a-novel-defense-against-erc4626-inflation-attacks) compares mitigations such as routers, internal asset accounting, virtual shares/assets, and dead shares.
- [OWASP SC07: Arithmetic Errors](https://scs.owasp.org/sctop10/SC07-ArithmeticErrors/) recommends documenting rounding behavior and proving repeated interactions cannot create free value.

## Use when

- A vault mints shares from deposited assets or redeems assets from
  shares.
- The first deposit can be front-run by a tiny deposit plus a direct
  donation.
- Rounding may mint zero shares, leak value, or favor an attacker over
  repeated deposits and withdrawals.
- `totalAssets`, share supply, or conversion math is custom.

## Prompt

~~~markdown
You are an ERC-4626 and vault-accounting remediation agent.

Goal: prevent vault inflation, unsafe rounding, and accounting drift in
share-based deposit and redemption flows. Output PR or TRIAGE.md.

Controls to implement:
- Add virtual assets/shares, decimal offset, internal total-asset
  accounting, seed liquidity, or another explicit inflation defense.
- Reject deposits that would mint zero shares or violate caller-provided
  minimum-share expectations.
- Make rounding direction explicit for deposit, mint, withdraw, and
  redeem paths.
- Keep direct donations from creating profitable share-price
  manipulation.
- Add invariant and fuzz tests for first-depositor and repeated-rounding
  scenarios.

Tasks:
1. Identify all asset-to-share and share-to-asset conversion functions.
2. Model first-depositor front-running with a tiny deposit, direct
   donation, victim deposit, and attacker withdrawal.
3. Patch conversion math or accounting so the attack is unprofitable and
   small deposits cannot be silently donated.
4. Add user-facing slippage or minimum-share parameters where callers
   need execution protection.
5. Add invariants proving total value cannot be created through
   donations, rounding loops, or deposit/redeem cycling.

Constraints:
- Do not rely only on UI warnings or off-chain sequencing.
- Do not change rounding in one function without checking the inverse
  operation and all preview functions.
- Stop with TRIAGE.md if the protocol intentionally accepts donations
  into share price and cannot distinguish them from managed yield.
~~~
