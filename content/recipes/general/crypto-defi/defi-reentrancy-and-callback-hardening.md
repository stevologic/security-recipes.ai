---
title: "DeFi reentrancy and callback hardening"
linkTitle: "Reentrancy and callback hardening"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "smart-contract", "reentrancy", "callbacks", "invariants"]
weight: 27
date: 2026-06-14
---

Use this prompt to harden DeFi contracts that make external calls,
transfer tokens, or rely on callback-capable standards.

## When to use it

Use this recipe when contracts send ETH, call unknown contracts, integrate with
routers, vaults, token receivers, bridges, ERC-777 hooks, ERC-4626 flows, plugin
systems, or any callback-capable standard. It is also useful when multiple
entry points mutate shared balances, shares, debt, rewards, reserves, or
liquidation state.

Use it to remove exploitable reentrancy, unchecked external-call assumptions,
and callback-driven accounting drift. Do not use it as a one-function guard
when the same accounting can be reached through another public path.

## Inputs

- Solidity/Vyper contracts, interfaces, external-call wrappers, token adapters,
  router integrations, vault adapters, bridge handlers, liquidation paths,
  reward contracts, and receiver/callback implementations.
- All value-moving entry points: deposit, withdraw, redeem, mint, borrow,
  repay, liquidate, claim, rebalance, harvest, flash-loan, swap, bridge, and
  rescue flows.
- Shared accounting state: balances, shares, reserves, debt, collateral,
  pending rewards, cumulative indexes, nonce/permit state, caps, and
  per-account snapshots.
- Existing unit tests, fuzz tests, invariant tests, malicious receiver fixtures,
  static-analysis findings, audit reports, and deployment constraints.
- External trust assumptions for tokens, routers, aggregators, callbacks,
  plugins, receivers, or downstream protocols that can execute code during the
  transaction.

## Research basis

- [OWASP SC08: Reentrancy Attacks](https://scs.owasp.org/sctop10/SC08-ReentrancyAttacks/) highlights stale-state exploits caused by external calls that can re-enter before the original invocation is complete.
- [OWASP SC06: Unchecked External Calls](https://scs.owasp.org/sctop10/SC06-UncheckedExternalCalls/) recommends treating external calls as untrusted, checking return values, and favoring pull-based flows.

## Use when

- Contracts send ETH, call unknown contracts, or use low-level `call`.
- Token flows involve ERC-777 hooks, ERC-4626 hooks, receivers,
  callbacks, or plugin-style integrations.
- Shared accounting can be touched by multiple public entry points.
- Tests do not include nested-call or cross-function reentrancy cases.

## Prompt

~~~markdown
You are a DeFi security remediation agent hardening reentrancy and
callback boundaries.

Goal: remove exploitable reentrancy, unchecked call assumptions, and
callback-driven accounting drift. Output PR or TRIAGE.md.

Controls to implement:
- Apply checks-effects-interactions to every value-moving path.
- Add scoped non-reentrant guards to sensitive entry points and
  cross-function shared-state paths.
- Prefer pull withdrawals over push transfers for untrusted recipients.
- Check low-level call results and token transfer return behavior.
- Treat token hooks, vault callbacks, receiver callbacks, and routers as
  untrusted external execution.

Tasks:
1. Inventory all external calls, token transfers, and callback-capable
   integrations.
2. Map shared balances, shares, debt, rewards, and reserves that can be
   mutated across multiple entry points.
3. Move state updates before external calls, or isolate the external
   call behind a post-state pull pattern.
4. Add tests for same-function, cross-function, and multi-contract
   reentrancy using malicious receivers or hook-enabled tokens.
5. Add invariants proving no nested call can withdraw, mint, redeem,
   borrow, liquidate, or claim more value than allowed.

Constraints:
- Do not silence a reentrancy finding only by adding a guard to one
  function if another entry point touches the same accounting.
- Do not switch to `transfer` or hardcoded gas assumptions as the sole
  mitigation.
- Stop with TRIAGE.md if an external dependency requires trusted
  callback behavior that cannot be constrained in this codebase.
~~~

## Output contract

Return one of:

- A reviewer-ready PR/change request that maps external calls and shared
  accounting, moves state updates before untrusted calls or converts them to
  pull flows, adds scoped non-reentrant protection across shared-state paths,
  checks low-level call and token-transfer results, adds malicious-callback
  tests and invariants, and documents remaining trusted-callback assumptions.
- `TRIAGE.md` when the repository does not own the value-moving code or an
  external dependency requires unconstrained callback behavior that cannot be
  remediated in this codebase.

The output must list each external call/callback path, the shared state it can
mutate, the mitigation applied, same-function and cross-function tests added,
invariants added, and residual dependencies that still require review. It must
not rely only on frontend controls, gas-stipend assumptions, or a guard on one
function while another path reaches the same accounting.

## Related recipes

- [ERC-4626 vault inflation and rounding guardrails]({{< relref "/recipes/general/crypto-defi/erc4626-vault-inflation-and-rounding-guardrails" >}})
- [DEX slippage and MEV guardrails]({{< relref "/recipes/general/crypto-defi/dex-slippage-and-mev-guardrails" >}})
- [Cross-chain message authenticity guardrails]({{< relref "/recipes/general/crypto-defi/cross-chain-message-authenticity-guardrails" >}})
