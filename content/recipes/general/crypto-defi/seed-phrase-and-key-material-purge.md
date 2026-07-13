---
title: "Seed phrase and key-material purge"
linkTitle: "Seed/key material purge"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["crypto", "secrets", "seed-phrase", "private-key", "incident-response"]
weight: 23
date: 2026-04-26
---

Use this prompt to locate and remove exposed wallet seed phrases,
private keys, and signing credentials from code and operational systems.

## When to use it

- A scan found possible BIP-39 mnemonics or private keys.
- Secrets appeared in logs, tickets, or CI output.
- Key rotation and chain migration runbooks are needed.

## Inputs

- Finding id, detector output, affected file/log/ticket locations, and
  first-seen evidence.
- Secret class, chain or wallet context, custody system, owner, and
  rotation authority.
- Approved redaction, placeholder, test-vector, and secret-scanning rules.
- Incident ticket, disclosure requirements, and balance-migration runbook.

## Prompt

~~~markdown
You are a security remediation agent handling exposed crypto key material.

Goal: eradicate exposed key material and stage rotation actions.
Output either:
- PR + incident audit note, or
- TRIAGE.md when privileged rotation steps are blocked.

Tasks:
1. Search repository and generated artifacts for candidate seed phrases,
   private keys, and keystore passphrases using approved detectors.
2. Remove exposures from source, examples, docs, tests, and fixtures.
3. Replace with redacted placeholders and safe test vectors.
4. Add pre-commit/CI secret detection rules tuned for crypto material.
5. Draft rotation checklist: revoke old keys, rotate signer identities,
   migrate remaining balances, and verify post-rotation health.

Constraints:
- Never print full secret values in output.
- Keep only minimal fingerprint/hash for audit correlation.
- If active key rotation requires production privileges, stop and write
  TRIAGE.md with explicit human steps.
~~~

## Output contract

- PR removing exposed key material from source, docs, tests, examples, and
  generated artifacts.
- Scanner or pre-commit rule update that prevents recurrence.
- Incident audit note with minimal fingerprints, affected locations,
  rotation owner, and remaining human actions.
- `TRIAGE.md` when production rotation, chain migration, or history
  rewriting requires a privileged human runbook.

## Verification

- Run the approved secret scanners over the repository and generated
  artifacts after remediation.
- Confirm outputs include only hashes or minimal fingerprints, never full
  key material.
- Verify safe test vectors replace real-looking private keys and seed
  phrases in fixtures.

## Guardrails

- Do not print, copy, or transform full seed phrases, private keys, or
  keystore passphrases into logs, commit messages, prompts, or PR bodies.
- Do not rewrite shared git history or rotate production keys from this
  recipe run.
- Stop if ownership, custody workflow, or rotation authority is missing.

## Related recipes

- [Sensitive data remediation]({{< relref "/recipes/github_copilot/sensitive-data-remediation" >}})
- [Hot-wallet policy enforcement]({{< relref "/recipes/general/crypto-defi/hot-wallet-transaction-policy-enforcement" >}})
- [Compromised package cache quarantine]({{< relref "/recipes/general/compromised-package-cache-quarantine" >}})
