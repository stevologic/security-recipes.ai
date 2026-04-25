---
title: "JWT — `alg: none` and algorithm confusion"
linkTitle: "JWT alg none"
description: "Force an explicit algorithm allowlist on every verify call; reject `none` at the import boundary."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["jwt", "auth", "uplift", "mitigate"]
weight: 25
date: 2026-04-25
---

JWTs are validated against an `alg` field the *token itself*
declares. The spec includes `none` (for "validation skipped");
some libraries used to honour it; some still do under specific
configurations. A second class of bug — the RS256 → HS256
algorithm-confusion attack — happens when an HMAC-verifier uses
the public RSA key as the HMAC secret because the token says
`alg: HS256`.

The robust shape is the same in both cases: never trust the
`alg` field. Decide the expected algorithm on the verifier
side and refuse anything else.

## Pattern

- `jwt.decode(token, key)` (PyJWT pre-2.0) without an
  `algorithms=[...]` argument.
- `jsonwebtoken.verify(token, secret)` (Node.js) without
  `{ algorithms: [...] }`.
- `JWT.decode(token, key)` (Ruby) without explicit
  `algorithm`.
- `Jwts.parser().setSigningKey(key).parseClaimsJws(token)`
  (Java jjwt 0.10–) without
  `.parseClaimsJws()` / `.parserBuilder().setSigningKey(...)`
  with explicit algorithm verification.
- Any custom verifier that reads `header.alg` and dispatches.

## Why it matters

A token with `alg: none` and an empty signature is valid in any
library that honours the field — the attacker forges any claim
they like. RS256-to-HS256 confusion is subtler: the attacker
takes the server's public RSA key (often published in a JWKS),
signs an HMAC with it, sets `alg: HS256`, and the verifier (if
naive) treats the public key as the HMAC secret and accepts.

## Mitigation — algorithm allowlist + import-time monkey patch

For codebases with many call sites, add a wrapper that refuses
to call any underlying JWT verifier without an explicit
algorithm allowlist:

```python
# Python (PyJWT)
import jwt
import os

_orig_decode = jwt.decode

def _safe_decode(token, key, algorithms=None, **kw):
    if not algorithms:
        raise jwt.InvalidAlgorithmError(
            "JWT verify requires an explicit algorithms allowlist"
        )
    if "none" in [a.lower() for a in algorithms]:
        raise jwt.InvalidAlgorithmError("JWT alg=none is forbidden")
    return _orig_decode(token, key, algorithms=algorithms, **kw)

jwt.decode = _safe_decode
```

Equivalent shims exist for `jsonwebtoken` (Node) and
`jwt-ruby`. Install at the application's entry point.

## Uplift — explicit algorithm allowlist at every call

The clean fix:

```python
payload = jwt.decode(
    token,
    key,
    algorithms=["RS256"],   # exactly one, named
    audience="myapi",
    issuer="https://idp.example",
    options={"require": ["exp", "iat", "aud", "iss", "sub"]},
)
```

Single algorithm, named. Plus require expected claims. Plus
verify `aud` and `iss` against the application's expected
values.

## Inputs

- **Call sites** — every JWT verify call.
- **Algorithm policy** — which algorithm(s) the application
  legitimately uses.
- **Required claims** — which claims must be present.

## The prompt

~~~markdown
You are remediating JWT verification call sites. Output a PR
or a TRIAGE.md.

## Step 0 — Inventory

1. List every JWT verification call across the repo.
2. For each, record: the library and version, the current
   algorithm argument (if any), the key source (HMAC secret
   vs. RSA/EC public key vs. JWKS endpoint), and the claim
   expectations.
3. Read the application's auth design docs (if available) to
   learn the legitimate algorithm.

## Step 1 — Pick the strategy

- Always uplift (explicit allowlist on every call).
- If there are >5 call sites, also install the import-time
  shim as defence-in-depth.

## Step 2 — Uplift each call

For each verify call, change to:

- `algorithms=["<expected-alg>"]` — exactly one, named.
- Verify `aud` against the application's expected audience.
- Verify `iss` against the application's expected issuer.
- Require `exp`, `iat`, and any other application-required
  claims.

## Step 3 — Install the shim (when chosen)

1. Add the wrapper module at a stable import path.
2. Import it from every application entry point.
3. Add a unit test that calls `jwt.decode` without an
   `algorithms` argument and asserts the wrapper rejects.

## Step 4 — Tests

Add tests:

- A token signed with the wrong algorithm is rejected.
- A token with `alg: none` is rejected.
- A token with `alg: HS256` and the public RSA key as the
  "secret" is rejected.
- A token with `alg: <expected>` and the right key but wrong
  `aud` is rejected.
- A valid token is accepted.

## Step 5 — Open the PR

- Branch: `remediate/jwt-alg-allowlist-<short-slug>`.
- Title: `[Security][jwt] enforce algorithm allowlist on every verify`.
- Body: call-site inventory, algorithm chosen per call, shim
  installation, test additions, and a follow-up checklist for
  any service whose tokens did not declare a single
  algorithm.
- Label: `sec-auto-remediation`.

## Stop conditions

- A service legitimately accepts multiple algorithms (e.g.,
  during a key-rotation window). Confirm with the auth team
  before allowlisting both; do not silently widen the
  allowlist.
- The verification path uses a custom signature implementation
  the agent cannot reason about safely.
- Tests on unrelated code break in ways the agent cannot
  resolve without touching auth logic.

## Scope

- Do not change token *issuance*. This recipe is for
  verifiers.
- Do not change key material.
- Do not bundle unrelated auth refactors.
~~~

## Watch for

- **Multi-algorithm services during key rotation.** During
  rotation, allowlists may legitimately include both old and
  new. Document the window and remove the old algorithm on
  schedule.
- **JWKS keys with `alg` unset.** Some IdPs ship JWKS without
  `alg`; the verifier *must* enforce the expected algorithm
  even when JWKS doesn't constrain it.
- **`kid` confusion.** A token can name a JWKS key id; if the
  verifier trusts the `kid` to pick the algorithm, you've
  re-introduced algorithm confusion through the back door.
  Decide the algorithm on the server, not the token.
- **`exp` without skew.** Refusing tokens for sub-second
  clock skew is an availability bug. Allow a small skew
  (e.g., 60 seconds) — but no more.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [OWASP Top 10 (2026) → A07 Authentication Failures]({{< relref "/prompt-library/general/owasp-top-10-2026-remediate" >}})
  — broader auth-failure pattern.
