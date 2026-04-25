---
title: "Disabled TLS verification — `verify=False` and friends"
linkTitle: "Disabled TLS verification"
description: "Install the right CA bundle; add a fail-closed shim that refuses `verify=False` outside an opt-in test environment."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["tls", "http-client", "uplift", "mitigate"]
weight: 27
date: 2026-04-25
---

`requests.get(url, verify=False)` is the line of Python that
disables TLS certificate verification. It's also one of the
most-copy-pasted lines on Stack Overflow. Equivalent lines exist
in every language's HTTP client. Each of them transforms a
secure channel into a man-in-the-middleable one. There is no
patch coming; the fix is "stop disabling verification, configure
the client correctly."

## Pattern

- **Python.** `requests.get(url, verify=False)`,
  `urllib3.disable_warnings()`, `httpx.Client(verify=False)`,
  `aiohttp.ClientSession(connector=TCPConnector(ssl=False))`.
- **Node.** `https.Agent({ rejectUnauthorized: false })`,
  `axios.create({ httpsAgent: new https.Agent({...}) })`,
  `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"`.
- **Java.**
  `HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true)`,
  `SSLContext` with a trust-all `TrustManager`.
- **Go.** `&tls.Config{InsecureSkipVerify: true}`.
- **curl.** `--insecure` / `-k` baked into shell scripts and
  CI steps.
- **Environment overrides.** `PYTHONHTTPSVERIFY=0`,
  `GIT_SSL_NO_VERIFY=true`, `HTTPS_PROXY` pointing to a proxy
  with cert-stripping.

## Why it matters

Disabled verification means an attacker on the network path
can substitute their own certificate, decrypt the traffic, and
re-encrypt to the real endpoint. The application sees a normal
response. Credentials, tokens, and personal data flow in the
clear to the attacker. The CVE shelf is not where this lives;
it lives in incident reports.

## Mitigation — fail-closed monkey patch

For the cases where the codebase has many `verify=False` calls
and a coordinated cleanup is impractical, install an
import-time shim that refuses to honour `verify=False` outside
of an opt-in test environment:

```python
# Python
import os, requests, ssl, warnings

if os.environ.get("ENV") not in ("dev-local", "test"):
    _orig_request = requests.Session.request

    def _safe_request(self, method, url, *, verify=True, **kw):
        if verify is False:
            raise ssl.SSLError(
                f"TLS verification is required (request to {url})"
            )
        return _orig_request(self, method, url, verify=verify, **kw)

    requests.Session.request = _safe_request
```

Equivalent shims exist for `httpx`, `aiohttp`, the Node
`https` module, and Java's `SSLContext` factories. Install at
the application's entry point.

## Uplift — configure the trust store correctly

Most `verify=False` calls are present because the developer
hit a TLS error and disabling was the fastest fix. The right
fix:

- **Self-signed cert in dev / staging:** install the cert into
  the system trust store, or pass `verify="/path/to/ca-bundle"`.
- **Internal CA:** install the org's CA into the application's
  trust bundle (`certifi`-merged in Python, `truststore` for
  system trust, JVM `cacerts` for Java).
- **Cert pinning:** use the framework's pinning API rather than
  disabling verification. `urllib3` exposes `assert_fingerprint`;
  Java has pin-based `TrustManager` patterns.
- **Proxy with TLS interception:** point the application at the
  org's TLS-intercepting proxy *with* the proxy's CA installed
  in the trust store. Don't disable verification just because
  the proxy is in the path.

## Inputs

- **Call sites** — every disabled-TLS call.
- **Reason classification** — why was verification disabled at
  each site?

## The prompt

~~~markdown
You are remediating disabled-TLS-verification call sites.
Output a PR or a TRIAGE.md.

## Step 0 — Inventory

1. Grep for `verify=False`, `verify = False`,
   `rejectUnauthorized: false`, `InsecureSkipVerify: true`,
   `HostnameVerifier((h,s)->true)`, `setDefaultHostnameVerifier`,
   `TrustManager` overrides, `--insecure` / `-k` curl flags,
   and the env-var overrides listed in the recipe.
2. For each call site, classify the reason: self-signed cert
   in dev, internal CA missing, broken cert chain, proxy in
   path, or unknown.

## Step 1 — Pick the strategy per call site

- **Self-signed dev cert / internal CA:** uplift — install
  the CA into the application's trust bundle.
- **Broken cert chain:** uplift — fix the chain (intermediate
  cert missing).
- **Proxy in path:** uplift — install the proxy's CA into the
  trust store; do not disable verification.
- **Unknown:** triage.

## Step 2 — Uplift

For each call site, do the language-appropriate fix:

- **Python:** pass `verify="/path/to/ca-bundle"` or
  `verify=True` with the CA installed via `certifi.where()`
  + a startup script that merges in the org CA.
- **Node:** load the CA via `tls.createSecureContext({ ca:
  ... })` and pass that as the agent's secure context.
- **Java:** load the CA into the JVM `cacerts` keystore (or
  application-specific keystore) and remove trust-all
  TrustManagers.
- **Go:** populate `RootCAs` on the TLS config; remove
  `InsecureSkipVerify`.
- **curl:** install the CA via `--cacert` or set
  `CURL_CA_BUNDLE`; remove `--insecure`.

## Step 3 — Install the fail-closed shim (when chosen)

For codebases with many call sites, install the import-time
shim at the application entry point. The shim should:

1. Allow `verify=False` only when an explicit
   `ENV=dev-local` (or equivalent) environment variable is
   set.
2. Otherwise raise `SSLError` immediately.
3. Log every shim activation so test environments are
   visible in audit.

## Step 4 — Tests

Add tests:

- A request to a server with a valid certificate succeeds.
- A request to a server with a self-signed certificate (in
  test env) succeeds *only* when an explicit `verify=...`
  argument names that cert.
- In a non-test environment, a `verify=False` call raises.

## Step 5 — Open the PR

- Branch: `remediate/tls-verify-<module-slug>`.
- Title: `[Security][TLS] re-enable verification across <module>`.
- Body: call-site inventory, reason per site, uplift chosen,
  shim installation, test additions.
- Label: `sec-auto-remediation`.

## Stop conditions

- A genuinely insecure-by-design integration (e.g., a legacy
  partner endpoint that has no valid cert and cannot get one).
  Do not auto-disable verification — flag and triage; the
  right path is a network-isolated proxy.
- The reason a site disabled verification cannot be
  classified.
- A test infrastructure depends on `verify=False` and the
  agent cannot reshape it without touching test infra.

## Scope

- Do not modify CI test infrastructure.
- Do not bundle unrelated refactors.
- Do not silently widen the shim's "allowed in dev" scope.
~~~

## Watch for

- **`urllib3.disable_warnings`.** Often paired with
  `verify=False`. Removing the warning suppression doesn't fix
  the bug; the warnings exist *because* the bug exists.
- **`NODE_TLS_REJECT_UNAUTHORIZED=0` baked into Dockerfiles.**
  Easy to miss when reviewing application code.
- **`GIT_SSL_NO_VERIFY=true`** baked into CI to clone
  internal git over a self-signed proxy. Same fix: install the
  proxy's CA, don't disable verification.
- **Trust-all `TrustManager` registered globally** in older
  Java apps — affects every HTTPS call in the JVM. The shim
  has to override the registration, not just the call sites.
- **TLS pin churn.** Pinning is a strong control but a deploy
  burden. Don't pin without a documented rotation playbook.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [OWASP Top 10 (2026) → A02 Cryptographic Failures]({{< relref "/prompt-library/general/owasp-top-10-2026-remediate" >}})
  — broader crypto-failure pattern.
