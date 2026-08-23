# Security Recipes Health Check action

One action that grounds an LLM in [security-recipes.ai](https://security-recipes.ai)
guidance — fetched live from the hosted MCP server — and evaluates your
repository's security health as CI checks. Every check is a boolean toggle;
disabled checks stay visible in the job summary so the gaps are never silent.

```yaml
jobs:
  security-health:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: stevologic/security-recipes.ai/actions/security-health@main
        with:
          provider: openai            # anthropic | openai | xai | ollama
          api-key: ${{ secrets.OPENAI_API_KEY }}
          check-containers: true      # opt in beyond the defaults
```

## Checks

| Toggle | Default | Grounded in |
| --- | --- | --- |
| `check-dependencies` | on | [Vulnerable dependencies](https://security-recipes.ai/security-remediation/vulnerable-dependencies/) |
| `check-secrets` | on | [Secrets and data exposure audit](https://security-recipes.ai/recipes/general/source-code-secrets-data-exposure-audit/) |
| `check-injection` | on | [Injection sink audit](https://security-recipes.ai/recipes/general/source-code-injection-sink-audit/) |
| `check-supply-chain` | on | [Supply chain build integrity audit](https://security-recipes.ai/recipes/general/source-code-supply-chain-build-integrity-audit/) |
| `check-authz` | off | [Authorization and tenant boundary audit](https://security-recipes.ai/recipes/general/source-code-authz-tenant-boundary-audit/) |
| `check-containers` | off | [Base image hygiene](https://security-recipes.ai/recipes/general/base-image-bump/) |
| `check-owasp` | off | [OWASP Top 10 audit](https://security-recipes.ai/recipes/general/owasp-top-10-2025-audit/) |
| `check-cve-exposure` | off | [CVE intelligence intake gate](https://security-recipes.ai/recipes/general/cve-intelligence-intake-gate/) |
| `check-compliance` | off | [Compliance standards](https://security-recipes.ai/recipes/general/compliance-standards/) |

## Models

Pick `provider` and optionally `model`. When `model` is empty the action
queries the provider's live model list and selects the **lowest available**
model (Ollama picks the smallest installed model by byte size), so the check
stays cheap by default. `base-url` points `ollama` — or any
OpenAI-compatible endpoint — at your own server.

## Behavior

- Recipe context comes from the hosted MCP server at
  `https://security-recipes.ai/mcp` (JSON-RPC over streamable HTTP), with an
  automatic fallback to the static `api/recipes.json` feed.
- Evidence is bounded: the action samples manifests, workflows, container
  files, and source excerpts deterministically and never uploads more than a
  few dozen kilobytes per check.
- Verdicts are strict JSON (`pass` / `warn` / `fail` with findings); the job
  fails on any failing enabled check (`fail-on: warn` tightens it,
  `fail-on: never` reports only).
- The job summary lists every check — including the ones you have not
  enabled — so CI always shows remaining coverage.
- The LLM judges only the excerpts it is shown. Treat results as a bounded
  review gate, not a proof of security; the site's
  [evaluation guidance](https://security-recipes.ai/agents/#evaluate-an-agent-before-broader-rollout)
  applies.
