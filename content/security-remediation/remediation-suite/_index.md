---
title: Python Remediation Suite
linkTitle: Python Remediation Suite
weight: -10
sidebar:
  open: true
description: >
  Domain-specific Python tools for planning security-recipes.ai remediation
  work across SCA, SAST, sensitive data, containers, cache purge, reviews,
  runtime controls, metrics, rollout, and audit.
---

The Python remediation suite turns each remediation section into a concrete
tool command. It does not replace scanners, ticketing systems, source control,
or human reviewers. It creates the bounded packet an agent or orchestrator needs
before work starts:

- the selected remediation domain,
- imported recipes from this site,
- enterprise tooling compatibility notes,
- allowed actions,
- stop conditions,
- evidence requirements,
- an agent handoff prompt,
- optional LLM-assist configuration.

<figure class="sr-suite-figure">
  <img src="/images/remediation-suite/suite-flow.svg" alt="Flow from finding to a domain-specific Python remediation tool, imported recipes and optional LLM help, then a PR handoff, triage note, evidence packet, or audit record." loading="lazy">
  <figcaption>The suite keeps one finding, one domain tool, one recipe-informed output, and human review.</figcaption>
</figure>

## Dashboard container and UI

The suite now ships with a browser workbench that sits on top of the same
Python planner. The UI lets an operator:

- choose a remediation domain;
- paste free-text, JSON, or SARIF findings;
- configure recipe source, tooling hints, ecosystem, and LLM mode;
- save non-secret access and context notes inside a mounted state directory;
- generate a remediation packet and inspect the JSON plus agent handoff prompt;
- download the latest packet for CI, SOAR, ticketing, or agent handoff.

Build the dashboard image from this repo:

```bash
docker build -f Dockerfile.remediation-suite-ui -t security-recipes-suite-ui .
```

Run it:

```bash
docker run --rm -p 8787:8787 \
  -v "$(pwd)/tmp/remediation-suite-ui:/data" \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  security-recipes-suite-ui
```

Open <http://localhost:8787>. The container starts:

```bash
python scripts/security_recipes_remediation_suite.py serve-dashboard \
  --host 0.0.0.0 \
  --port 8787 \
  --state-dir /data
```

Useful runtime environment variables:

| Variable | Purpose |
| --- | --- |
| `SECURITY_RECIPES_DASHBOARD_HOST` | Bind host for the web server. |
| `SECURITY_RECIPES_DASHBOARD_PORT` | Port exposed by the UI, default `8787`. |
| `SECURITY_RECIPES_DASHBOARD_STATE_DIR` | Directory for persisted non-secret dashboard configuration. |
| `OPENAI_API_KEY` | Example API key used when the UI is set to `llm-mode call` with `OPENAI_API_KEY` as the configured env var. |

Health endpoint:

```text
GET /api/health
```

## Install from this repo

The suite uses the Python standard library. From a checkout of
`security-recipes.ai`:

```bash
python scripts/security_recipes_remediation_suite.py list-domains
```

Start the local dashboard without Docker:

```bash
python scripts/security_recipes_remediation_suite.py serve-dashboard
```

Run a domain-specific tool:

```bash
python scripts/security_recipes_remediation_suite.py deps \
  --finding dependabot-alert.json \
  --recipes-source public/api/recipes.json \
  --tooling github,snyk,jira \
  --ecosystem npm \
  --llm-mode prompt \
  --output out/deps-packet.json
```

The same suite works from CI, SOAR, a ticket webhook, a scheduled scanner job,
or an agent handoff. The command writes a JSON remediation packet by default.
Use `--finding -` to read a free-text, generic JSON, or SARIF finding from
standard input.

## Tool commands

| Section | Command | Best input |
| --- | --- | --- |
| Sensitive Data Element Remediation | `sde` | DLP, secret scanning, SDE JSON |
| Vulnerable Dependency Remediation | `deps` | CVE, GHSA, OSV, Dependabot, SCA, SBOM |
| SAST Finding Remediation | `sast` | SARIF, CodeQL, Semgrep, SonarQube, Snyk Code |
| Base Image and Container Layer Remediation | `base-image` | Trivy, Grype, container scanner, Dockerfile evidence |
| Artifact Cache and Mirror Quarantine | `cache-purge` | registry, mirror, cache, or malicious-artifact advisory |
| Recipe Recommender | `recommend` | any messy finding that needs routing first |
| Gatekeeping Patterns | `gate` | workflow, agent identity, policy, approval data |
| Runtime Controls | `runtime` | session, tool-call, proxy, egress, and telemetry data |
| Classic Vulnerable Defaults | `defaults` | unsafe parser, deserialization, XML, JWT, shell, TLS patterns |
| Crypto Payments Security | `crypto-payments` | wallet, address, settlement, custody, or payment-flow findings |
| DeFi and Blockchain Security | `defi` | smart contract, oracle, bridge, governance, or multisig findings |
| Program Metrics and KPIs | `metrics` | run records, PR data, scanner backlog, review metadata |
| Reviewer Playbook | `review` | PR diff, recipe id, run receipt, tests, scans |
| Rollout and Maturity Model | `rollout` | pilot state, controls, reviewer capacity, metrics |
| Compliance and Audit | `audit` | run receipt, approvals, control framework, evidence request |

You can also use the generic command:

```bash
python scripts/security_recipes_remediation_suite.py plan \
  --domain auto \
  --finding finding.sarif \
  --recipes-source https://security-recipes.ai/api/recipes.json
```

`--domain auto` scores the first finding against the domain registry and chooses
the strongest match. For production dispatch, prefer an explicit command when
the scanner already knows the finding class.

## Import recipes from the site

Every domain can import recipes from the built site or the public endpoint:

```bash
--recipes-source public/api/recipes.json
--recipes-source https://security-recipes.ai/api/recipes.json
```

Agents can also use the MCP server tools when the site is deployed with MCP:

- `recipes_search`
- `recipes_get`
- `recipes_match_finding`

The Python suite does not need MCP to run. It imports the same recipe corpus
through JSON so enterprise schedulers and security platforms can use it without
embedding a browser or a site-specific client.

## Optional LLM assist

LLM assist is opt-in and has three modes:

| Mode | Behavior |
| --- | --- |
| `off` | No model prompt or call is attached. |
| `prompt` | The packet includes the domain-specific prompt for another agent to use. |
| `call` | The suite calls an OpenAI-compatible chat completions endpoint using an API key from the configured environment variable. |

Example config:

```json
{
  "endpoint": "https://api.openai.com/v1/chat/completions",
  "model": "gpt-5.5",
  "api_key_env": "OPENAI_API_KEY",
  "temperature": 0.2,
  "timeout": 30
}
```

Run with:

```bash
python scripts/security_recipes_remediation_suite.py sast \
  --finding codeql.sarif \
  --recipes-source public/api/recipes.json \
  --llm-config llm.json \
  --llm-mode call
```

Use `prompt` mode first in regulated environments. It produces the model prompt
without transmitting data, which makes review and redaction easier.

## Packet anatomy

<figure class="sr-suite-figure">
  <img src="/images/remediation-suite/tool-packet.svg" alt="A remediation packet containing classification, imported recipes, enterprise tooling, workflow rules, optional LLM assist, and human-review output." loading="lazy">
  <figcaption>The JSON packet is the handoff contract between scanners, agents, reviewers, and audit systems.</figcaption>
</figure>

Each packet contains:

- `classification` - domain score and routing rationale.
- `findings` - normalized finding identity, source, severity, asset, location,
  and raw evidence.
- `recipe_import` - recipes matched from `/api/recipes.json`.
- `enterprise_tooling` - compatible source control, scanner, ticketing,
  registry, GRC, SIEM, or platform categories.
- `workflow` - inputs, allowed actions, stop conditions, evidence, and outputs.
- `agent_handoff` - a domain-specific prompt with guardrails.
- `llm_assist` - disabled, prompt-only, or configured model-call metadata.

## Enterprise integration pattern

```mermaid
flowchart LR
    A[Scanner or ticket] --> B[Python domain tool]
    B --> C[Import recipes JSON]
    B --> D[Normalize enterprise tooling]
    B --> E{Optional LLM?}
    E -->|off or prompt| F[Packet only]
    E -->|call| G[Configured LLM endpoint]
    F --> H[Agent runner]
    G --> H
    H --> I[PR handoff or TRIAGE.md]
    I --> J[Human review]
    J --> K[Audit evidence]

    classDef source fill:#0a2540,stroke:#00e5ff,color:#f5f7fb;
    classDef gate fill:#2a1040,stroke:#ff4ecb,color:#f5f7fb;
    classDef output fill:#1a2a1a,stroke:#86efac,color:#f5f7fb;
    class A,B,C,D source
    class E,G,J gate
    class F,H,I,K output
```

The integrations are intentionally broad:

- source control: GitHub, GitLab, Azure DevOps, Bitbucket;
- scanners: CodeQL, Semgrep, SonarQube, Snyk, Wiz, Trivy, Grype, OSV,
  Gitleaks, TruffleHog, Veracode, Checkmarx, Fortify;
- registries and artifact systems: Artifactory, Nexus, Harbor, ECR, ACR, GAR,
  Quay, npm, PyPI, Maven, NuGet;
- ticketing and response: Jira, Linear, ServiceNow, PagerDuty, SOAR;
- evidence and audit: Drata, Vanta, Secureframe, ServiceNow GRC, Archer,
  AuditBoard, SIEM and data warehouse exports.

The suite only shapes the packet. Connector credentials, write access,
approval policies, and production actions stay in the enterprise control plane.

## Domain reference

{{< remediation-tool domain="sensitive-data" >}}

{{< remediation-tool domain="vulnerable-dependencies" >}}

{{< remediation-tool domain="sast-findings" >}}

{{< remediation-tool domain="base-images" >}}

{{< remediation-tool domain="artifact-cache-purge" >}}

{{< remediation-tool domain="recipe-recommender" >}}

{{< remediation-tool domain="gatekeeping" >}}

{{< remediation-tool domain="runtime-controls" >}}

{{< remediation-tool domain="classic-vulnerable-defaults" >}}

{{< remediation-tool domain="crypto-payments" >}}

{{< remediation-tool domain="defi-blockchain" >}}

{{< remediation-tool domain="metrics" >}}

{{< remediation-tool domain="reviewer-playbook" >}}

{{< remediation-tool domain="maturity" >}}

{{< remediation-tool domain="compliance" >}}

## Guardrails

- One finding goes into one domain tool.
- A packet can produce a plan, PR handoff, audit packet, or triage note.
- The suite never auto-merges.
- The suite does not mutate cloud, registry, ticketing, source-control, GRC, or
  payment systems by itself.
- LLM calls are off by default.
- Secrets, private findings, customer data, and source snippets should stay out
  of `--llm-mode call` unless your approved boundary permits that transmission.
