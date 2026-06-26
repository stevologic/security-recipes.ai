---
title: MCP Integration
linkTitle: MCP Integration
weight: 5
toc: true
sidebar:
  open: true
description: >
  How to connect security-recipes.ai, its MCP server, and approved security
  context sources to AI remediation agents.
---

MCP lets an AI application connect to external context and tools through a
standard protocol. For security remediation, use it to give an agent the
evidence it needs to fix one finding: the recipe, advisory data, scanner output,
repository context, and review rules.

{{< callout type="info" >}}
**Safer default:** start read-only. Treat write-capable, deploy-capable, or
command-executing MCP tools as a separate security review.
{{< /callout >}}

Last reviewed against the public MCP documentation and this repository's
`mcp_server.py` implementation on **June 14, 2026**.

## MCP in one minute

The [Model Context Protocol](https://modelcontextprotocol.io/docs/getting-started/intro)
is an open standard for connecting AI applications to external systems. The
current public specification page identifies version
[2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) as the
latest stable spec.

The main roles are:

| Role | Meaning |
| --- | --- |
| Host | The AI application a user works in, such as an IDE, desktop assistant, or browser assistant. |
| Client | The connector inside that host that speaks MCP. |
| Server | The program or service that exposes context and capabilities. |

MCP servers can expose:

| Server feature | Use it for | Remediation example |
| --- | --- | --- |
| Tools | Model-invoked functions with input schemas. | Search recipes, fetch a SARIF alert, query an approved advisory source. |
| Resources | Application-selected context identified by URI. | Attach a package SBOM, policy file, or source document. |
| Prompts | Reusable workflows or message templates. | Start a dependency update or SAST triage flow with consistent instructions. |

MCP uses JSON-RPC. The standard transports are
[stdio and Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
Use Streamable HTTP for hosted or browser-reachable servers. Use stdio when the
client starts a local subprocess.

## Recommended context stack

Start with three layers. Add more only when the finding requires it.

| Layer | Purpose | Examples |
| --- | --- | --- |
| Recipe context | Tell the agent how this class of fix should be handled. | security-recipes.ai recipe index, matching recipe page, local `SECURITY_RECIPES.md`. |
| Finding context | Explain the specific vulnerability or alert. | OSV, deps.dev, GitHub Advisory data, Snyk, Semgrep, CodeQL, SARIF, SBOMs. |
| Repository context | Let the agent inspect code and evidence. | GitHub, GitLab, Azure DevOps, CI logs, branch protections, CODEOWNERS, runbooks. |

An agent does not need every connector for every task. A dependency update may
need only the recipe, package metadata, lockfile, and CI. A SAST remediation may
need the SARIF alert, affected source file, related tests, and secure coding
rule.

## Read-only context

Read-only context means the agent can retrieve evidence, but the context layer
does not give it mutation authority. The agent may search recipes, fetch a
scanner finding, read an advisory, inspect a repository file, or collect CI
status. It should not create tickets, push branches, edit secrets, rotate keys,
deploy, dismiss alerts, or write back to source systems through the same
connector.

That split matters because context gathering is high-volume and low-risk, while
mutation is where authorization mistakes become durable. Keep the default MCP
profile read-only and route write-capable tools through a separate approval
path.

For a remediation run, a read-only context packet usually includes:

- the selected recipe and its stop conditions;
- the specific finding, alert, CVE, GHSA, package, rule, or source/sink pair;
- affected source files, manifests, lockfiles, SBOMs, SARIF, and CI logs;
- relevant ownership and review policy, such as CODEOWNERS or branch
  protection;
- generated evidence requirements that the PR must satisfy.

If a workflow truly needs mutation, split the flow: use read-only MCP to gather
context first, then ask for a narrower write grant tied to one action, one
repository, one branch, one ticket, or one output route. The review step should
be able to see which grant was used and why.

## Security Recipes MCP server

This repository includes an optional FastMCP server in `mcp_server.py`. It is a
read-first knowledge server for security-recipes.ai.

It exposes **MCP tools** that let compatible clients:

| Tool group | What it does | Examples |
| --- | --- | --- |
| Server metadata and cache | Inspect configuration and refresh the in-memory recipe index. | `recipes_server_info`, `recipes_refresh` |
| Recipe search and retrieval | Search, list, fetch, and match recipes to a finding. | `recipes_search`, `recipes_list`, `recipes_get`, `recipes_match_finding` |
| Control and gateway policy | Return generated workflow and MCP gateway policy packs. | `recipes_workflow_control_plane`, `recipes_mcp_gateway_policy` |
| Agent and secure-context evidence | Return generated trust, identity, entitlement, telemetry, incident, and assurance packs. | `recipes_agentic_assurance_pack`, `recipes_agent_identity_ledger`, `recipes_secure_context_trust_pack` |
| MCP governance evidence | Return connector intake, authorization, elicitation, stdio boundary, tool-risk, and drift packs. | `recipes_mcp_connector_intake_pack`, `recipes_mcp_authorization_conformance_pack`, `recipes_mcp_tool_risk_contract` |
| Optional upstream bridge | List configured upstream MCP servers, inspect tools, call allowed tools, and collect bounded context. | `recipes_mcp_upstream_servers`, `recipes_mcp_upstream_tools`, `recipes_mcp_upstream_call`, `recipes_mcp_upstream_context` |

The exact tool list is available through your MCP client's `tools/list` view.
This repo currently defines 66 `recipes_*` tools.

### What it is not

The Security Recipes MCP server is not a scanner, ticket writer, deployment
system, or general-purpose command runner. Its default job is to retrieve
recipes and generated evidence. If you add upstream MCP servers, keep that
bridge read-only unless a separate review approves mutation.

### Which endpoint should I use?

| Situation | Endpoint |
| --- | --- |
| This repo running through Docker Compose on your machine | `http://localhost/mcp` |
| Standalone MCP Docker image mapped with `-p 8123:80` | `http://localhost:8123/mcp` |
| A deployed Docker/nginx instance of this site | `https://YOUR-HOST/mcp` |
| A static-only site host | No MCP endpoint; run the MCP server separately. |

Opening `/mcp` in a normal browser can show an MCP or HTTP method error. That is
expected. MCP clients connect by sending JSON-RPC messages over the selected
transport.

## Configure this Security Recipes MCP server

Use the values below for the page you are viewing now. They update from the
browser's current host, so a local Docker port such as `127.0.0.1:18080`, a
plain localhost run, and the hosted `security-recipes.ai` site all produce the
right client URL and public metadata.

<div class="sr-mcp-config-helper" data-mcp-config-helper>
  <div class="sr-mcp-config-helper__header">
    <div>
      <p class="sr-mcp-config-helper__eyebrow">Current host</p>
      <h3 data-mcp-config-mode>Detecting host</h3>
      <p data-mcp-config-summary>Preparing MCP endpoint details for this deployment.</p>
    </div>
    <span data-mcp-config-badge>dynamic</span>
  </div>

  <div class="sr-mcp-config-helper__facts">
    <div>
      <span>MCP client URL</span>
      <code data-mcp-config-url>...</code>
    </div>
    <div>
      <span>Recipe feed</span>
      <code data-mcp-config-feed>...</code>
    </div>
    <div>
      <span>Source allow-list</span>
      <code data-mcp-config-hosts>...</code>
    </div>
  </div>

  <div class="sr-mcp-config-helper__grid">
    <section>
      <div class="sr-mcp-config-helper__section-head">
        <h4>MCP client JSON</h4>
        <button type="button" data-mcp-config-copy="client">Copy</button>
      </div>
      <pre><code data-mcp-config-client-json>{}</code></pre>
    </section>
    <section>
      <div class="sr-mcp-config-helper__section-head">
        <h4>Docker Compose environment</h4>
        <button type="button" data-mcp-config-copy="env">Copy</button>
      </div>
      <pre><code data-mcp-config-env>RECIPES_MCP_SOURCE_INDEX_URL=...</code></pre>
    </section>
    <section>
      <div class="sr-mcp-config-helper__section-head">
        <h4>Standalone `mcp-server.toml`</h4>
        <button type="button" data-mcp-config-copy="toml">Copy</button>
      </div>
      <pre><code data-mcp-config-toml>source_index_url = "..."</code></pre>
    </section>
    <section>
      <div class="sr-mcp-config-helper__section-head">
        <h4>Health check commands</h4>
        <button type="button" data-mcp-config-copy="checks">Copy</button>
      </div>
      <pre><code data-mcp-config-checks>docker compose ps</code></pre>
    </section>
  </div>

  <p class="sr-mcp-config-helper__status" data-mcp-config-status aria-live="polite"></p>
</div>

For Docker Compose, keep `RECIPES_MCP_SOURCE_INDEX_URL` on the internal
`http://security-recipes/api/recipes.json` feed. That lets the MCP container
read the exact recipes built from this checkout, even before a public domain or
TLS certificate is ready. For a standalone MCP server, point `source_index_url`
at the public recipe feed shown above.

## Quick local setup

Run the site and MCP server together:

```powershell
docker compose up -d --build
```

Then connect an MCP client to:

```text
http://localhost/mcp
```

For clients that accept JSON configuration, adapt this shape to the client's
own config format:

```json
{
  "mcpServers": {
    "security-recipes": {
      "transport": "streamable-http",
      "url": "http://localhost/mcp"
    }
  }
}
```

If you want to run only the MCP image:

```powershell
docker build -f Dockerfile.mcp-server -t security-recipes-mcp .
docker run --rm -p 8123:80 security-recipes-mcp
```

Then use:

```text
http://localhost:8123/mcp
```

If a client only supports local stdio servers, run the Python server with
`RECIPES_MCP_TRANSPORT=stdio` and do not publish an HTTP port.

## First tool calls to try

After the client connects, start with low-risk read calls:

1. Call `recipes_server_info` to confirm the source index, cache TTL, and
   upstream server count.
2. Call `recipes_search` with a short finding description, for example
   `log4j dependency update` or `stored xss sanitizer bypass`.
3. Call `recipes_match_finding` with a CVE, package, ecosystem, rule ID, or
   keywords.
4. Call `recipes_get` with a returned slug or path to retrieve the full recipe
   record.

If those work, add evidence-pack tools only when the workflow needs them.

## Custom configuration

Copy the template before changing server behavior:

```powershell
Copy-Item mcp-server.toml.example mcp-server.toml
```

Mount it into the container:

```powershell
docker run --rm -p 8123:80 `
  -v "${PWD}/mcp-server.toml:/app/mcp-server.toml:ro" `
  security-recipes-mcp
```

Use `mcp-server.toml` to change:

- `source_index_url`: the generated `/api/recipes.json` agent feed to read.
  The legacy `/recipes-index.json` array is still accepted.
- `allowed_source_hosts`: the host allow-list for that index.
- generated evidence-pack file paths.
- cache TTL, request timeout, and result limits.
- optional upstream MCP servers.

Keep credentials out of the TOML file. Put secrets in environment variables.

## Optional upstream MCP context

No upstream MCP servers are configured by default. That keeps the public/site
deployment from holding customer credentials or spending third-party tokens.

For a business deployment, add one `[[upstream_mcp_servers]]` entry per approved
HTTP or Streamable HTTP endpoint:

```toml
[[upstream_mcp_servers]]
id = "github"
label = "GitHub MCP Server"
description = "Repository, issue, PR, Actions, and code-security context."
url = "https://YOUR-GITHUB-MCP-ENDPOINT/mcp"
auth_token_env = "GITHUB_TOKEN"
allowed_tools = ["search_repositories", "get_issue", "get_pull_request"]
context_tool = "search_repositories"
context_query_argument = "query"
max_response_chars = 12000
```

Then pass the token at runtime:

```powershell
docker run --rm -p 8123:80 `
  -e GITHUB_TOKEN="$env:GITHUB_TOKEN" `
  -v "${PWD}/mcp-server.toml:/app/mcp-server.toml:ro" `
  security-recipes-mcp
```

Only HTTP or Streamable HTTP upstreams are called directly. If an upstream
connector is stdio-only, run it behind a reviewed internal gateway before
attaching it to this server.

For production, prefer explicit `allowed_tools`. Do not rely on tool-name
heuristics for connectors that can access private code, cloud resources,
customer data, tickets, deployments, secrets, or terminals.

## Public and product context sources

Not every useful source needs to be an MCP server. Use the simplest safe source
that provides the evidence.

| Source | Use it for | Safer configuration |
| --- | --- | --- |
| [deps.dev API](https://docs.deps.dev/api/v3/) | Package metadata, dependency graph signals, advisory aliases, and version context. | No deps.dev token. Use package coordinates or SBOM-derived package URLs. |
| [OSV.dev API](https://google.github.io/osv.dev/api/) | Open source vulnerability lookup by package URL, ecosystem, version, commit, or batch query. | No OSV token. Bound queries to the packages in the finding. |
| GitHub APIs or [GitHub MCP Server](https://github.com/github/github-mcp-server) | Repository, issue, pull request, Actions, Dependabot, secret scanning, code scanning, and advisory context. | Use repo-scoped read permissions first. Enable mutation separately. |
| [Semgrep docs MCP](https://semgrep.dev/docs/mcp) and Semgrep integrations | Semgrep documentation lookup, SAST/SCA/secrets guidance, and finding triage. | Public docs can be no-token; organization findings require Semgrep auth. |
| [Snyk Studio / Snyk MCP integrations](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/getting-started-with-snyk-studio) | Snyk-backed vulnerability context, fix advice, and agentic security workflows. | Require tenant, org, and API/platform auth appropriate to the integration. |
| [AWS Labs MCP servers](https://github.com/awslabs/mcp) | Cloud intelligence, documentation, account/resource inspection, and service-specific investigation. | Use account, region, and role scoping. Review every write-capable tool. |
| [Azure MCP Server](https://github.com/Azure/azure-mcp) | Azure resource, subscription, and cloud context. | Use tenant/subscription scoping and least-privilege Azure auth. |
| [Cloudflare MCP servers](https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/) | Cloudflare account, zone, Workers, observability, and docs context. | Use account-scoped permissions and review zone-changing tools. |
| [Docker MCP Toolkit and Catalog](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/) | Curated server discovery, gatewaying, and containerized MCP execution. | Review each catalog server before promotion. |

Do not install random MCP servers because they mention security. Review source,
package provenance, token scopes, network access, tool descriptions, update
cadence, and whether the connector can write or execute commands.

## AI Remediation chatbot support

The browser AI Remediation panel has three ways to gather context:

| Mode | Sources | Notes |
| --- | --- | --- |
| No-token browser context | Current page, recipe index, public GitHub repo metadata, deps.dev, OSV.dev, local SARIF, local scanner export, local SBOM. | Best first step for public or local evidence. deps.dev and OSV enrichment need package coordinates or accessible SBOM data. |
| Browser-local API credentials | GitHub code scanning, Snyk issues, Defender XDR incidents, Sentinel incidents, GitLab, Azure DevOps, Confluence, and delivery routes. | Credentials are stored in browser settings and sent only to the selected provider/API from the page. |
| MCP HTTP gateway | Security Recipes MCP server, GitHub MCP Server, Semgrep docs MCP, Snyk/AWS/Azure/Cloudflare/Docker gateways, or an internal gateway. | The browser can call HTTP-reachable MCP endpoints with compatible CORS and bounded read-style tools. |

The browser chatbot does not launch local stdio MCP servers. Use the agent
host's native MCP client for stdio connectors, or wrap the connector behind an
approved HTTP gateway.

## Connector policy

Before adding any MCP server to a remediation workflow, answer these questions:

| Question | Safer default |
| --- | --- |
| Does this finding need the connector? | No, unless the task fails without it. |
| Can any exposed tool write, delete, deploy, execute, or send messages? | Disable or isolate until reviewed. |
| What token scopes are required? | Read-only, repo-scoped, tenant-scoped, and time-bound where possible. |
| Could tool output include secrets, customer data, private code, or sensitive findings? | Keep it internal and policy-gated. |
| Are tool descriptions and versions pinned? | Pin versions and review tool-list changes before promotion. |
| Are calls logged? | Prefer gateways that log tool name, input class, output class, actor, and run ID. |

## Per-agent setup pattern

Every client config looks different, but the safe shape is the same:

1. Add the recipe source or Security Recipes MCP endpoint.
2. Add only the MCP servers needed for the finding class.
3. Grant read-only scopes first.
4. Put stop conditions in the agent's native rules file.
5. Test with one low-risk finding before using the connector on a backlog.

Example task text:

```text
Use the matching security-recipes.ai recipe.
Read advisory and repository context from approved read-only MCP connectors.
Do not use write-capable MCP tools.
Make one PR or stop with a triage note.
```

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| The client cannot connect to `http://localhost/mcp`. | Confirm `docker compose ps` shows both `security-recipes` and `mcp-server` running. |
| `/mcp` opens to an error in the browser. | This can be normal. Test with an MCP client or the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector). |
| The server log says `transport 'stdio'`. | Set `RECIPES_MCP_TRANSPORT=streamable-http` for HTTP clients and rebuild/restart the container. |
| Tools cannot find recipes. | Check `recipes_server_info`, `source_index_url`, `allowed_source_hosts`, and whether the index URL is reachable. |
| Upstream tools are missing. | Call `recipes_mcp_upstream_servers`, then `recipes_mcp_upstream_tools`. Confirm the upstream URL, token env var, and `allowed_tools`. |
| A client only supports stdio. | Run `python mcp_server.py` with `RECIPES_MCP_TRANSPORT=stdio`, or use a client/gateway that supports Streamable HTTP. |

## When not to use MCP

Skip MCP when a local file or task attachment is enough. A scanner alert copied
into an issue, a vendored recipe file, and the repository's test command may be
better for a small dependency bump.

Use MCP when the agent needs fresh structured context: advisory metadata, code
scanning results, SBOM evidence, CI status, ownership data, or a large recipe
catalog that would be awkward to paste into every task.

## See also

- [Integrate an AI Agent]({{< relref "/docs/agent-integration" >}})
- [Agent Setup]({{< relref "/agents" >}})
- [Recipe Browser]({{< relref "/prompt-library" >}})
- [Security Remediation]({{< relref "/security-remediation" >}})
- [Local MCP runbook](https://github.com/stevologic/security-recipes.ai/blob/main/README.mcp-localhost.md)
