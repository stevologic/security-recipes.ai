# security-recipes.ai

[security-recipes.ai](https://security-recipes.ai/) is a Hugo site for
security recipes that AI agents can consume during remediation work.

The project is intentionally narrow:

- practical security remediation recipes,
- prompt and rules-file examples,
- agent setup guides,
- MCP integration patterns,
- a browser AI assistant,
- an optional read-only MCP server for recipe search and approved upstream MCP
  context.

It is not a scanner, ticketing system, SOAR platform, deployment tool, or custom
security toolkit. Existing security tools should produce the findings; this
site helps agents use the right remediation context and stop at the right time.

## What this project is for

AI coding agents can help close security findings when their work is bounded:
one finding, one recipe, one reviewed output.

security-recipes.ai helps teams answer:

- Which recipe matches this finding?
- Which prompt should the agent use?
- Where do I put the instructions for Copilot, Claude, Cursor, Codex, or Devin?
- Which MCP servers should the agent read for advisory, scanner, repository, or
  runbook context?
- What should the PR or triage note include before a reviewer trusts it?

## What ships

- Hugo + Hextra documentation site.
- Custom home page for the recipe-focused identity.
- Recipe hubs for dependency, SAST, sensitive-data, base-image, CVE, and
  default-hardening remediation.
- CVE intelligence intake policy, prompt, fixtures, and evaluator for routing
  advisory signals before an agent patches.
- Recipes with existing prompt collections preserved.
- Agent setup guides for GitHub Copilot, Claude, Cursor, Codex, and Devin.
- MCP integration guidance for public and organization-approved security data
  sources.
- Browser AI assistant that uses user-supplied provider credentials.
- Optional read-only FastMCP server in `mcp_server.py` for recipe search,
  retrieval, and opt-in upstream MCP context.
- Docker and Docker Compose configuration for local or droplet hosting.
- Helper scripts for site maintenance, validation, imports, and deployment.

## Repository map

| Path | Purpose |
| --- | --- |
| `content/` | Recipes, docs, recipes, and agent setup pages. |
| `layouts/` | Hugo templates, home page, shortcodes, and JSON indexes. |
| `assets/` | Site CSS and JavaScript, including the AI assistant. |
| `static/` | Images, logos, schemas, and static assets. |
| `mcp_server.py` | Optional read-only MCP server for recipe search and approved upstream MCP context. |
| `mcp-server.toml.example` | MCP server configuration template. |
| `Dockerfile` | Site image. |
| `Dockerfile.mcp-server` | Optional MCP server image. |
| `docker-compose.yml` | Production-style local stack. |
| `scripts/` | Helper scripts for maintenance and deployment. |

## Core content areas

- **Quick Start**: one finding to one reviewed PR or triage note.
- **Recipes**: remediation playbooks agents can follow.
- **Agent Setup**: how to feed recipes into Copilot, Claude, Cursor, Codex, and
  Devin.
- **Recipes**: reusable prompts, instructions, rules, skills, and review
  checklists.
- **MCP Integration**: how to connect security context safely.
- **Docs**: site usage, agent consumption patterns, and contribution guidance.

## Helper scripts only

The scripts in this repository support the content. They are useful for local
maintenance, validation, advisory imports, and deployment, but they are not
required for a company to use the recipes.

Recommended operating model:

1. Let existing SCA, SAST, secrets, CI, cloud, and ticketing systems produce
   findings.
2. Attach a matching security-recipes.ai recipe and prompt.
3. Let the agent read only the files and MCP context needed for the finding.
4. Require tests and human review before merge.
5. Keep broad automation, write access, and deployment outside the first loop.

## AI assistant

The site includes a browser AI assistant implemented in:

- `assets/js/ai-chatbot.js`
- `assets/css/ai-chatbot.css`

Users bring their own provider credentials in the browser. The production
Docker/nginx setup proxies provider requests through same-origin paths for the
current request; the site does not require storing OpenAI, Anthropic, or xAI
keys in server environment variables.

The intended architecture is BYO-key and browser-local for privacy and low
operating cost. The same-origin provider relay is pass-through network plumbing
only; it should not become a server-held-key chat backend.

Architecture notes and change points live in
`content/docs/chatbot-architecture/_index.md`.

## Optional MCP server

The MCP server is read-only by default. Its baseline role is to let
MCP-compatible agents search and retrieve recipes. Self-hosted deployments can
also configure it as a context hub for approved upstream MCP servers without
putting those credentials into the public site.

Common tools:

- `recipes_search`
- `recipes_list`
- `recipes_get`
- `recipes_match_finding`
- `recipes_mcp_upstream_servers`
- `recipes_mcp_upstream_tools`
- `recipes_mcp_upstream_call`
- `recipes_mcp_upstream_context`

Run it with Docker:

```bash
docker build -f Dockerfile.mcp-server -t security-recipes-mcp .
docker run --rm -p 8123:80 security-recipes-mcp
```

Connect an MCP client to:

```text
http://localhost:8123/mcp
```

Run it locally with Python:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-mcp-server.txt
python mcp_server.py
```

Windows PowerShell activation:

```powershell
.\.venv\Scripts\Activate.ps1
python mcp_server.py
```

## Run the site locally

Prerequisites:

- Hugo extended `>= 0.139`
- Go `>= 1.21`
- Git

```bash
hugo mod get -u
hugo server -D
```

Open:

```text
http://localhost:1313
```

If Hugo is not installed globally, download a Hugo extended release and run the
binary directly.

## Docker Compose

Create an environment file:

```bash
cp .env.example .env
```

Start the stack:

```bash
docker compose up -d --build
```

Use the Docker Compose v2 plugin (`docker compose`) when possible. The legacy
Python `docker-compose` v1 package can throw `KeyError: 'id'` from
`compose/cli/log_printer.py` while following logs; that is a Compose watcher
crash, not an nginx or site-container crash. If you only have v1 installed, run
the stack detached and inspect logs through Docker directly:

```bash
docker-compose up -d --build
docker ps
docker logs -f "$(docker-compose ps -q security-recipes)"
```

Default routes:

```text
site: http://127.0.0.1:8080/
AI provider relay: /ai-provider-proxy/openai/v1/responses
MCP endpoint: /mcp
```

The Compose stack is intentionally small:

- `security-recipes`: Hugo/nginx static site and provider relay routes.
- `mcp-server`: optional read-only MCP server.

Do not put model-provider API keys in `.env` for normal site use. Users provide
their own keys in the browser assistant.

For an nginx or Caddy reverse proxy with Let's Encrypt, keep Docker bound to
loopback and let the proxy own public ports `80` and `443`:

```env
SECURITY_RECIPES_HTTP_PORT=127.0.0.1:8080
```

Then proxy to:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## DigitalOcean droplet

For a fresh Ubuntu droplet, use the helper script:

```bash
sudo bash scripts/setup_digitalocean_droplet.sh \
  --domain security-recipes.ai \
  --email admin@security-recipes.ai
```

The script installs Docker/Compose, configures a locked app user, enables basic
host hardening, starts the Compose stack, and can place Caddy in front for
HTTPS.

For a local-only or pre-proxied droplet:

```bash
sudo bash scripts/setup_digitalocean_droplet.sh --no-caddy --no-firewall --no-upgrade
docker compose up -d --build
```

If the Hugo build is killed with exit code `137` during the `hugo --gc
--minify` step, the droplet is out of memory. Use one or more of these
options:

```bash
# Lower Hugo build concurrency and skip minification on small droplets.
SECURITY_RECIPES_HUGO_GOMAXPROCS=1 \
SECURITY_RECIPES_HUGO_MINIFY=false \
docker compose up -d --build
```

You can also add temporary swap before rebuilding:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

`SECURITY_RECIPES_HUGO_MINIFY` defaults to `true`; disabling it only affects
the generated asset size, not the site content or routes.

## MCP integration philosophy

Use MCP to give agents context, not unchecked authority.

Good context sources include:

- official GitHub MCP capabilities for repository and code-security context,
- Semgrep and Snyk agentic/MCP integrations where approved,
- OSV, GitHub Advisories, deps.dev, package registries, and NVD-backed mirrors,
- SARIF, SBOM, CI, ownership, and internal runbook sources,
- read-only documentation connectors.

Write-capable connectors deserve separate review. Ticket creation, branch
mutation, deployment, secret rotation, cloud changes, and SOAR actions should
not be enabled just because an agent can read a recipe.

## Contributing

Contributions should improve the recipe library:

- new remediation recipes,
- better prompts,
- clearer agent setup,
- MCP integration examples,
- reviewer checklists,
- documentation fixes.

Scrub secrets, internal hostnames, customer data, and private vulnerability
details before opening a pull request.

Run a local build before submitting:

```bash
hugo --gc --minify
```
