# AGENTS.md

## Cursor Cloud specific instructions

This repo is an [Eleventy](https://www.11ty.dev/) static documentation site
(`security-recipes.ai`) with two optional Python companions. See `README.md`
("Run the site locally", "Optional MCP server") and `CONTRIBUTING.md` for the
canonical commands; the notes below only cover non-obvious, durable gotchas.

### Services

| Service | What it is | Run command | Port |
| --- | --- | --- | --- |
| Eleventy site (primary product) | CVE database + remediation recipe site | `npm run serve` | 8080 |
| FastMCP server (optional) | Read-only recipe/CVE MCP endpoint at `/mcp` | `python mcp_server.py` | 8000 |
| Remediation suite (optional) | Python CLI for playbook packets | `python scripts/security_recipes_remediation_suite.py ...` | n/a |

### Non-obvious gotchas

- **`python` must resolve to Python 3.10+.** The Node build scripts
  (`scripts/check_build_prerequisites.js`, `package.json` `build`) invoke the
  bare command `python`, not `python3`. The environment provides this via the
  `python-is-python3` system package plus the deps from `requirements-dev.txt`
  (which includes `requirements-mcp-server.txt`). If `python` is missing or
  lacks `fastmcp/httpx/markdown/tomli`, the build fails in `prebuild`.
- **`npm run serve` does NOT generate the canonical `/cve/<ID>/` detail
  pages.** Those pages are materialized by `python scripts/materialize_cve_pages.py`,
  which only runs as part of `npm run build` (not `eleventy --serve`). To browse
  CVE detail routes (e.g. `/cve/CVE-2021-44228/`) in the dev server, run
  `npm run build` once first to populate `public/cve/`, then start
  `npm run serve` (it keeps the already-materialized files). A fresh checkout
  served without a prior build will show blank/missing CVE detail pages even
  though the `/cve-database/` search page and `/api/*.json` feeds work.
- **MCP server source feed.** `python mcp_server.py` defaults its recipe index
  to the public `https://security-recipes.ai/...` URL. To run fully local,
  build+serve the site, then start it with
  `RECIPES_MCP_SOURCE_INDEX_URL=http://localhost:8080/api/recipes-index.json`
  and `RECIPES_MCP_ALLOWED_SOURCE_HOSTS=localhost`. It speaks
  `streamable-http`; hit `POST /mcp` with
  `Accept: application/json, text/event-stream` (a bare `GET /mcp` returns 406,
  which is expected).

### Lint / test / build

- Lint + full check suite: `python scripts/run_checks.py` (runs `ruff`,
  `compileall`, Python `unittest` discovery, the compliance/code-hygiene/
  marketplace validators, and `node --check`/`node --test` over `assets/js` and
  `tests/*.js`). Takes ~3 minutes.
- Lint only: `python -m ruff check .`
- Production build: `npm run build` (Eleventy → `public/`, then the Python CVE
  materializer and asset precompression).
