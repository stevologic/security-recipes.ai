# Security Recipes MCP over localhost

This MCP server runs FastMCP with Streamable HTTP when started from the
Docker image. The localhost endpoint is:

```text
http://localhost:8123/mcp
```

Use that URL in MCP clients that support remote or HTTP MCP servers.

## Build the image

From the repository root:

```powershell
docker build -f Dockerfile.mcp-server -t mcp.server .
```

## Run on localhost

```powershell
docker run --rm -it -p 8123:80 mcp.server
```

The container listens on port `80`; Docker maps that to `8123` on your
machine. The server log should include:

```text
Starting MCP server 'security-recipes-mcp' with transport 'streamable-http' on http://0.0.0.0:80/mcp
```

## Connect an MCP client

For clients that accept MCP server JSON, use:

```json
{
  "mcpServers": {
    "security-recipes": {
      "transport": "streamable-http",
      "url": "http://localhost:8123/mcp"
    }
  }
}
```

Some clients infer the transport from the URL and only need:

```json
{
  "mcpServers": {
    "security-recipes": {
      "url": "http://localhost:8123/mcp"
    }
  }
}
```

After connecting, the server exposes these tools:

- `recipes_server_info`
- `recipes_refresh`
- `recipes_search`
- `recipes_list`
- `recipes_get`
- `recipes_workflow_control_plane`
- `recipes_mcp_gateway_policy`
- `recipes_evaluate_mcp_gateway_decision`
- `recipes_agentic_assurance_pack`
- `recipes_agent_identity_ledger`
- `recipes_mcp_connector_trust_pack`
- `recipes_agentic_red_team_drill_pack`
- `recipes_agentic_readiness_scorecard`
- `recipes_match_finding`

## Use a custom config

Create a local config from the template:

```powershell
Copy-Item mcp-server.toml.example mcp-server.toml
```

Then mount it into the container:

```powershell
docker run --rm -it -p 8123:80 `
  -v "${PWD}/mcp-server.toml:/app/mcp-server.toml:ro" `
  mcp.server
```

Edit `mcp-server.toml` when you need to point the MCP server at a forked
or self-hosted `recipes-index.json`, workflow manifest, gateway policy,
assurance pack, identity ledger, connector trust pack, red-team drill
pack, or readiness scorecard.

## Change the local port

If `8123` is already in use, map a different host port:

```powershell
docker run --rm -it -p 8124:80 mcp.server
```

Then connect to:

```text
http://localhost:8124/mcp
```

## Troubleshooting

- If the log says `transport 'stdio'`, rebuild the image. Older images
  started in stdio mode, which is why publishing `-p 8123:80` did not
  create a usable localhost endpoint.
- Opening `/mcp` in a browser may show an MCP or HTTP method error. That
  does not mean the server is down; MCP clients connect with JSON-RPC over
  Streamable HTTP.
- If your MCP client only supports stdio servers, run with
  `RECIPES_MCP_TRANSPORT=stdio` and do not publish a port.
