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
- `recipes_agentic_entitlement_review_pack`
- `recipes_evaluate_agentic_entitlement_decision`
- `recipes_agentic_approval_receipt_pack`
- `recipes_evaluate_agentic_approval_receipt_decision`
- `recipes_mcp_connector_trust_pack`
- `recipes_mcp_connector_intake_pack`
- `recipes_mcp_stdio_launch_boundary_pack`
- `recipes_evaluate_mcp_stdio_launch_decision`
- `recipes_mcp_authorization_conformance_pack`
- `recipes_evaluate_mcp_authorization_decision`
- `recipes_mcp_elicitation_boundary_pack`
- `recipes_evaluate_mcp_elicitation_boundary_decision`
- `recipes_mcp_tool_risk_contract`
- `recipes_evaluate_mcp_tool_risk_decision`
- `recipes_mcp_tool_surface_drift_pack`
- `recipes_evaluate_mcp_tool_surface_drift_decision`
- `recipes_agentic_red_team_drill_pack`
- `recipes_agentic_readiness_scorecard`
- `recipes_agent_capability_risk_register`
- `recipes_agent_memory_boundary_pack`
- `recipes_evaluate_agent_memory_decision`
- `recipes_agent_skill_supply_chain_pack`
- `recipes_evaluate_agent_skill_decision`
- `recipes_agent_handoff_boundary_pack`
- `recipes_evaluate_agent_handoff_decision`
- `recipes_a2a_agent_card_trust_profile`
- `recipes_evaluate_a2a_agent_card_trust_decision`
- `recipes_agentic_system_bom`
- `recipes_agentic_run_receipt_pack`
- `recipes_secure_context_trust_pack`
- `recipes_evaluate_context_retrieval_decision`
- `recipes_secure_context_attestation_pack`
- `recipes_evaluate_context_attestation_decision`
- `recipes_secure_context_lineage_ledger`
- `recipes_evaluate_secure_context_lineage_decision`
- `recipes_secure_context_eval_pack`
- `recipes_evaluate_secure_context_eval_case`
- `recipes_context_poisoning_guard_pack`
- `recipes_context_egress_boundary_pack`
- `recipes_evaluate_context_egress_decision`
- `recipes_agentic_threat_radar`
- `recipes_agentic_standards_crosswalk`
- `recipes_agentic_source_freshness_watch`
- `recipes_mcp_risk_coverage_pack`
- `recipes_agentic_protocol_conformance_pack`
- `recipes_evaluate_agentic_protocol_conformance_decision`
- `recipes_agentic_control_plane_blueprint`
- `recipes_agentic_exposure_graph`
- `recipes_agentic_posture_snapshot`
- `recipes_evaluate_agentic_posture_decision`
- `recipes_agentic_aivss_risk_scoring_pack`
- `recipes_evaluate_agentic_aivss_risk_decision`
- `recipes_agentic_app_intake_pack`
- `recipes_evaluate_agentic_app_intake_decision`
- `recipes_model_provider_routing_pack`
- `recipes_evaluate_model_provider_routing_decision`
- `recipes_agentic_catastrophic_risk_annex`
- `recipes_evaluate_agentic_catastrophic_risk_decision`
- `recipes_critical_infrastructure_secure_context_pack`
- `recipes_evaluate_critical_infrastructure_context_decision`
- `recipes_agentic_incident_response_pack`
- `recipes_evaluate_agentic_incident_response_decision`
- `recipes_agentic_action_runtime_pack`
- `recipes_evaluate_agentic_action_runtime_decision`
- `recipes_browser_agent_boundary_pack`
- `recipes_evaluate_browser_agent_boundary_decision`
- `recipes_agentic_measurement_probe_pack`
- `recipes_agentic_telemetry_contract`
- `recipes_evaluate_agentic_telemetry_event`
- `recipes_agentic_soc_detection_pack`
- `recipes_evaluate_agentic_soc_detection_event`
- `recipes_enterprise_trust_center_export`
- `recipes_secure_context_value_model`
- `recipes_design_partner_pilot_pack`
- `recipes_secure_context_buyer_diligence_brief`
- `recipes_secure_context_customer_proof_pack`
- `recipes_hosted_mcp_readiness_pack`
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
assurance pack, identity ledger, entitlement review pack, connector trust
pack, approval receipt pack, connector intake pack, STDIO launch boundary pack, authorization conformance pack,
MCP elicitation boundary pack, MCP tool-risk contract, red-team drill pack,
red-team replay harness, readiness scorecard,
tool-surface drift pack, agent handoff boundary pack, A2A Agent Card trust profile,
Agentic System BOM, secure
context trust pack, context attestation pack, secure context eval pack,
context poisoning guard pack, context egress boundary pack, or agentic
threat radar, agentic standards crosswalk, MCP risk coverage pack, protocol conformance pack, control plane blueprint,
exposure graph, catastrophic-risk annex, incident response pack,
critical-infrastructure secure-context pack, action runtime pack, measurement probe pack, telemetry contract, SOC detection pack, or
trust-center export, secure context value model, design partner pilot
pack, buyer diligence brief, customer proof pack, hosted MCP readiness pack, browser-agent boundary pack,
agentic AIVSS risk scoring pack, agentic app intake pack, model provider
routing pack, or agentic posture snapshot.
The secure context retrieval, attestation, eval, authorization, elicitation,
MCP tool-risk, STDIO launch, handoff, A2A Agent Card trust,
tool-surface drift, protocol-conformance, catastrophic-risk, incident-response, action-runtime,
critical-infrastructure, browser-agent boundary, entitlement-review, AIVSS risk, posture, model-provider
red-team replay, routing, telemetry, SOC-detection, approval-receipt, and egress evaluators use those generated packs and
do not require separate config paths.

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
