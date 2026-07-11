#!/usr/bin/env python3
"""security-recipes.ai MCP server.

Exposes a read-only MCP tool surface backed by the site's generated recipe feeds.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import httpx
import tomli
from fastmcp import FastMCP

DEFAULT_CONFIG_PATH = os.environ.get("RECIPES_MCP_CONFIG", "./mcp-server.toml")
DEFAULT_TRANSPORT = os.environ.get("RECIPES_MCP_TRANSPORT", "streamable-http")
DEFAULT_HOST = os.environ.get("RECIPES_MCP_HOST", "0.0.0.0")
DEFAULT_PORT = os.environ.get("RECIPES_MCP_PORT", "8000")
DEFAULT_PATH = os.environ.get("RECIPES_MCP_PATH")
DEFAULT_LOG_LEVEL = os.environ.get("RECIPES_MCP_LOG_LEVEL")
MCP_PROTOCOL_VERSION = os.environ.get("RECIPES_MCP_PROTOCOL_VERSION", "2025-06-18")
READ_ONLY_TOOL_NAME_RE = re.compile(
    r"^(search|query|list|get|read|find|lookup|fetch|describe|inspect|analyze|scan|retrieve|resolve)[A-Za-z0-9_.:-]*$",
    re.IGNORECASE,
)


def _env_csv_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class UpstreamMCPServerConfig:
    """Opt-in upstream MCP server configuration for self-hosted deployments."""

    id: str
    label: str
    url: str
    description: str = ""
    enabled: bool = True
    auth_token_env: str | None = None
    auth_scheme: str = "Bearer"
    headers: dict[str, str] = field(default_factory=dict)
    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)
    allow_unlisted_read_only_tools: bool = False
    context_tool: str | None = None
    context_query_argument: str = "query"
    context_static_arguments: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 20
    max_response_chars: int = 12000


@dataclass
class ServerConfig:
    # Prefer /api/recipes-index.json: the lean MCP index carries full recipe
    # bodies (content_text) plus category, facets, and quality metadata, but
    # drops the static agent boilerplate that the rich /api/recipes.json repeats
    # on every recipe (~1 KB each), so the feed MCP refetches stays smaller as
    # the library grows. Both feeds normalize identically; /api/recipes.json
    # still works if set. The body-less /recipes-index.json (in-browser site
    # search) is not a good agent context source.
    source_index_url: str = os.environ.get(
        "RECIPES_MCP_SOURCE_INDEX_URL",
        "https://security-recipes.ai/api/recipes-index.json",
    )
    allowed_source_hosts: list[str] = field(
        default_factory=lambda: _env_csv_list("RECIPES_MCP_ALLOWED_SOURCE_HOSTS", ["security-recipes.ai"])
    )
    cache_ttl_seconds: int = 3600
    request_timeout_seconds: int = 15
    max_results_default: int = 8
    max_results_cap: int = 25
    # Public-facing URL for this MCP server (metadata only).
    server_public_base_url: str = os.environ.get(
        "RECIPES_MCP_PUBLIC_BASE_URL",
        "https://mcp.security-recipes.ai",
    )
    control_plane_manifest_path: str = os.environ.get(
        "RECIPES_MCP_CONTROL_PLANE_PATH",
        "./data/control-plane/workflow-manifests.json",
    )
    gateway_policy_path: str = os.environ.get(
        "RECIPES_MCP_GATEWAY_POLICY_PATH",
        "./data/policy/mcp-gateway-policy.json",
    )
    assurance_pack_path: str = os.environ.get(
        "RECIPES_MCP_ASSURANCE_PACK_PATH",
        "./data/evidence/agentic-assurance-pack.json",
    )
    identity_ledger_path: str = os.environ.get(
        "RECIPES_MCP_IDENTITY_LEDGER_PATH",
        "./data/evidence/agent-identity-delegation-ledger.json",
    )
    entitlement_review_pack_path: str = os.environ.get(
        "RECIPES_MCP_ENTITLEMENT_REVIEW_PACK_PATH",
        "./data/evidence/agentic-entitlement-review-pack.json",
    )
    approval_receipt_pack_path: str = os.environ.get(
        "RECIPES_MCP_APPROVAL_RECEIPT_PACK_PATH",
        "./data/evidence/agentic-approval-receipt-pack.json",
    )
    connector_trust_pack_path: str = os.environ.get(
        "RECIPES_MCP_CONNECTOR_TRUST_PACK_PATH",
        "./data/evidence/mcp-connector-trust-pack.json",
    )
    connector_intake_pack_path: str = os.environ.get(
        "RECIPES_MCP_CONNECTOR_INTAKE_PACK_PATH",
        "./data/evidence/mcp-connector-intake-pack.json",
    )
    mcp_stdio_launch_boundary_pack_path: str = os.environ.get(
        "RECIPES_MCP_STDIO_LAUNCH_BOUNDARY_PACK_PATH",
        "./data/evidence/mcp-stdio-launch-boundary-pack.json",
    )
    authorization_conformance_pack_path: str = os.environ.get(
        "RECIPES_MCP_AUTHORIZATION_CONFORMANCE_PACK_PATH",
        "./data/evidence/mcp-authorization-conformance-pack.json",
    )
    elicitation_boundary_pack_path: str = os.environ.get(
        "RECIPES_MCP_ELICITATION_BOUNDARY_PACK_PATH",
        "./data/evidence/mcp-elicitation-boundary-pack.json",
    )
    tool_risk_contract_path: str = os.environ.get(
        "RECIPES_MCP_TOOL_RISK_CONTRACT_PATH",
        "./data/evidence/mcp-tool-risk-contract.json",
    )
    tool_surface_drift_pack_path: str = os.environ.get(
        "RECIPES_MCP_TOOL_SURFACE_DRIFT_PACK_PATH",
        "./data/evidence/mcp-tool-surface-drift-pack.json",
    )
    red_team_drill_pack_path: str = os.environ.get(
        "RECIPES_MCP_RED_TEAM_DRILL_PACK_PATH",
        "./data/evidence/agentic-red-team-drill-pack.json",
    )
    red_team_replay_harness_path: str = os.environ.get(
        "RECIPES_MCP_RED_TEAM_REPLAY_HARNESS_PATH",
        "./data/evidence/agentic-red-team-replay-harness.json",
    )
    readiness_scorecard_path: str = os.environ.get(
        "RECIPES_MCP_READINESS_SCORECARD_PATH",
        "./data/evidence/agentic-readiness-scorecard.json",
    )
    capability_risk_register_path: str = os.environ.get(
        "RECIPES_MCP_CAPABILITY_RISK_REGISTER_PATH",
        "./data/evidence/agent-capability-risk-register.json",
    )
    agent_memory_boundary_pack_path: str = os.environ.get(
        "RECIPES_MCP_AGENT_MEMORY_BOUNDARY_PACK_PATH",
        "./data/evidence/agent-memory-boundary-pack.json",
    )
    agent_skill_supply_chain_pack_path: str = os.environ.get(
        "RECIPES_MCP_AGENT_SKILL_SUPPLY_CHAIN_PACK_PATH",
        "./data/evidence/agent-skill-supply-chain-pack.json",
    )
    agent_handoff_boundary_pack_path: str = os.environ.get(
        "RECIPES_MCP_AGENT_HANDOFF_BOUNDARY_PACK_PATH",
        "./data/evidence/agent-handoff-boundary-pack.json",
    )
    a2a_agent_card_trust_profile_path: str = os.environ.get(
        "RECIPES_MCP_A2A_AGENT_CARD_TRUST_PROFILE_PATH",
        "./data/evidence/a2a-agent-card-trust-profile.json",
    )
    agentic_system_bom_path: str = os.environ.get(
        "RECIPES_MCP_AGENTIC_SYSTEM_BOM_PATH",
        "./data/evidence/agentic-system-bom.json",
    )
    agentic_run_receipt_pack_path: str = os.environ.get(
        "RECIPES_MCP_AGENTIC_RUN_RECEIPT_PACK_PATH",
        "./data/evidence/agentic-run-receipt-pack.json",
    )
    secure_context_trust_pack_path: str = os.environ.get(
        "RECIPES_MCP_SECURE_CONTEXT_TRUST_PACK_PATH",
        "./data/evidence/secure-context-trust-pack.json",
    )
    secure_context_attestation_pack_path: str = os.environ.get(
        "RECIPES_MCP_SECURE_CONTEXT_ATTESTATION_PACK_PATH",
        "./data/evidence/secure-context-attestation-pack.json",
    )
    secure_context_lineage_ledger_path: str = os.environ.get(
        "RECIPES_MCP_SECURE_CONTEXT_LINEAGE_LEDGER_PATH",
        "./data/evidence/secure-context-lineage-ledger.json",
    )
    secure_context_eval_pack_path: str = os.environ.get(
        "RECIPES_MCP_SECURE_CONTEXT_EVAL_PACK_PATH",
        "./data/evidence/secure-context-eval-pack.json",
    )
    context_poisoning_guard_pack_path: str = os.environ.get(
        "RECIPES_MCP_CONTEXT_POISONING_GUARD_PACK_PATH",
        "./data/evidence/context-poisoning-guard-pack.json",
    )
    context_egress_boundary_pack_path: str = os.environ.get(
        "RECIPES_MCP_CONTEXT_EGRESS_BOUNDARY_PACK_PATH",
        "./data/evidence/context-egress-boundary-pack.json",
    )
    threat_radar_path: str = os.environ.get(
        "RECIPES_MCP_THREAT_RADAR_PATH",
        "./data/evidence/agentic-threat-radar.json",
    )
    standards_crosswalk_path: str = os.environ.get(
        "RECIPES_MCP_STANDARDS_CROSSWALK_PATH",
        "./data/evidence/agentic-standards-crosswalk.json",
    )
    source_freshness_watch_path: str = os.environ.get(
        "RECIPES_MCP_SOURCE_FRESHNESS_WATCH_PATH",
        "./data/evidence/agentic-source-freshness-watch.json",
    )
    mcp_risk_coverage_pack_path: str = os.environ.get(
        "RECIPES_MCP_RISK_COVERAGE_PACK_PATH",
        "./data/evidence/mcp-risk-coverage-pack.json",
    )
    protocol_conformance_pack_path: str = os.environ.get(
        "RECIPES_MCP_PROTOCOL_CONFORMANCE_PACK_PATH",
        "./data/evidence/agentic-protocol-conformance-pack.json",
    )
    control_plane_blueprint_path: str = os.environ.get(
        "RECIPES_MCP_CONTROL_PLANE_BLUEPRINT_PATH",
        "./data/evidence/agentic-control-plane-blueprint.json",
    )
    measurement_probe_pack_path: str = os.environ.get(
        "RECIPES_MCP_MEASUREMENT_PROBE_PACK_PATH",
        "./data/evidence/agentic-measurement-probe-pack.json",
    )
    telemetry_contract_path: str = os.environ.get(
        "RECIPES_MCP_TELEMETRY_CONTRACT_PATH",
        "./data/evidence/agentic-telemetry-contract.json",
    )
    soc_detection_pack_path: str = os.environ.get(
        "RECIPES_MCP_SOC_DETECTION_PACK_PATH",
        "./data/evidence/agentic-soc-detection-pack.json",
    )
    enterprise_trust_center_export_path: str = os.environ.get(
        "RECIPES_MCP_ENTERPRISE_TRUST_CENTER_EXPORT_PATH",
        "./data/evidence/enterprise-trust-center-export.json",
    )
    secure_context_value_model_path: str = os.environ.get(
        "RECIPES_MCP_SECURE_CONTEXT_VALUE_MODEL_PATH",
        "./data/evidence/secure-context-value-model.json",
    )
    design_partner_pilot_pack_path: str = os.environ.get(
        "RECIPES_MCP_DESIGN_PARTNER_PILOT_PACK_PATH",
        "./data/evidence/design-partner-pilot-pack.json",
    )
    buyer_diligence_brief_path: str = os.environ.get(
        "RECIPES_MCP_BUYER_DILIGENCE_BRIEF_PATH",
        "./data/evidence/secure-context-buyer-diligence-brief.json",
    )
    customer_proof_pack_path: str = os.environ.get(
        "RECIPES_MCP_CUSTOMER_PROOF_PACK_PATH",
        "./data/evidence/secure-context-customer-proof-pack.json",
    )
    evidence_contract_path: str = os.environ.get(
        "RECIPES_MCP_EVIDENCE_CONTRACT_PATH",
        "./data/evidence/secure-context-evidence-contract.json",
    )
    hosted_mcp_readiness_pack_path: str = os.environ.get(
        "RECIPES_MCP_HOSTED_MCP_READINESS_PACK_PATH",
        "./data/evidence/hosted-mcp-readiness-pack.json",
    )
    catastrophic_risk_annex_path: str = os.environ.get(
        "RECIPES_MCP_CATASTROPHIC_RISK_ANNEX_PATH",
        "./data/evidence/agentic-catastrophic-risk-annex.json",
    )
    critical_infrastructure_pack_path: str = os.environ.get(
        "RECIPES_MCP_CRITICAL_INFRASTRUCTURE_PACK_PATH",
        "./data/evidence/critical-infrastructure-secure-context-pack.json",
    )
    incident_response_pack_path: str = os.environ.get(
        "RECIPES_MCP_INCIDENT_RESPONSE_PACK_PATH",
        "./data/evidence/agentic-incident-response-pack.json",
    )
    action_runtime_pack_path: str = os.environ.get(
        "RECIPES_MCP_ACTION_RUNTIME_PACK_PATH",
        "./data/evidence/agentic-action-runtime-pack.json",
    )
    agent_trust_fabric_pack_path: str = os.environ.get(
        "RECIPES_MCP_AGENT_TRUST_FABRIC_PACK_PATH",
        "./data/evidence/agent-trust-fabric-pack.json",
    )
    browser_agent_boundary_pack_path: str = os.environ.get(
        "RECIPES_MCP_BROWSER_AGENT_BOUNDARY_PACK_PATH",
        "./data/evidence/browser-agent-boundary-pack.json",
    )
    exposure_graph_path: str = os.environ.get(
        "RECIPES_MCP_EXPOSURE_GRAPH_PATH",
        "./data/evidence/agentic-exposure-graph.json",
    )
    posture_snapshot_path: str = os.environ.get(
        "RECIPES_MCP_POSTURE_SNAPSHOT_PATH",
        "./data/evidence/agentic-posture-snapshot.json",
    )
    agentic_aivss_risk_scoring_pack_path: str = os.environ.get(
        "RECIPES_MCP_AGENTIC_AIVSS_RISK_SCORING_PACK_PATH",
        "./data/evidence/agentic-aivss-risk-scoring-pack.json",
    )
    app_intake_pack_path: str = os.environ.get(
        "RECIPES_MCP_APP_INTAKE_PACK_PATH",
        "./data/evidence/agentic-app-intake-pack.json",
    )
    model_provider_routing_pack_path: str = os.environ.get(
        "RECIPES_MCP_MODEL_PROVIDER_ROUTING_PACK_PATH",
        "./data/evidence/model-provider-routing-pack.json",
    )
    upstream_mcp_servers: list[UpstreamMCPServerConfig] = field(default_factory=list)


def _safe_public_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or ""
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _validate_upstream_url(url: str, server_id: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"upstream_mcp_servers[{server_id}] url must be an http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError(f"upstream_mcp_servers[{server_id}] must not embed credentials in the URL")


def _string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list of strings")
    return [str(item).strip() for item in value if str(item).strip()]


def _string_dict(value: Any, field_name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a table/object of string values")
    return {str(key): str(item) for key, item in value.items()}


def _parse_upstream_mcp_servers(value: Any, default_timeout_seconds: int) -> list[UpstreamMCPServerConfig]:
    if not value:
        return []
    if not isinstance(value, list):
        raise ValueError("upstream_mcp_servers must be a list of tables")

    servers: list[UpstreamMCPServerConfig] = []
    seen_ids: set[str] = set()
    for idx, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"upstream_mcp_servers[{idx}] must be a table/object")

        server_id = str(item.get("id", "")).strip()
        if not server_id:
            raise ValueError(f"upstream_mcp_servers[{idx}] requires id")
        if server_id in seen_ids:
            raise ValueError(f"duplicate upstream_mcp_servers id: {server_id}")
        seen_ids.add(server_id)

        enabled = bool(item.get("enabled", True))
        if not enabled:
            continue

        url = str(item.get("url", "")).strip()
        if not url:
            raise ValueError(f"upstream_mcp_servers[{server_id}] requires url")
        _validate_upstream_url(url, server_id)

        timeout_seconds = int(item.get("timeout_seconds", default_timeout_seconds))
        max_response_chars = int(item.get("max_response_chars", 12000))
        if timeout_seconds <= 0:
            raise ValueError(f"upstream_mcp_servers[{server_id}] timeout_seconds must be positive")
        if max_response_chars < 1000:
            raise ValueError(f"upstream_mcp_servers[{server_id}] max_response_chars must be at least 1000")

        servers.append(
            UpstreamMCPServerConfig(
                id=server_id,
                label=str(item.get("label", server_id)).strip() or server_id,
                url=url,
                description=str(item.get("description", "")).strip(),
                enabled=enabled,
                auth_token_env=str(item.get("auth_token_env", "")).strip() or None,
                auth_scheme=str(item.get("auth_scheme", "Bearer")).strip(),
                headers=_string_dict(item.get("headers"), f"upstream_mcp_servers[{server_id}].headers"),
                allowed_tools=_string_list(
                    item.get("allowed_tools"),
                    f"upstream_mcp_servers[{server_id}].allowed_tools",
                ),
                blocked_tools=_string_list(
                    item.get("blocked_tools"),
                    f"upstream_mcp_servers[{server_id}].blocked_tools",
                ),
                allow_unlisted_read_only_tools=bool(item.get("allow_unlisted_read_only_tools", False)),
                context_tool=str(item.get("context_tool", "")).strip() or None,
                context_query_argument=str(item.get("context_query_argument", "query")).strip() or "query",
                context_static_arguments=dict(item.get("context_static_arguments") or {}),
                timeout_seconds=timeout_seconds,
                max_response_chars=max_response_chars,
            )
        )
    return servers


class UpstreamMCPRegistry:
    def __init__(self, servers: list[UpstreamMCPServerConfig]):
        self._servers = {server.id: server for server in servers}
        self._sessions: dict[str, str] = {}
        self._initialized: set[str] = set()
        self._request_id = 0
        self._lock = asyncio.Lock()

    def list_public(self) -> list[dict[str, Any]]:
        return [self._public_summary(server) for server in self._servers.values()]

    def _public_summary(self, server: UpstreamMCPServerConfig) -> dict[str, Any]:
        return {
            "id": server.id,
            "label": server.label,
            "description": server.description,
            "url": _safe_public_url(server.url),
            "auth_token_env": server.auth_token_env,
            "has_auth_token": bool(server.auth_token_env and os.environ.get(server.auth_token_env)),
            "allowed_tools": server.allowed_tools,
            "blocked_tools": server.blocked_tools,
            "allow_unlisted_read_only_tools": server.allow_unlisted_read_only_tools,
            "context_tool": server.context_tool,
            "context_query_argument": server.context_query_argument,
            "max_response_chars": server.max_response_chars,
        }

    def _get_server(self, server_id: str) -> UpstreamMCPServerConfig:
        key = server_id.strip()
        server = self._servers.get(key)
        if not server:
            raise ValueError(f"unknown upstream MCP server: {server_id}")
        return server

    def _headers(self, server: UpstreamMCPServerConfig) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        }
        headers.update(server.headers)

        session_id = self._sessions.get(server.id)
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        if server.auth_token_env:
            token = os.environ.get(server.auth_token_env, "").strip()
            if token:
                headers["Authorization"] = f"{server.auth_scheme} {token}".strip()
        return headers

    def _next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _decode_response(self, response: httpx.Response, request_id: int | None) -> dict[str, Any] | None:
        if response.status_code == 202 or not response.content:
            return None

        text = response.text.strip()
        if not text:
            return None

        content_type = response.headers.get("content-type", "").lower()
        frames: list[Any] = []
        if "text/event-stream" in content_type or text.startswith("event:") or text.startswith("data:"):
            for block in re.split(r"\n\s*\n", text):
                data_lines = []
                for line in block.splitlines():
                    if line.startswith("data:"):
                        data_lines.append(line[5:].strip())
                if not data_lines:
                    continue
                data = "\n".join(data_lines).strip()
                if not data or data == "[DONE]":
                    continue
                frames.append(json.loads(data))
        else:
            frames.append(response.json())

        for frame in frames:
            if isinstance(frame, list):
                for item in frame:
                    if isinstance(item, dict) and (request_id is None or item.get("id") == request_id):
                        return item
            if isinstance(frame, dict) and (request_id is None or frame.get("id") == request_id):
                return frame
        return frames[-1] if frames and isinstance(frames[-1], dict) else None

    async def _rpc(
        self,
        server: UpstreamMCPServerConfig,
        method: str,
        params: dict[str, Any] | None = None,
        expect_response: bool = True,
    ) -> dict[str, Any] | None:
        request_id = self._next_request_id() if expect_response else None
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if request_id is not None:
            payload["id"] = request_id

        timeout = httpx.Timeout(server.timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.post(server.url, headers=self._headers(server), json=payload)

        session_id = response.headers.get("mcp-session-id")
        if session_id:
            self._sessions[server.id] = session_id

        response.raise_for_status()
        frame = self._decode_response(response, request_id)
        if frame and frame.get("error"):
            error = frame["error"]
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise RuntimeError(f"{method} failed on upstream MCP server {server.id}: {message}")
        if frame:
            return frame.get("result")
        return None

    async def _ensure_initialized(self, server: UpstreamMCPServerConfig) -> None:
        async with self._lock:
            if server.id in self._initialized:
                return
            await self._rpc(
                server,
                "initialize",
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "security-recipes-mcp",
                        "version": "1.0.0",
                    },
                },
            )
            await self._rpc(server, "notifications/initialized", expect_response=False)
            self._initialized.add(server.id)

    def _is_tool_allowed(self, server: UpstreamMCPServerConfig, tool_name: str) -> tuple[bool, str]:
        if tool_name in set(server.blocked_tools):
            return False, "tool is explicitly blocked"
        if tool_name in set(server.allowed_tools):
            return True, "tool is explicitly allowed"
        if server.allowed_tools:
            return False, "tool is not in allowed_tools"
        if server.allow_unlisted_read_only_tools and READ_ONLY_TOOL_NAME_RE.match(tool_name):
            return True, "tool name matches the read-only allow pattern"
        return False, "tool is not allowed; add it to allowed_tools or enable allow_unlisted_read_only_tools"

    @staticmethod
    def _text_from_tool_result(result: Any) -> str:
        if isinstance(result, dict) and isinstance(result.get("content"), list):
            parts = []
            for item in result["content"]:
                if isinstance(item, dict):
                    if item.get("type") == "text" and item.get("text"):
                        parts.append(str(item["text"]))
                    elif "text" in item:
                        parts.append(str(item["text"]))
                    elif "data" in item:
                        parts.append(json.dumps(item["data"], ensure_ascii=False, sort_keys=True))
                else:
                    parts.append(str(item))
            if parts:
                return "\n\n".join(parts)
        return json.dumps(result, ensure_ascii=False, sort_keys=True, default=str)

    @staticmethod
    def _truncate_text(text: str, max_chars: int) -> tuple[str, bool]:
        if len(text) <= max_chars:
            return text, False
        return text[:max_chars].rstrip() + "\n...[truncated]", True

    async def list_tools(self, server_id: str) -> dict[str, Any]:
        server = self._get_server(server_id)
        await self._ensure_initialized(server)
        result = await self._rpc(server, "tools/list", {})
        tools = result.get("tools", []) if isinstance(result, dict) else []
        shaped = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", ""))
            allowed, reason = self._is_tool_allowed(server, name)
            shaped.append(
                {
                    "name": name,
                    "description": tool.get("description"),
                    "input_schema": tool.get("inputSchema") or tool.get("input_schema"),
                    "allowed": allowed,
                    "allow_reason": reason,
                }
            )
        return {
            "server": self._public_summary(server),
            "count": len(shaped),
            "tools": shaped,
        }

    async def call_tool(
        self,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        server = self._get_server(server_id)
        allowed, reason = self._is_tool_allowed(server, tool_name)
        if not allowed:
            return {
                "ok": False,
                "server": self._public_summary(server),
                "tool_name": tool_name,
                "error": reason,
            }

        await self._ensure_initialized(server)
        result = await self._rpc(
            server,
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments or {},
            },
        )
        text = self._text_from_tool_result(result)
        text, truncated = self._truncate_text(text, server.max_response_chars)
        return {
            "ok": True,
            "server": self._public_summary(server),
            "tool_name": tool_name,
            "arguments": arguments or {},
            "content_text": text,
            "truncated": truncated,
            "security_boundary": "Only explicitly configured upstream HTTP MCP servers are called. Secrets are read from environment variables and are not returned.",
        }

    async def context_bundle(
        self,
        query: str,
        server_ids: list[str] | None = None,
        max_chars: int = 24000,
    ) -> dict[str, Any]:
        selected_ids = server_ids or list(self._servers.keys())
        budget = max(1000, max_chars)
        results = []
        remaining = budget

        for server_id in selected_ids:
            try:
                server = self._get_server(server_id)
                if not server.context_tool:
                    results.append(
                        {
                            "server_id": server_id,
                            "ok": False,
                            "error": "server has no context_tool configured",
                        }
                    )
                    continue

                args = dict(server.context_static_arguments)
                args[server.context_query_argument] = query
                response = await self.call_tool(server.id, server.context_tool, args)
                if response.get("ok"):
                    text = str(response.get("content_text", ""))
                    text, truncated = self._truncate_text(text, max(1000, remaining))
                    remaining -= len(text)
                    response["content_text"] = text
                    response["truncated"] = bool(response.get("truncated") or truncated)
                results.append(response)
                if remaining <= 0:
                    break
            except Exception as exc:
                results.append(
                    {
                        "server_id": server_id,
                        "ok": False,
                        "error": str(exc),
                    }
                )

        return {
            "query": query,
            "server_count": len(selected_ids),
            "results": results,
            "security_boundary": "Upstream MCP context is disabled unless configured in mcp-server.toml or RECIPES_MCP_UPSTREAM_SERVERS_JSON.",
        }


class RecipeIndex:
    def __init__(self, config: ServerConfig):
        self.config = config
        self._docs: list[dict[str, Any]] = []
        self._doc_by_slug: dict[str, dict[str, Any]] = {}
        self._doc_by_path: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._etag: str | None = None
        self._lock = asyncio.Lock()

    def _assert_allowed_host(self) -> None:
        parsed = urlparse(self.config.source_index_url)
        if parsed.scheme not in {"http", "https"}:
            return
        host = parsed.hostname
        if not host:
            raise ValueError("source_index_url must include a hostname")
        if host not in set(self.config.allowed_source_hosts):
            raise ValueError(
                f"source host '{host}' is not in allowed_source_hosts={self.config.allowed_source_hosts}"
            )

    async def _fetch_payload(self, headers: dict[str, str]) -> tuple[Any, str | None, int | None]:
        parsed = urlparse(self.config.source_index_url)
        if parsed.scheme in {"http", "https"}:
            timeout = httpx.Timeout(self.config.request_timeout_seconds)
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.get(self.config.source_index_url, headers=headers)

            if response.status_code == 304:
                return None, response.headers.get("ETag"), 304

            response.raise_for_status()
            return response.json(), response.headers.get("ETag"), response.status_code

        if parsed.scheme == "file":
            path_text = unquote(parsed.path)
            if re.match(r"^/[A-Za-z]:", path_text):
                path_text = path_text[1:]
            source_path = Path(path_text)
        else:
            source_path = Path(self.config.source_index_url)
        if not source_path.is_absolute():
            source_path = Path.cwd() / source_path
        return json.loads(source_path.read_text(encoding="utf-8")), None, None

    @staticmethod
    def _category_slug(doc: dict[str, Any]) -> str:
        category = doc.get("category")
        if isinstance(category, dict):
            return str(category.get("slug") or category.get("label") or "").strip()
        return str(category or "").strip()

    @staticmethod
    def _normalize_doc(row: dict[str, Any]) -> dict[str, Any]:
        doc = dict(row)
        doc["content"] = str(doc.get("content") or doc.get("content_text") or "")
        doc["summary"] = str(doc.get("summary") or doc.get("description") or "")
        facets = doc.get("facets") or []
        if isinstance(facets, str):
            facets = [part for part in re.split(r"[\s,]+", facets) if part]
        doc["facets"] = [str(facet).strip().lower() for facet in facets if str(facet).strip()]
        quality = doc.get("quality") if isinstance(doc.get("quality"), dict) else {}
        try:
            quality_score = int(quality.get("score", doc.get("quality_score", 0)))
        except (TypeError, ValueError):
            quality_score = 0
        doc["quality"] = {
            **quality,
            "score": quality_score,
            "tier": str(quality.get("tier") or doc.get("readiness") or "starter"),
            "signals": quality.get("signals") or [],
        }

        category_slug = RecipeIndex._category_slug(doc)
        source_file = str(doc.get("source_file") or doc.get("sourceFile") or "").replace("\\", "/")
        path = str(doc.get("path") or "").strip()
        if not doc.get("section"):
            if source_file:
                doc["section"] = source_file.split("/", 1)[0]
            elif path:
                doc["section"] = path.strip("/").split("/", 1)[0]
            elif category_slug:
                doc["section"] = category_slug

        if category_slug and not isinstance(doc.get("category"), dict):
            doc["category"] = {"slug": category_slug, "label": category_slug}
        if source_file:
            doc["source_file"] = source_file

        return doc

    @staticmethod
    def _normalize_payload(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict) and isinstance(payload.get("recipes"), list):
            payload = payload["recipes"]
        if not isinstance(payload, list) or not payload:
            raise ValueError("recipe index payload must be a non-empty JSON array or an object with a non-empty recipes array")

        required = {"slug", "title", "url", "content"}
        normalized = []
        for idx, row in enumerate(payload):
            if not isinstance(row, dict):
                raise ValueError(f"row[{idx}] must be an object")
            doc = RecipeIndex._normalize_doc(row)
            missing = sorted(required - {key for key, value in doc.items() if value not in (None, "")})
            if missing:
                raise ValueError(f"row[{idx}] missing required fields: {missing}")
            normalized.append(doc)
        return normalized

    @staticmethod
    def _candidate_keys(value: Any) -> list[str]:
        raw = str(value or "").strip()
        if not raw:
            return []
        keys = [raw]
        stripped = raw.strip("/")
        if stripped and stripped != raw:
            keys.append(stripped)
        if stripped:
            keys.append(f"/{stripped}/")
            keys.append(f"/{stripped}")
        return list(dict.fromkeys(keys))

    @classmethod
    def _index_by_keys(cls, docs: list[dict[str, Any]], fields: list[str]) -> dict[str, dict[str, Any]]:
        indexed: dict[str, dict[str, Any]] = {}
        for doc in docs:
            for field_name in fields:
                for key in cls._candidate_keys(doc.get(field_name)):
                    indexed.setdefault(key, doc)
        return indexed

    async def refresh(self, force: bool = False) -> dict[str, Any]:
        async with self._lock:
            if not force and self._docs and (time.time() - self._fetched_at) < self.config.cache_ttl_seconds:
                return {
                    "status": "cached",
                    "fetched_at_unix": int(self._fetched_at),
                    "doc_count": len(self._docs),
                }

            self._assert_allowed_host()
            headers: dict[str, str] = {}
            if self._etag and not force:
                headers["If-None-Match"] = self._etag

            payload, etag, status_code = await self._fetch_payload(headers=headers)
            if status_code == 304:
                self._fetched_at = time.time()
                return {
                    "status": "not_modified",
                    "fetched_at_unix": int(self._fetched_at),
                    "doc_count": len(self._docs),
                }

            payload = self._normalize_payload(payload)
            self._docs = payload
            self._doc_by_slug = self._index_by_keys(payload, ["slug"])
            self._doc_by_path = self._index_by_keys(payload, ["path", "source_file", "url"])
            self._fetched_at = time.time()
            self._etag = etag

            return {
                "status": "refreshed",
                "fetched_at_unix": int(self._fetched_at),
                "doc_count": len(self._docs),
                "etag": self._etag,
            }

    async def ensure_fresh(self) -> None:
        await self.refresh(force=False)

    async def list_docs(
        self,
        section: str | None = None,
        agent: str | None = None,
        severity: str | None = None,
        tags: list[str] | None = None,
        facets: list[str] | None = None,
        min_quality: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        await self.ensure_fresh()
        docs = self._docs

        if section:
            docs = [d for d in docs if self._section_matches(d, section)]
        if agent:
            docs = [d for d in docs if str(d.get("agent", "")).lower() == agent.lower()]
        if severity:
            docs = [d for d in docs if str(d.get("severity", "")).lower() == severity.lower()]
        if tags:
            tags_lower = {t.lower() for t in tags}
            docs = [
                d
                for d in docs
                if tags_lower.intersection({str(tag).lower() for tag in (d.get("tags") or [])})
            ]
        if facets:
            facets_lower = {f.lower() for f in facets}
            docs = [
                d
                for d in docs
                if facets_lower.intersection({str(facet).lower() for facet in (d.get("facets") or [])})
            ]
        if min_quality is not None:
            docs = [d for d in docs if int((d.get("quality") or {}).get("score") or 0) >= min_quality]

        cap = self.config.max_results_cap
        if limit is None:
            limit = self.config.max_results_default
        limit = max(1, min(limit, cap))
        return [self._shape_preview(d) for d in docs[:limit]]

    async def get_doc(self, slug_or_path: str) -> dict[str, Any] | None:
        await self.ensure_fresh()
        key = slug_or_path.strip()
        for candidate in self._candidate_keys(key):
            doc = self._doc_by_slug.get(candidate) or self._doc_by_path.get(candidate)
            if doc:
                return doc
        return None

    async def quality_report(
        self,
        facet: str | None = None,
        tier: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        await self.ensure_fresh()
        docs = self._docs
        if facet:
            facet_key = facet.lower().strip()
            docs = [d for d in docs if facet_key in {str(f).lower() for f in (d.get("facets") or [])}]
        if tier:
            tier_key = tier.lower().strip()
            docs = [d for d in docs if str((d.get("quality") or {}).get("tier", "")).lower() == tier_key]

        required_signals = [
            "inputs",
            "selection-guidance",
            "output-contract",
            "verification",
            "guardrails",
            "related-context",
        ]
        tier_counts: dict[str, int] = {}
        facet_counts: dict[str, int] = {}
        gaps: list[dict[str, Any]] = []

        for doc in docs:
            quality = doc.get("quality") or {}
            doc_tier = str(quality.get("tier") or "starter")
            tier_counts[doc_tier] = tier_counts.get(doc_tier, 0) + 1
            for doc_facet in doc.get("facets") or []:
                key = str(doc_facet)
                facet_counts[key] = facet_counts.get(key, 0) + 1

            signals = {str(signal) for signal in quality.get("signals") or []}
            missing = [signal for signal in required_signals if signal not in signals]
            score = int(quality.get("score") or 0)
            if missing or score < 85:
                gaps.append(
                    {
                        **self._shape_preview(doc),
                        "missing_quality_signals": missing,
                        "next_action": self._quality_next_action(missing, score),
                    }
                )

        gaps.sort(key=lambda item: (int((item.get("quality") or {}).get("score") or 0), item.get("title") or ""))
        cap = self.config.max_results_cap
        if limit is None:
            limit = self.config.max_results_default
        limit = max(1, min(limit, cap))

        return {
            "recipe_count": len(docs),
            "tier_counts": dict(sorted(tier_counts.items())),
            "facet_counts": dict(sorted(facet_counts.items())),
            "world_class_threshold": 85,
            "required_signals": required_signals,
            "gap_count": len(gaps),
            "gaps": gaps[:limit],
        }

    async def search(
        self,
        query: str,
        section: str | None = None,
        agent: str | None = None,
        tags: list[str] | None = None,
        facets: list[str] | None = None,
        min_quality: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        await self.ensure_fresh()
        terms = [t for t in re.split(r"\s+", query.lower().strip()) if t]
        if not terms:
            return []

        candidates: list[dict[str, Any]] = self._docs
        if section:
            candidates = [d for d in candidates if self._section_matches(d, section)]
        if agent:
            candidates = [d for d in candidates if str(d.get("agent", "")).lower() == agent.lower()]
        if tags:
            tags_lower = {t.lower() for t in tags}
            candidates = [
                d
                for d in candidates
                if tags_lower.intersection({str(tag).lower() for tag in (d.get("tags") or [])})
            ]
        if facets:
            facets_lower = {f.lower() for f in facets}
            candidates = [
                d
                for d in candidates
                if facets_lower.intersection({str(facet).lower() for facet in (d.get("facets") or [])})
            ]
        if min_quality is not None:
            candidates = [
                d for d in candidates if int((d.get("quality") or {}).get("score") or 0) >= min_quality
            ]

        scored: list[tuple[float, dict[str, Any]]] = []
        for d in candidates:
            hay = " ".join(
                [
                    str(d.get("title", "")),
                    str(d.get("summary", "")),
                    str(d.get("content", ""))[:8000],
                    " ".join([str(x) for x in (d.get("tags") or [])]),
                    " ".join([str(x) for x in (d.get("aliases") or [])]),
                    str(d.get("slug", "")),
                    str(d.get("path", "")),
                    str(d.get("source_file", "")),
                    str(d.get("agent", "")),
                    str(d.get("severity", "")),
                    str(d.get("ecosystem", "")),
                    " ".join([str(x) for x in (d.get("facets") or [])]),
                    str((d.get("quality") or {}).get("tier", "")),
                    str(d.get("cve", "")),
                    str(d.get("ghsa", "")),
                    RecipeIndex._category_slug(d),
                ]
            ).lower()
            score = 0.0
            for term in terms:
                hits = hay.count(term)
                if hits:
                    score += 1.0 + math.log1p(hits)
                    if term in str(d.get("title", "")).lower():
                        score += 1.5
                    if term in str(d.get("slug", "")).lower():
                        score += 1.0
            if score > 0:
                scored.append((score, d))

        scored.sort(key=lambda x: x[0], reverse=True)

        cap = self.config.max_results_cap
        if limit is None:
            limit = self.config.max_results_default
        limit = max(1, min(limit, cap))

        return [self._shape_preview(d, score=s) for s, d in scored[:limit]]

    @classmethod
    def _section_matches(cls, doc: dict[str, Any], section: str) -> bool:
        target = section.lower().strip()
        candidates = {
            str(doc.get("section", "")).lower(),
            cls._category_slug(doc).lower(),
            str(doc.get("path", "")).strip("/").split("/", 1)[0].lower(),
            str(doc.get("source_file", "")).split("/", 1)[0].lower(),
        }
        return target in candidates

    @staticmethod
    def _shape_preview(doc: dict[str, Any], score: float | None = None) -> dict[str, Any]:
        out = {
            "slug": doc.get("slug"),
            "title": doc.get("title"),
            "path": doc.get("path"),
            "url": doc.get("url"),
            "section": doc.get("section"),
            "category": doc.get("category"),
            "agent": doc.get("agent"),
            "severity": doc.get("severity"),
            "maturity": doc.get("maturity"),
            "ecosystem": doc.get("ecosystem"),
            "cve": doc.get("cve"),
            "ghsa": doc.get("ghsa"),
            "zero_day": doc.get("zero_day"),
            "tags": doc.get("tags") or [],
            "facets": doc.get("facets") or [],
            "quality": doc.get("quality") or {},
            "aliases": doc.get("aliases") or [],
            "summary": doc.get("summary"),
            "last_updated": doc.get("last_updated"),
            "source_file": doc.get("source_file"),
        }
        if score is not None:
            out["score"] = round(score, 4)
        return out

    @staticmethod
    def _quality_next_action(missing: list[str], score: int) -> str:
        if "output-contract" in missing:
            return "Add an explicit Output contract section with expected artifact, review evidence, and prohibited outputs."
        if "verification" in missing:
            return "Add concrete verification commands, tests, or evidence checks the agent must run or report as unavailable."
        if "guardrails" in missing:
            return "Add guardrails and stop conditions for scope, secrets, production systems, and unsafe actions."
        if "inputs" in missing:
            return "Add an Inputs section that names the finding, repo scope, evidence, and optional context."
        if "selection-guidance" in missing:
            return "Add When to use guidance so agents can choose this recipe over broader or narrower alternatives."
        if "related-context" in missing:
            return "Link related recipes or standards so agents can hand off to the next best context pack."
        if score < 85:
            return "Promote this recipe by adding stronger contracts, verification, and related context until it reaches world-class readiness."
        return "No immediate quality gap detected."


class WorkflowControlPlane:
    def __init__(self, manifest_path: str):
        self.path = Path(manifest_path)
        self._mtime: float | None = None
        self._manifest: dict[str, Any] | None = None
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._manifest is not None and self._mtime == stat.st_mtime:
            return self._manifest

        manifest = json.loads(self.path.read_text(encoding="utf-8"))
        workflows = manifest.get("workflows") if isinstance(manifest, dict) else []
        self._workflow_by_id = {
            str(workflow.get("id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("id")
        }
        self._manifest = manifest
        self._mtime = stat.st_mtime
        return manifest

    def get(self, workflow_id: str | None = None) -> dict[str, Any]:
        try:
            manifest = self._load()
        except Exception as exc:
            return {
                "available": False,
                "manifest_path": str(self.path),
                "error": f"failed to load workflow control plane manifest: {exc}",
            }

        if manifest is None:
            return {
                "available": False,
                "manifest_path": str(self.path),
                "error": "workflow control plane manifest is not present",
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_id": workflow_id,
                "workflow": workflow,
            }

        return {
            "available": True,
            "schema_version": manifest.get("schema_version"),
            "last_reviewed": manifest.get("last_reviewed"),
            "required_gate_phases": manifest.get("required_gate_phases", []),
            "standards_alignment": manifest.get("standards_alignment", []),
            "workflow_count": len(self._workflow_by_id),
            "workflows": [
                {
                    "id": workflow.get("id"),
                    "title": workflow.get("title"),
                    "status": workflow.get("status"),
                    "maturity_stage": workflow.get("maturity_stage"),
                    "public_path": workflow.get("public_path"),
                }
                for workflow in self._workflow_by_id.values()
            ],
        }


class MCPGatewayPolicyPack:
    def __init__(self, policy_path: str):
        self.path = Path(policy_path)
        self._mtime: float | None = None
        self._policy_pack: dict[str, Any] | None = None
        self._policy_by_workflow_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._policy_pack is not None and self._mtime == stat.st_mtime:
            return self._policy_pack

        policy_pack = json.loads(self.path.read_text(encoding="utf-8"))
        policies = policy_pack.get("workflow_policies") if isinstance(policy_pack, dict) else []
        self._policy_by_workflow_id = {
            str(policy.get("workflow_id")): policy
            for policy in policies
            if isinstance(policy, dict) and policy.get("workflow_id")
        }
        self._policy_pack = policy_pack
        self._mtime = stat.st_mtime
        return policy_pack

    def get(self, workflow_id: str | None = None) -> dict[str, Any]:
        try:
            policy_pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "policy_path": str(self.path),
                "error": f"failed to load MCP gateway policy pack: {exc}",
            }

        if policy_pack is None:
            return {
                "available": False,
                "policy_path": str(self.path),
                "error": "MCP gateway policy pack is not present",
            }

        if not isinstance(policy_pack, dict):
            return {
                "available": False,
                "policy_path": str(self.path),
                "error": "MCP gateway policy pack root must be an object",
            }

        if workflow_id:
            policy = self._policy_by_workflow_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": policy is not None,
                "workflow_id": workflow_id,
                "policy": policy,
            }

        return {
            "available": True,
            "schema_version": policy_pack.get("schema_version"),
            "generated_at": policy_pack.get("generated_at"),
            "policy_id": policy_pack.get("policy_id"),
            "source_manifest": policy_pack.get("source_manifest"),
            "decision_contract": policy_pack.get("decision_contract"),
            "policy_summary": policy_pack.get("policy_summary"),
            "workflow_policies": [
                {
                    "workflow_id": policy.get("workflow_id"),
                    "title": policy.get("title"),
                    "status": policy.get("status"),
                    "maturity_stage": policy.get("maturity_stage"),
                    "public_path": policy.get("public_path"),
                    "default_decision": policy.get("default_decision"),
                }
                for policy in self._policy_by_workflow_id.values()
            ],
        }

class AgenticAssurancePack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._control_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        controls = pack.get("control_objectives") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_assurance") if isinstance(pack, dict) else []
        self._control_by_id = {
            str(control.get("id")): control
            for control in controls
            if isinstance(control, dict) and control.get("id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    def get(self, control_id: str | None = None, workflow_id: str | None = None) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "pack_path": str(self.path),
                "error": f"failed to load agentic assurance pack: {exc}",
            }

        if pack is None:
            return {
                "available": False,
                "pack_path": str(self.path),
                "error": "agentic assurance pack is not present",
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "pack_path": str(self.path),
                "error": "agentic assurance pack root must be an object",
            }

        if control_id:
            control = self._control_by_id.get(control_id.strip())
            return {
                "available": True,
                "control_id": control_id,
                "found": control is not None,
                "control": control,
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_id": workflow_id,
                "workflow_assurance": workflow,
            }

        return {
            "agent_bom_seed": pack.get("agent_bom_seed"),
            "assurance_summary": pack.get("assurance_summary"),
            "available": True,
            "control_objectives": [
                {
                    "id": control.get("id"),
                    "title": control.get("title"),
                    "buyer_value": control.get("buyer_value"),
                }
                for control in self._control_by_id.values()
            ],
            "generated_at": pack.get("generated_at"),
            "positioning": pack.get("positioning"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "workflow_assurance": [
                {
                    "workflow_id": workflow.get("workflow_id"),
                    "title": workflow.get("title"),
                    "status": workflow.get("status"),
                    "maturity_stage": workflow.get("maturity_stage"),
                    "gateway_decisions": workflow.get("gateway_decisions", []),
                }
                for workflow in self._workflow_by_id.values()
            ],
        }


class AgentIdentityDelegationLedger:
    def __init__(self, ledger_path: str):
        self.path = Path(ledger_path)
        self._mtime: float | None = None
        self._ledger: dict[str, Any] | None = None
        self._identity_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._ledger is not None and self._mtime == stat.st_mtime:
            return self._ledger

        ledger = json.loads(self.path.read_text(encoding="utf-8"))
        identities = ledger.get("agent_identities") if isinstance(ledger, dict) else []
        self._identity_by_id = {
            str(identity.get("identity_id")): identity
            for identity in identities
            if isinstance(identity, dict) and identity.get("identity_id")
        }
        self._ledger = ledger
        self._mtime = stat.st_mtime
        return ledger

    @staticmethod
    def _preview(identity: dict[str, Any]) -> dict[str, Any]:
        authority = identity.get("delegated_authority") if isinstance(identity.get("delegated_authority"), dict) else {}
        return {
            "agent_class": identity.get("agent_class"),
            "identity_id": identity.get("identity_id"),
            "maturity_stage": identity.get("maturity_stage"),
            "mcp_namespaces": [
                scope.get("namespace")
                for scope in authority.get("mcp_scopes", [])
                if isinstance(scope, dict)
            ],
            "owner": identity.get("owner"),
            "risk_tier": identity.get("risk_tier"),
            "status": identity.get("status"),
            "workflow_id": identity.get("workflow_id"),
            "workflow_title": identity.get("workflow_title"),
        }

    def get(
        self,
        identity_id: str | None = None,
        workflow_id: str | None = None,
        agent_class: str | None = None,
    ) -> dict[str, Any]:
        try:
            ledger = self._load()
        except Exception as exc:
            return {
                "available": False,
                "ledger_path": str(self.path),
                "error": f"failed to load agent identity delegation ledger: {exc}",
            }

        if ledger is None:
            return {
                "available": False,
                "ledger_path": str(self.path),
                "error": "agent identity delegation ledger is not present",
            }

        if not isinstance(ledger, dict):
            return {
                "available": False,
                "ledger_path": str(self.path),
                "error": "agent identity delegation ledger root must be an object",
            }

        if identity_id:
            identity = self._identity_by_id.get(identity_id.strip())
            return {
                "available": True,
                "found": identity is not None,
                "identity": identity,
                "identity_id": identity_id,
            }

        identities = [
            identity
            for identity in self._identity_by_id.values()
            if (not workflow_id or str(identity.get("workflow_id")) == workflow_id.strip())
            and (not agent_class or str(identity.get("agent_class")) == agent_class.strip())
        ]

        if workflow_id or agent_class:
            return {
                "available": True,
                "agent_class": agent_class,
                "count": len(identities),
                "identities": identities,
                "workflow_id": workflow_id,
            }

        return {
            "available": True,
            "delegation_graph": ledger.get("delegation_graph", []),
            "enterprise_iam_contract": ledger.get("enterprise_iam_contract"),
            "generated_at": ledger.get("generated_at"),
            "identity_summary": ledger.get("identity_summary"),
            "ledger_id": ledger.get("ledger_id"),
            "schema_version": ledger.get("schema_version"),
            "source_artifacts": ledger.get("source_artifacts"),
            "standards_alignment": ledger.get("standards_alignment", []),
            "identities": [self._preview(identity) for identity in identities],
        }


class AgenticEntitlementReviewPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._entitlement_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        entitlements = pack.get("entitlements") if isinstance(pack, dict) else []
        self._entitlement_by_id = {
            str(row.get("entitlement_id")): row
            for row in entitlements
            if isinstance(row, dict) and row.get("entitlement_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "access_mode": row.get("access_mode"),
            "entitlement_id": row.get("entitlement_id"),
            "identity_id": row.get("identity_id"),
            "lease_ttl_days": row.get("lease_ttl_days"),
            "namespace": row.get("namespace"),
            "requires_human_approval": row.get("requires_human_approval"),
            "review_cadence_days": row.get("review_cadence_days"),
            "risk_tier": row.get("risk_tier"),
            "tier_id": row.get("tier_id"),
            "workflow_id": row.get("workflow_id"),
        }

    def get(
        self,
        entitlement_id: str | None = None,
        identity_id: str | None = None,
        workflow_id: str | None = None,
        namespace: str | None = None,
        access_mode: str | None = None,
        risk_tier: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic entitlement review pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic entitlement review pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic entitlement review pack root must be an object",
                "pack_path": str(self.path),
            }

        if entitlement_id:
            key = entitlement_id.strip()
            entitlement = self._entitlement_by_id.get(key)
            return {
                "available": True,
                "entitlement": entitlement,
                "entitlement_id": key,
                "found": entitlement is not None,
            }

        entitlements = list(self._entitlement_by_id.values())
        if identity_id:
            entitlements = [row for row in entitlements if str(row.get("identity_id")) == identity_id.strip()]
        if workflow_id:
            entitlements = [row for row in entitlements if str(row.get("workflow_id")) == workflow_id.strip()]
        if namespace:
            entitlements = [row for row in entitlements if str(row.get("namespace")) == namespace.strip()]
        if access_mode:
            entitlements = [row for row in entitlements if str(row.get("access_mode")) == access_mode.strip()]
        if risk_tier:
            entitlements = [row for row in entitlements if str(row.get("risk_tier")) == risk_tier.strip()]

        return {
            "available": True,
            "buyer_views": pack.get("buyer_views", []),
            "commercialization_path": pack.get("commercialization_path", {}),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "entitlement_count": len(entitlements),
            "entitlement_review_summary": pack.get("entitlement_review_summary"),
            "entitlements": [self._preview(row) for row in entitlements],
            "filters": {
                "access_mode": access_mode,
                "identity_id": identity_id,
                "namespace": namespace,
                "risk_tier": risk_tier,
                "workflow_id": workflow_id,
            },
            "generated_at": pack.get("generated_at"),
            "review_contract": pack.get("review_contract", {}),
            "runtime_policy": pack.get("runtime_policy", {}),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts", {}),
            "standards_alignment": pack.get("standards_alignment", []),
            "workflow_entitlement_rollups": pack.get("workflow_entitlement_rollups", []),
        }

class AgenticApprovalReceiptPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._profile_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        profiles = pack.get("approval_profiles") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_approval_matrix") if isinstance(pack, dict) else []
        self._profile_by_id = {
            str(row.get("id")): row
            for row in profiles
            if isinstance(row, dict) and row.get("id")
        }
        self._workflow_by_id = {
            str(row.get("workflow_id")): row
            for row in workflows
            if isinstance(row, dict) and row.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _profile_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "action_class_ids": row.get("action_class_ids", []),
            "default_decision": row.get("default_decision"),
            "id": row.get("id"),
            "max_ttl_minutes": row.get("max_ttl_minutes"),
            "minimum_approvers": row.get("minimum_approvers"),
            "required_roles": row.get("required_roles", []),
            "requires_risk_acceptance": row.get("requires_risk_acceptance"),
            "requires_separation_of_duties": row.get("requires_separation_of_duties"),
            "risk_tier": row.get("risk_tier"),
            "title": row.get("title"),
        }

    @staticmethod
    def _workflow_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "approval_required_action_count": row.get("approval_required_action_count"),
            "decision_floor": row.get("decision_floor"),
            "maturity_stage": row.get("maturity_stage"),
            "receipt_id": row.get("receipt_id"),
            "receipt_status": row.get("receipt_status"),
            "title": row.get("title"),
            "workflow_id": row.get("workflow_id"),
        }

    def get(
        self,
        approval_profile_id: str | None = None,
        workflow_id: str | None = None,
        action_class: str | None = None,
        risk_tier: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic approval receipt pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic approval receipt pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic approval receipt pack root must be an object",
                "pack_path": str(self.path),
            }

        if approval_profile_id:
            key = approval_profile_id.strip()
            profile = self._profile_by_id.get(key)
            return {
                "approval_profile": profile,
                "approval_profile_id": key,
                "available": True,
                "found": profile is not None,
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_approval": workflow,
                "workflow_id": key,
            }

        profiles = list(self._profile_by_id.values())
        if action_class:
            key = action_class.strip()
            profiles = [
                row
                for row in profiles
                if key in {str(item) for item in row.get("action_class_ids", [])}
            ]
        if risk_tier:
            key = risk_tier.strip()
            profiles = [row for row in profiles if str(row.get("risk_tier")) == key]
        if decision:
            key = decision.strip()
            profiles = [row for row in profiles if str(row.get("default_decision")) == key]

        return {
            "approval_contract": pack.get("approval_contract", {}),
            "approval_profiles": [self._profile_preview(row) for row in profiles],
            "approval_profile_count": len(profiles),
            "approval_receipt_summary": pack.get("approval_receipt_summary"),
            "available": True,
            "buyer_views": pack.get("buyer_views", []),
            "commercialization_path": pack.get("commercialization_path", {}),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "filters": {
                "action_class": action_class,
                "decision": decision,
                "risk_tier": risk_tier,
            },
            "generated_at": pack.get("generated_at"),
            "runtime_policy": pack.get("runtime_policy", {}),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts", {}),
            "standards_alignment": pack.get("standards_alignment", []),
            "workflow_approval_matrix": [
                self._workflow_preview(row)
                for row in self._workflow_by_id.values()
            ],
        }

class MCPConnectorTrustPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._connector_by_id: dict[str, dict[str, Any]] = {}
        self._connector_by_namespace: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        connectors = pack.get("connectors") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_connector_map") if isinstance(pack, dict) else []
        self._connector_by_id = {
            str(connector.get("connector_id")): connector
            for connector in connectors
            if isinstance(connector, dict) and connector.get("connector_id")
        }
        self._connector_by_namespace = {
            str(connector.get("namespace")): connector
            for connector in connectors
            if isinstance(connector, dict) and connector.get("namespace")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _preview(connector: dict[str, Any]) -> dict[str, Any]:
        trust_tier = connector.get("trust_tier") if isinstance(connector.get("trust_tier"), dict) else {}
        return {
            "access_modes": connector.get("access_modes", []),
            "category": connector.get("category"),
            "connector_id": connector.get("connector_id"),
            "namespace": connector.get("namespace"),
            "owner": connector.get("owner"),
            "status": connector.get("status"),
            "title": connector.get("title"),
            "trust_tier": trust_tier.get("id"),
        }

    def get(
        self,
        connector_id: str | None = None,
        namespace: str | None = None,
        workflow_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "pack_path": str(self.path),
                "error": f"failed to load MCP connector trust pack: {exc}",
            }

        if pack is None:
            return {
                "available": False,
                "pack_path": str(self.path),
                "error": "MCP connector trust pack is not present",
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "pack_path": str(self.path),
                "error": "MCP connector trust pack root must be an object",
            }

        if connector_id:
            connector = self._connector_by_id.get(connector_id.strip())
            return {
                "available": True,
                "connector": connector,
                "connector_id": connector_id,
                "found": connector is not None,
            }

        if namespace:
            connector = self._connector_by_namespace.get(namespace.strip())
            return {
                "available": True,
                "connector": connector,
                "found": connector is not None,
                "namespace": namespace,
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_connector_map": workflow,
                "workflow_id": workflow_id,
            }

        return {
            "available": True,
            "connector_trust_summary": pack.get("connector_trust_summary"),
            "connectors": [self._preview(connector) for connector in self._connector_by_id.values()],
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "global_control_objectives": pack.get("global_control_objectives", []),
            "policy_alignment": pack.get("policy_alignment"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "trust_tiers": pack.get("trust_tiers", []),
        }


class MCPConnectorIntakePack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._candidate_by_id: dict[str, dict[str, Any]] = {}
        self._candidate_by_namespace: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        candidates = pack.get("candidate_evaluations") if isinstance(pack, dict) else []
        self._candidate_by_id = {
            str(candidate.get("candidate_id")): candidate
            for candidate in candidates
            if isinstance(candidate, dict) and candidate.get("candidate_id")
        }
        self._candidate_by_namespace = {
            str(candidate.get("namespace")): candidate
            for candidate in candidates
            if isinstance(candidate, dict) and candidate.get("namespace")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _preview(candidate: dict[str, Any]) -> dict[str, Any]:
        return {
            "candidate_id": candidate.get("candidate_id"),
            "control_gap_count": len(candidate.get("control_gaps", []) or []),
            "intake_decision": candidate.get("intake_decision"),
            "namespace": candidate.get("namespace"),
            "recommended_trust_tier": candidate.get("recommended_trust_tier"),
            "risk_score": candidate.get("risk_score"),
            "title": candidate.get("title"),
            "transport": candidate.get("transport"),
        }

    def get(
        self,
        candidate_id: str | None = None,
        namespace: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load MCP connector intake pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "MCP connector intake pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "MCP connector intake pack root must be an object",
                "pack_path": str(self.path),
            }

        if candidate_id:
            candidate = self._candidate_by_id.get(candidate_id.strip())
            return {
                "available": True,
                "candidate": candidate,
                "candidate_id": candidate_id,
                "found": candidate is not None,
            }

        if namespace:
            candidate = self._candidate_by_namespace.get(namespace.strip())
            return {
                "available": True,
                "candidate": candidate,
                "found": candidate is not None,
                "namespace": namespace,
            }

        candidates = list(self._candidate_by_id.values())
        if decision:
            key = decision.strip()
            candidates = [
                candidate
                for candidate in candidates
                if str(candidate.get("intake_decision")) == key
            ]

        return {
            "available": True,
            "candidate_evaluations": [self._preview(candidate) for candidate in candidates],
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "intake_contract": pack.get("intake_contract"),
            "intake_summary": pack.get("intake_summary"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
        }


class MCPStdioLaunchBoundaryPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._launch_by_id: dict[str, dict[str, Any]] = {}
        self._profile_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        launches = pack.get("launch_boundaries") if isinstance(pack, dict) else []
        profiles = pack.get("launch_profiles") if isinstance(pack, dict) else []
        self._launch_by_id = {
            str(launch.get("launch_id")): launch
            for launch in launches
            if isinstance(launch, dict) and launch.get("launch_id")
        }
        self._profile_by_id = {
            str(profile.get("profile_id")): profile
            for profile in profiles
            if isinstance(profile, dict) and profile.get("profile_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _preview(launch: dict[str, Any]) -> dict[str, Any]:
        return {
            "computed_decision": launch.get("computed_decision"),
            "control_gap_count": len(launch.get("control_gaps", []) or []),
            "launch_id": launch.get("launch_id"),
            "namespace": launch.get("namespace"),
            "package_install_on_launch": launch.get("package_install_on_launch"),
            "profile_id": launch.get("profile_id"),
            "risk_finding_count": len(launch.get("risk_findings", []) or []),
            "title": launch.get("title"),
            "transport": launch.get("transport"),
        }

    def get(
        self,
        launch_id: str | None = None,
        profile_id: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load MCP STDIO launch boundary pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "MCP STDIO launch boundary pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "MCP STDIO launch boundary pack root must be an object",
                "pack_path": str(self.path),
            }

        if launch_id:
            key = launch_id.strip()
            launch = self._launch_by_id.get(key)
            return {
                "available": True,
                "found": launch is not None,
                "launch": launch,
                "launch_id": key,
            }

        launches = list(self._launch_by_id.values())
        if profile_id:
            key = profile_id.strip()
            launches = [
                launch
                for launch in launches
                if str(launch.get("profile_id")) == key
            ]
        if decision:
            key = decision.strip()
            launches = [
                launch
                for launch in launches
                if str(launch.get("computed_decision")) == key
            ]

        return {
            "available": True,
            "decision": decision,
            "decision_contract": pack.get("decision_contract"),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "launch_boundaries": [self._preview(launch) for launch in launches],
            "launch_profiles": pack.get("launch_profiles", []),
            "profile_id": profile_id,
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "stdio_launch_summary": pack.get("stdio_launch_summary"),
        }

class MCPAuthorizationConformancePack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._profile_by_id: dict[str, dict[str, Any]] = {}
        self._profile_by_namespace: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        registered = pack.get("registered_connector_authorization") if isinstance(pack, dict) else []
        candidates = pack.get("candidate_authorization") if isinstance(pack, dict) else []
        profiles = [
            profile
            for profile in [*registered, *candidates]
            if isinstance(profile, dict)
        ]
        self._profile_by_id = {
            str(profile.get("connector_id") or profile.get("candidate_id")): profile
            for profile in profiles
            if profile.get("connector_id") or profile.get("candidate_id")
        }
        self._profile_by_namespace = {
            str(profile.get("namespace")): profile
            for profile in profiles
            if profile.get("namespace")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in pack.get("workflow_authorization_map", [])
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _profile_preview(profile: dict[str, Any]) -> dict[str, Any]:
        return {
            "access_modes": profile.get("access_modes", []),
            "canonical_resource_uri": profile.get("canonical_resource_uri"),
            "conformance_decision": profile.get("conformance_decision"),
            "connector_id": profile.get("connector_id") or profile.get("candidate_id"),
            "control_gap_count": len(profile.get("control_gaps", []) or []),
            "evidence_mode": profile.get("evidence_mode"),
            "metadata_evidence_required_count": len(profile.get("metadata_evidence_required", []) or []),
            "namespace": profile.get("namespace"),
            "title": profile.get("title"),
            "transport": profile.get("transport"),
        }

    def get(
        self,
        connector_id: str | None = None,
        namespace: str | None = None,
        workflow_id: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load MCP authorization conformance pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "MCP authorization conformance pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "MCP authorization conformance pack root must be an object",
                "pack_path": str(self.path),
            }

        if connector_id:
            key = connector_id.strip()
            profile = self._profile_by_id.get(key)
            return {
                "available": True,
                "authorization_profile": profile,
                "connector_id": key,
                "found": profile is not None,
            }

        if namespace:
            key = namespace.strip()
            profile = self._profile_by_namespace.get(key)
            return {
                "available": True,
                "authorization_profile": profile,
                "found": profile is not None,
                "namespace": key,
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_authorization": workflow,
                "workflow_id": key,
            }

        profiles = list(self._profile_by_id.values())
        if decision:
            key = decision.strip()
            profiles = [
                profile
                for profile in profiles
                if str(profile.get("conformance_decision")) == key
            ]

        return {
            "available": True,
            "authorization_contract": pack.get("authorization_contract"),
            "authorization_summary": pack.get("authorization_summary"),
            "connector_authorization": [self._profile_preview(profile) for profile in profiles],
            "control_checks": pack.get("control_checks", []),
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
        }

class MCPElicitationBoundaryPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._profile_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        profiles = pack.get("elicitation_profiles") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_elicitation_map") if isinstance(pack, dict) else []
        self._profile_by_id = {
            str(profile.get("id")): profile
            for profile in profiles
            if isinstance(profile, dict) and profile.get("id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _profile_preview(profile: dict[str, Any]) -> dict[str, Any]:
        return {
            "computed_decision": profile.get("computed_decision"),
            "control_gap_count": len(profile.get("control_gaps", []) or []),
            "id": profile.get("id"),
            "mode": profile.get("mode"),
            "request_class": profile.get("request_class"),
            "risk_score": profile.get("risk_score"),
            "risk_tier": profile.get("risk_tier"),
            "title": profile.get("title"),
            "workflow_ids": profile.get("workflow_ids", []),
        }

    def get(
        self,
        profile_id: str | None = None,
        mode: str | None = None,
        decision: str | None = None,
        workflow_id: str | None = None,
        risk_tier: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load MCP elicitation boundary pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "MCP elicitation boundary pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "MCP elicitation boundary pack root must be an object",
                "pack_path": str(self.path),
            }

        if profile_id:
            key = profile_id.strip()
            profile = self._profile_by_id.get(key)
            return {
                "available": True,
                "elicitation_profile": profile,
                "found": profile is not None,
                "profile_id": key,
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_elicitation": workflow,
                "workflow_id": key,
            }

        profiles = list(self._profile_by_id.values())
        if mode:
            key = mode.strip()
            profiles = [profile for profile in profiles if str(profile.get("mode")) == key]
        if decision:
            key = decision.strip()
            profiles = [profile for profile in profiles if str(profile.get("computed_decision")) == key]
        if risk_tier:
            key = risk_tier.strip()
            profiles = [profile for profile in profiles if str(profile.get("risk_tier")) == key]

        return {
            "available": True,
            "boundary_contract": pack.get("boundary_contract"),
            "buyer_due_diligence_questions": pack.get("buyer_due_diligence_questions", []),
            "commercialization_path": pack.get("commercialization_path"),
            "control_checks": pack.get("control_checks", []),
            "decision": decision,
            "elicitation_boundary_pack_id": pack.get("elicitation_boundary_pack_id"),
            "elicitation_boundary_summary": pack.get("elicitation_boundary_summary"),
            "elicitation_profiles": [self._profile_preview(profile) for profile in profiles],
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "mode": mode,
            "risk_tier": risk_tier,
            "runtime_evidence_contract": pack.get("runtime_evidence_contract"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_pack_summaries": pack.get("source_pack_summaries"),
            "standards_alignment": pack.get("standards_alignment", []),
            "workflow_elicitation_map": pack.get("workflow_elicitation_map", []),
        }

class MCPToolRiskContract:
    def __init__(self, contract_path: str):
        self.path = Path(contract_path)
        self._mtime: float | None = None
        self._contract: dict[str, Any] | None = None
        self._profile_by_namespace: dict[str, dict[str, Any]] = {}
        self._profile_by_connector_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._contract is not None and self._mtime == stat.st_mtime:
            return self._contract

        contract = json.loads(self.path.read_text(encoding="utf-8"))
        profiles = contract.get("tool_profiles") if isinstance(contract, dict) else []
        workflows = contract.get("workflow_tool_risk") if isinstance(contract, dict) else []
        self._profile_by_namespace = {
            str(profile.get("namespace")): profile
            for profile in profiles
            if isinstance(profile, dict) and profile.get("namespace")
        }
        self._profile_by_connector_id = {
            str(profile.get("connector_id")): profile
            for profile in profiles
            if isinstance(profile, dict) and profile.get("connector_id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._contract = contract
        self._mtime = stat.st_mtime
        return contract

    @staticmethod
    def _profile_preview(profile: dict[str, Any]) -> dict[str, Any]:
        return {
            "access_modes": profile.get("access_modes", []),
            "annotation_source": profile.get("annotation_source"),
            "authorization_decision": profile.get("authorization_decision"),
            "connector_id": profile.get("connector_id"),
            "default_runtime_decision": profile.get("default_runtime_decision"),
            "namespace": profile.get("namespace"),
            "risk_factors": profile.get("risk_factors"),
            "risk_tier": profile.get("risk_tier"),
            "suggested_annotations": profile.get("suggested_annotations"),
            "title": profile.get("title"),
            "trusted_server": profile.get("trusted_server"),
        }

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "aggregate_risk_factors": workflow.get("aggregate_risk_factors"),
            "lethal_combination_possible": workflow.get("lethal_combination_possible"),
            "maturity_stage": workflow.get("maturity_stage"),
            "namespace_count": len(workflow.get("namespaces", []) or []),
            "public_path": workflow.get("public_path"),
            "recommended_session_default": workflow.get("recommended_session_default"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        namespace: str | None = None,
        connector_id: str | None = None,
        workflow_id: str | None = None,
        risk_tier: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            contract = self._load()
        except Exception as exc:
            return {
                "available": False,
                "contract_path": str(self.path),
                "error": f"failed to load MCP tool-risk contract: {exc}",
            }

        if contract is None:
            return {
                "available": False,
                "contract_path": str(self.path),
                "error": "MCP tool-risk contract is not present",
            }

        if not isinstance(contract, dict):
            return {
                "available": False,
                "contract_path": str(self.path),
                "error": "MCP tool-risk contract root must be an object",
            }

        if namespace:
            key = namespace.strip()
            profile = self._profile_by_namespace.get(key)
            return {
                "available": True,
                "found": profile is not None,
                "namespace": key,
                "tool_profile": profile,
            }

        if connector_id:
            key = connector_id.strip()
            profile = self._profile_by_connector_id.get(key)
            return {
                "available": True,
                "connector_id": key,
                "found": profile is not None,
                "tool_profile": profile,
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_id": key,
                "workflow_tool_risk": workflow,
            }

        profiles = list(self._profile_by_namespace.values())
        if risk_tier:
            key = risk_tier.strip()
            profiles = [profile for profile in profiles if str(profile.get("risk_tier")) == key]
        if decision:
            key = decision.strip()
            profiles = [profile for profile in profiles if str(profile.get("default_runtime_decision")) == key]

        return {
            "available": True,
            "control_checks": contract.get("control_checks", []),
            "decision": decision,
            "enterprise_adoption_packet": contract.get("enterprise_adoption_packet"),
            "evaluator_contract": contract.get("evaluator_contract"),
            "generated_at": contract.get("generated_at"),
            "risk_tier": risk_tier,
            "risk_tiers": contract.get("risk_tiers", []),
            "schema_version": contract.get("schema_version"),
            "selected_feature": contract.get("selected_feature"),
            "source_artifacts": contract.get("source_artifacts"),
            "standards_alignment": contract.get("standards_alignment", []),
            "tool_profile_count": len(profiles),
            "tool_profiles": [self._profile_preview(profile) for profile in profiles],
            "tool_risk_contract": contract.get("tool_risk_contract"),
            "tool_risk_summary": contract.get("tool_risk_summary"),
            "workflows": [self._workflow_preview(workflow) for workflow in self._workflow_by_id.values()],
        }

class MCPToolSurfaceDriftPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._surface_by_id: dict[str, dict[str, Any]] = {}
        self._surfaces_by_namespace: dict[str, list[dict[str, Any]]] = {}
        self._surface_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        surfaces = pack.get("tool_surfaces") if isinstance(pack, dict) else []
        self._surface_by_id = {
            str(surface.get("id")): surface
            for surface in surfaces
            if isinstance(surface, dict) and surface.get("id")
        }
        self._surfaces_by_namespace = {}
        self._surface_by_key = {}
        for surface in surfaces:
            if not isinstance(surface, dict):
                continue
            namespace = str(surface.get("namespace") or "")
            tool_name = str(surface.get("tool_name") or "")
            if namespace:
                self._surfaces_by_namespace.setdefault(namespace, []).append(surface)
            if namespace and tool_name:
                self._surface_by_key[(namespace, tool_name)] = surface
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _surface_preview(surface: dict[str, Any]) -> dict[str, Any]:
        return {
            "access_mode": surface.get("access_mode"),
            "annotations_sha256": surface.get("annotations_sha256"),
            "connector_id": surface.get("connector_id"),
            "default_runtime_decision": surface.get("default_runtime_decision"),
            "description_sha256": surface.get("description_sha256"),
            "high_impact_surface": surface.get("high_impact_surface"),
            "id": surface.get("id"),
            "input_schema_sha256": surface.get("input_schema_sha256"),
            "namespace": surface.get("namespace"),
            "output_schema_sha256": surface.get("output_schema_sha256"),
            "risk_tier": surface.get("risk_tier"),
            "source_kind": surface.get("source_kind"),
            "surface_hash": surface.get("surface_hash"),
            "title": surface.get("title"),
            "tool_name": surface.get("tool_name"),
        }

    def get(
        self,
        surface_id: str | None = None,
        namespace: str | None = None,
        tool_name: str | None = None,
        source_kind: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load MCP tool-surface drift pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "MCP tool-surface drift pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "MCP tool-surface drift pack root must be an object",
                "pack_path": str(self.path),
            }

        if surface_id:
            key = surface_id.strip()
            surface = self._surface_by_id.get(key)
            return {
                "available": True,
                "found": surface is not None,
                "surface_id": key,
                "tool_surface": surface,
            }

        if namespace and tool_name:
            namespace_key = namespace.strip()
            tool_key = tool_name.strip()
            surface = self._surface_by_key.get((namespace_key, tool_key))
            return {
                "available": True,
                "found": surface is not None,
                "namespace": namespace_key,
                "tool_name": tool_key,
                "tool_surface": surface,
            }

        surfaces = list(self._surface_by_id.values())
        if namespace:
            key = namespace.strip()
            surfaces = self._surfaces_by_namespace.get(key, [])
        if source_kind:
            key = source_kind.strip()
            surfaces = [surface for surface in surfaces if str(surface.get("source_kind")) == key]
        if decision:
            key = decision.strip()
            surfaces = [surface for surface in surfaces if str(surface.get("default_runtime_decision")) == key]

        return {
            "available": True,
            "control_checks": pack.get("control_checks", []),
            "decision": decision,
            "drift_contract": pack.get("drift_contract"),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "sample_runtime_decisions": pack.get("sample_runtime_decisions", []),
            "schema_version": pack.get("schema_version"),
            "selected_feature": pack.get("selected_feature"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_kind": source_kind,
            "standards_alignment": pack.get("standards_alignment", []),
            "tool_surface_summary": pack.get("tool_surface_summary"),
            "tool_surfaces": [self._surface_preview(surface) for surface in surfaces],
            "tool_surface_count": len(surfaces),
        }

class AgenticRedTeamDrillPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._scenario_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        scenarios = pack.get("scenario_library") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_drills") if isinstance(pack, dict) else []
        self._scenario_by_id = {
            str(scenario.get("id")): scenario
            for scenario in scenarios
            if isinstance(scenario, dict) and scenario.get("id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "drill_count": workflow.get("drill_count"),
            "maturity_stage": workflow.get("maturity_stage"),
            "public_path": workflow.get("public_path"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    @staticmethod
    def _drill_preview(workflow: dict[str, Any], drill: dict[str, Any]) -> dict[str, Any]:
        return {
            "attack_family": drill.get("attack_family"),
            "drill_id": drill.get("drill_id"),
            "expected_policy_decisions": drill.get("expected_policy_decisions", []),
            "matched_namespaces": drill.get("matched_namespaces", []),
            "required_gate_phases": drill.get("required_gate_phases", []),
            "scenario_id": drill.get("scenario_id"),
            "scenario_title": drill.get("scenario_title"),
            "severity": drill.get("severity"),
            "workflow_id": workflow.get("workflow_id"),
            "workflow_title": workflow.get("title"),
        }

    def get(
        self,
        scenario_id: str | None = None,
        workflow_id: str | None = None,
        attack_family: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "pack_path": str(self.path),
                "error": f"failed to load agentic red-team drill pack: {exc}",
            }

        if pack is None:
            return {
                "available": False,
                "pack_path": str(self.path),
                "error": "agentic red-team drill pack is not present",
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "pack_path": str(self.path),
                "error": "agentic red-team drill pack root must be an object",
            }

        workflows = list(self._workflow_by_id.values())

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_drills": workflow,
                "workflow_id": workflow_id,
            }

        if scenario_id:
            key = scenario_id.strip()
            scenario = self._scenario_by_id.get(key)
            drills = [
                self._drill_preview(workflow, drill)
                for workflow in workflows
                for drill in workflow.get("drills", [])
                if isinstance(drill, dict) and str(drill.get("scenario_id")) == key
            ]
            return {
                "available": True,
                "drill_count": len(drills),
                "drills": drills,
                "found": scenario is not None,
                "scenario": scenario,
                "scenario_id": scenario_id,
            }

        if attack_family:
            key = attack_family.strip()
            drills = [
                self._drill_preview(workflow, drill)
                for workflow in workflows
                for drill in workflow.get("drills", [])
                if isinstance(drill, dict) and str(drill.get("attack_family")) == key
            ]
            scenarios = [
                scenario
                for scenario in self._scenario_by_id.values()
                if str(scenario.get("attack_family")) == key
            ]
            return {
                "available": True,
                "attack_family": attack_family,
                "drill_count": len(drills),
                "drills": drills,
                "scenario_count": len(scenarios),
                "scenarios": scenarios,
            }

        return {
            "available": True,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "red_team_summary": pack.get("red_team_summary"),
            "scenario_contract": pack.get("scenario_contract"),
            "scenario_library": list(self._scenario_by_id.values()),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "workflow_drills": [self._workflow_preview(workflow) for workflow in workflows],
        }


class AgenticRedTeamReplayHarness:
    def __init__(self, harness_path: str):
        self.path = Path(harness_path)
        self._mtime: float | None = None
        self._harness: dict[str, Any] | None = None
        self._replay_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._harness is not None and self._mtime == stat.st_mtime:
            return self._harness

        harness = json.loads(self.path.read_text(encoding="utf-8"))
        replays = harness.get("replay_fixtures") if isinstance(harness, dict) else []
        self._replay_by_id = {
            str(replay.get("replay_id")): replay
            for replay in replays
            if isinstance(replay, dict) and replay.get("replay_id")
        }
        self._harness = harness
        self._mtime = stat.st_mtime
        return harness

    @staticmethod
    def _replay_preview(replay: dict[str, Any]) -> dict[str, Any]:
        return {
            "attack_family": replay.get("attack_family"),
            "expected_policy_decisions": replay.get("expected_policy_decisions", []),
            "expected_runtime_outcome": replay.get("expected_runtime_outcome"),
            "fixture_count": len(replay.get("fixture_inputs", []) or []),
            "replay_id": replay.get("replay_id"),
            "scenario_id": replay.get("scenario_id"),
            "scenario_title": replay.get("scenario_title"),
            "severity": replay.get("severity"),
            "status": replay.get("status"),
            "workflow_id": replay.get("workflow_id"),
            "workflow_title": replay.get("workflow_title"),
        }

    def get(
        self,
        replay_id: str | None = None,
        workflow_id: str | None = None,
        scenario_id: str | None = None,
        attack_family: str | None = None,
        severity: str | None = None,
    ) -> dict[str, Any]:
        try:
            harness = self._load()
        except Exception as exc:
            return {
                "available": False,
                "harness_path": str(self.path),
                "error": f"failed to load agentic red-team replay harness: {exc}",
            }

        if harness is None:
            return {
                "available": False,
                "harness_path": str(self.path),
                "error": "agentic red-team replay harness is not present",
            }

        if not isinstance(harness, dict):
            return {
                "available": False,
                "harness_path": str(self.path),
                "error": "agentic red-team replay harness root must be an object",
            }

        if replay_id:
            replay = self._replay_by_id.get(replay_id.strip())
            return {
                "available": True,
                "found": replay is not None,
                "replay": replay,
                "replay_id": replay_id,
            }

        replays = list(self._replay_by_id.values())
        if workflow_id:
            key = workflow_id.strip()
            replays = [replay for replay in replays if str(replay.get("workflow_id")) == key]
        if scenario_id:
            key = scenario_id.strip()
            replays = [replay for replay in replays if str(replay.get("scenario_id")) == key]
        if attack_family:
            key = attack_family.strip()
            replays = [replay for replay in replays if str(replay.get("attack_family")) == key]
        if severity:
            key = severity.strip()
            replays = [replay for replay in replays if str(replay.get("severity")) == key]

        if workflow_id or scenario_id or attack_family or severity:
            return {
                "available": True,
                "count": len(replays),
                "filters": {
                    "attack_family": attack_family,
                    "scenario_id": scenario_id,
                    "severity": severity,
                    "workflow_id": workflow_id,
                },
                "replays": [self._replay_preview(replay) for replay in replays],
            }

        return {
            "available": True,
            "enterprise_adoption_packet": harness.get("enterprise_adoption_packet"),
            "evaluator_contract": harness.get("evaluator_contract"),
            "generated_at": harness.get("generated_at"),
            "harness_contract": harness.get("harness_contract"),
            "red_team_replay_harness_id": harness.get("red_team_replay_harness_id"),
            "replay_modes": harness.get("replay_modes", []),
            "replay_pass_gates": harness.get("replay_pass_gates", []),
            "replay_summary": harness.get("replay_summary"),
            "schema_version": harness.get("schema_version"),
            "source_artifacts": harness.get("source_artifacts"),
            "source_references": harness.get("source_references", []),
            "workflow_replay_matrix": harness.get("workflow_replay_matrix", []),
        }

class AgenticReadinessScorecard:
    def __init__(self, scorecard_path: str):
        self.path = Path(scorecard_path)
        self._mtime: float | None = None
        self._scorecard: dict[str, Any] | None = None
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._scorecard is not None and self._mtime == stat.st_mtime:
            return self._scorecard

        scorecard = json.loads(self.path.read_text(encoding="utf-8"))
        workflows = scorecard.get("workflow_readiness") if isinstance(scorecard, dict) else []
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._scorecard = scorecard
        self._mtime = stat.st_mtime
        return scorecard

    @staticmethod
    def _preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "blocker_count": len(workflow.get("blockers", []) or []),
            "decision": workflow.get("decision"),
            "maturity_stage": workflow.get("maturity_stage"),
            "next_actions": workflow.get("next_actions", []),
            "pilot_connectors": [
                connector.get("namespace")
                for connector in workflow.get("connector_statuses", [])
                if isinstance(connector, dict) and connector.get("status") == "pilot"
            ],
            "public_path": workflow.get("public_path"),
            "score": workflow.get("score"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        workflow_id: str | None = None,
        decision: str | None = None,
        minimum_score: int | None = None,
    ) -> dict[str, Any]:
        try:
            scorecard = self._load()
        except Exception as exc:
            return {
                "available": False,
                "scorecard_path": str(self.path),
                "error": f"failed to load agentic readiness scorecard: {exc}",
            }

        if scorecard is None:
            return {
                "available": False,
                "scorecard_path": str(self.path),
                "error": "agentic readiness scorecard is not present",
            }

        if not isinstance(scorecard, dict):
            return {
                "available": False,
                "scorecard_path": str(self.path),
                "error": "agentic readiness scorecard root must be an object",
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_id": workflow_id,
                "workflow_readiness": workflow,
            }

        workflows = list(self._workflow_by_id.values())
        if decision:
            key = decision.strip()
            workflows = [
                workflow
                for workflow in workflows
                if str(workflow.get("decision")) == key
            ]
        if minimum_score is not None:
            workflows = [
                workflow
                for workflow in workflows
                if int(workflow.get("score") or 0) >= minimum_score
            ]

        return {
            "available": True,
            "decision": decision,
            "decision_contract": scorecard.get("decision_contract"),
            "enterprise_adoption_packet": scorecard.get("enterprise_adoption_packet"),
            "generated_at": scorecard.get("generated_at"),
            "minimum_score": minimum_score,
            "readiness_summary": scorecard.get("readiness_summary"),
            "scale_plan": scorecard.get("scale_plan"),
            "schema_version": scorecard.get("schema_version"),
            "score_dimensions": scorecard.get("score_dimensions", []),
            "source_artifacts": scorecard.get("source_artifacts"),
            "standards_alignment": scorecard.get("standards_alignment", []),
            "workflows": [self._preview(workflow) for workflow in workflows],
        }


class AgentCapabilityRiskRegister:
    def __init__(self, register_path: str):
        self.path = Path(register_path)
        self._mtime: float | None = None
        self._register: dict[str, Any] | None = None
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._register is not None and self._mtime == stat.st_mtime:
            return self._register

        register = json.loads(self.path.read_text(encoding="utf-8"))
        workflows = register.get("workflow_capability_risks") if isinstance(register, dict) else []
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._register = register
        self._mtime = stat.st_mtime
        return register

    @staticmethod
    def _preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "control_credit": workflow.get("control_credit"),
            "decision": workflow.get("decision"),
            "maturity_stage": workflow.get("maturity_stage"),
            "next_actions": workflow.get("next_actions", []),
            "raw_capability_score": workflow.get("raw_capability_score"),
            "readiness_decision": workflow.get("readiness_decision"),
            "readiness_score": workflow.get("readiness_score"),
            "residual_risk_score": workflow.get("residual_risk_score"),
            "risk_tier": workflow.get("risk_tier"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        workflow_id: str | None = None,
        risk_tier: str | None = None,
        decision: str | None = None,
        minimum_residual_score: int | None = None,
    ) -> dict[str, Any]:
        try:
            register = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agent capability risk register: {exc}",
                "register_path": str(self.path),
            }

        if register is None:
            return {
                "available": False,
                "error": "agent capability risk register is not present",
                "register_path": str(self.path),
            }

        if not isinstance(register, dict):
            return {
                "available": False,
                "error": "agent capability risk register root must be an object",
                "register_path": str(self.path),
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_capability_risk": workflow,
                "workflow_id": workflow_id,
            }

        workflows = list(self._workflow_by_id.values())
        if risk_tier:
            key = risk_tier.strip()
            workflows = [
                workflow
                for workflow in workflows
                if str(workflow.get("risk_tier")) == key
            ]
        if decision:
            key = decision.strip()
            workflows = [
                workflow
                for workflow in workflows
                if str(workflow.get("decision")) == key
            ]
        if minimum_residual_score is not None:
            workflows = [
                workflow
                for workflow in workflows
                if int(workflow.get("residual_risk_score") or 0) >= minimum_residual_score
            ]

        workflows = sorted(
            workflows,
            key=lambda workflow: (
                -int(workflow.get("residual_risk_score") or 0),
                str(workflow.get("workflow_id")),
            ),
        )
        return {
            "available": True,
            "capability_risk_summary": register.get("capability_risk_summary"),
            "decision": decision,
            "enterprise_adoption_packet": register.get("enterprise_adoption_packet"),
            "factor_model": register.get("factor_model", []),
            "generated_at": register.get("generated_at"),
            "minimum_residual_score": minimum_residual_score,
            "risk_tier": risk_tier,
            "risk_tiers": register.get("risk_tiers", []),
            "schema_version": register.get("schema_version"),
            "source_artifacts": register.get("source_artifacts"),
            "standards_alignment": register.get("standards_alignment", []),
            "workflow_capability_risks": [
                self._preview(workflow)
                for workflow in workflows
            ],
        }


class AgentSkillSupplyChainPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._skill_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        skills = pack.get("skill_profiles") if isinstance(pack, dict) else []
        self._skill_by_id = {
            str(skill.get("skill_id")): skill
            for skill in skills
            if isinstance(skill, dict) and skill.get("skill_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _preview(skill: dict[str, Any]) -> dict[str, Any]:
        return {
            "allowed_workflow_ids": skill.get("allowed_workflow_ids", []),
            "decision": skill.get("decision"),
            "lethal_trifecta": skill.get("lethal_trifecta"),
            "next_actions": skill.get("next_actions", []),
            "package_hash": skill.get("package_hash"),
            "platforms": skill.get("platforms", []),
            "publisher": skill.get("publisher", {}),
            "registry": skill.get("registry", {}),
            "residual_risk_score": skill.get("residual_risk_score"),
            "risk_tier": skill.get("risk_tier"),
            "sandbox_required": skill.get("sandbox_required"),
            "scan_status": skill.get("scan_status"),
            "signature_present": skill.get("signature_present"),
            "skill_id": skill.get("skill_id"),
            "title": skill.get("title"),
            "version": skill.get("version"),
            "version_pinned": skill.get("version_pinned"),
        }

    def get(
        self,
        skill_id: str | None = None,
        platform: str | None = None,
        decision: str | None = None,
        risk_tier: str | None = None,
        minimum_score: int | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agent skill supply-chain pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agent skill supply-chain pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agent skill supply-chain pack root must be an object",
                "pack_path": str(self.path),
            }

        if skill_id:
            skill = self._skill_by_id.get(skill_id.strip())
            return {
                "available": True,
                "found": skill is not None,
                "skill": skill,
                "skill_id": skill_id,
            }

        skills = list(self._skill_by_id.values())
        if platform:
            key = platform.strip()
            skills = [
                skill
                for skill in skills
                if key in {str(item) for item in skill.get("platforms", []) or []}
            ]
        if decision:
            key = decision.strip()
            skills = [
                skill
                for skill in skills
                if str(skill.get("decision")) == key
            ]
        if risk_tier:
            key = risk_tier.strip()
            skills = [
                skill
                for skill in skills
                if str(skill.get("risk_tier")) == key
            ]
        if minimum_score is not None:
            skills = [
                skill
                for skill in skills
                if int(skill.get("residual_risk_score") or 0) >= minimum_score
            ]

        skills = sorted(
            skills,
            key=lambda skill: (
                -int(skill.get("residual_risk_score") or 0),
                str(skill.get("skill_id")),
            ),
        )
        return {
            "available": True,
            "decision": decision,
            "decision_contract": pack.get("decision_contract"),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "minimum_score": minimum_score,
            "platform": platform,
            "risk_model": pack.get("risk_model", {}),
            "risk_tier": risk_tier,
            "schema_version": pack.get("schema_version"),
            "skill_profiles": [self._preview(skill) for skill in skills],
            "skill_supply_chain_summary": pack.get("skill_supply_chain_summary"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
        }

class AgentHandoffBoundaryPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._profile_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        profiles = pack.get("handoff_profiles") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_handoff_map") if isinstance(pack, dict) else []
        self._profile_by_id = {
            str(profile.get("profile_id")): profile
            for profile in profiles
            if isinstance(profile, dict) and profile.get("profile_id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _profile_preview(profile: dict[str, Any]) -> dict[str, Any]:
        return {
            "allowed_protocols": profile.get("allowed_protocols", []),
            "default_decision": profile.get("default_decision"),
            "profile_id": profile.get("profile_id"),
            "required_controls": profile.get("required_controls", []),
            "risk_tier": profile.get("risk_tier"),
            "title": profile.get("title"),
        }

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "agent_classes": workflow.get("agent_classes", []),
            "approved_profile_ids": workflow.get("approved_profile_ids", []),
            "context_package_hash": workflow.get("context_package_hash"),
            "egress_policy_hash": workflow.get("egress_policy_hash"),
            "identity_ids": workflow.get("identity_ids", []),
            "maturity_stage": workflow.get("maturity_stage"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        profile_id: str | None = None,
        workflow_id: str | None = None,
        protocol: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agent handoff boundary pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agent handoff boundary pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agent handoff boundary pack root must be an object",
                "pack_path": str(self.path),
            }

        if profile_id:
            profile = self._profile_by_id.get(profile_id.strip())
            return {
                "available": True,
                "found": profile is not None,
                "profile": profile,
                "profile_id": profile_id,
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow": workflow,
                "workflow_id": workflow_id,
            }

        profiles = list(self._profile_by_id.values())
        if protocol:
            key = protocol.strip()
            profiles = [
                profile
                for profile in profiles
                if key in {str(item) for item in profile.get("allowed_protocols", []) or []}
            ]
        if decision:
            key = decision.strip()
            profiles = [
                profile
                for profile in profiles
                if str(profile.get("default_decision")) == key
            ]

        return {
            "available": True,
            "decision": decision,
            "decision_contract": pack.get("decision_contract"),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "handoff_boundary_summary": pack.get("handoff_boundary_summary"),
            "handoff_profiles": [self._profile_preview(profile) for profile in profiles],
            "protocol": protocol,
            "protocol_surfaces": pack.get("protocol_surfaces", []),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "threat_signal_coverage": pack.get("threat_signal_coverage", []),
            "workflow_handoff_map": [
                self._workflow_preview(workflow)
                for workflow in self._workflow_by_id.values()
            ],
        }

class A2AAgentCardTrustProfile:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._profile_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        profiles = pack.get("intake_profiles") if isinstance(pack, dict) else []
        self._profile_by_id = {
            str(profile.get("id")): profile
            for profile in profiles
            if isinstance(profile, dict) and profile.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _profile_preview(profile: dict[str, Any]) -> dict[str, Any]:
        return {
            "allowed_handoff_profiles": profile.get("allowed_handoff_profiles", []),
            "default_decision": profile.get("default_decision"),
            "id": profile.get("id"),
            "required_controls": profile.get("required_controls", []),
            "risk_tier": profile.get("risk_tier"),
            "title": profile.get("title"),
        }

    def get(
        self,
        profile_id: str | None = None,
        decision: str | None = None,
        risk_tier: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load A2A Agent Card trust profile: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "A2A Agent Card trust profile is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "A2A Agent Card trust profile root must be an object",
                "pack_path": str(self.path),
            }

        if profile_id:
            profile = self._profile_by_id.get(profile_id.strip())
            return {
                "available": True,
                "found": profile is not None,
                "profile": profile,
                "profile_id": profile_id,
            }

        profiles = list(self._profile_by_id.values())
        if decision:
            key = decision.strip()
            profiles = [
                profile
                for profile in profiles
                if str(profile.get("default_decision")) == key
            ]
        if risk_tier:
            key = risk_tier.strip()
            profiles = [
                profile
                for profile in profiles
                if str(profile.get("risk_tier")) == key
            ]

        return {
            "available": True,
            "agent_card_trust_summary": pack.get("agent_card_trust_summary"),
            "commercialization_path": pack.get("commercialization_path"),
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "handoff_integration": pack.get("handoff_integration"),
            "intake_profiles": [self._profile_preview(profile) for profile in profiles],
            "risk_tier": risk_tier,
            "sample_agent_card_evaluations": pack.get("sample_agent_card_evaluations", []),
            "schema_version": pack.get("schema_version"),
            "skill_risk_taxonomy": pack.get("skill_risk_taxonomy", []),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "threat_signal_coverage": pack.get("threat_signal_coverage", []),
            "trust_contract": pack.get("trust_contract"),
        }

class AgentMemoryBoundaryPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._class_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        classes = pack.get("memory_classes") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_memory_profiles") if isinstance(pack, dict) else []
        self._class_by_id = {
            str(memory_class.get("id")): memory_class
            for memory_class in classes
            if isinstance(memory_class, dict) and memory_class.get("id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _class_preview(memory_class: dict[str, Any]) -> dict[str, Any]:
        return {
            "default_decision": memory_class.get("default_decision"),
            "exposure": memory_class.get("exposure"),
            "human_approval_required": memory_class.get("human_approval_required"),
            "id": memory_class.get("id"),
            "kind": memory_class.get("kind"),
            "max_ttl_days": memory_class.get("max_ttl_days"),
            "persistent": memory_class.get("persistent"),
            "runtime_writes_allowed": memory_class.get("runtime_writes_allowed"),
            "tenant_id_required": memory_class.get("tenant_id_required"),
            "title": memory_class.get("title"),
            "trust_tier": memory_class.get("trust_tier"),
        }

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "allowed_memory_class_ids": workflow.get("allowed_memory_class_ids", []),
            "hold_memory_class_ids": workflow.get("hold_memory_class_ids", []),
            "kill_memory_class_ids": workflow.get("kill_memory_class_ids", []),
            "maturity_stage": workflow.get("maturity_stage"),
            "memory_profile_hash": workflow.get("memory_profile_hash"),
            "public_path": workflow.get("public_path"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        memory_class_id: str | None = None,
        workflow_id: str | None = None,
        decision: str | None = None,
        persistent: bool | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agent memory boundary pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agent memory boundary pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agent memory boundary pack root must be an object",
                "pack_path": str(self.path),
            }

        if memory_class_id:
            memory_class = self._class_by_id.get(memory_class_id.strip())
            return {
                "available": True,
                "found": memory_class is not None,
                "memory_class": memory_class,
                "memory_class_id": memory_class_id,
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_id": workflow_id,
                "workflow_memory_profile": workflow,
            }

        classes = list(self._class_by_id.values())
        if decision:
            key = decision.strip()
            classes = [
                memory_class
                for memory_class in classes
                if str(memory_class.get("default_decision")) == key
            ]
        if persistent is not None:
            classes = [
                memory_class
                for memory_class in classes
                if bool(memory_class.get("persistent")) is persistent
            ]

        return {
            "available": True,
            "agent_memory_boundary_summary": pack.get("agent_memory_boundary_summary"),
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "memory_classes": [
                self._class_preview(memory_class)
                for memory_class in classes
            ],
            "memory_decision_contract": pack.get("memory_decision_contract"),
            "persistent": persistent,
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "workflow_memory_defaults": pack.get("workflow_memory_defaults"),
            "workflows": [
                self._workflow_preview(workflow)
                for workflow in self._workflow_by_id.values()
            ],
        }

class AgenticSystemBOM:
    def __init__(self, bom_path: str):
        self.path = Path(bom_path)
        self._mtime: float | None = None
        self._bom: dict[str, Any] | None = None
        self._components: dict[str, list[dict[str, Any]]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}
        self._agent_class_by_name: dict[str, dict[str, Any]] = {}
        self._connector_by_namespace: dict[str, dict[str, Any]] = {}
        self._identity_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._bom is not None and self._mtime == stat.st_mtime:
            return self._bom

        bom = json.loads(self.path.read_text(encoding="utf-8"))
        components = bom.get("components") if isinstance(bom, dict) and isinstance(bom.get("components"), dict) else {}
        self._components = {
            str(component_type): [
                item for item in items if isinstance(item, dict)
            ]
            for component_type, items in components.items()
            if isinstance(items, list)
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in self._components.get("workflows", [])
            if workflow.get("workflow_id")
        }
        self._agent_class_by_name = {
            str(agent_class.get("agent_class")): agent_class
            for agent_class in self._components.get("agent_classes", [])
            if agent_class.get("agent_class")
        }
        self._connector_by_namespace = {
            str(connector.get("namespace")): connector
            for connector in self._components.get("mcp_connectors", [])
            if connector.get("namespace")
        }
        self._identity_by_id = {
            str(identity.get("component_id")): identity
            for identity in self._components.get("agent_identities", [])
            if identity.get("component_id")
        }
        self._bom = bom
        self._mtime = stat.st_mtime
        return bom

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "agent_classes": workflow.get("agent_classes", []),
            "maturity_stage": workflow.get("maturity_stage"),
            "mcp_namespaces": [
                namespace.get("namespace")
                for namespace in workflow.get("mcp_namespaces", [])
                if isinstance(namespace, dict)
            ],
            "readiness_decision": workflow.get("readiness_decision"),
            "readiness_score": workflow.get("readiness_score"),
            "red_team_drill_count": workflow.get("red_team_drill_count"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        component_type: str | None = None,
        workflow_id: str | None = None,
        agent_class: str | None = None,
        namespace: str | None = None,
    ) -> dict[str, Any]:
        try:
            bom = self._load()
        except Exception as exc:
            return {
                "available": False,
                "bom_path": str(self.path),
                "error": f"failed to load agentic system BOM: {exc}",
            }

        if bom is None:
            return {
                "available": False,
                "bom_path": str(self.path),
                "error": "agentic system BOM is not present",
            }

        if not isinstance(bom, dict):
            return {
                "available": False,
                "bom_path": str(self.path),
                "error": "agentic system BOM root must be an object",
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_bom": workflow,
                "workflow_id": workflow_id,
            }

        if agent_class:
            key = agent_class.strip()
            identities = [
                identity
                for identity in self._identity_by_id.values()
                if str(identity.get("agent_class")) == key
            ]
            return {
                "agent_class": key,
                "agent_class_component": self._agent_class_by_name.get(key),
                "available": True,
                "found": key in self._agent_class_by_name,
                "identity_count": len(identities),
                "identities": identities,
            }

        if namespace:
            key = namespace.strip()
            workflows = [
                self._workflow_preview(workflow)
                for workflow in self._workflow_by_id.values()
                if any(
                    isinstance(item, dict) and item.get("namespace") == key
                    for item in workflow.get("mcp_namespaces", [])
                )
            ]
            return {
                "available": True,
                "connector": self._connector_by_namespace.get(key),
                "found": key in self._connector_by_namespace,
                "namespace": key,
                "workflow_count": len(workflows),
                "workflows": workflows,
            }

        if component_type:
            key = component_type.strip()
            components = self._components.get(key)
            return {
                "available": True,
                "component_type": key,
                "components": components or [],
                "count": len(components or []),
                "found": components is not None,
            }

        return {
            "available": True,
            "bom_format": bom.get("bom_format"),
            "bom_id": bom.get("bom_id"),
            "bom_summary": bom.get("bom_summary"),
            "change_control_contract": bom.get("change_control_contract"),
            "enterprise_adoption_packet": bom.get("enterprise_adoption_packet"),
            "generated_at": bom.get("generated_at"),
            "schema_version": bom.get("schema_version"),
            "source_artifacts": bom.get("source_artifacts"),
            "standards_alignment": bom.get("standards_alignment", []),
            "update_triggers": bom.get("update_triggers", []),
            "workflows": [
                self._workflow_preview(workflow)
                for workflow in self._workflow_by_id.values()
            ],
        }


class AgenticRunReceiptPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._template_by_receipt_id: dict[str, dict[str, Any]] = {}
        self._template_by_workflow_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        templates = pack.get("workflow_receipt_templates") if isinstance(pack, dict) else []
        self._template_by_receipt_id = {
            str(template.get("receipt_id")): template
            for template in templates
            if isinstance(template, dict) and template.get("receipt_id")
        }
        self._template_by_workflow_id = {
            str(template.get("workflow_id")): template
            for template in templates
            if isinstance(template, dict) and template.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _template_preview(template: dict[str, Any]) -> dict[str, Any]:
        return {
            "agent_classes": template.get("agent_classes", []),
            "approval_required_namespaces": template.get("approval_required_namespaces", []),
            "context_package_hash": template.get("context_package_hash"),
            "egress_policy_hash": template.get("egress_policy_hash"),
            "mcp_namespaces": template.get("mcp_namespaces", []),
            "readiness_decision": template.get("readiness_decision"),
            "readiness_score": template.get("readiness_score"),
            "receipt_id": template.get("receipt_id"),
            "receipt_status": template.get("receipt_status"),
            "red_team_drill_count": template.get("red_team_drill_count"),
            "required_event_class_count": template.get("required_event_class_count"),
            "title": template.get("title"),
            "workflow_id": template.get("workflow_id"),
        }

    def get(
        self,
        workflow_id: str | None = None,
        receipt_id: str | None = None,
        minimum_score: int | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic run receipt pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic run receipt pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic run receipt pack root must be an object",
                "pack_path": str(self.path),
            }

        if receipt_id:
            key = receipt_id.strip()
            template = self._template_by_receipt_id.get(key)
            return {
                "available": True,
                "found": template is not None,
                "receipt_id": key,
                "receipt_template": template,
            }

        if workflow_id:
            key = workflow_id.strip()
            template = self._template_by_workflow_id.get(key)
            return {
                "available": True,
                "found": template is not None,
                "receipt_template": template,
                "workflow_id": key,
            }

        templates = list(self._template_by_workflow_id.values())
        if minimum_score is not None:
            templates = [
                template
                for template in templates
                if isinstance(template.get("readiness_score"), int)
                and template.get("readiness_score") >= minimum_score
            ]

        return {
            "available": True,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "example_receipt_envelope": pack.get("example_receipt_envelope"),
            "generated_at": pack.get("generated_at"),
            "minimum_score": minimum_score,
            "receipt_contract": pack.get("receipt_contract"),
            "receipt_pack_id": pack.get("receipt_pack_id"),
            "receipt_summary": pack.get("receipt_summary"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "workflow_receipt_templates": [
                self._template_preview(template)
                for template in templates
            ],
        }


class SecureContextTrustPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._source_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        sources = pack.get("context_sources") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_context_map") if isinstance(pack, dict) else []
        self._source_by_id = {
            str(source.get("source_id")): source
            for source in sources
            if isinstance(source, dict) and source.get("source_id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _source_preview(source: dict[str, Any]) -> dict[str, Any]:
        trust_tier = source.get("trust_tier") if isinstance(source.get("trust_tier"), dict) else {}
        return {
            "citation_required": source.get("citation_required"),
            "decision": source.get("decision"),
            "exposure": source.get("exposure"),
            "file_count": source.get("file_count"),
            "freshness_state": source.get("freshness_state"),
            "kind": source.get("kind"),
            "root": source.get("root"),
            "source_hash": source.get("source_hash"),
            "source_id": source.get("source_id"),
            "title": source.get("title"),
            "trust_tier": trust_tier.get("id"),
        }

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "context_package_hash": workflow.get("context_package_hash"),
            "context_source_count": workflow.get("context_source_count"),
            "freshness_state": workflow.get("freshness_state"),
            "maturity_stage": workflow.get("maturity_stage"),
            "mcp_namespaces": workflow.get("mcp_namespaces", []),
            "source_ids": workflow.get("source_ids", []),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        source_id: str | None = None,
        workflow_id: str | None = None,
        trust_tier: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load secure context trust pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "secure context trust pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "secure context trust pack root must be an object",
                "pack_path": str(self.path),
            }

        if source_id:
            source = self._source_by_id.get(source_id.strip())
            return {
                "available": True,
                "found": source is not None,
                "source": source,
                "source_id": source_id,
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            sources = []
            if workflow:
                sources = [
                    self._source_preview(self._source_by_id[source])
                    for source in workflow.get("source_ids", [])
                    if source in self._source_by_id
                ]
            return {
                "available": True,
                "found": workflow is not None,
                "sources": sources,
                "workflow_context": workflow,
                "workflow_id": workflow_id,
            }

        sources = list(self._source_by_id.values())
        if trust_tier:
            key = trust_tier.strip()
            sources = [
                source
                for source in sources
                if isinstance(source.get("trust_tier"), dict)
                and source.get("trust_tier", {}).get("id") == key
            ]
        if decision:
            key = decision.strip()
            sources = [
                source
                for source in sources
                if str(source.get("decision")) == key
            ]

        return {
            "available": True,
            "context_sources": [self._source_preview(source) for source in sources],
            "context_trust_summary": pack.get("context_trust_summary"),
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "retrieval_decision_contract": pack.get("retrieval_decision_contract"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_contract": pack.get("source_contract"),
            "standards_alignment": pack.get("standards_alignment", []),
            "trust_tier": trust_tier,
            "workflow_context_map": [
                self._workflow_preview(workflow)
                for workflow in self._workflow_by_id.values()
            ],
        }

class SecureContextAttestationPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._source_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}
        self._artifact_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        manifest = pack.get("attestation_manifest") if isinstance(pack, dict) else {}
        sources = manifest.get("context_source_attestations") if isinstance(manifest, dict) else []
        workflows = manifest.get("workflow_context_package_attestations") if isinstance(manifest, dict) else []
        artifacts = manifest.get("source_artifact_attestations") if isinstance(manifest, dict) else []
        self._source_by_id = {
            str(source.get("source_id")): source
            for source in sources
            if isinstance(source, dict) and source.get("source_id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._artifact_by_id = {
            str(artifact.get("attestation_id")).removeprefix("artifact-"): artifact
            for artifact in artifacts
            if isinstance(artifact, dict) and artifact.get("attestation_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _subject_preview(subject: dict[str, Any]) -> dict[str, Any]:
        return {
            "attestation_id": subject.get("attestation_id"),
            "decision": subject.get("decision"),
            "freshness_state": subject.get("freshness_state"),
            "source_id": subject.get("source_id"),
            "status": subject.get("status"),
            "subject_type": subject.get("subject_type"),
            "title": subject.get("title"),
            "trust_tier": subject.get("trust_tier"),
            "workflow_id": subject.get("workflow_id"),
        }

    def get(
        self,
        source_id: str | None = None,
        workflow_id: str | None = None,
        artifact_id: str | None = None,
        subject_type: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load secure context attestation pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "secure context attestation pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "secure context attestation pack root must be an object",
                "pack_path": str(self.path),
            }

        if source_id:
            subject = self._source_by_id.get(source_id.strip())
            return {
                "available": True,
                "found": subject is not None,
                "source_id": source_id,
                "subject": subject,
            }

        if workflow_id:
            subject = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": subject is not None,
                "subject": subject,
                "workflow_id": workflow_id,
            }

        if artifact_id:
            subject = self._artifact_by_id.get(artifact_id.strip())
            return {
                "artifact_id": artifact_id,
                "available": True,
                "found": subject is not None,
                "subject": subject,
            }

        subjects = [
            *self._source_by_id.values(),
            *self._workflow_by_id.values(),
            *self._artifact_by_id.values(),
        ]
        if subject_type:
            key = subject_type.strip()
            subjects = [subject for subject in subjects if str(subject.get("subject_type")) == key]
        if status:
            key = status.strip()
            subjects = [subject for subject in subjects if str(subject.get("status")) == key]

        return {
            "available": True,
            "attestation_contract": pack.get("attestation_contract"),
            "attestation_summary": pack.get("attestation_summary"),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "in_toto_statement_sha256": pack.get("in_toto_statement_sha256"),
            "recertification_queue": pack.get("recertification_queue", []),
            "schema_version": pack.get("schema_version"),
            "signature_readiness": pack.get("signature_readiness"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "subjects": [self._subject_preview(subject) for subject in subjects],
            "verification_policy": pack.get("verification_policy"),
        }

class SecureContextLineageLedger:
    def __init__(self, ledger_path: str):
        self.path = Path(ledger_path)
        self._mtime: float | None = None
        self._ledger: dict[str, Any] | None = None
        self._source_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._ledger is not None and self._mtime == stat.st_mtime:
            return self._ledger

        ledger = json.loads(self.path.read_text(encoding="utf-8"))
        sources = ledger.get("source_lineage") if isinstance(ledger, dict) else []
        workflows = ledger.get("workflow_lineage") if isinstance(ledger, dict) else []
        self._source_by_id = {
            str(source.get("source_id")): source
            for source in sources
            if isinstance(source, dict) and source.get("source_id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._ledger = ledger
        self._mtime = stat.st_mtime
        return ledger

    @staticmethod
    def _source_preview(source: dict[str, Any]) -> dict[str, Any]:
        poisoning = source.get("poisoning") if isinstance(source.get("poisoning"), dict) else {}
        return {
            "allowed_reuse_classes": source.get("allowed_reuse_classes", []),
            "decision": source.get("decision"),
            "exposure": source.get("exposure"),
            "poisoning_decision": poisoning.get("decision"),
            "source_hash": source.get("source_hash"),
            "source_id": source.get("source_id"),
            "title": source.get("title"),
            "trust_tier": source.get("trust_tier"),
        }

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "approved_reuse_classes": workflow.get("approved_reuse_classes", []),
            "context_package_hash": workflow.get("context_package_hash"),
            "decision": workflow.get("decision"),
            "egress_policy_hash": workflow.get("egress_policy_hash"),
            "mcp_namespaces": workflow.get("mcp_namespaces", []),
            "receipt_id": workflow.get("receipt_id"),
            "source_decision_counts": workflow.get("source_decision_counts", {}),
            "source_ids": workflow.get("source_ids", []),
            "telemetry_decision": workflow.get("telemetry_decision"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        source_id: str | None = None,
        workflow_id: str | None = None,
        decision: str | None = None,
        reuse_class: str | None = None,
        stage_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            ledger = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load secure context lineage ledger: {exc}",
                "ledger_path": str(self.path),
            }

        if ledger is None:
            return {
                "available": False,
                "error": "secure context lineage ledger is not present",
                "ledger_path": str(self.path),
            }

        if not isinstance(ledger, dict):
            return {
                "available": False,
                "error": "secure context lineage ledger root must be an object",
                "ledger_path": str(self.path),
            }

        if source_id:
            source = self._source_by_id.get(source_id.strip())
            return {
                "available": True,
                "found": source is not None,
                "source": source,
                "source_id": source_id,
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            sources = []
            if workflow:
                sources = [
                    self._source_preview(self._source_by_id[source])
                    for source in workflow.get("source_ids", [])
                    if source in self._source_by_id
                ]
            return {
                "available": True,
                "found": workflow is not None,
                "sources": sources,
                "workflow_id": workflow_id,
                "workflow_lineage": workflow,
            }

        source_rows = list(self._source_by_id.values())
        workflow_rows = list(self._workflow_by_id.values())
        if decision:
            key = decision.strip()
            source_rows = [source for source in source_rows if str(source.get("decision")) == key]
            workflow_rows = [workflow for workflow in workflow_rows if str(workflow.get("decision")) == key]
        if reuse_class:
            key = reuse_class.strip()
            source_rows = [
                source
                for source in source_rows
                if key in {str(item) for item in source.get("allowed_reuse_classes", [])}
            ]
            workflow_rows = [
                workflow
                for workflow in workflow_rows
                if key in {str(item) for item in workflow.get("approved_reuse_classes", [])}
            ]

        stages = ledger.get("lineage_stages", [])
        if stage_id:
            key = stage_id.strip()
            stages = [
                stage
                for stage in stages
                if isinstance(stage, dict) and str(stage.get("id")) == key
            ]

        return {
            "available": True,
            "buyer_views": ledger.get("buyer_views", []),
            "enterprise_adoption_packet": ledger.get("enterprise_adoption_packet"),
            "generated_at": ledger.get("generated_at"),
            "lineage_contract": ledger.get("lineage_contract"),
            "lineage_stages": stages,
            "lineage_summary": ledger.get("lineage_summary"),
            "reuse_policy": ledger.get("reuse_policy"),
            "schema_version": ledger.get("schema_version"),
            "source_artifacts": ledger.get("source_artifacts"),
            "source_lineage": [self._source_preview(source) for source in source_rows],
            "standards_alignment": ledger.get("standards_alignment", []),
            "workflow_lineage": [self._workflow_preview(workflow) for workflow in workflow_rows],
        }

class SecureContextEvalPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._scenario_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        scenarios = pack.get("scenarios") if isinstance(pack, dict) else []
        self._scenario_by_id = {
            str(scenario.get("scenario_id")): scenario
            for scenario in scenarios
            if isinstance(scenario, dict) and scenario.get("scenario_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _scenario_preview(scenario: dict[str, Any]) -> dict[str, Any]:
        return {
            "decision": scenario.get("decision"),
            "failed_check_count": scenario.get("failed_check_count"),
            "mapped_signal_ids": scenario.get("mapped_signal_ids", []),
            "scenario_id": scenario.get("scenario_id"),
            "scenario_type": scenario.get("scenario_type"),
            "score": scenario.get("score"),
            "title": scenario.get("title"),
            "workflow_id": scenario.get("workflow_id"),
        }

    def get(
        self,
        scenario_id: str | None = None,
        workflow_id: str | None = None,
        scenario_type: str | None = None,
        decision: str | None = None,
        minimum_score: int | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load secure context eval pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "secure context eval pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "secure context eval pack root must be an object",
                "pack_path": str(self.path),
            }

        if scenario_id:
            scenario = self._scenario_by_id.get(scenario_id.strip())
            return {
                "available": True,
                "found": scenario is not None,
                "scenario": scenario,
                "scenario_id": scenario_id,
            }

        scenarios = list(self._scenario_by_id.values())
        if workflow_id:
            key = workflow_id.strip()
            scenarios = [scenario for scenario in scenarios if str(scenario.get("workflow_id")) == key]
        if scenario_type:
            key = scenario_type.strip()
            scenarios = [scenario for scenario in scenarios if str(scenario.get("scenario_type")) == key]
        if decision:
            key = decision.strip()
            scenarios = [scenario for scenario in scenarios if str(scenario.get("decision")) == key]
        if minimum_score is not None:
            scenarios = [
                scenario
                for scenario in scenarios
                if int(scenario.get("score") or 0) >= minimum_score
            ]

        return {
            "available": True,
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "eval_summary": pack.get("eval_summary"),
            "evaluation_contract": pack.get("evaluation_contract"),
            "generated_at": pack.get("generated_at"),
            "minimum_score": minimum_score,
            "runtime_answer_contract": pack.get("runtime_answer_contract"),
            "scenario_count": len(scenarios),
            "scenario_type": scenario_type,
            "scenarios": [self._scenario_preview(scenario) for scenario in scenarios],
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "threat_signal_coverage": pack.get("threat_signal_coverage", []),
            "workflow_id": workflow_id,
        }

class AgenticThreatRadar:
    def __init__(self, radar_path: str):
        self.path = Path(radar_path)
        self._mtime: float | None = None
        self._radar: dict[str, Any] | None = None
        self._signal_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._radar is not None and self._mtime == stat.st_mtime:
            return self._radar

        radar = json.loads(self.path.read_text(encoding="utf-8"))
        signals = radar.get("threat_signals") if isinstance(radar, dict) else []
        self._signal_by_id = {
            str(signal.get("id")): signal
            for signal in signals
            if isinstance(signal, dict) and signal.get("id")
        }
        self._radar = radar
        self._mtime = stat.st_mtime
        return radar

    @staticmethod
    def _signal_preview(signal: dict[str, Any]) -> dict[str, Any]:
        return {
            "buyer_trigger": signal.get("buyer_trigger"),
            "capability_ids": signal.get("mapped_capability_ids", []),
            "confidence": signal.get("confidence"),
            "horizon": signal.get("horizon"),
            "id": signal.get("id"),
            "priority": signal.get("priority"),
            "roadmap_action": signal.get("roadmap_action"),
            "source_ids": signal.get("source_ids", []),
            "strategic_score": signal.get("strategic_score"),
            "title": signal.get("title"),
        }

    def get(
        self,
        signal_id: str | None = None,
        priority: str | None = None,
        horizon: str | None = None,
        capability_id: str | None = None,
        minimum_score: int | None = None,
    ) -> dict[str, Any]:
        try:
            radar = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic threat radar: {exc}",
                "radar_path": str(self.path),
            }

        if radar is None:
            return {
                "available": False,
                "error": "agentic threat radar is not present",
                "radar_path": str(self.path),
            }

        if not isinstance(radar, dict):
            return {
                "available": False,
                "error": "agentic threat radar root must be an object",
                "radar_path": str(self.path),
            }

        if signal_id:
            signal = self._signal_by_id.get(signal_id.strip())
            return {
                "available": True,
                "found": signal is not None,
                "signal": signal,
                "signal_id": signal_id,
            }

        signals = list(self._signal_by_id.values())
        if priority:
            key = priority.strip()
            signals = [signal for signal in signals if str(signal.get("priority")) == key]
        if horizon:
            key = horizon.strip()
            signals = [signal for signal in signals if str(signal.get("horizon")) == key]
        if capability_id:
            key = capability_id.strip()
            signals = [
                signal
                for signal in signals
                if key in {str(item) for item in signal.get("mapped_capability_ids", [])}
            ]
        if minimum_score is not None:
            signals = [
                signal
                for signal in signals
                if int(signal.get("strategic_score") or 0) >= minimum_score
            ]

        return {
            "available": True,
            "acquisition_story": radar.get("acquisition_story"),
            "capability_coverage": radar.get("capability_coverage", []),
            "enterprise_adoption_packet": radar.get("enterprise_adoption_packet"),
            "feature_backlog": radar.get("feature_backlog", []),
            "generated_at": radar.get("generated_at"),
            "horizon": horizon,
            "minimum_score": minimum_score,
            "priority": priority,
            "product_capabilities": radar.get("product_capabilities", []),
            "schema_version": radar.get("schema_version"),
            "signal_count": len(signals),
            "signals": [self._signal_preview(signal) for signal in signals],
            "source_artifacts": radar.get("source_artifacts"),
            "source_references": radar.get("source_references", []),
            "threat_radar_summary": radar.get("threat_radar_summary"),
        }


class AgenticControlPlaneBlueprint:
    def __init__(self, blueprint_path: str):
        self.path = Path(blueprint_path)
        self._mtime: float | None = None
        self._blueprint: dict[str, Any] | None = None
        self._layer_by_id: dict[str, dict[str, Any]] = {}
        self._question_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._blueprint is not None and self._mtime == stat.st_mtime:
            return self._blueprint

        blueprint = json.loads(self.path.read_text(encoding="utf-8"))
        layers = blueprint.get("layers") if isinstance(blueprint, dict) else []
        questions = blueprint.get("buyer_due_diligence_matrix") if isinstance(blueprint, dict) else []
        self._layer_by_id = {
            str(layer.get("id")): layer
            for layer in layers
            if isinstance(layer, dict) and layer.get("id")
        }
        self._question_by_id = {
            str(question.get("id")): question
            for question in questions
            if isinstance(question, dict) and question.get("id")
        }
        self._blueprint = blueprint
        self._mtime = stat.st_mtime
        return blueprint

    @staticmethod
    def _layer_preview(layer: dict[str, Any]) -> dict[str, Any]:
        return {
            "evidence_coverage_score": layer.get("evidence_coverage_score"),
            "evidence_paths": layer.get("evidence_paths", []),
            "id": layer.get("id"),
            "mcp_tools": layer.get("mcp_tools", []),
            "premium_path": layer.get("premium_path"),
            "proof_question": layer.get("proof_question"),
            "status": layer.get("status"),
            "title": layer.get("title"),
        }

    def get(
        self,
        layer_id: str | None = None,
        question_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            blueprint = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic control plane blueprint: {exc}",
                "pack_path": str(self.path),
            }

        if blueprint is None:
            return {
                "available": False,
                "error": "agentic control plane blueprint is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(blueprint, dict):
            return {
                "available": False,
                "error": "agentic control plane blueprint root must be an object",
                "pack_path": str(self.path),
            }

        if layer_id:
            layer = self._layer_by_id.get(layer_id.strip())
            return {
                "available": True,
                "found": layer is not None,
                "layer": layer,
                "layer_id": layer_id,
            }

        if question_id:
            question = self._question_by_id.get(question_id.strip())
            return {
                "available": True,
                "found": question is not None,
                "question": question,
                "question_id": question_id,
            }

        layers = list(self._layer_by_id.values())
        if status:
            key = status.strip()
            layers = [layer for layer in layers if str(layer.get("status")) == key]

        return {
            "available": True,
            "acquisition_readiness": blueprint.get("acquisition_readiness"),
            "buyer_due_diligence_matrix": list(self._question_by_id.values()),
            "commercialization_path": blueprint.get("commercialization_path", {}),
            "control_plane_contract": blueprint.get("control_plane_contract", {}),
            "control_plane_summary": blueprint.get("control_plane_summary"),
            "enterprise_adoption_packet": blueprint.get("enterprise_adoption_packet"),
            "generated_at": blueprint.get("generated_at"),
            "layer_count": len(layers),
            "layers": [self._layer_preview(layer) for layer in layers],
            "pack_summaries": blueprint.get("pack_summaries", {}),
            "schema_version": blueprint.get("schema_version"),
            "source_artifacts": blueprint.get("source_artifacts"),
            "standards_alignment": blueprint.get("standards_alignment", []),
            "status": status,
        }


class AgenticExposureGraph:
    def __init__(self, graph_path: str):
        self.path = Path(graph_path)
        self._mtime: float | None = None
        self._graph: dict[str, Any] | None = None
        self._path_by_id: dict[str, dict[str, Any]] = {}
        self._node_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._graph is not None and self._mtime == stat.st_mtime:
            return self._graph

        graph = json.loads(self.path.read_text(encoding="utf-8"))
        paths = graph.get("exposure_paths") if isinstance(graph, dict) else []
        nodes = graph.get("nodes") if isinstance(graph, dict) else []
        self._path_by_id = {
            str(path.get("path_id")): path
            for path in paths
            if isinstance(path, dict) and path.get("path_id")
        }
        self._node_by_id = {
            str(node.get("id")): node
            for node in nodes
            if isinstance(node, dict) and node.get("id")
        }
        self._graph = graph
        self._mtime = stat.st_mtime
        return graph

    @staticmethod
    def _path_preview(path: dict[str, Any]) -> dict[str, Any]:
        return {
            "access": path.get("access"),
            "agent_class": path.get("agent_class"),
            "authorization_decision": path.get("authorization_decision"),
            "connector_status": path.get("connector_status"),
            "decision": path.get("decision"),
            "egress_sensitivity": path.get("egress_sensitivity"),
            "identity_id": path.get("identity_id"),
            "mcp_namespace": path.get("mcp_namespace"),
            "path_class_id": path.get("path_class_id"),
            "path_id": path.get("path_id"),
            "readiness_decision": path.get("readiness_decision"),
            "risk_tier": path.get("risk_tier"),
            "score": path.get("score"),
            "workflow_id": path.get("workflow_id"),
            "workflow_title": path.get("workflow_title"),
        }

    @staticmethod
    def _node_preview(node: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": node.get("id"),
            "label": node.get("label"),
            "node_type": node.get("node_type"),
            "properties": node.get("properties", {}),
        }

    def get(
        self,
        path_id: str | None = None,
        workflow_id: str | None = None,
        identity_id: str | None = None,
        namespace: str | None = None,
        decision: str | None = None,
        path_class_id: str | None = None,
        minimum_score: int | None = None,
        node_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            graph = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic exposure graph: {exc}",
                "graph_path": str(self.path),
            }

        if graph is None:
            return {
                "available": False,
                "error": "agentic exposure graph is not present",
                "graph_path": str(self.path),
            }

        if not isinstance(graph, dict):
            return {
                "available": False,
                "error": "agentic exposure graph root must be an object",
                "graph_path": str(self.path),
            }

        if path_id:
            key = path_id.strip()
            path = self._path_by_id.get(key)
            return {
                "available": True,
                "found": path is not None,
                "path": path,
                "path_id": key,
            }

        if node_id:
            key = node_id.strip()
            node = self._node_by_id.get(key)
            return {
                "available": True,
                "found": node is not None,
                "node": node,
                "node_id": key,
            }

        paths = list(self._path_by_id.values())
        if workflow_id:
            key = workflow_id.strip()
            paths = [path for path in paths if str(path.get("workflow_id")) == key]
        if identity_id:
            key = identity_id.strip()
            paths = [path for path in paths if str(path.get("identity_id")) == key]
        if namespace:
            key = namespace.strip()
            paths = [path for path in paths if str(path.get("mcp_namespace")) == key]
        if decision:
            key = decision.strip()
            paths = [path for path in paths if str(path.get("decision")) == key]
        if path_class_id:
            key = path_class_id.strip()
            paths = [path for path in paths if str(path.get("path_class_id")) == key]
        if minimum_score is not None:
            paths = [
                path
                for path in paths
                if int(path.get("score") or 0) >= minimum_score
            ]

        return {
            "available": True,
            "commercialization_path": graph.get("commercialization_path"),
            "decision": decision,
            "enterprise_adoption_packet": graph.get("enterprise_adoption_packet"),
            "exposure_graph_summary": graph.get("exposure_graph_summary"),
            "generated_at": graph.get("generated_at"),
            "graph_contract": graph.get("graph_contract"),
            "minimum_score": minimum_score,
            "node_count": len(self._node_by_id),
            "path_class_id": path_class_id,
            "path_classes": graph.get("path_classes", []),
            "path_count": len(paths),
            "paths": [self._path_preview(path) for path in paths],
            "schema_version": graph.get("schema_version"),
            "selected_feature": graph.get("selected_feature"),
            "source_artifacts": graph.get("source_artifacts"),
            "standards_alignment": graph.get("standards_alignment", []),
            "workflow_id": workflow_id,
        }


class AgenticPostureSnapshot:
    def __init__(self, snapshot_path: str):
        self.path = Path(snapshot_path)
        self._mtime: float | None = None
        self._snapshot: dict[str, Any] | None = None
        self._workflow_by_id: dict[str, dict[str, Any]] = {}
        self._finding_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._snapshot is not None and self._mtime == stat.st_mtime:
            return self._snapshot

        snapshot = json.loads(self.path.read_text(encoding="utf-8"))
        workflows = snapshot.get("workflow_posture") if isinstance(snapshot, dict) else []
        findings = snapshot.get("posture_findings") if isinstance(snapshot, dict) else []
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._finding_by_id = {
            str(finding.get("id")): finding
            for finding in findings
            if isinstance(finding, dict) and finding.get("id")
        }
        self._snapshot = snapshot
        self._mtime = stat.st_mtime
        return snapshot

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "highest_exposure_path": workflow.get("highest_exposure_path", {}),
            "maturity_stage": workflow.get("maturity_stage"),
            "mcp_namespaces": workflow.get("mcp_namespaces", []),
            "posture_decision": workflow.get("posture_decision"),
            "posture_score": workflow.get("posture_score"),
            "public_path": workflow.get("public_path"),
            "readiness_decision": workflow.get("readiness_decision"),
            "readiness_score": workflow.get("readiness_score"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        workflow_id: str | None = None,
        posture_decision: str | None = None,
        minimum_score: int | None = None,
        risk_factor_id: str | None = None,
        finding_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            snapshot = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic posture snapshot: {exc}",
                "snapshot_path": str(self.path),
            }

        if snapshot is None:
            return {
                "available": False,
                "error": "agentic posture snapshot is not present",
                "snapshot_path": str(self.path),
            }

        if not isinstance(snapshot, dict):
            return {
                "available": False,
                "error": "agentic posture snapshot root must be an object",
                "snapshot_path": str(self.path),
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_id": key,
                "workflow_posture": workflow,
            }

        if finding_id:
            key = finding_id.strip()
            finding = self._finding_by_id.get(key)
            return {
                "available": True,
                "finding": finding,
                "finding_id": key,
                "found": finding is not None,
            }

        workflows = list(self._workflow_by_id.values())
        if posture_decision:
            key = posture_decision.strip()
            workflows = [workflow for workflow in workflows if str(workflow.get("posture_decision")) == key]
        if minimum_score is not None:
            workflows = [
                workflow
                for workflow in workflows
                if int(workflow.get("posture_score") or 0) >= minimum_score
            ]

        risk_factors = snapshot.get("risk_factors", [])
        if risk_factor_id:
            key = risk_factor_id.strip()
            risk_factors = [
                risk_factor
                for risk_factor in risk_factors
                if isinstance(risk_factor, dict) and str(risk_factor.get("id")) == key
            ]

        return {
            "available": True,
            "buyer_views": snapshot.get("buyer_views", []),
            "commercialization_path": snapshot.get("commercialization_path", {}),
            "decision_contract": snapshot.get("decision_contract", {}),
            "enterprise_adoption_packet": snapshot.get("enterprise_adoption_packet"),
            "generated_at": snapshot.get("generated_at"),
            "minimum_score": minimum_score,
            "posture_decision": posture_decision,
            "posture_dimensions": snapshot.get("posture_dimensions", []),
            "posture_findings": snapshot.get("posture_findings", []),
            "posture_summary": snapshot.get("posture_summary"),
            "risk_factor_id": risk_factor_id,
            "risk_factor_summary": snapshot.get("risk_factor_summary"),
            "risk_factors": risk_factors,
            "schema_version": snapshot.get("schema_version"),
            "selected_feature": snapshot.get("selected_feature"),
            "source_artifacts": snapshot.get("source_artifacts"),
            "standards_alignment": snapshot.get("standards_alignment", []),
            "workflow_count": len(workflows),
            "workflows": [self._workflow_preview(workflow) for workflow in workflows],
        }

class AgenticAivssRiskScoringPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._scenario_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        scores = pack.get("risk_scores") if isinstance(pack, dict) else []
        self._scenario_by_id = {
            str(score.get("scenario_id")): score
            for score in scores
            if isinstance(score, dict) and score.get("scenario_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _score_preview(score: dict[str, Any]) -> dict[str, Any]:
        return {
            "aivss_score": score.get("aivss_score"),
            "hosted_mcp_wedge": score.get("hosted_mcp_wedge"),
            "owner": score.get("owner"),
            "remediation_sla": score.get("remediation_sla"),
            "runtime_default_decision": score.get("runtime_default_decision"),
            "scenario_id": score.get("scenario_id"),
            "severity": score.get("severity"),
            "title": score.get("title"),
        }

    def get(
        self,
        scenario_id: str | None = None,
        severity: str | None = None,
        runtime_default_decision: str | None = None,
        minimum_score: float | None = None,
        owner: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic AIVSS risk scoring pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic AIVSS risk scoring pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic AIVSS risk scoring pack root must be an object",
                "pack_path": str(self.path),
            }

        if scenario_id:
            key = scenario_id.strip()
            score = self._scenario_by_id.get(key)
            return {
                "available": True,
                "found": score is not None,
                "risk_score": score,
                "scenario_id": key,
            }

        scores = list(self._scenario_by_id.values())
        if severity:
            key = severity.strip()
            scores = [score for score in scores if str(score.get("severity")) == key]
        if runtime_default_decision:
            key = runtime_default_decision.strip()
            scores = [
                score
                for score in scores
                if str(score.get("runtime_default_decision")) == key
            ]
        if minimum_score is not None:
            scores = [
                score
                for score in scores
                if float(score.get("aivss_score") or 0) >= minimum_score
            ]
        if owner:
            key = owner.strip().lower()
            scores = [
                score
                for score in scores
                if key in str(score.get("owner", "")).lower()
            ]

        return {
            "available": True,
            "buyer_views": pack.get("buyer_views", []),
            "commercialization_path": pack.get("commercialization_path", {}),
            "decision_contract": pack.get("decision_contract", {}),
            "evidence_signal_summary": pack.get("evidence_signal_summary", {}),
            "generated_at": pack.get("generated_at"),
            "hosted_mcp_wedges": pack.get("hosted_mcp_wedges", []),
            "minimum_score": minimum_score,
            "remediation_queue": pack.get("remediation_queue", []),
            "risk_score_count": len(scores),
            "risk_scores": [self._score_preview(score) for score in scores],
            "schema_version": pack.get("schema_version"),
            "severity": severity,
            "severity_summary": pack.get("severity_summary"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_references": pack.get("source_references", []),
        }

class AgenticAppIntakePack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._app_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        apps = pack.get("app_intake_profiles") if isinstance(pack, dict) else []
        self._app_by_id = {
            str(app.get("app_id")): app
            for app in apps
            if isinstance(app, dict) and app.get("app_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _preview(app: dict[str, Any]) -> dict[str, Any]:
        return {
            "app_id": app.get("app_id"),
            "autonomy_level": app.get("autonomy_level"),
            "buyer_stage": app.get("buyer_stage"),
            "decision": app.get("decision"),
            "external_write": app.get("external_write"),
            "indirect_prompt_injection_risk": app.get("indirect_prompt_injection_risk"),
            "lethal_secret_or_signer_path": app.get("lethal_secret_or_signer_path"),
            "mcp_namespaces": app.get("mcp_namespaces", []),
            "missing_control_evidence": app.get("missing_control_evidence", []),
            "production_write": app.get("production_write"),
            "residual_risk_score": app.get("residual_risk_score"),
            "risk_tier": app.get("risk_tier"),
            "title": app.get("title"),
        }

    def get(
        self,
        app_id: str | None = None,
        decision: str | None = None,
        risk_tier: str | None = None,
        buyer_stage: str | None = None,
        minimum_score: int | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic app intake pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic app intake pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic app intake pack root must be an object",
                "pack_path": str(self.path),
            }

        if app_id:
            key = app_id.strip()
            app = self._app_by_id.get(key)
            return {
                "app_id": key,
                "app_intake_profile": app,
                "available": True,
                "found": app is not None,
            }

        apps = list(self._app_by_id.values())
        if decision:
            key = decision.strip()
            apps = [app for app in apps if str(app.get("decision")) == key]
        if risk_tier:
            key = risk_tier.strip()
            apps = [app for app in apps if str(app.get("risk_tier")) == key]
        if buyer_stage:
            key = buyer_stage.strip()
            apps = [app for app in apps if str(app.get("buyer_stage")) == key]
        if minimum_score is not None:
            apps = [
                app
                for app in apps
                if int(app.get("residual_risk_score") or 0) >= minimum_score
            ]

        return {
            "app_count": len(apps),
            "app_intake_profiles": [self._preview(app) for app in apps],
            "app_intake_summary": pack.get("app_intake_summary"),
            "available": True,
            "buyer_stage": buyer_stage,
            "decision": decision,
            "decision_contract": pack.get("decision_contract", {}),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "evaluator_contract": pack.get("evaluator_contract"),
            "generated_at": pack.get("generated_at"),
            "risk_tier": risk_tier,
            "schema_version": pack.get("schema_version"),
            "selected_feature": pack.get("selected_feature"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
        }

class ModelProviderRoutingPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._provider_by_id: dict[str, dict[str, Any]] = {}
        self._route_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        providers = pack.get("provider_profiles") if isinstance(pack, dict) else []
        routes = pack.get("model_route_profiles") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_route_matrix") if isinstance(pack, dict) else []
        self._provider_by_id = {
            str(provider.get("provider_id")): provider
            for provider in providers
            if isinstance(provider, dict) and provider.get("provider_id")
        }
        self._route_by_id = {
            str(route.get("route_id")): route
            for route in routes
            if isinstance(route, dict) and route.get("route_id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _provider_preview(provider: dict[str, Any]) -> dict[str, Any]:
        return {
            "default_decision": provider.get("default_decision"),
            "provider_id": provider.get("provider_id"),
            "provider_type": provider.get("provider_type"),
            "risk_tier": provider.get("risk_tier"),
            "status": provider.get("status"),
            "title": provider.get("title"),
        }

    @staticmethod
    def _route_preview(route: dict[str, Any]) -> dict[str, Any]:
        return {
            "default_decision": route.get("default_decision"),
            "dpa_required": route.get("dpa_required"),
            "human_approval_required": route.get("human_approval_required"),
            "max_autonomy_level": route.get("max_autonomy_level"),
            "model_id": route.get("model_id"),
            "provider_id": route.get("provider_id"),
            "residency_match_required": route.get("residency_match_required"),
            "risk_tier": route.get("risk_tier"),
            "route_class": route.get("route_class"),
            "route_hash": route.get("route_hash"),
            "route_id": route.get("route_id"),
            "title": route.get("title"),
            "zero_data_retention_required": route.get("zero_data_retention_required"),
        }

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "data_classes": workflow.get("data_classes", []),
            "default_decision": workflow.get("default_decision"),
            "minimum_controls": workflow.get("minimum_controls", []),
            "preferred_route_ids": workflow.get("preferred_route_ids", []),
            "route_count": workflow.get("route_count"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
            "workflow_route_hash": workflow.get("workflow_route_hash"),
        }

    def get(
        self,
        provider_id: str | None = None,
        model_id: str | None = None,
        route_id: str | None = None,
        workflow_id: str | None = None,
        decision: str | None = None,
        risk_tier: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load model provider routing pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "model provider routing pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "model provider routing pack root must be an object",
                "pack_path": str(self.path),
            }

        if provider_id:
            key = provider_id.strip()
            provider = self._provider_by_id.get(key)
            return {
                "available": True,
                "found": provider is not None,
                "provider_id": key,
                "provider_profile": provider,
            }

        if route_id:
            key = route_id.strip()
            route = self._route_by_id.get(key)
            return {
                "available": True,
                "found": route is not None,
                "route_id": key,
                "route_profile": route,
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_id": key,
                "workflow_route": workflow,
            }

        providers = list(self._provider_by_id.values())
        routes = list(self._route_by_id.values())
        workflows = list(self._workflow_by_id.values())
        if model_id:
            key = model_id.strip()
            routes = [route for route in routes if str(route.get("model_id")) == key]
        if decision:
            key = decision.strip()
            routes = [route for route in routes if str(route.get("default_decision")) == key]
            workflows = [workflow for workflow in workflows if str(workflow.get("default_decision")) == key]
        if risk_tier:
            key = risk_tier.strip()
            providers = [provider for provider in providers if str(provider.get("risk_tier")) == key]
            routes = [route for route in routes if str(route.get("risk_tier")) == key]

        return {
            "available": True,
            "decision": decision,
            "decision_contract": pack.get("decision_contract", {}),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet", {}),
            "evaluator_contract": pack.get("evaluator_contract", {}),
            "generated_at": pack.get("generated_at"),
            "model_id": model_id,
            "model_provider_routing_summary": pack.get("model_provider_routing_summary"),
            "model_route_profiles": [self._route_preview(route) for route in routes],
            "positioning": pack.get("positioning", {}),
            "provider_profiles": [self._provider_preview(provider) for provider in providers],
            "risk_tier": risk_tier,
            "route_count": len(routes),
            "schema_version": pack.get("schema_version"),
            "selected_feature": pack.get("selected_feature"),
            "source_artifacts": pack.get("source_artifacts", []),
            "standards_alignment": pack.get("standards_alignment", []),
            "workflow_route_matrix": [self._workflow_preview(workflow) for workflow in workflows],
            "workflow_route_count": len(workflows),
        }

class AgenticCatastrophicRiskAnnex:
    def __init__(self, annex_path: str):
        self.path = Path(annex_path)
        self._mtime: float | None = None
        self._annex: dict[str, Any] | None = None
        self._scenario_by_id: dict[str, dict[str, Any]] = {}
        self._control_by_id: dict[str, dict[str, Any]] = {}
        self._buyer_view_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._annex is not None and self._mtime == stat.st_mtime:
            return self._annex

        annex = json.loads(self.path.read_text(encoding="utf-8"))
        scenarios = annex.get("catastrophic_scenarios") if isinstance(annex, dict) else []
        controls = annex.get("annex_controls") if isinstance(annex, dict) else []
        buyer_views = annex.get("buyer_views") if isinstance(annex, dict) else []
        self._scenario_by_id = {
            str(scenario.get("id")): scenario
            for scenario in scenarios
            if isinstance(scenario, dict) and scenario.get("id")
        }
        self._control_by_id = {
            str(control.get("id")): control
            for control in controls
            if isinstance(control, dict) and control.get("id")
        }
        self._buyer_view_by_id = {
            str(view.get("id")): view
            for view in buyer_views
            if isinstance(view, dict) and view.get("id")
        }
        self._annex = annex
        self._mtime = stat.st_mtime
        return annex

    @staticmethod
    def _scenario_preview(scenario: dict[str, Any]) -> dict[str, Any]:
        return {
            "board_question": scenario.get("board_question"),
            "default_decision": scenario.get("default_decision"),
            "evidence_coverage_score": scenario.get("evidence_coverage_score"),
            "id": scenario.get("id"),
            "impact_domain": scenario.get("impact_domain"),
            "required_mcp_tools": scenario.get("required_mcp_tools", []),
            "status": scenario.get("status"),
            "title": scenario.get("title"),
            "trigger_action_classes": scenario.get("trigger_action_classes", []),
        }

    @staticmethod
    def _control_preview(control: dict[str, Any]) -> dict[str, Any]:
        return {
            "diligence_question": control.get("diligence_question"),
            "evidence_paths": control.get("evidence_paths", []),
            "id": control.get("id"),
            "mcp_tools": control.get("mcp_tools", []),
            "scenario_ids": control.get("scenario_ids", []),
            "status": control.get("status"),
            "title": control.get("title"),
        }

    def get(
        self,
        scenario_id: str | None = None,
        control_id: str | None = None,
        buyer_view_id: str | None = None,
        impact_domain: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            annex = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic catastrophic-risk annex: {exc}",
                "pack_path": str(self.path),
            }

        if annex is None:
            return {
                "available": False,
                "error": "agentic catastrophic-risk annex is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(annex, dict):
            return {
                "available": False,
                "error": "agentic catastrophic-risk annex root must be an object",
                "pack_path": str(self.path),
            }

        if scenario_id:
            key = scenario_id.strip()
            scenario = self._scenario_by_id.get(key)
            return {
                "available": True,
                "found": scenario is not None,
                "scenario": scenario,
                "scenario_id": key,
            }

        if control_id:
            key = control_id.strip()
            control = self._control_by_id.get(key)
            return {
                "available": True,
                "control": control,
                "control_id": key,
                "found": control is not None,
            }

        if buyer_view_id:
            key = buyer_view_id.strip()
            buyer_view = self._buyer_view_by_id.get(key)
            return {
                "available": True,
                "buyer_view": buyer_view,
                "buyer_view_id": key,
                "found": buyer_view is not None,
            }

        scenarios = list(self._scenario_by_id.values())
        controls = list(self._control_by_id.values())
        if impact_domain:
            key = impact_domain.strip()
            scenarios = [scenario for scenario in scenarios if str(scenario.get("impact_domain")) == key]
        if status:
            key = status.strip()
            scenarios = [scenario for scenario in scenarios if str(scenario.get("status")) == key]
            controls = [control for control in controls if str(control.get("status")) == key]

        return {
            "annex_contract": annex.get("annex_contract", {}),
            "annex_summary": annex.get("annex_summary"),
            "available": True,
            "buyer_view_count": len(self._buyer_view_by_id),
            "buyer_views": list(self._buyer_view_by_id.values()),
            "commercialization_path": annex.get("commercialization_path", {}),
            "control_count": len(controls),
            "controls": [self._control_preview(control) for control in controls],
            "enterprise_adoption_packet": annex.get("enterprise_adoption_packet"),
            "generated_at": annex.get("generated_at"),
            "impact_domain": impact_domain,
            "runtime_decision_contract": annex.get("runtime_decision_contract", {}),
            "scenario_count": len(scenarios),
            "scenarios": [self._scenario_preview(scenario) for scenario in scenarios],
            "schema_version": annex.get("schema_version"),
            "source_artifacts": annex.get("source_artifacts"),
            "standards_alignment": annex.get("standards_alignment", []),
            "status": status,
        }

class CriticalInfrastructureSecureContextPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._sector_by_id: dict[str, dict[str, Any]] = {}
        self._control_by_id: dict[str, dict[str, Any]] = {}
        self._buyer_view_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        sectors = pack.get("sector_profiles") if isinstance(pack, dict) else []
        controls = pack.get("control_objectives") if isinstance(pack, dict) else []
        buyer_views = pack.get("buyer_views") if isinstance(pack, dict) else []
        self._sector_by_id = {
            str(sector.get("id")): sector
            for sector in sectors
            if isinstance(sector, dict) and sector.get("id")
        }
        self._control_by_id = {
            str(control.get("id")): control
            for control in controls
            if isinstance(control, dict) and control.get("id")
        }
        self._buyer_view_by_id = {
            str(view.get("id")): view
            for view in buyer_views
            if isinstance(view, dict) and view.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _sector_preview(sector: dict[str, Any]) -> dict[str, Any]:
        return {
            "default_decision": sector.get("default_decision"),
            "id": sector.get("id"),
            "operator_evidence_needed": sector.get("operator_evidence_needed"),
            "prohibited_without_safety_case": sector.get("prohibited_without_safety_case", []),
            "readiness_status": sector.get("readiness_status"),
            "title": sector.get("title"),
        }

    @staticmethod
    def _control_preview(control: dict[str, Any]) -> dict[str, Any]:
        return {
            "evidence_paths": control.get("evidence_paths", []),
            "hazard_flags": control.get("hazard_flags", []),
            "id": control.get("id"),
            "mcp_tools": control.get("mcp_tools", []),
            "status": control.get("status"),
            "title": control.get("title"),
        }

    def get(
        self,
        sector_id: str | None = None,
        control_id: str | None = None,
        buyer_view_id: str | None = None,
        decision: str | None = None,
        readiness_status: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load critical-infrastructure secure-context pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "critical-infrastructure secure-context pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "critical-infrastructure secure-context pack root must be an object",
                "pack_path": str(self.path),
            }

        if sector_id:
            key = sector_id.strip()
            sector = self._sector_by_id.get(key)
            return {
                "available": True,
                "found": sector is not None,
                "sector": sector,
                "sector_id": key,
            }

        if control_id:
            key = control_id.strip()
            control = self._control_by_id.get(key)
            return {
                "available": True,
                "control": control,
                "control_id": key,
                "found": control is not None,
            }

        if buyer_view_id:
            key = buyer_view_id.strip()
            buyer_view = self._buyer_view_by_id.get(key)
            return {
                "available": True,
                "buyer_view": buyer_view,
                "buyer_view_id": key,
                "found": buyer_view is not None,
            }

        sectors = list(self._sector_by_id.values())
        controls = list(self._control_by_id.values())
        lanes = pack.get("rollout_lanes", []) if isinstance(pack.get("rollout_lanes"), list) else []
        if decision:
            key = decision.strip()
            sectors = [sector for sector in sectors if str(sector.get("default_decision")) == key]
            lanes = [lane for lane in lanes if isinstance(lane, dict) and str(lane.get("decision")) == key]
        if readiness_status:
            key = readiness_status.strip()
            sectors = [sector for sector in sectors if str(sector.get("readiness_status")) == key]

        return {
            "available": True,
            "buyer_view_count": len(self._buyer_view_by_id),
            "buyer_views": list(self._buyer_view_by_id.values()),
            "commercialization_path": pack.get("commercialization_path", {}),
            "control_count": len(controls),
            "controls": [self._control_preview(control) for control in controls],
            "critical_infrastructure_summary": pack.get("critical_infrastructure_summary"),
            "decision": decision,
            "evidence_index": pack.get("evidence_index", []),
            "generated_at": pack.get("generated_at"),
            "readiness_contract": pack.get("readiness_contract", {}),
            "readiness_status": readiness_status,
            "rollout_lanes": lanes,
            "schema_version": pack.get("schema_version"),
            "sector_count": len(sectors),
            "sectors": [self._sector_preview(sector) for sector in sectors],
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
        }

class AgenticIncidentResponsePack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._class_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        classes = pack.get("incident_classes") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_response_matrix") if isinstance(pack, dict) else []
        self._class_by_id = {
            str(row.get("id")): row
            for row in classes
            if isinstance(row, dict) and row.get("id")
        }
        self._workflow_by_id = {
            str(row.get("workflow_id")): row
            for row in workflows
            if isinstance(row, dict) and row.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _class_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "default_decision": row.get("default_decision"),
            "default_severity": row.get("default_severity"),
            "evidence_paths": row.get("evidence_paths", []),
            "id": row.get("id"),
            "mcp_tools": row.get("mcp_tools", []),
            "title": row.get("title"),
        }

    @staticmethod
    def _workflow_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "assigned_incident_class_ids": row.get("assigned_incident_class_ids", []),
            "default_response_decision": row.get("default_response_decision"),
            "readiness_decision": row.get("readiness_decision"),
            "risk_tier": row.get("risk_tier"),
            "severity_floor": row.get("severity_floor"),
            "title": row.get("title"),
            "workflow_id": row.get("workflow_id"),
        }

    def get(
        self,
        incident_class_id: str | None = None,
        workflow_id: str | None = None,
        severity: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic incident response pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic incident response pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic incident response pack root must be an object",
                "pack_path": str(self.path),
            }

        if incident_class_id:
            key = incident_class_id.strip()
            incident_class = self._class_by_id.get(key)
            return {
                "available": True,
                "found": incident_class is not None,
                "incident_class": incident_class,
                "incident_class_id": key,
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow": workflow,
                "workflow_id": key,
            }

        classes = list(self._class_by_id.values())
        workflows = list(self._workflow_by_id.values())
        if severity:
            key = severity.strip()
            classes = [row for row in classes if str(row.get("default_severity")) == key]
            workflows = [row for row in workflows if str(row.get("severity_floor")) == key]
        if decision:
            key = decision.strip()
            classes = [row for row in classes if str(row.get("default_decision")) == key]
            workflows = [row for row in workflows if str(row.get("default_response_decision")) == key]

        return {
            "available": True,
            "commercialization_path": pack.get("commercialization_path", {}),
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "incident_classes": [self._class_preview(row) for row in classes],
            "incident_contract": pack.get("incident_contract", {}),
            "incident_response_summary": pack.get("incident_response_summary"),
            "response_phases": pack.get("response_phases", []),
            "schema_version": pack.get("schema_version"),
            "severity": severity,
            "source_artifacts": pack.get("source_artifacts", {}),
            "standards_alignment": pack.get("standards_alignment", []),
            "tabletop_cases": pack.get("tabletop_cases", []),
            "workflow_count": len(workflows),
            "workflows": [self._workflow_preview(row) for row in workflows],
        }

class AgenticActionRuntimePack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._action_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        action_classes = pack.get("action_classes") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_action_matrix") if isinstance(pack, dict) else []
        self._action_by_id = {
            str(row.get("id")): row
            for row in action_classes
            if isinstance(row, dict) and row.get("id")
        }
        self._workflow_by_id = {
            str(row.get("workflow_id")): row
            for row in workflows
            if isinstance(row, dict) and row.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _action_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "default_decision": row.get("default_decision"),
            "evidence_paths": row.get("evidence_paths", []),
            "id": row.get("id"),
            "mcp_tools": row.get("mcp_tools", []),
            "required_evidence": row.get("required_evidence", []),
            "risk_tier": row.get("risk_tier"),
            "title": row.get("title"),
        }

    @staticmethod
    def _workflow_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "action_class_ids": row.get("action_class_ids", []),
            "decision_floor": row.get("decision_floor"),
            "maturity_stage": row.get("maturity_stage"),
            "mcp_namespaces": row.get("mcp_namespaces", []),
            "title": row.get("title"),
            "workflow_id": row.get("workflow_id"),
        }

    def get(
        self,
        action_class_id: str | None = None,
        workflow_id: str | None = None,
        risk_tier: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic action runtime pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic action runtime pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic action runtime pack root must be an object",
                "pack_path": str(self.path),
            }

        if action_class_id:
            key = action_class_id.strip()
            action_class = self._action_by_id.get(key)
            return {
                "action_class": action_class,
                "action_class_id": key,
                "available": True,
                "found": action_class is not None,
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow": workflow,
                "workflow_id": key,
            }

        action_classes = list(self._action_by_id.values())
        workflows = list(self._workflow_by_id.values())
        if risk_tier:
            key = risk_tier.strip()
            action_classes = [row for row in action_classes if str(row.get("risk_tier")) == key]
        if decision:
            key = decision.strip()
            action_classes = [row for row in action_classes if str(row.get("default_decision")) == key]
            workflows = [row for row in workflows if str(row.get("decision_floor")) == key]

        return {
            "action_classes": [self._action_preview(row) for row in action_classes],
            "action_contract": pack.get("action_contract", {}),
            "action_runtime_summary": pack.get("action_runtime_summary"),
            "available": True,
            "commercialization_path": pack.get("commercialization_path", {}),
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "risk_tier": risk_tier,
            "runtime_policy": pack.get("runtime_policy", {}),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts", {}),
            "standards_alignment": pack.get("standards_alignment", []),
            "tabletop_cases": pack.get("tabletop_cases", []),
            "workflow_count": len(workflows),
            "workflows": [self._workflow_preview(row) for row in workflows],
        }

class AgentTrustFabricPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._dimension_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}
        self._tier_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        dimensions = pack.get("trust_dimensions") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_trust_matrix") if isinstance(pack, dict) else []
        tiers = pack.get("trust_tiers") if isinstance(pack, dict) else []
        self._dimension_by_id = {
            str(row.get("id")): row
            for row in dimensions
            if isinstance(row, dict) and row.get("id")
        }
        self._workflow_by_id = {
            str(row.get("workflow_id")): row
            for row in workflows
            if isinstance(row, dict) and row.get("workflow_id")
        }
        self._tier_by_id = {
            str(row.get("id")): row
            for row in tiers
            if isinstance(row, dict) and row.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _dimension_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "evidence_paths": row.get("evidence_paths", []),
            "failure_modes": row.get("failure_modes", []),
            "id": row.get("id"),
            "mcp_tools": row.get("mcp_tools", []),
            "question": row.get("question"),
            "title": row.get("title"),
            "weight": row.get("weight"),
        }

    @staticmethod
    def _workflow_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "default_trust_tier": row.get("default_trust_tier"),
            "maturity_stage": row.get("maturity_stage"),
            "mcp_namespaces": row.get("mcp_namespaces", []),
            "risk_flags": row.get("risk_flags", []),
            "title": row.get("title"),
            "workflow_id": row.get("workflow_id"),
        }

    def get(
        self,
        dimension_id: str | None = None,
        workflow_id: str | None = None,
        trust_tier: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agent trust fabric pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agent trust fabric pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agent trust fabric pack root must be an object",
                "pack_path": str(self.path),
            }

        if dimension_id:
            key = dimension_id.strip()
            dimension = self._dimension_by_id.get(key)
            return {
                "available": True,
                "dimension": dimension,
                "dimension_id": key,
                "found": dimension is not None,
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow": workflow,
                "workflow_id": key,
            }

        workflows = list(self._workflow_by_id.values())
        if trust_tier:
            key = trust_tier.strip()
            workflows = [row for row in workflows if str(row.get("default_trust_tier")) == key]

        return {
            "agent_trust_fabric_pack_id": pack.get("agent_trust_fabric_pack_id"),
            "available": True,
            "commercialization_path": pack.get("commercialization_path", {}),
            "dimension_count": len(self._dimension_by_id),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet", {}),
            "executive_readout": pack.get("executive_readout", {}),
            "generated_at": pack.get("generated_at"),
            "runtime_policy": pack.get("runtime_policy", {}),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts", {}),
            "source_references": pack.get("source_references", []),
            "status": status,
            "tabletop_cases": pack.get("tabletop_cases", []),
            "trust_contract": pack.get("trust_contract", {}),
            "trust_dimensions": [self._dimension_preview(row) for row in self._dimension_by_id.values()],
            "trust_fabric_summary": pack.get("trust_fabric_summary"),
            "trust_tier": trust_tier,
            "trust_tiers": list(self._tier_by_id.values()),
            "workflow_count": len(workflows),
            "workflows": [self._workflow_preview(row) for row in workflows],
        }

class BrowserAgentBoundaryPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._workspace_by_id: dict[str, dict[str, Any]] = {}
        self._task_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        workspaces = pack.get("workspace_classes") if isinstance(pack, dict) else []
        tasks = pack.get("task_profiles") if isinstance(pack, dict) else []
        self._workspace_by_id = {
            str(row.get("id")): row
            for row in workspaces
            if isinstance(row, dict) and row.get("id")
        }
        self._task_by_id = {
            str(row.get("id")): row
            for row in tasks
            if isinstance(row, dict) and row.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _workspace_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "default_decision": row.get("default_decision"),
            "effective_decision": row.get("effective_decision"),
            "id": row.get("id"),
            "residual_risk_score": row.get("residual_risk_score"),
            "risk_tier": row.get("risk_tier"),
            "title": row.get("title"),
        }

    @staticmethod
    def _task_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "allowed_workspace_class_ids": row.get("allowed_workspace_class_ids", []),
            "default_decision": row.get("default_decision"),
            "effective_decision": row.get("effective_decision"),
            "id": row.get("id"),
            "max_workspace_residual_risk_score": row.get("max_workspace_residual_risk_score"),
            "required_controls": row.get("required_controls", []),
            "title": row.get("title"),
        }

    def get(
        self,
        workspace_class_id: str | None = None,
        task_profile_id: str | None = None,
        risk_tier: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load browser-agent boundary pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "browser-agent boundary pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "browser-agent boundary pack root must be an object",
                "pack_path": str(self.path),
            }

        if workspace_class_id:
            key = workspace_class_id.strip()
            workspace = self._workspace_by_id.get(key)
            return {
                "available": True,
                "found": workspace is not None,
                "workspace_class": workspace,
                "workspace_class_id": key,
            }

        if task_profile_id:
            key = task_profile_id.strip()
            task = self._task_by_id.get(key)
            return {
                "available": True,
                "found": task is not None,
                "task_profile": task,
                "task_profile_id": key,
            }

        workspaces = list(self._workspace_by_id.values())
        tasks = list(self._task_by_id.values())
        if risk_tier:
            key = risk_tier.strip()
            workspaces = [row for row in workspaces if str(row.get("risk_tier")) == key]
        if decision:
            key = decision.strip()
            workspaces = [row for row in workspaces if str(row.get("effective_decision")) == key]
            tasks = [row for row in tasks if str(row.get("effective_decision")) == key]

        return {
            "available": True,
            "boundary_contract": pack.get("boundary_contract", {}),
            "browser_agent_boundary_summary": pack.get("browser_agent_boundary_summary"),
            "commercialization_path": pack.get("commercialization_path", {}),
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "risk_tier": risk_tier,
            "runtime_risk_weights": pack.get("runtime_risk_weights", {}),
            "schema_version": pack.get("schema_version"),
            "selected_feature": pack.get("selected_feature"),
            "source_artifacts": pack.get("source_artifacts", {}),
            "standards_alignment": pack.get("standards_alignment", []),
            "task_count": len(tasks),
            "task_profiles": [self._task_preview(row) for row in tasks],
            "workspace_count": len(workspaces),
            "workspace_classes": [self._workspace_preview(row) for row in workspaces],
        }

class AgenticMeasurementProbePack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._workflow_by_id: dict[str, dict[str, Any]] = {}
        self._probe_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        workflows = pack.get("workflow_probes") if isinstance(pack, dict) else []
        probes = pack.get("probes") if isinstance(pack, dict) else []
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._probe_by_id = {
            str(probe.get("id")): probe
            for probe in probes
            if isinstance(probe, dict) and probe.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _probe_preview(probe: dict[str, Any]) -> dict[str, Any]:
        return {
            "class_id": probe.get("class_id"),
            "earned_weight": probe.get("earned_weight"),
            "mapped_signal_ids": probe.get("mapped_signal_ids", []),
            "probe_id": probe.get("probe_id"),
            "status": probe.get("status"),
            "title": probe.get("title"),
            "weight": probe.get("weight"),
            "workflow_id": probe.get("workflow_id"),
        }

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "decision": workflow.get("decision"),
            "failed_probe_count": workflow.get("failed_probe_count"),
            "maturity_stage": workflow.get("maturity_stage"),
            "probe_count": workflow.get("probe_count"),
            "public_path": workflow.get("public_path"),
            "readiness_decision": workflow.get("readiness_decision"),
            "readiness_score": workflow.get("readiness_score"),
            "risk_tier": workflow.get("risk_tier"),
            "score": workflow.get("score"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        probe_id: str | None = None,
        workflow_id: str | None = None,
        decision: str | None = None,
        class_id: str | None = None,
        status: str | None = None,
        minimum_score: int | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic measurement probe pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic measurement probe pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic measurement probe pack root must be an object",
                "pack_path": str(self.path),
            }

        if probe_id:
            probe = self._probe_by_id.get(probe_id.strip())
            return {
                "available": True,
                "found": probe is not None,
                "probe": probe,
                "probe_id": probe_id,
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow": workflow,
                "workflow_id": workflow_id,
            }

        workflows = list(self._workflow_by_id.values())
        if decision:
            key = decision.strip()
            workflows = [workflow for workflow in workflows if str(workflow.get("decision")) == key]
        if minimum_score is not None:
            workflows = [
                workflow
                for workflow in workflows
                if int(workflow.get("score") or 0) >= minimum_score
            ]

        probe_results = [
            probe
            for workflow in workflows
            for probe in workflow.get("probe_results", [])
            if isinstance(probe, dict)
        ]
        if class_id:
            key = class_id.strip()
            probe_results = [probe for probe in probe_results if str(probe.get("class_id")) == key]
        if status:
            key = status.strip()
            probe_results = [probe for probe in probe_results if str(probe.get("status")) == key]

        return {
            "available": True,
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "measurement_probe_summary": pack.get("measurement_probe_summary"),
            "minimum_score": minimum_score,
            "probe_class": class_id,
            "probe_classes": pack.get("probe_classes", []),
            "probe_contract": pack.get("probe_contract"),
            "probe_count": len(probe_results),
            "probes": [self._probe_preview(probe) for probe in probe_results],
            "schema_version": pack.get("schema_version"),
            "selected_feature": pack.get("selected_feature"),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "status": status,
            "workflow_count": len(workflows),
            "workflows": [self._workflow_preview(workflow) for workflow in workflows],
        }


class AgenticTelemetryContract:
    def __init__(self, contract_path: str):
        self.path = Path(contract_path)
        self._mtime: float | None = None
        self._contract: dict[str, Any] | None = None
        self._workflow_by_id: dict[str, dict[str, Any]] = {}
        self._signal_by_id: dict[str, dict[str, Any]] = {}
        self._check_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._contract is not None and self._mtime == stat.st_mtime:
            return self._contract

        contract = json.loads(self.path.read_text(encoding="utf-8"))
        workflows = contract.get("workflow_telemetry_contracts") if isinstance(contract, dict) else []
        signals = contract.get("signal_classes") if isinstance(contract, dict) else []
        checks = contract.get("telemetry_checks") if isinstance(contract, dict) else []
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._signal_by_id = {
            str(signal.get("id")): signal
            for signal in signals
            if isinstance(signal, dict) and signal.get("id")
        }
        self._check_by_id = {
            str(check.get("id")): check
            for check in checks
            if isinstance(check, dict) and check.get("id")
        }
        self._contract = contract
        self._mtime = stat.st_mtime
        return contract

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "decision": workflow.get("decision"),
            "maturity_stage": workflow.get("maturity_stage"),
            "measurement_score": workflow.get("measurement_score"),
            "mcp_namespaces": workflow.get("mcp_namespaces", []),
            "public_path": workflow.get("public_path"),
            "receipt_id": workflow.get("receipt_id"),
            "required_signal_classes": workflow.get("required_signal_classes", []),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    @staticmethod
    def _signal_preview(signal: dict[str, Any]) -> dict[str, Any]:
        return {
            "default_failure_decision": signal.get("default_failure_decision"),
            "event_class": signal.get("event_class"),
            "id": signal.get("id"),
            "otel_span_name": signal.get("otel_span_name"),
            "required_attributes": signal.get("required_attributes", []),
            "title": signal.get("title"),
        }

    @staticmethod
    def _check_preview(check: dict[str, Any]) -> dict[str, Any]:
        return {
            "class_id": check.get("class_id"),
            "failure_decision": check.get("failure_decision"),
            "id": check.get("id"),
            "required_attributes": check.get("required_attributes", []),
            "title": check.get("title"),
        }

    def get(
        self,
        workflow_id: str | None = None,
        signal_class_id: str | None = None,
        check_id: str | None = None,
        decision: str | None = None,
        required_attribute: str | None = None,
    ) -> dict[str, Any]:
        try:
            contract = self._load()
        except Exception as exc:
            return {
                "available": False,
                "contract_path": str(self.path),
                "error": f"failed to load agentic telemetry contract: {exc}",
            }

        if contract is None:
            return {
                "available": False,
                "contract_path": str(self.path),
                "error": "agentic telemetry contract is not present",
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow": workflow,
                "workflow_id": key,
            }

        if signal_class_id:
            key = signal_class_id.strip()
            signal = self._signal_by_id.get(key)
            return {
                "available": True,
                "found": signal is not None,
                "signal_class": signal,
                "signal_class_id": key,
            }

        if check_id:
            key = check_id.strip()
            check = self._check_by_id.get(key)
            return {
                "available": True,
                "check": check,
                "check_id": key,
                "found": check is not None,
            }

        workflows = list(self._workflow_by_id.values())
        if decision:
            key = decision.strip()
            workflows = [workflow for workflow in workflows if str(workflow.get("decision")) == key]
        if required_attribute:
            key = required_attribute.strip()
            workflows = [
                workflow
                for workflow in workflows
                if key in set(str(item) for item in workflow.get("required_attributes", []))
            ]

        return {
            "available": True,
            "commercialization_path": contract.get("commercialization_path"),
            "decision": decision,
            "enterprise_adoption_packet": contract.get("enterprise_adoption_packet"),
            "evaluator_contract": contract.get("evaluator_contract"),
            "generated_at": contract.get("generated_at"),
            "redaction_tiers": contract.get("redaction_tiers", []),
            "required_attribute": required_attribute,
            "schema_version": contract.get("schema_version"),
            "selected_feature": contract.get("selected_feature"),
            "signal_classes": [self._signal_preview(signal) for signal in self._signal_by_id.values()],
            "source_artifacts": contract.get("source_artifacts"),
            "standards_alignment": contract.get("standards_alignment", []),
            "telemetry_checks": [self._check_preview(check) for check in self._check_by_id.values()],
            "telemetry_contract": contract.get("telemetry_contract"),
            "telemetry_summary": contract.get("telemetry_summary"),
            "workflow_count": len(workflows),
            "workflows": [self._workflow_preview(workflow) for workflow in workflows],
        }

class AgenticSocDetectionPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._rule_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        rules = pack.get("detection_rules") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_detection_overlays") if isinstance(pack, dict) else []
        self._rule_by_id = {
            str(rule.get("id")): rule
            for rule in rules
            if isinstance(rule, dict) and rule.get("id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _rule_preview(rule: dict[str, Any]) -> dict[str, Any]:
        return {
            "decision": rule.get("decision"),
            "event_classes": rule.get("event_classes", []),
            "id": rule.get("id"),
            "mapped_risks": rule.get("mapped_risks", []),
            "response_playbook": rule.get("response_playbook"),
            "severity": rule.get("severity"),
            "severity_score": rule.get("severity_score"),
            "siem_queries": rule.get("siem_queries", {}),
            "title": rule.get("title"),
        }

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "detection_rule_ids": workflow.get("detection_rule_ids", []),
            "maturity_stage": workflow.get("maturity_stage"),
            "mcp_namespaces": workflow.get("mcp_namespaces", []),
            "public_path": workflow.get("public_path"),
            "receipt_id": workflow.get("receipt_id"),
            "replay_fixture_count": workflow.get("replay_fixture_count"),
            "soc_default_decision": workflow.get("soc_default_decision"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    def get(
        self,
        rule_id: str | None = None,
        workflow_id: str | None = None,
        severity: str | None = None,
        decision: str | None = None,
        event_class: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic SOC detection pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic SOC detection pack is not present",
                "pack_path": str(self.path),
            }

        if rule_id:
            key = rule_id.strip()
            rule = self._rule_by_id.get(key)
            return {
                "available": True,
                "found": rule is not None,
                "rule": rule,
                "rule_id": key,
            }

        if workflow_id:
            key = workflow_id.strip()
            workflow = self._workflow_by_id.get(key)
            return {
                "available": True,
                "found": workflow is not None,
                "workflow": workflow,
                "workflow_id": key,
            }

        rules = list(self._rule_by_id.values())
        if severity:
            key = severity.strip()
            rules = [rule for rule in rules if str(rule.get("severity")) == key]
        if decision:
            key = decision.strip()
            rules = [rule for rule in rules if str(rule.get("decision")) == key]
        if event_class:
            key = event_class.strip()
            rules = [
                rule
                for rule in rules
                if key in set(str(item) for item in rule.get("event_classes", []))
            ]

        return {
            "available": True,
            "commercialization_path": pack.get("commercialization_path"),
            "decision": decision,
            "detection_contract": pack.get("detection_contract"),
            "detection_summary": pack.get("detection_summary"),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "event_class": event_class,
            "evaluator_contract": pack.get("evaluator_contract"),
            "generated_at": pack.get("generated_at"),
            "rule_count": len(rules),
            "rules": [self._rule_preview(rule) for rule in rules],
            "schema_version": pack.get("schema_version"),
            "selected_feature": pack.get("selected_feature"),
            "severity": severity,
            "siem_targets": pack.get("siem_targets", []),
            "source_artifacts": pack.get("source_artifacts"),
            "standards_alignment": pack.get("standards_alignment", []),
            "workflow_count": len(self._workflow_by_id),
            "workflows": [self._workflow_preview(workflow) for workflow in self._workflow_by_id.values()],
        }

class ContextPoisoningGuardPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._source_by_id: dict[str, dict[str, Any]] = {}
        self._finding_by_rule: dict[str, list[dict[str, Any]]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        sources = pack.get("source_results") if isinstance(pack, dict) else []
        findings = pack.get("findings") if isinstance(pack, dict) else []
        self._source_by_id = {
            str(source.get("source_id")): source
            for source in sources
            if isinstance(source, dict) and source.get("source_id")
        }
        by_rule: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            if not isinstance(finding, dict) or not finding.get("rule_id"):
                continue
            by_rule.setdefault(str(finding.get("rule_id")), []).append(finding)
        self._finding_by_rule = by_rule
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _source_preview(source: dict[str, Any]) -> dict[str, Any]:
        return {
            "actionable_finding_count": source.get("actionable_finding_count"),
            "decision": source.get("decision"),
            "file_count": source.get("file_count"),
            "finding_count": source.get("finding_count"),
            "risk_family_counts": source.get("risk_family_counts", {}),
            "root": source.get("root"),
            "severity_counts": source.get("severity_counts", {}),
            "source_hash": source.get("source_hash"),
            "source_id": source.get("source_id"),
            "title": source.get("title"),
            "trust_tier": source.get("trust_tier"),
        }

    @staticmethod
    def _finding_preview(finding: dict[str, Any]) -> dict[str, Any]:
        return {
            "actionable": finding.get("actionable"),
            "disposition": finding.get("disposition"),
            "line": finding.get("line"),
            "match": finding.get("match"),
            "path": finding.get("path"),
            "risk_family": finding.get("risk_family"),
            "rule_id": finding.get("rule_id"),
            "severity": finding.get("severity"),
            "source_id": finding.get("source_id"),
        }

    def get(
        self,
        source_id: str | None = None,
        decision: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        actionable_only: bool = False,
        limit: int | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load context poisoning guard pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "context poisoning guard pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "context poisoning guard pack root must be an object",
                "pack_path": str(self.path),
            }

        if source_id:
            source = self._source_by_id.get(source_id.strip())
            findings = [
                finding
                for finding in pack.get("findings", [])
                if isinstance(finding, dict)
                and str(finding.get("source_id")) == source_id.strip()
            ]
            if severity:
                findings = [
                    finding
                    for finding in findings
                    if str(finding.get("severity")) == severity.strip()
                ]
            if rule_id:
                findings = [
                    finding
                    for finding in findings
                    if str(finding.get("rule_id")) == rule_id.strip()
                ]
            if actionable_only:
                findings = [finding for finding in findings if finding.get("actionable")]
            cap = max(1, min(limit or 25, 100))
            return {
                "available": True,
                "finding_count": len(findings),
                "findings": [self._finding_preview(finding) for finding in findings[:cap]],
                "found": source is not None,
                "source": source,
                "source_id": source_id,
            }

        sources = list(self._source_by_id.values())
        if decision:
            key = decision.strip()
            sources = [
                source
                for source in sources
                if str(source.get("decision")) == key
            ]

        findings = [
            finding
            for finding in pack.get("findings", [])
            if isinstance(finding, dict)
        ]
        if severity:
            findings = [
                finding
                for finding in findings
                if str(finding.get("severity")) == severity.strip()
            ]
        if rule_id:
            findings = [
                finding
                for finding in findings
                if str(finding.get("rule_id")) == rule_id.strip()
            ]
        if actionable_only:
            findings = [finding for finding in findings if finding.get("actionable")]
        cap = max(1, min(limit or 25, 100))

        return {
            "available": True,
            "decision": decision,
            "decision_contract": pack.get("decision_contract"),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "finding_count": len(findings),
            "findings": [self._finding_preview(finding) for finding in findings[:cap]],
            "generated_at": pack.get("generated_at"),
            "guard_summary": pack.get("guard_summary"),
            "schema_version": pack.get("schema_version"),
            "scanner_rules": pack.get("scanner_rules", []),
            "severity": severity,
            "source_artifacts": pack.get("source_artifacts"),
            "source_count": len(sources),
            "sources": [self._source_preview(source) for source in sources],
            "standards_alignment": pack.get("standards_alignment", []),
        }


class ContextEgressBoundaryPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._source_by_id: dict[str, dict[str, Any]] = {}
        self._workflow_by_id: dict[str, dict[str, Any]] = {}
        self._policy_by_data_class: dict[str, dict[str, Any]] = {}
        self._destination_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        sources = pack.get("source_egress_map") if isinstance(pack, dict) else []
        workflows = pack.get("workflow_egress_map") if isinstance(pack, dict) else []
        policies = pack.get("data_class_policies") if isinstance(pack, dict) else []
        destinations = pack.get("destination_classes") if isinstance(pack, dict) else []
        self._source_by_id = {
            str(source.get("source_id")): source
            for source in sources
            if isinstance(source, dict) and source.get("source_id")
        }
        self._workflow_by_id = {
            str(workflow.get("workflow_id")): workflow
            for workflow in workflows
            if isinstance(workflow, dict) and workflow.get("workflow_id")
        }
        self._policy_by_data_class = {
            str(policy.get("id")): policy
            for policy in policies
            if isinstance(policy, dict) and policy.get("id")
        }
        self._destination_by_id = {
            str(destination.get("id")): destination
            for destination in destinations
            if isinstance(destination, dict) and destination.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _source_preview(source: dict[str, Any]) -> dict[str, Any]:
        return {
            "data_class": source.get("data_class"),
            "default_decision": source.get("default_decision"),
            "exposure": source.get("exposure"),
            "root": source.get("root"),
            "sensitivity": source.get("sensitivity"),
            "source_hash": source.get("source_hash"),
            "source_id": source.get("source_id"),
            "title": source.get("title"),
            "trust_tier": source.get("trust_tier"),
        }

    @staticmethod
    def _workflow_preview(workflow: dict[str, Any]) -> dict[str, Any]:
        return {
            "egress_policy_hash": workflow.get("egress_policy_hash"),
            "maturity_stage": workflow.get("maturity_stage"),
            "namespace_count": len(workflow.get("namespace_policies", []) or []),
            "public_path": workflow.get("public_path"),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        }

    @staticmethod
    def _policy_preview(policy: dict[str, Any]) -> dict[str, Any]:
        return {
            "allowed_destination_classes": policy.get("allowed_destination_classes", []),
            "default_decision": policy.get("default_decision"),
            "hold_destination_classes": policy.get("hold_destination_classes", []),
            "id": policy.get("id"),
            "prohibited_destination_classes": policy.get("prohibited_destination_classes", []),
            "sensitivity": policy.get("sensitivity"),
            "title": policy.get("title"),
        }

    @staticmethod
    def _destination_preview(destination: dict[str, Any]) -> dict[str, Any]:
        return {
            "category": destination.get("category"),
            "external_processor": destination.get("external_processor"),
            "id": destination.get("id"),
            "requires_dpa": destination.get("requires_dpa"),
            "requires_residency_match": destination.get("requires_residency_match"),
            "requires_zero_data_retention": destination.get("requires_zero_data_retention"),
            "title": destination.get("title"),
            "trusted": destination.get("trusted"),
        }

    def get(
        self,
        data_class: str | None = None,
        destination_class: str | None = None,
        source_id: str | None = None,
        workflow_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load context egress boundary pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "context egress boundary pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "context egress boundary pack root must be an object",
                "pack_path": str(self.path),
            }

        if source_id:
            source = self._source_by_id.get(source_id.strip())
            return {
                "available": True,
                "found": source is not None,
                "source": source,
                "source_id": source_id,
            }

        if workflow_id:
            workflow = self._workflow_by_id.get(workflow_id.strip())
            return {
                "available": True,
                "found": workflow is not None,
                "workflow_egress": workflow,
                "workflow_id": workflow_id,
            }

        if data_class:
            policy = self._policy_by_data_class.get(data_class.strip())
            return {
                "available": True,
                "data_class": data_class,
                "found": policy is not None,
                "policy": policy,
            }

        if destination_class:
            destination = self._destination_by_id.get(destination_class.strip())
            return {
                "available": True,
                "destination": destination,
                "destination_class": destination_class,
                "found": destination is not None,
            }

        return {
            "available": True,
            "data_class_policies": [
                self._policy_preview(policy)
                for policy in self._policy_by_data_class.values()
            ],
            "destination_classes": [
                self._destination_preview(destination)
                for destination in self._destination_by_id.values()
            ],
            "egress_boundary_summary": pack.get("egress_boundary_summary"),
            "egress_decision_contract": pack.get("egress_decision_contract"),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "sources": [
                self._source_preview(source)
                for source in self._source_by_id.values()
            ],
            "standards_alignment": pack.get("standards_alignment", []),
            "workflows": [
                self._workflow_preview(workflow)
                for workflow in self._workflow_by_id.values()
            ],
        }

class AgenticStandardsCrosswalk:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._standard_by_id: dict[str, dict[str, Any]] = {}
        self._control_by_id: dict[str, dict[str, Any]] = {}
        self._capability_by_id: dict[str, dict[str, Any]] = {}
        self._source_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        standards = pack.get("standards") if isinstance(pack, dict) else []
        controls = pack.get("controls") if isinstance(pack, dict) else []
        coverage = pack.get("capability_coverage") if isinstance(pack, dict) else []
        sources = pack.get("source_references") if isinstance(pack, dict) else []
        self._standard_by_id = {
            str(standard.get("id")): standard
            for standard in standards
            if isinstance(standard, dict) and standard.get("id")
        }
        self._control_by_id = {}
        for control in controls:
            if not isinstance(control, dict) or not control.get("id"):
                continue
            control_id = str(control.get("id"))
            standard_id = str(control.get("standard_id", ""))
            self._control_by_id[control_id] = control
            if standard_id:
                self._control_by_id[f"{standard_id}::{control_id}"] = control
        self._capability_by_id = {
            str(row.get("capability_id")): row
            for row in coverage
            if isinstance(row, dict) and row.get("capability_id")
        }
        self._source_by_id = {
            str(source.get("id")): source
            for source in sources
            if isinstance(source, dict) and source.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _standard_preview(standard: dict[str, Any]) -> dict[str, Any]:
        return {
            "buyer_question": standard.get("buyer_question"),
            "capability_count": standard.get("capability_count"),
            "control_count": standard.get("control_count"),
            "coverage_score": standard.get("coverage_score"),
            "id": standard.get("id"),
            "kind": standard.get("kind"),
            "mcp_tools": standard.get("mcp_tools", []),
            "ready_control_count": standard.get("ready_control_count"),
            "source_ids": standard.get("source_ids", []),
            "status": standard.get("status"),
            "title": standard.get("title"),
        }

    @staticmethod
    def _control_preview(control: dict[str, Any]) -> dict[str, Any]:
        return {
            "diligence_question": control.get("diligence_question"),
            "evidence_paths": control.get("evidence_paths", []),
            "id": control.get("id"),
            "mcp_tools": control.get("mcp_tools", []),
            "required_capability_ids": control.get("required_capability_ids", []),
            "standard_id": control.get("standard_id"),
            "status": control.get("status"),
            "title": control.get("title"),
        }

    @staticmethod
    def _capability_preview(row: dict[str, Any]) -> dict[str, Any]:
        capability = row.get("capability") if isinstance(row.get("capability"), dict) else {}
        return {
            "capability_id": row.get("capability_id"),
            "control_count": row.get("control_count"),
            "mcp_tools": capability.get("mcp_tools", []),
            "standard_count": row.get("standard_count"),
            "status": row.get("status"),
            "title": capability.get("title"),
        }

    @staticmethod
    def _source_preview(source: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": source.get("id"),
            "name": source.get("name"),
            "published": source.get("published"),
            "publisher": source.get("publisher"),
            "source_class": source.get("source_class"),
            "url": source.get("url"),
        }

    def get(
        self,
        standard_id: str | None = None,
        control_id: str | None = None,
        capability_id: str | None = None,
        source_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic standards crosswalk: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic standards crosswalk is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic standards crosswalk root must be an object",
                "pack_path": str(self.path),
            }

        if standard_id:
            key = standard_id.strip()
            standard = self._standard_by_id.get(key)
            controls = [
                control
                for control in pack.get("controls", [])
                if isinstance(control, dict) and str(control.get("standard_id")) == key
            ]
            return {
                "available": True,
                "controls": controls,
                "found": standard is not None,
                "standard": standard,
                "standard_id": key,
            }

        if control_id:
            key = control_id.strip()
            control = self._control_by_id.get(key)
            return {
                "available": True,
                "control": control,
                "control_id": key,
                "found": control is not None,
            }

        if capability_id:
            key = capability_id.strip()
            capability = self._capability_by_id.get(key)
            return {
                "available": True,
                "capability": capability,
                "capability_id": key,
                "found": capability is not None,
            }

        if source_id:
            key = source_id.strip()
            source = self._source_by_id.get(key)
            return {
                "available": True,
                "found": source is not None,
                "source": source,
                "source_id": key,
            }

        standards = list(self._standard_by_id.values())
        controls = [
            control
            for control in pack.get("controls", [])
            if isinstance(control, dict)
        ]
        if status:
            key = status.strip()
            standards = [standard for standard in standards if str(standard.get("status")) == key]
            controls = [control for control in controls if str(control.get("status")) == key]

        return {
            "available": True,
            "buyer_views": pack.get("buyer_views", []),
            "capability_coverage": [
                self._capability_preview(row)
                for row in self._capability_by_id.values()
            ],
            "commercialization_path": pack.get("commercialization_path", {}),
            "control_count": len(controls),
            "control_plane_contract": pack.get("control_plane_contract", {}),
            "controls": [self._control_preview(control) for control in controls],
            "crosswalk_summary": pack.get("crosswalk_summary"),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_references": [
                self._source_preview(source)
                for source in self._source_by_id.values()
            ],
            "standard_count": len(standards),
            "standards": [self._standard_preview(standard) for standard in standards],
            "status": status,
        }


class AgenticSourceFreshnessWatch:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._watch_by_id: dict[str, dict[str, Any]] = {}
        self._source_by_id: dict[str, dict[str, Any]] = {}
        self._primary_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        watches = pack.get("watch_sources") if isinstance(pack, dict) else []
        sources = pack.get("source_catalog") if isinstance(pack, dict) else []
        primary = pack.get("primary_watchlist_coverage") if isinstance(pack, dict) else []
        self._watch_by_id = {
            str(row.get("id")): row
            for row in watches
            if isinstance(row, dict) and row.get("id")
        }
        self._source_by_id = {
            str(row.get("id")): row
            for row in sources
            if isinstance(row, dict) and row.get("id")
        }
        self._primary_by_id = {
            str(row.get("id")): row
            for row in primary
            if isinstance(row, dict) and row.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _watch_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "blockers": row.get("blockers", []),
            "business_criticality": row.get("business_criticality"),
            "decision": row.get("decision"),
            "id": row.get("id"),
            "last_reviewed": row.get("last_reviewed"),
            "path": row.get("path"),
            "reference_count": row.get("reference_count"),
            "review_due_at": row.get("review_due_at"),
            "title": row.get("title"),
        }

    @staticmethod
    def _source_preview(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "freshness_class": row.get("freshness_class"),
            "id": row.get("id"),
            "name": row.get("name"),
            "published": row.get("published"),
            "published_age_days": row.get("published_age_days"),
            "publisher_family": row.get("publisher_family"),
            "referenced_by": row.get("referenced_by", []),
            "source_class": row.get("source_class"),
            "source_class_family": row.get("source_class_family"),
            "url": row.get("url"),
        }

    def get(
        self,
        watched_source_id: str | None = None,
        source_id: str | None = None,
        primary_watchlist_id: str | None = None,
        publisher_family: str | None = None,
        source_class_family: str | None = None,
        freshness_class: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic source freshness watch: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic source freshness watch is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic source freshness watch root must be an object",
                "pack_path": str(self.path),
            }

        if watched_source_id:
            key = watched_source_id.strip()
            watch = self._watch_by_id.get(key)
            return {
                "available": True,
                "found": watch is not None,
                "watch_source": watch,
                "watched_source_id": key,
            }

        if source_id:
            key = source_id.strip()
            source = self._source_by_id.get(key)
            return {
                "available": True,
                "found": source is not None,
                "source": source,
                "source_id": key,
            }

        if primary_watchlist_id:
            key = primary_watchlist_id.strip()
            primary = self._primary_by_id.get(key)
            return {
                "available": True,
                "found": primary is not None,
                "primary_watchlist": primary,
                "primary_watchlist_id": key,
            }

        watches = list(self._watch_by_id.values())
        sources = list(self._source_by_id.values())
        if decision:
            key = decision.strip()
            watches = [row for row in watches if str(row.get("decision")) == key]
        if publisher_family:
            key = publisher_family.strip().lower()
            sources = [row for row in sources if str(row.get("publisher_family", "")).lower() == key]
        if source_class_family:
            key = source_class_family.strip().lower()
            sources = [row for row in sources if str(row.get("source_class_family", "")).lower() == key]
        if freshness_class:
            key = freshness_class.strip()
            sources = [row for row in sources if str(row.get("freshness_class")) == key]

        return {
            "available": True,
            "buyer_views": pack.get("buyer_views", []),
            "commercialization_path": pack.get("commercialization_path", {}),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "filters": {
                "decision": decision,
                "freshness_class": freshness_class,
                "publisher_family": publisher_family,
                "source_class_family": source_class_family,
            },
            "freshness_contract": pack.get("freshness_contract", {}),
            "freshness_summary": pack.get("freshness_summary"),
            "generated_at": pack.get("generated_at"),
            "primary_watchlist_coverage": pack.get("primary_watchlist_coverage", []),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_catalog": [self._source_preview(row) for row in sources],
            "source_count": len(sources),
            "watch_source_count": len(watches),
            "watch_sources": [self._watch_preview(row) for row in watches],
        }


class MCPRiskCoveragePack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._risk_by_id: dict[str, dict[str, Any]] = {}
        self._standard_by_id: dict[str, dict[str, Any]] = {}
        self._capability_by_id: dict[str, dict[str, Any]] = {}
        self._source_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        risks = pack.get("risk_coverage") if isinstance(pack, dict) else []
        standards = pack.get("standards") if isinstance(pack, dict) else []
        coverage = pack.get("capability_coverage") if isinstance(pack, dict) else []
        sources = pack.get("source_references") if isinstance(pack, dict) else []
        self._risk_by_id = {
            str(risk.get("id")): risk
            for risk in risks
            if isinstance(risk, dict) and risk.get("id")
        }
        self._standard_by_id = {
            str(standard.get("id")): standard
            for standard in standards
            if isinstance(standard, dict) and standard.get("id")
        }
        self._capability_by_id = {
            str(row.get("capability_id")): row
            for row in coverage
            if isinstance(row, dict) and row.get("capability_id")
        }
        self._source_by_id = {
            str(source.get("id")): source
            for source in sources
            if isinstance(source, dict) and source.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _risk_preview(risk: dict[str, Any]) -> dict[str, Any]:
        return {
            "coverage_status": risk.get("coverage_status"),
            "evidence_paths": risk.get("evidence_paths", []),
            "id": risk.get("id"),
            "mcp_tools": risk.get("mcp_tools", []),
            "required_capability_ids": risk.get("required_capability_ids", []),
            "risk_tier": risk.get("risk_tier"),
            "standard_id": risk.get("standard_id"),
            "title": risk.get("title"),
        }

    @staticmethod
    def _standard_preview(standard: dict[str, Any]) -> dict[str, Any]:
        return {
            "capability_count": standard.get("capability_count"),
            "coverage_score": standard.get("coverage_score"),
            "id": standard.get("id"),
            "mcp_tools": standard.get("mcp_tools", []),
            "risk_count": standard.get("risk_count"),
            "risk_ids": standard.get("risk_ids", []),
            "source_ids": standard.get("source_ids", []),
            "status": standard.get("status"),
            "title": standard.get("title"),
        }

    @staticmethod
    def _capability_preview(row: dict[str, Any]) -> dict[str, Any]:
        capability = row.get("capability") if isinstance(row.get("capability"), dict) else {}
        return {
            "capability_id": row.get("capability_id"),
            "mcp_tools": capability.get("mcp_tools", []),
            "risk_count": row.get("risk_count"),
            "risk_ids": row.get("risk_ids", []),
            "standard_count": row.get("standard_count"),
            "status": row.get("status"),
            "title": capability.get("title"),
        }

    @staticmethod
    def _source_preview(source: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": source.get("id"),
            "name": source.get("name"),
            "published": source.get("published"),
            "publisher": source.get("publisher"),
            "source_class": source.get("source_class"),
            "url": source.get("url"),
        }

    def get(
        self,
        risk_id: str | None = None,
        standard_id: str | None = None,
        capability_id: str | None = None,
        source_id: str | None = None,
        risk_tier: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load MCP risk coverage pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "MCP risk coverage pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "MCP risk coverage pack root must be an object",
                "pack_path": str(self.path),
            }

        if risk_id:
            key = risk_id.strip()
            risk = self._risk_by_id.get(key)
            return {
                "available": True,
                "found": risk is not None,
                "risk": risk,
                "risk_id": key,
            }

        risks = list(self._risk_by_id.values())
        if standard_id:
            key = standard_id.strip()
            standard = self._standard_by_id.get(key)
            return {
                "available": True,
                "found": standard is not None,
                "risks": [
                    risk
                    for risk in risks
                    if str(risk.get("standard_id")) == key
                ],
                "standard": standard,
                "standard_id": key,
            }

        if capability_id:
            key = capability_id.strip()
            capability = self._capability_by_id.get(key)
            return {
                "available": True,
                "capability": capability,
                "capability_id": key,
                "found": capability is not None,
                "risks": [
                    risk
                    for risk in risks
                    if key in [str(item) for item in risk.get("required_capability_ids", [])]
                ],
            }

        if source_id:
            key = source_id.strip()
            source = self._source_by_id.get(key)
            return {
                "available": True,
                "found": source is not None,
                "risks": [
                    risk
                    for risk in risks
                    if key in [str(item) for item in risk.get("source_ids", [])]
                ],
                "source": source,
                "source_id": key,
            }

        if risk_tier:
            key = risk_tier.strip()
            risks = [risk for risk in risks if str(risk.get("risk_tier")) == key]
        if status:
            key = status.strip()
            risks = [risk for risk in risks if str(risk.get("coverage_status")) == key]

        return {
            "available": True,
            "buyer_views": pack.get("buyer_views", []),
            "capability_coverage": [
                self._capability_preview(row)
                for row in self._capability_by_id.values()
            ],
            "commercialization_path": pack.get("commercialization_path", {}),
            "coverage_contract": pack.get("coverage_contract", {}),
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "risk_count": len(risks),
            "risk_coverage": [self._risk_preview(risk) for risk in risks],
            "risk_coverage_summary": pack.get("risk_coverage_summary"),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_references": [
                self._source_preview(source)
                for source in self._source_by_id.values()
            ],
            "standard_count": len(self._standard_by_id),
            "standards": [
                self._standard_preview(standard)
                for standard in self._standard_by_id.values()
            ],
            "status": status,
        }


class AgenticProtocolConformancePack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._protocol_by_id: dict[str, dict[str, Any]] = {}
        self._check_by_id: dict[str, dict[str, Any]] = {}
        self._source_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        protocols = pack.get("protocol_profiles") if isinstance(pack, dict) else []
        checks = pack.get("control_checks") if isinstance(pack, dict) else []
        sources = pack.get("source_references") if isinstance(pack, dict) else []
        self._protocol_by_id = {
            str(protocol.get("id")): protocol
            for protocol in protocols
            if isinstance(protocol, dict) and protocol.get("id")
        }
        self._check_by_id = {}
        for check in checks:
            if not isinstance(check, dict) or not check.get("id"):
                continue
            check_id = str(check.get("id"))
            protocol_id = str(check.get("protocol_id", ""))
            self._check_by_id[check_id] = check
            if protocol_id:
                self._check_by_id[f"{protocol_id}::{check_id}"] = check
        self._source_by_id = {
            str(source.get("id")): source
            for source in sources
            if isinstance(source, dict) and source.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _protocol_preview(protocol: dict[str, Any]) -> dict[str, Any]:
        return {
            "conformance_check_count": protocol.get("conformance_check_count"),
            "current_versions": protocol.get("current_versions", []),
            "effective_decision": protocol.get("effective_decision"),
            "id": protocol.get("id"),
            "readiness_score": protocol.get("readiness_score"),
            "ready_check_count": protocol.get("ready_check_count"),
            "source_ids": protocol.get("source_ids", []),
            "title": protocol.get("title"),
        }

    @staticmethod
    def _check_preview(check: dict[str, Any]) -> dict[str, Any]:
        return {
            "evidence_paths": check.get("evidence_paths", []),
            "fail_closed_decision": check.get("fail_closed_decision"),
            "id": check.get("id"),
            "protocol_id": check.get("protocol_id"),
            "required_runtime_attributes": check.get("required_runtime_attributes", []),
            "source_pack_keys": check.get("source_pack_keys", []),
            "status": check.get("status"),
            "title": check.get("title"),
        }

    @staticmethod
    def _source_preview(source: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": source.get("id"),
            "name": source.get("name"),
            "published": source.get("published"),
            "publisher": source.get("publisher"),
            "source_class": source.get("source_class"),
            "url": source.get("url"),
        }

    def get(
        self,
        protocol_id: str | None = None,
        check_id: str | None = None,
        source_id: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load agentic protocol conformance pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "agentic protocol conformance pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "agentic protocol conformance pack root must be an object",
                "pack_path": str(self.path),
            }

        if protocol_id:
            key = protocol_id.strip()
            protocol = self._protocol_by_id.get(key)
            return {
                "available": True,
                "found": protocol is not None,
                "protocol": protocol,
                "protocol_id": key,
            }

        if check_id:
            key = check_id.strip()
            check = self._check_by_id.get(key)
            return {
                "available": True,
                "check": check,
                "check_id": key,
                "found": check is not None,
            }

        if source_id:
            key = source_id.strip()
            source = self._source_by_id.get(key)
            return {
                "available": True,
                "found": source is not None,
                "source": source,
                "source_id": key,
            }

        protocols = list(self._protocol_by_id.values())
        checks = [
            check
            for check in pack.get("control_checks", [])
            if isinstance(check, dict)
        ]
        if decision:
            key = decision.strip()
            protocols = [
                protocol
                for protocol in protocols
                if str(protocol.get("effective_decision")) == key
            ]

        return {
            "available": True,
            "buyer_views": pack.get("buyer_views", []),
            "commercialization_path": pack.get("commercialization_path", {}),
            "conformance_contract": pack.get("conformance_contract", {}),
            "control_check_count": len(checks),
            "control_checks": [self._check_preview(check) for check in checks],
            "decision": decision,
            "enterprise_adoption_packet": pack.get("enterprise_adoption_packet"),
            "generated_at": pack.get("generated_at"),
            "protocol_conformance_pack_id": pack.get("protocol_conformance_pack_id"),
            "protocol_conformance_summary": pack.get("protocol_conformance_summary"),
            "protocol_count": len(protocols),
            "protocol_profiles": [self._protocol_preview(protocol) for protocol in protocols],
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_references": [
                self._source_preview(source)
                for source in self._source_by_id.values()
            ],
        }

class EnterpriseTrustCenterExport:
    def __init__(self, export_path: str):
        self.path = Path(export_path)
        self._mtime: float | None = None
        self._export: dict[str, Any] | None = None
        self._section_by_id: dict[str, dict[str, Any]] = {}
        self._pack_by_id: dict[str, dict[str, Any]] = {}
        self._question_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._export is not None and self._mtime == stat.st_mtime:
            return self._export

        export = json.loads(self.path.read_text(encoding="utf-8"))
        sections = export.get("trust_center_sections") if isinstance(export, dict) else []
        packs = export.get("pack_index") if isinstance(export, dict) else []
        questions = export.get("diligence_questions") if isinstance(export, dict) else []
        self._section_by_id = {
            str(section.get("id")): section
            for section in sections
            if isinstance(section, dict) and section.get("id")
        }
        self._pack_by_id = {
            str(pack.get("id")): pack
            for pack in packs
            if isinstance(pack, dict) and pack.get("id")
        }
        self._question_by_id = {
            str(question.get("id")): question
            for question in questions
            if isinstance(question, dict) and question.get("id")
        }
        self._export = export
        self._mtime = stat.st_mtime
        return export

    @staticmethod
    def _section_preview(section: dict[str, Any]) -> dict[str, Any]:
        return {
            "evidence_pack_ids": section.get("evidence_pack_ids", []),
            "id": section.get("id"),
            "mcp_tools": section.get("mcp_tools", []),
            "question_count": section.get("question_count"),
            "ready_evidence_count": section.get("ready_evidence_count"),
            "status": section.get("status"),
            "title": section.get("title"),
            "total_evidence_count": section.get("total_evidence_count"),
        }

    @staticmethod
    def _pack_preview(pack: dict[str, Any]) -> dict[str, Any]:
        return {
            "category": pack.get("category"),
            "failure_count": pack.get("failure_count"),
            "id": pack.get("id"),
            "mcp_tools": pack.get("mcp_tools", []),
            "path": pack.get("path"),
            "required": pack.get("required"),
            "schema_version": pack.get("schema_version"),
            "sha256": pack.get("sha256"),
            "status": pack.get("status"),
            "title": pack.get("title"),
        }

    def get(
        self,
        section_id: str | None = None,
        pack_id: str | None = None,
        question_id: str | None = None,
        category: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            export = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load enterprise trust-center export: {exc}",
                "export_path": str(self.path),
            }

        if export is None:
            return {
                "available": False,
                "error": "enterprise trust-center export is not present",
                "export_path": str(self.path),
            }

        if not isinstance(export, dict):
            return {
                "available": False,
                "error": "enterprise trust-center export root must be an object",
                "export_path": str(self.path),
            }

        if section_id:
            key = section_id.strip()
            section = self._section_by_id.get(key)
            return {
                "available": True,
                "found": section is not None,
                "section": section,
                "section_id": key,
            }

        if pack_id:
            key = pack_id.strip()
            pack = self._pack_by_id.get(key)
            return {
                "available": True,
                "found": pack is not None,
                "pack": pack,
                "pack_id": key,
            }

        if question_id:
            key = question_id.strip()
            question = self._question_by_id.get(key)
            return {
                "available": True,
                "found": question is not None,
                "question": question,
                "question_id": key,
            }

        packs = list(self._pack_by_id.values())
        sections = list(self._section_by_id.values())
        if category:
            key = category.strip()
            packs = [pack for pack in packs if str(pack.get("category")) == key]
        if status:
            key = status.strip()
            packs = [pack for pack in packs if str(pack.get("status")) == key]
            sections = [section for section in sections if str(section.get("status")) == key]

        return {
            "available": True,
            "category": category,
            "commercialization_path": export.get("commercialization_path"),
            "diligence_question_count": len(self._question_by_id),
            "enterprise_trust_center_export_id": export.get("enterprise_trust_center_export_id"),
            "executive_readout": export.get("executive_readout"),
            "export_summary": export.get("export_summary"),
            "generated_at": export.get("generated_at"),
            "pack_count": len(packs),
            "packs": [self._pack_preview(pack) for pack in packs],
            "runtime_evidence_contract": export.get("runtime_evidence_contract", []),
            "schema_version": export.get("schema_version"),
            "section_count": len(sections),
            "sections": [self._section_preview(section) for section in sections],
            "source_artifacts": export.get("source_artifacts"),
            "standards_alignment": export.get("standards_alignment", []),
            "status": status,
        }


class SecureContextValueModel:
    def __init__(self, model_path: str):
        self.path = Path(model_path)
        self._mtime: float | None = None
        self._model: dict[str, Any] | None = None
        self._driver_by_id: dict[str, dict[str, Any]] = {}
        self._segment_by_id: dict[str, dict[str, Any]] = {}
        self._scenario_by_id: dict[str, dict[str, Any]] = {}
        self._wedge_by_id: dict[str, dict[str, Any]] = {}
        self._question_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._model is not None and self._mtime == stat.st_mtime:
            return self._model

        model = json.loads(self.path.read_text(encoding="utf-8"))
        drivers = model.get("value_drivers") if isinstance(model, dict) else []
        segments = model.get("buyer_segments") if isinstance(model, dict) else []
        scenarios = model.get("adoption_scenarios") if isinstance(model, dict) else []
        wedges = model.get("monetization_wedges") if isinstance(model, dict) else []
        questions = model.get("diligence_questions") if isinstance(model, dict) else []
        self._driver_by_id = {
            str(driver.get("id")): driver
            for driver in drivers
            if isinstance(driver, dict) and driver.get("id")
        }
        self._segment_by_id = {
            str(segment.get("id")): segment
            for segment in segments
            if isinstance(segment, dict) and segment.get("id")
        }
        self._scenario_by_id = {
            str(scenario.get("id")): scenario
            for scenario in scenarios
            if isinstance(scenario, dict) and scenario.get("id")
        }
        self._wedge_by_id = {
            str(wedge.get("id")): wedge
            for wedge in wedges
            if isinstance(wedge, dict) and wedge.get("id")
        }
        self._question_by_id = {
            str(question.get("id")): question
            for question in questions
            if isinstance(question, dict) and question.get("id")
        }
        self._model = model
        self._mtime = stat.st_mtime
        return model

    @staticmethod
    def _driver_preview(driver: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": driver.get("id"),
            "premium_surface": driver.get("premium_surface"),
            "ready_evidence_count": driver.get("ready_evidence_count"),
            "status": driver.get("status"),
            "title": driver.get("title"),
            "total_evidence_count": driver.get("total_evidence_count"),
        }

    @staticmethod
    def _segment_preview(segment: dict[str, Any]) -> dict[str, Any]:
        return {
            "buyer_trigger": segment.get("buyer_trigger"),
            "id": segment.get("id"),
            "primary_wedge_ids": segment.get("primary_wedge_ids", []),
            "title": segment.get("title"),
        }

    @staticmethod
    def _scenario_preview(scenario: dict[str, Any]) -> dict[str, Any]:
        economics = scenario.get("economics") if isinstance(scenario.get("economics"), dict) else {}
        return {
            "annual_net_value_usd": economics.get("annual_net_value_usd"),
            "first_year_net_after_implementation_usd": economics.get("first_year_net_after_implementation_usd"),
            "id": scenario.get("id"),
            "payback_months": economics.get("payback_months"),
            "time_horizon": scenario.get("time_horizon"),
            "title": scenario.get("title"),
        }

    def get(
        self,
        driver_id: str | None = None,
        segment_id: str | None = None,
        scenario_id: str | None = None,
        wedge_id: str | None = None,
        question_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            model = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load secure context value model: {exc}",
                "model_path": str(self.path),
            }

        if model is None:
            return {
                "available": False,
                "error": "secure context value model is not present",
                "model_path": str(self.path),
            }

        if not isinstance(model, dict):
            return {
                "available": False,
                "error": "secure context value model root must be an object",
                "model_path": str(self.path),
            }

        if driver_id:
            key = driver_id.strip()
            driver = self._driver_by_id.get(key)
            return {"available": True, "driver": driver, "driver_id": key, "found": driver is not None}

        if segment_id:
            key = segment_id.strip()
            segment = self._segment_by_id.get(key)
            return {"available": True, "found": segment is not None, "segment": segment, "segment_id": key}

        if scenario_id:
            key = scenario_id.strip()
            scenario = self._scenario_by_id.get(key)
            return {"available": True, "found": scenario is not None, "scenario": scenario, "scenario_id": key}

        if wedge_id:
            key = wedge_id.strip()
            wedge = self._wedge_by_id.get(key)
            return {"available": True, "found": wedge is not None, "wedge": wedge, "wedge_id": key}

        if question_id:
            key = question_id.strip()
            question = self._question_by_id.get(key)
            return {"available": True, "found": question is not None, "question": question, "question_id": key}

        drivers = list(self._driver_by_id.values())
        if status:
            key = status.strip()
            drivers = [driver for driver in drivers if str(driver.get("status")) == key]

        return {
            "available": True,
            "acquisition_readiness": model.get("acquisition_readiness"),
            "adoption_scenarios": [self._scenario_preview(scenario) for scenario in self._scenario_by_id.values()],
            "buyer_segments": [self._segment_preview(segment) for segment in self._segment_by_id.values()],
            "diligence_question_count": len(self._question_by_id),
            "evidence_rollup": model.get("evidence_rollup"),
            "generated_at": model.get("generated_at"),
            "monetization_wedges": list(self._wedge_by_id.values()),
            "schema_version": model.get("schema_version"),
            "secure_context_value_model_id": model.get("secure_context_value_model_id"),
            "source_artifacts": model.get("source_artifacts"),
            "source_pack_index": model.get("source_pack_index", []),
            "source_references": model.get("source_references", []),
            "status": status,
            "value_contract": model.get("value_contract"),
            "value_drivers": [self._driver_preview(driver) for driver in drivers],
            "value_model_summary": model.get("value_model_summary"),
        }


class DesignPartnerPilotPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._segment_by_id: dict[str, dict[str, Any]] = {}
        self._phase_by_id: dict[str, dict[str, Any]] = {}
        self._wedge_by_id: dict[str, dict[str, Any]] = {}
        self._metric_by_id: dict[str, dict[str, Any]] = {}
        self._question_by_id: dict[str, dict[str, Any]] = {}
        self._risk_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        segments = pack.get("buyer_segments") if isinstance(pack, dict) else []
        phases = pack.get("pilot_phases") if isinstance(pack, dict) else []
        wedges = pack.get("monetization_wedges") if isinstance(pack, dict) else []
        metrics = pack.get("success_metrics") if isinstance(pack, dict) else []
        questions = pack.get("diligence_questions") if isinstance(pack, dict) else []
        risks = pack.get("risk_register") if isinstance(pack, dict) else []
        self._segment_by_id = {
            str(segment.get("id")): segment
            for segment in segments
            if isinstance(segment, dict) and segment.get("id")
        }
        self._phase_by_id = {
            str(phase.get("id")): phase
            for phase in phases
            if isinstance(phase, dict) and phase.get("id")
        }
        self._wedge_by_id = {
            str(wedge.get("id")): wedge
            for wedge in wedges
            if isinstance(wedge, dict) and wedge.get("id")
        }
        self._metric_by_id = {
            str(metric.get("id")): metric
            for metric in metrics
            if isinstance(metric, dict) and metric.get("id")
        }
        self._question_by_id = {
            str(question.get("id")): question
            for question in questions
            if isinstance(question, dict) and question.get("id")
        }
        self._risk_by_id = {
            str(risk.get("id")): risk
            for risk in risks
            if isinstance(risk, dict) and risk.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _segment_preview(segment: dict[str, Any]) -> dict[str, Any]:
        return {
            "buyer_trigger": segment.get("buyer_trigger"),
            "id": segment.get("id"),
            "primary_wedge_ids": segment.get("primary_wedge_ids", []),
            "title": segment.get("title"),
        }

    @staticmethod
    def _phase_preview(phase: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": phase.get("id"),
            "minimum_duration_days": phase.get("minimum_duration_days"),
            "status": phase.get("status"),
            "title": phase.get("title"),
        }

    @staticmethod
    def _wedge_preview(wedge: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": wedge.get("id"),
            "paid_surface": wedge.get("paid_surface"),
            "pricing_guardrail": wedge.get("pricing_guardrail"),
            "status": wedge.get("status"),
            "title": wedge.get("title"),
        }

    @staticmethod
    def _metric_preview(metric: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": metric.get("id"),
            "metric_type": metric.get("metric_type"),
            "status": metric.get("status"),
            "target": metric.get("target"),
            "title": metric.get("title"),
        }

    def get(
        self,
        segment_id: str | None = None,
        phase_id: str | None = None,
        wedge_id: str | None = None,
        metric_id: str | None = None,
        question_id: str | None = None,
        risk_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load design partner pilot pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "design partner pilot pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "design partner pilot pack root must be an object",
                "pack_path": str(self.path),
            }

        if segment_id:
            key = segment_id.strip()
            segment = self._segment_by_id.get(key)
            return {"available": True, "found": segment is not None, "segment": segment, "segment_id": key}

        if phase_id:
            key = phase_id.strip()
            phase = self._phase_by_id.get(key)
            return {"available": True, "found": phase is not None, "phase": phase, "phase_id": key}

        if wedge_id:
            key = wedge_id.strip()
            wedge = self._wedge_by_id.get(key)
            return {"available": True, "found": wedge is not None, "wedge": wedge, "wedge_id": key}

        if metric_id:
            key = metric_id.strip()
            metric = self._metric_by_id.get(key)
            return {"available": True, "found": metric is not None, "metric": metric, "metric_id": key}

        if question_id:
            key = question_id.strip()
            question = self._question_by_id.get(key)
            return {"available": True, "found": question is not None, "question": question, "question_id": key}

        if risk_id:
            key = risk_id.strip()
            risk = self._risk_by_id.get(key)
            return {"available": True, "found": risk is not None, "risk": risk, "risk_id": key}

        phases = list(self._phase_by_id.values())
        wedges = list(self._wedge_by_id.values())
        metrics = list(self._metric_by_id.values())
        if status:
            key = status.strip()
            phases = [phase for phase in phases if str(phase.get("status")) == key]
            wedges = [wedge for wedge in wedges if str(wedge.get("status")) == key]
            metrics = [metric for metric in metrics if str(metric.get("status")) == key]

        return {
            "available": True,
            "buyer_segments": [self._segment_preview(segment) for segment in self._segment_by_id.values()],
            "design_partner_pilot_pack_id": pack.get("design_partner_pilot_pack_id"),
            "diligence_question_count": len(self._question_by_id),
            "generated_at": pack.get("generated_at"),
            "monetization_wedges": [self._wedge_preview(wedge) for wedge in wedges],
            "pilot_contract": pack.get("pilot_contract"),
            "pilot_phases": [self._phase_preview(phase) for phase in phases],
            "pilot_summary": pack.get("pilot_summary"),
            "pricing_guardrails": pack.get("pricing_guardrails"),
            "readiness": pack.get("readiness"),
            "risk_count": len(self._risk_by_id),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_pack_index": pack.get("source_pack_index", []),
            "source_references": pack.get("source_references", []),
            "status": status,
            "success_metrics": [self._metric_preview(metric) for metric in metrics],
            "telemetry_requirements": pack.get("telemetry_requirements"),
        }


class SecureContextBuyerDiligenceBrief:
    def __init__(self, brief_path: str):
        self.path = Path(brief_path)
        self._mtime: float | None = None
        self._brief: dict[str, Any] | None = None
        self._buyer_by_id: dict[str, dict[str, Any]] = {}
        self._question_by_id: dict[str, dict[str, Any]] = {}
        self._objection_by_id: dict[str, dict[str, Any]] = {}
        self._bet_by_id: dict[str, dict[str, Any]] = {}
        self._source_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._brief is not None and self._mtime == stat.st_mtime:
            return self._brief

        brief = json.loads(self.path.read_text(encoding="utf-8"))
        buyers = brief.get("buyer_briefs") if isinstance(brief, dict) else []
        questions = brief.get("enterprise_questions") if isinstance(brief, dict) else []
        objections = brief.get("objection_handlers") if isinstance(brief, dict) else []
        bets = brief.get("industry_bets") if isinstance(brief, dict) else []
        sources = brief.get("source_references") if isinstance(brief, dict) else []
        self._buyer_by_id = {
            str(buyer.get("id")): buyer
            for buyer in buyers
            if isinstance(buyer, dict) and buyer.get("id")
        }
        self._question_by_id = {
            str(question.get("id")): question
            for question in questions
            if isinstance(question, dict) and question.get("id")
        }
        self._objection_by_id = {
            str(objection.get("id")): objection
            for objection in objections
            if isinstance(objection, dict) and objection.get("id")
        }
        self._bet_by_id = {
            str(bet.get("id")): bet
            for bet in bets
            if isinstance(bet, dict) and bet.get("id")
        }
        self._source_by_id = {
            str(source.get("id")): source
            for source in sources
            if isinstance(source, dict) and source.get("id")
        }
        self._brief = brief
        self._mtime = stat.st_mtime
        return brief

    @staticmethod
    def _buyer_preview(buyer: dict[str, Any]) -> dict[str, Any]:
        return {
            "customer_evidence_needed": buyer.get("customer_evidence_needed"),
            "evidence_status": buyer.get("evidence_status"),
            "id": buyer.get("id"),
            "paid_wedge": buyer.get("paid_wedge"),
            "primary_decision": buyer.get("primary_decision"),
            "title": buyer.get("title"),
        }

    @staticmethod
    def _question_preview(question: dict[str, Any]) -> dict[str, Any]:
        return {
            "acquirer_signal": question.get("acquirer_signal"),
            "current_state": question.get("current_state"),
            "evidence_status": question.get("evidence_status"),
            "id": question.get("id"),
            "question": question.get("question"),
            "short_answer": question.get("short_answer"),
        }

    @staticmethod
    def _objection_preview(objection: dict[str, Any]) -> dict[str, Any]:
        return {
            "evidence_status": objection.get("evidence_status"),
            "id": objection.get("id"),
            "next_proof": objection.get("next_proof"),
            "objection": objection.get("objection"),
            "proof_state": objection.get("proof_state"),
        }

    def get(
        self,
        buyer_id: str | None = None,
        question_id: str | None = None,
        objection_id: str | None = None,
        bet_id: str | None = None,
        source_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            brief = self._load()
        except Exception as exc:
            return {
                "available": False,
                "brief_path": str(self.path),
                "error": f"failed to load secure context buyer diligence brief: {exc}",
            }

        if brief is None:
            return {
                "available": False,
                "brief_path": str(self.path),
                "error": "secure context buyer diligence brief is not present",
            }

        if not isinstance(brief, dict):
            return {
                "available": False,
                "brief_path": str(self.path),
                "error": "secure context buyer diligence brief root must be an object",
            }

        if buyer_id:
            key = buyer_id.strip()
            buyer = self._buyer_by_id.get(key)
            return {"available": True, "buyer": buyer, "buyer_id": key, "found": buyer is not None}

        if question_id:
            key = question_id.strip()
            question = self._question_by_id.get(key)
            return {"available": True, "found": question is not None, "question": question, "question_id": key}

        if objection_id:
            key = objection_id.strip()
            objection = self._objection_by_id.get(key)
            return {"available": True, "found": objection is not None, "objection": objection, "objection_id": key}

        if bet_id:
            key = bet_id.strip()
            bet = self._bet_by_id.get(key)
            return {"available": True, "bet": bet, "bet_id": key, "found": bet is not None}

        if source_id:
            key = source_id.strip()
            source = self._source_by_id.get(key)
            return {"available": True, "found": source is not None, "source": source, "source_id": key}

        buyers = list(self._buyer_by_id.values())
        questions = list(self._question_by_id.values())
        objections = list(self._objection_by_id.values())
        if status:
            key = status.strip()
            buyers = [
                buyer
                for buyer in buyers
                if str(buyer.get("evidence_status", {}).get("status")) == key
            ]
            questions = [
                question
                for question in questions
                if str(question.get("evidence_status", {}).get("status")) == key
            ]
            objections = [
                objection
                for objection in objections
                if str(objection.get("evidence_status", {}).get("status")) == key
            ]

        return {
            "available": True,
            "brief_summary": brief.get("brief_summary"),
            "buyer_briefs": [self._buyer_preview(buyer) for buyer in buyers],
            "deal_room_next_steps": brief.get("deal_room_next_steps", []),
            "diligence_contract": brief.get("diligence_contract", {}),
            "enterprise_questions": [self._question_preview(question) for question in questions],
            "evidence_rollup": brief.get("evidence_rollup"),
            "features_assessed": brief.get("features_assessed", []),
            "generated_at": brief.get("generated_at"),
            "industry_bets": list(self._bet_by_id.values()),
            "objection_handlers": [self._objection_preview(objection) for objection in objections],
            "pack_index": brief.get("pack_index", []),
            "positioning": brief.get("positioning", {}),
            "schema_version": brief.get("schema_version"),
            "secure_context_buyer_diligence_brief_id": brief.get("secure_context_buyer_diligence_brief_id"),
            "source_artifacts": brief.get("source_artifacts"),
            "source_references": list(self._source_by_id.values()),
            "status": status,
        }


class SecureContextCustomerProofPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._claim_by_id: dict[str, dict[str, Any]] = {}
        self._event_by_id: dict[str, dict[str, Any]] = {}
        self._metric_by_id: dict[str, dict[str, Any]] = {}
        self._gate_by_id: dict[str, dict[str, Any]] = {}
        self._risk_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        claims = pack.get("proof_claims") if isinstance(pack, dict) else []
        events = pack.get("runtime_event_classes") if isinstance(pack, dict) else []
        metrics = pack.get("metric_definitions") if isinstance(pack, dict) else []
        gates = pack.get("renewal_gates") if isinstance(pack, dict) else []
        risks = pack.get("risk_register") if isinstance(pack, dict) else []
        self._claim_by_id = {
            str(claim.get("id")): claim
            for claim in claims
            if isinstance(claim, dict) and claim.get("id")
        }
        self._event_by_id = {
            str(event.get("id")): event
            for event in events
            if isinstance(event, dict) and event.get("id")
        }
        self._metric_by_id = {
            str(metric.get("id")): metric
            for metric in metrics
            if isinstance(metric, dict) and metric.get("id")
        }
        self._gate_by_id = {
            str(gate.get("id")): gate
            for gate in gates
            if isinstance(gate, dict) and gate.get("id")
        }
        self._risk_by_id = {
            str(risk.get("id")): risk
            for risk in risks
            if isinstance(risk, dict) and risk.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _claim_preview(claim: dict[str, Any]) -> dict[str, Any]:
        return {
            "buyer_question": claim.get("buyer_question"),
            "customer_proof_state": claim.get("customer_proof_state"),
            "evidence_status": claim.get("evidence_status"),
            "id": claim.get("id"),
            "minimum_signal_count": claim.get("minimum_signal_count"),
            "status": claim.get("status"),
            "title": claim.get("title"),
        }

    @staticmethod
    def _event_preview(event: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": event.get("id"),
            "redaction_default": event.get("redaction_default"),
            "required_fields": event.get("required_fields", []),
            "title": event.get("title"),
        }

    @staticmethod
    def _metric_preview(metric: dict[str, Any]) -> dict[str, Any]:
        return {
            "claim_states": metric.get("claim_states", []),
            "customer_proof_state": metric.get("customer_proof_state"),
            "id": metric.get("id"),
            "metric_type": metric.get("metric_type"),
            "status": metric.get("status"),
            "target": metric.get("target"),
            "title": metric.get("title"),
        }

    @staticmethod
    def _gate_preview(gate: dict[str, Any]) -> dict[str, Any]:
        return {
            "decision": gate.get("decision"),
            "id": gate.get("id"),
            "linked_metric_ids": gate.get("linked_metric_ids", []),
            "status": gate.get("status"),
            "title": gate.get("title"),
            "what_passes": gate.get("what_passes"),
        }

    def get(
        self,
        claim_id: str | None = None,
        event_id: str | None = None,
        metric_id: str | None = None,
        gate_id: str | None = None,
        risk_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load secure context customer proof pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "secure context customer proof pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "secure context customer proof pack root must be an object",
                "pack_path": str(self.path),
            }

        if claim_id:
            key = claim_id.strip()
            claim = self._claim_by_id.get(key)
            return {"available": True, "claim": claim, "claim_id": key, "found": claim is not None}

        if event_id:
            key = event_id.strip()
            event = self._event_by_id.get(key)
            return {"available": True, "event": event, "event_id": key, "found": event is not None}

        if metric_id:
            key = metric_id.strip()
            metric = self._metric_by_id.get(key)
            return {"available": True, "found": metric is not None, "metric": metric, "metric_id": key}

        if gate_id:
            key = gate_id.strip()
            gate = self._gate_by_id.get(key)
            return {"available": True, "found": gate is not None, "gate": gate, "gate_id": key}

        if risk_id:
            key = risk_id.strip()
            risk = self._risk_by_id.get(key)
            return {"available": True, "found": risk is not None, "risk": risk, "risk_id": key}

        claims = list(self._claim_by_id.values())
        metrics = list(self._metric_by_id.values())
        gates = list(self._gate_by_id.values())
        if status:
            key = status.strip()
            claims = [claim for claim in claims if str(claim.get("status")) == key]
            metrics = [metric for metric in metrics if str(metric.get("status")) == key]
            gates = [gate for gate in gates if str(gate.get("status")) == key]

        return {
            "acquirer_readout": pack.get("acquirer_readout", {}),
            "available": True,
            "customer_proof_pack_id": pack.get("customer_proof_pack_id"),
            "customer_proof_summary": pack.get("customer_proof_summary"),
            "evidence_sources": pack.get("evidence_sources", []),
            "generated_at": pack.get("generated_at"),
            "metric_definitions": [self._metric_preview(metric) for metric in metrics],
            "positioning": pack.get("positioning", {}),
            "proof_claims": [self._claim_preview(claim) for claim in claims],
            "proof_contract": pack.get("proof_contract", {}),
            "renewal_gates": [self._gate_preview(gate) for gate in gates],
            "risk_count": len(self._risk_by_id),
            "runtime_event_classes": [self._event_preview(event) for event in self._event_by_id.values()],
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_pack_index": pack.get("source_pack_index", []),
            "source_references": pack.get("source_references", []),
            "status": status,
        }


class SecureContextEvidenceContract:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._object_by_id: dict[str, dict[str, Any]] = {}
        self._channel_by_id: dict[str, dict[str, Any]] = {}
        self._endpoint_by_id: dict[str, dict[str, Any]] = {}
        self._artifact_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        objects = pack.get("evidence_object_types") if isinstance(pack, dict) else []
        channels = pack.get("release_channels") if isinstance(pack, dict) else []
        api_surface = pack.get("hosted_api_surface") if isinstance(pack, dict) else {}
        endpoints = api_surface.get("endpoints") if isinstance(api_surface, dict) else []
        artifacts = pack.get("source_pack_index") if isinstance(pack, dict) else []
        self._object_by_id = {
            str(item.get("id")): item
            for item in objects
            if isinstance(item, dict) and item.get("id")
        }
        self._channel_by_id = {
            str(item.get("id")): item
            for item in channels
            if isinstance(item, dict) and item.get("id")
        }
        self._endpoint_by_id = {
            str(item.get("id")): item
            for item in endpoints
            if isinstance(item, dict) and item.get("id")
        }
        self._artifact_by_id = {
            str(item.get("id")): item
            for item in artifacts
            if isinstance(item, dict) and item.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _object_preview(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": item.get("id"),
            "linked_source_pack_ids": item.get("linked_source_pack_ids", []),
            "object_contract_hash": item.get("object_contract_hash"),
            "required_fields": item.get("required_fields", []),
            "title": item.get("title"),
        }

    @staticmethod
    def _channel_preview(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "audience": item.get("audience"),
            "id": item.get("id"),
            "required_controls": item.get("required_controls", []),
            "requires_customer_runtime_evidence": item.get("requires_customer_runtime_evidence"),
            "requires_signature": item.get("requires_signature"),
            "requires_tenant_binding": item.get("requires_tenant_binding"),
            "status": item.get("status"),
            "title": item.get("title"),
        }

    @staticmethod
    def _endpoint_preview(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "endpoint_hash": item.get("endpoint_hash"),
            "id": item.get("id"),
            "linked_object_type_ids": item.get("linked_object_type_ids", []),
            "linked_source_pack_ids": item.get("linked_source_pack_ids", []),
            "method": item.get("method"),
            "path": item.get("path"),
            "premium_surface": item.get("premium_surface"),
            "status": item.get("status"),
        }

    @staticmethod
    def _artifact_preview(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "category": item.get("category"),
            "failure_count": item.get("failure_count"),
            "id": item.get("id"),
            "mcp_tools": item.get("mcp_tools", []),
            "path": item.get("path"),
            "schema_version": item.get("schema_version"),
            "sha256": item.get("sha256"),
            "status": item.get("status"),
            "title": item.get("title"),
        }

    def get(
        self,
        object_type_id: str | None = None,
        channel_id: str | None = None,
        endpoint_id: str | None = None,
        artifact_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load secure context evidence contract: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "secure context evidence contract is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "secure context evidence contract root must be an object",
                "pack_path": str(self.path),
            }

        if object_type_id:
            key = object_type_id.strip()
            item = self._object_by_id.get(key)
            return {"available": True, "evidence_object_type": item, "found": item is not None, "object_type_id": key}

        if channel_id:
            key = channel_id.strip()
            item = self._channel_by_id.get(key)
            return {"available": True, "channel": item, "channel_id": key, "found": item is not None}

        if endpoint_id:
            key = endpoint_id.strip()
            item = self._endpoint_by_id.get(key)
            return {"available": True, "endpoint": item, "endpoint_id": key, "found": item is not None}

        if artifact_id:
            key = artifact_id.strip()
            item = self._artifact_by_id.get(key)
            return {"available": True, "artifact": item, "artifact_id": key, "found": item is not None}

        objects = list(self._object_by_id.values())
        channels = list(self._channel_by_id.values())
        endpoints = list(self._endpoint_by_id.values())
        artifacts = list(self._artifact_by_id.values())
        if status:
            key = status.strip()
            channels = [item for item in channels if str(item.get("status")) == key]
            endpoints = [item for item in endpoints if str(item.get("status")) == key]
            artifacts = [item for item in artifacts if str(item.get("status")) == key]

        return {
            "available": True,
            "buyer_views": pack.get("buyer_views", []),
            "commercialization_path": pack.get("commercialization_path", {}),
            "evidence_contract_summary": pack.get("evidence_contract_summary"),
            "evidence_object_types": [self._object_preview(item) for item in objects],
            "failures": pack.get("failures", []),
            "generated_at": pack.get("generated_at"),
            "hosted_api_surface": {
                **(pack.get("hosted_api_surface", {}) if isinstance(pack.get("hosted_api_surface"), dict) else {}),
                "endpoints": [self._endpoint_preview(item) for item in endpoints],
            },
            "positioning": pack.get("positioning", {}),
            "release_channels": [self._channel_preview(item) for item in channels],
            "release_contract": pack.get("release_contract", {}),
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_pack_index": [self._artifact_preview(item) for item in artifacts],
            "source_references": pack.get("source_references", []),
            "status": status,
        }

class HostedMcpReadinessPack:
    def __init__(self, pack_path: str):
        self.path = Path(pack_path)
        self._mtime: float | None = None
        self._pack: dict[str, Any] | None = None
        self._stage_by_id: dict[str, dict[str, Any]] = {}
        self._control_by_id: dict[str, dict[str, Any]] = {}
        self._gate_by_id: dict[str, dict[str, Any]] = {}
        self._buyer_evidence_by_id: dict[str, dict[str, Any]] = {}
        self._risk_by_id: dict[str, dict[str, Any]] = {}

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        stat = self.path.stat()
        if self._pack is not None and self._mtime == stat.st_mtime:
            return self._pack

        pack = json.loads(self.path.read_text(encoding="utf-8"))
        stages = pack.get("readiness_stages") if isinstance(pack, dict) else []
        controls = pack.get("readiness_controls") if isinstance(pack, dict) else []
        gates = pack.get("rollout_gates") if isinstance(pack, dict) else []
        buyer_items = pack.get("buyer_evidence_items") if isinstance(pack, dict) else []
        risks = pack.get("risk_register") if isinstance(pack, dict) else []
        self._stage_by_id = {
            str(stage.get("id")): stage
            for stage in stages
            if isinstance(stage, dict) and stage.get("id")
        }
        self._control_by_id = {
            str(control.get("id")): control
            for control in controls
            if isinstance(control, dict) and control.get("id")
        }
        self._gate_by_id = {
            str(gate.get("id")): gate
            for gate in gates
            if isinstance(gate, dict) and gate.get("id")
        }
        self._buyer_evidence_by_id = {
            str(item.get("id")): item
            for item in buyer_items
            if isinstance(item, dict) and item.get("id")
        }
        self._risk_by_id = {
            str(risk.get("id")): risk
            for risk in risks
            if isinstance(risk, dict) and risk.get("id")
        }
        self._pack = pack
        self._mtime = stat.st_mtime
        return pack

    @staticmethod
    def _stage_preview(stage: dict[str, Any]) -> dict[str, Any]:
        return {
            "control_state_counts": stage.get("control_state_counts"),
            "current_state": stage.get("current_state"),
            "id": stage.get("id"),
            "linked_control_count": stage.get("linked_control_count"),
            "status": stage.get("status"),
            "title": stage.get("title"),
        }

    @staticmethod
    def _control_preview(control: dict[str, Any]) -> dict[str, Any]:
        return {
            "control_family": control.get("control_family"),
            "default_decision": control.get("default_decision"),
            "id": control.get("id"),
            "implementation_state": control.get("implementation_state"),
            "priority": control.get("priority"),
            "source_packs_ready": control.get("source_packs_ready"),
            "status": control.get("status"),
            "title": control.get("title"),
        }

    @staticmethod
    def _gate_preview(gate: dict[str, Any]) -> dict[str, Any]:
        return {
            "decision": gate.get("decision"),
            "gate_state": gate.get("gate_state"),
            "id": gate.get("id"),
            "linked_control_ids": gate.get("linked_control_ids", []),
            "status": gate.get("status"),
            "title": gate.get("title"),
            "what_passes": gate.get("what_passes"),
        }

    @staticmethod
    def _buyer_evidence_preview(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "buyer_question": item.get("buyer_question"),
            "id": item.get("id"),
            "linked_control_ids": item.get("linked_control_ids", []),
            "required_artifact": item.get("required_artifact"),
            "status": item.get("status"),
            "title": item.get("title"),
        }

    def get(
        self,
        stage_id: str | None = None,
        control_id: str | None = None,
        gate_id: str | None = None,
        buyer_evidence_id: str | None = None,
        risk_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            pack = self._load()
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to load hosted MCP readiness pack: {exc}",
                "pack_path": str(self.path),
            }

        if pack is None:
            return {
                "available": False,
                "error": "hosted MCP readiness pack is not present",
                "pack_path": str(self.path),
            }

        if not isinstance(pack, dict):
            return {
                "available": False,
                "error": "hosted MCP readiness pack root must be an object",
                "pack_path": str(self.path),
            }

        if stage_id:
            key = stage_id.strip()
            stage = self._stage_by_id.get(key)
            return {"available": True, "found": stage is not None, "stage": stage, "stage_id": key}

        if control_id:
            key = control_id.strip()
            control = self._control_by_id.get(key)
            return {"available": True, "control": control, "control_id": key, "found": control is not None}

        if gate_id:
            key = gate_id.strip()
            gate = self._gate_by_id.get(key)
            return {"available": True, "found": gate is not None, "gate": gate, "gate_id": key}

        if buyer_evidence_id:
            key = buyer_evidence_id.strip()
            buyer_item = self._buyer_evidence_by_id.get(key)
            return {
                "available": True,
                "buyer_evidence": buyer_item,
                "buyer_evidence_id": key,
                "found": buyer_item is not None,
            }

        if risk_id:
            key = risk_id.strip()
            risk = self._risk_by_id.get(key)
            return {"available": True, "found": risk is not None, "risk": risk, "risk_id": key}

        stages = list(self._stage_by_id.values())
        controls = list(self._control_by_id.values())
        gates = list(self._gate_by_id.values())
        buyer_items = list(self._buyer_evidence_by_id.values())
        if status:
            key = status.strip()
            stages = [stage for stage in stages if str(stage.get("status") or stage.get("current_state")) == key]
            controls = [control for control in controls if str(control.get("status") or control.get("implementation_state")) == key]
            gates = [gate for gate in gates if str(gate.get("status") or gate.get("gate_state")) == key]
            buyer_items = [item for item in buyer_items if str(item.get("status")) == key]

        return {
            "available": True,
            "buyer_evidence_items": [self._buyer_evidence_preview(item) for item in buyer_items],
            "commercial_packaging": pack.get("commercial_packaging", {}),
            "evidence_sources": pack.get("evidence_sources", []),
            "generated_at": pack.get("generated_at"),
            "hosted_mcp_readiness_pack_id": pack.get("hosted_mcp_readiness_pack_id"),
            "hosted_mcp_readiness_summary": pack.get("hosted_mcp_readiness_summary"),
            "next_90_days": pack.get("next_90_days", []),
            "positioning": pack.get("positioning", {}),
            "readiness_contract": pack.get("readiness_contract", {}),
            "readiness_controls": [self._control_preview(control) for control in controls],
            "readiness_stages": [self._stage_preview(stage) for stage in stages],
            "risk_count": len(self._risk_by_id),
            "rollout_gates": [self._gate_preview(gate) for gate in gates],
            "schema_version": pack.get("schema_version"),
            "source_artifacts": pack.get("source_artifacts"),
            "source_pack_index": pack.get("source_pack_index", []),
            "source_references": pack.get("source_references", []),
            "status": status,
        }


def load_config(config_path: str) -> ServerConfig:
    path = Path(config_path)
    cfg = ServerConfig()
    data: dict[str, Any] = {}
    if path.exists():
        data = tomli.loads(path.read_text(encoding="utf-8"))

    cfg.source_index_url = data.get("source_index_url", cfg.source_index_url)
    cfg.allowed_source_hosts = data.get("allowed_source_hosts", cfg.allowed_source_hosts)
    cfg.cache_ttl_seconds = int(data.get("cache_ttl_seconds", cfg.cache_ttl_seconds))
    cfg.request_timeout_seconds = int(data.get("request_timeout_seconds", cfg.request_timeout_seconds))
    cfg.max_results_default = int(data.get("max_results_default", cfg.max_results_default))
    cfg.max_results_cap = int(data.get("max_results_cap", cfg.max_results_cap))
    cfg.server_public_base_url = data.get("server_public_base_url", cfg.server_public_base_url)
    cfg.control_plane_manifest_path = data.get(
        "control_plane_manifest_path",
        cfg.control_plane_manifest_path,
    )
    cfg.gateway_policy_path = data.get("gateway_policy_path", cfg.gateway_policy_path)
    cfg.assurance_pack_path = data.get("assurance_pack_path", cfg.assurance_pack_path)
    cfg.identity_ledger_path = data.get("identity_ledger_path", cfg.identity_ledger_path)
    cfg.entitlement_review_pack_path = data.get(
        "entitlement_review_pack_path",
        cfg.entitlement_review_pack_path,
    )
    cfg.approval_receipt_pack_path = data.get(
        "approval_receipt_pack_path",
        cfg.approval_receipt_pack_path,
    )
    cfg.connector_trust_pack_path = data.get(
        "connector_trust_pack_path",
        cfg.connector_trust_pack_path,
    )
    cfg.connector_intake_pack_path = data.get(
        "connector_intake_pack_path",
        cfg.connector_intake_pack_path,
    )
    cfg.mcp_stdio_launch_boundary_pack_path = data.get(
        "mcp_stdio_launch_boundary_pack_path",
        cfg.mcp_stdio_launch_boundary_pack_path,
    )
    cfg.authorization_conformance_pack_path = data.get(
        "authorization_conformance_pack_path",
        cfg.authorization_conformance_pack_path,
    )
    cfg.elicitation_boundary_pack_path = data.get(
        "elicitation_boundary_pack_path",
        cfg.elicitation_boundary_pack_path,
    )
    cfg.tool_risk_contract_path = data.get(
        "tool_risk_contract_path",
        cfg.tool_risk_contract_path,
    )
    cfg.tool_surface_drift_pack_path = data.get(
        "tool_surface_drift_pack_path",
        cfg.tool_surface_drift_pack_path,
    )
    cfg.red_team_drill_pack_path = data.get(
        "red_team_drill_pack_path",
        cfg.red_team_drill_pack_path,
    )
    cfg.red_team_replay_harness_path = data.get(
        "red_team_replay_harness_path",
        cfg.red_team_replay_harness_path,
    )
    cfg.readiness_scorecard_path = data.get(
        "readiness_scorecard_path",
        cfg.readiness_scorecard_path,
    )
    cfg.capability_risk_register_path = data.get(
        "capability_risk_register_path",
        cfg.capability_risk_register_path,
    )
    cfg.agent_memory_boundary_pack_path = data.get(
        "agent_memory_boundary_pack_path",
        cfg.agent_memory_boundary_pack_path,
    )
    cfg.agent_skill_supply_chain_pack_path = data.get(
        "agent_skill_supply_chain_pack_path",
        cfg.agent_skill_supply_chain_pack_path,
    )
    cfg.agent_handoff_boundary_pack_path = data.get(
        "agent_handoff_boundary_pack_path",
        cfg.agent_handoff_boundary_pack_path,
    )
    cfg.a2a_agent_card_trust_profile_path = data.get(
        "a2a_agent_card_trust_profile_path",
        cfg.a2a_agent_card_trust_profile_path,
    )
    cfg.agentic_system_bom_path = data.get(
        "agentic_system_bom_path",
        cfg.agentic_system_bom_path,
    )
    cfg.agentic_run_receipt_pack_path = data.get(
        "agentic_run_receipt_pack_path",
        cfg.agentic_run_receipt_pack_path,
    )
    cfg.secure_context_trust_pack_path = data.get(
        "secure_context_trust_pack_path",
        cfg.secure_context_trust_pack_path,
    )
    cfg.secure_context_attestation_pack_path = data.get(
        "secure_context_attestation_pack_path",
        cfg.secure_context_attestation_pack_path,
    )
    cfg.secure_context_lineage_ledger_path = data.get(
        "secure_context_lineage_ledger_path",
        cfg.secure_context_lineage_ledger_path,
    )
    cfg.secure_context_eval_pack_path = data.get(
        "secure_context_eval_pack_path",
        cfg.secure_context_eval_pack_path,
    )
    cfg.context_poisoning_guard_pack_path = data.get(
        "context_poisoning_guard_pack_path",
        cfg.context_poisoning_guard_pack_path,
    )
    cfg.context_egress_boundary_pack_path = data.get(
        "context_egress_boundary_pack_path",
        cfg.context_egress_boundary_pack_path,
    )
    cfg.threat_radar_path = data.get("threat_radar_path", cfg.threat_radar_path)
    cfg.standards_crosswalk_path = data.get(
        "standards_crosswalk_path",
        cfg.standards_crosswalk_path,
    )
    cfg.source_freshness_watch_path = data.get(
        "source_freshness_watch_path",
        cfg.source_freshness_watch_path,
    )
    cfg.mcp_risk_coverage_pack_path = data.get(
        "mcp_risk_coverage_pack_path",
        cfg.mcp_risk_coverage_pack_path,
    )
    cfg.protocol_conformance_pack_path = data.get(
        "protocol_conformance_pack_path",
        cfg.protocol_conformance_pack_path,
    )
    cfg.control_plane_blueprint_path = data.get(
        "control_plane_blueprint_path",
        cfg.control_plane_blueprint_path,
    )
    cfg.measurement_probe_pack_path = data.get(
        "measurement_probe_pack_path",
        cfg.measurement_probe_pack_path,
    )
    cfg.telemetry_contract_path = data.get(
        "telemetry_contract_path",
        cfg.telemetry_contract_path,
    )
    cfg.soc_detection_pack_path = data.get(
        "soc_detection_pack_path",
        cfg.soc_detection_pack_path,
    )
    cfg.enterprise_trust_center_export_path = data.get(
        "enterprise_trust_center_export_path",
        cfg.enterprise_trust_center_export_path,
    )
    cfg.secure_context_value_model_path = data.get(
        "secure_context_value_model_path",
        cfg.secure_context_value_model_path,
    )
    cfg.design_partner_pilot_pack_path = data.get(
        "design_partner_pilot_pack_path",
        cfg.design_partner_pilot_pack_path,
    )
    cfg.buyer_diligence_brief_path = data.get(
        "buyer_diligence_brief_path",
        cfg.buyer_diligence_brief_path,
    )
    cfg.customer_proof_pack_path = data.get(
        "customer_proof_pack_path",
        cfg.customer_proof_pack_path,
    )
    cfg.evidence_contract_path = data.get(
        "evidence_contract_path",
        cfg.evidence_contract_path,
    )
    cfg.hosted_mcp_readiness_pack_path = data.get(
        "hosted_mcp_readiness_pack_path",
        cfg.hosted_mcp_readiness_pack_path,
    )
    cfg.catastrophic_risk_annex_path = data.get(
        "catastrophic_risk_annex_path",
        cfg.catastrophic_risk_annex_path,
    )
    cfg.critical_infrastructure_pack_path = data.get(
        "critical_infrastructure_pack_path",
        cfg.critical_infrastructure_pack_path,
    )
    cfg.incident_response_pack_path = data.get(
        "incident_response_pack_path",
        cfg.incident_response_pack_path,
    )
    cfg.action_runtime_pack_path = data.get(
        "action_runtime_pack_path",
        cfg.action_runtime_pack_path,
    )
    cfg.agent_trust_fabric_pack_path = data.get(
        "agent_trust_fabric_pack_path",
        cfg.agent_trust_fabric_pack_path,
    )
    cfg.browser_agent_boundary_pack_path = data.get(
        "browser_agent_boundary_pack_path",
        cfg.browser_agent_boundary_pack_path,
    )
    cfg.exposure_graph_path = data.get(
        "exposure_graph_path",
        cfg.exposure_graph_path,
    )
    cfg.posture_snapshot_path = data.get(
        "posture_snapshot_path",
        cfg.posture_snapshot_path,
    )
    cfg.agentic_aivss_risk_scoring_pack_path = data.get(
        "agentic_aivss_risk_scoring_pack_path",
        cfg.agentic_aivss_risk_scoring_pack_path,
    )
    cfg.app_intake_pack_path = data.get(
        "app_intake_pack_path",
        cfg.app_intake_pack_path,
    )
    cfg.model_provider_routing_pack_path = data.get(
        "model_provider_routing_pack_path",
        cfg.model_provider_routing_pack_path,
    )
    cfg.upstream_mcp_servers = _parse_upstream_mcp_servers(
        data.get("upstream_mcp_servers", []),
        cfg.request_timeout_seconds,
    )
    upstream_json = os.environ.get("RECIPES_MCP_UPSTREAM_SERVERS_JSON", "").strip()
    if upstream_json:
        cfg.upstream_mcp_servers = _parse_upstream_mcp_servers(
            json.loads(upstream_json),
            cfg.request_timeout_seconds,
        )
    cfg.source_index_url = os.environ.get("RECIPES_MCP_SOURCE_INDEX_URL", cfg.source_index_url)
    cfg.allowed_source_hosts = _env_csv_list("RECIPES_MCP_ALLOWED_SOURCE_HOSTS", cfg.allowed_source_hosts)
    cfg.server_public_base_url = os.environ.get("RECIPES_MCP_PUBLIC_BASE_URL", cfg.server_public_base_url)
    return cfg


def _optional_env(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _env_int(name: str, value: str, default: int) -> int:
    value = value.strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "on"}


def run_mcp_server() -> None:
    transport = (_optional_env(DEFAULT_TRANSPORT) or "streamable-http").lower()
    log_level = _optional_env(DEFAULT_LOG_LEVEL)

    if transport == "stdio":
        mcp.run(transport="stdio", log_level=log_level)
        return

    if transport not in {"http", "streamable-http", "sse"}:
        raise ValueError(
            "RECIPES_MCP_TRANSPORT must be one of: stdio, http, streamable-http, sse"
        )

    default_path = "/sse" if transport == "sse" else "/mcp"
    mcp.run(
        transport=transport,
        host=_optional_env(DEFAULT_HOST) or "0.0.0.0",
        port=_env_int("RECIPES_MCP_PORT", DEFAULT_PORT, 8000),
        path=_optional_env(DEFAULT_PATH) or default_path,
        log_level=log_level,
    )


config = load_config(DEFAULT_CONFIG_PATH)
index = RecipeIndex(config)
control_plane = WorkflowControlPlane(config.control_plane_manifest_path)
gateway_policy = MCPGatewayPolicyPack(config.gateway_policy_path)
assurance_pack = AgenticAssurancePack(config.assurance_pack_path)
identity_ledger = AgentIdentityDelegationLedger(config.identity_ledger_path)
entitlement_review_pack = AgenticEntitlementReviewPack(config.entitlement_review_pack_path)
approval_receipt_pack = AgenticApprovalReceiptPack(config.approval_receipt_pack_path)
connector_trust_pack = MCPConnectorTrustPack(config.connector_trust_pack_path)
connector_intake_pack = MCPConnectorIntakePack(config.connector_intake_pack_path)
mcp_stdio_launch_boundary_pack = MCPStdioLaunchBoundaryPack(config.mcp_stdio_launch_boundary_pack_path)
authorization_conformance_pack = MCPAuthorizationConformancePack(config.authorization_conformance_pack_path)
elicitation_boundary_pack = MCPElicitationBoundaryPack(config.elicitation_boundary_pack_path)
tool_risk_contract = MCPToolRiskContract(config.tool_risk_contract_path)
tool_surface_drift_pack = MCPToolSurfaceDriftPack(config.tool_surface_drift_pack_path)
red_team_drill_pack = AgenticRedTeamDrillPack(config.red_team_drill_pack_path)
red_team_replay_harness = AgenticRedTeamReplayHarness(config.red_team_replay_harness_path)
readiness_scorecard = AgenticReadinessScorecard(config.readiness_scorecard_path)
capability_risk_register = AgentCapabilityRiskRegister(config.capability_risk_register_path)
agent_memory_boundary_pack = AgentMemoryBoundaryPack(config.agent_memory_boundary_pack_path)
agent_skill_supply_chain_pack = AgentSkillSupplyChainPack(config.agent_skill_supply_chain_pack_path)
agent_handoff_boundary_pack = AgentHandoffBoundaryPack(config.agent_handoff_boundary_pack_path)
a2a_agent_card_trust_profile = A2AAgentCardTrustProfile(config.a2a_agent_card_trust_profile_path)
agentic_system_bom = AgenticSystemBOM(config.agentic_system_bom_path)
agentic_run_receipt_pack = AgenticRunReceiptPack(config.agentic_run_receipt_pack_path)
secure_context_trust_pack = SecureContextTrustPack(config.secure_context_trust_pack_path)
secure_context_attestation_pack = SecureContextAttestationPack(config.secure_context_attestation_pack_path)
secure_context_lineage_ledger = SecureContextLineageLedger(config.secure_context_lineage_ledger_path)
secure_context_eval_pack = SecureContextEvalPack(config.secure_context_eval_pack_path)
context_poisoning_guard_pack = ContextPoisoningGuardPack(config.context_poisoning_guard_pack_path)
context_egress_boundary_pack = ContextEgressBoundaryPack(config.context_egress_boundary_pack_path)
threat_radar = AgenticThreatRadar(config.threat_radar_path)
standards_crosswalk = AgenticStandardsCrosswalk(config.standards_crosswalk_path)
source_freshness_watch = AgenticSourceFreshnessWatch(config.source_freshness_watch_path)
mcp_risk_coverage_pack = MCPRiskCoveragePack(config.mcp_risk_coverage_pack_path)
protocol_conformance_pack = AgenticProtocolConformancePack(config.protocol_conformance_pack_path)
control_plane_blueprint = AgenticControlPlaneBlueprint(config.control_plane_blueprint_path)
exposure_graph = AgenticExposureGraph(config.exposure_graph_path)
posture_snapshot = AgenticPostureSnapshot(config.posture_snapshot_path)
agentic_aivss_risk_scoring_pack = AgenticAivssRiskScoringPack(config.agentic_aivss_risk_scoring_pack_path)
app_intake_pack = AgenticAppIntakePack(config.app_intake_pack_path)
model_provider_routing_pack = ModelProviderRoutingPack(config.model_provider_routing_pack_path)
catastrophic_risk_annex = AgenticCatastrophicRiskAnnex(config.catastrophic_risk_annex_path)
critical_infrastructure_pack = CriticalInfrastructureSecureContextPack(config.critical_infrastructure_pack_path)
incident_response_pack = AgenticIncidentResponsePack(config.incident_response_pack_path)
action_runtime_pack = AgenticActionRuntimePack(config.action_runtime_pack_path)
agent_trust_fabric_pack = AgentTrustFabricPack(config.agent_trust_fabric_pack_path)
browser_agent_boundary_pack = BrowserAgentBoundaryPack(config.browser_agent_boundary_pack_path)
measurement_probe_pack = AgenticMeasurementProbePack(config.measurement_probe_pack_path)
telemetry_contract = AgenticTelemetryContract(config.telemetry_contract_path)
soc_detection_pack = AgenticSocDetectionPack(config.soc_detection_pack_path)
enterprise_trust_center_export = EnterpriseTrustCenterExport(config.enterprise_trust_center_export_path)
secure_context_value_model = SecureContextValueModel(config.secure_context_value_model_path)
design_partner_pilot_pack = DesignPartnerPilotPack(config.design_partner_pilot_pack_path)
buyer_diligence_brief = SecureContextBuyerDiligenceBrief(config.buyer_diligence_brief_path)
customer_proof_pack = SecureContextCustomerProofPack(config.customer_proof_pack_path)
evidence_contract = SecureContextEvidenceContract(config.evidence_contract_path)
hosted_mcp_readiness_pack = HostedMcpReadinessPack(config.hosted_mcp_readiness_pack_path)
upstream_mcp = UpstreamMCPRegistry(config.upstream_mcp_servers)
mcp = FastMCP(name="security-recipes-mcp")


@mcp.tool()
async def recipes_server_info() -> dict[str, Any]:
    """Return MCP server metadata and source-index configuration."""
    return {
        "name": "security-recipes-mcp",
        "server_public_base_url": config.server_public_base_url,
        "source_index_url": config.source_index_url,
        "allowed_source_hosts": config.allowed_source_hosts,
        "cache_ttl_seconds": config.cache_ttl_seconds,
        "control_plane_manifest_path": config.control_plane_manifest_path,
        "gateway_policy_path": config.gateway_policy_path,
        "assurance_pack_path": config.assurance_pack_path,
        "identity_ledger_path": config.identity_ledger_path,
        "entitlement_review_pack_path": config.entitlement_review_pack_path,
        "approval_receipt_pack_path": config.approval_receipt_pack_path,
        "connector_trust_pack_path": config.connector_trust_pack_path,
        "connector_intake_pack_path": config.connector_intake_pack_path,
        "mcp_stdio_launch_boundary_pack_path": config.mcp_stdio_launch_boundary_pack_path,
        "authorization_conformance_pack_path": config.authorization_conformance_pack_path,
        "elicitation_boundary_pack_path": config.elicitation_boundary_pack_path,
        "tool_risk_contract_path": config.tool_risk_contract_path,
        "tool_surface_drift_pack_path": config.tool_surface_drift_pack_path,
        "red_team_drill_pack_path": config.red_team_drill_pack_path,
        "red_team_replay_harness_path": config.red_team_replay_harness_path,
        "readiness_scorecard_path": config.readiness_scorecard_path,
        "capability_risk_register_path": config.capability_risk_register_path,
        "agent_memory_boundary_pack_path": config.agent_memory_boundary_pack_path,
        "agent_skill_supply_chain_pack_path": config.agent_skill_supply_chain_pack_path,
        "agent_handoff_boundary_pack_path": config.agent_handoff_boundary_pack_path,
        "a2a_agent_card_trust_profile_path": config.a2a_agent_card_trust_profile_path,
        "agentic_system_bom_path": config.agentic_system_bom_path,
        "agentic_run_receipt_pack_path": config.agentic_run_receipt_pack_path,
        "secure_context_trust_pack_path": config.secure_context_trust_pack_path,
        "secure_context_attestation_pack_path": config.secure_context_attestation_pack_path,
        "secure_context_lineage_ledger_path": config.secure_context_lineage_ledger_path,
        "secure_context_eval_pack_path": config.secure_context_eval_pack_path,
        "context_poisoning_guard_pack_path": config.context_poisoning_guard_pack_path,
        "context_egress_boundary_pack_path": config.context_egress_boundary_pack_path,
        "threat_radar_path": config.threat_radar_path,
        "standards_crosswalk_path": config.standards_crosswalk_path,
        "source_freshness_watch_path": config.source_freshness_watch_path,
        "mcp_risk_coverage_pack_path": config.mcp_risk_coverage_pack_path,
        "protocol_conformance_pack_path": config.protocol_conformance_pack_path,
        "control_plane_blueprint_path": config.control_plane_blueprint_path,
        "exposure_graph_path": config.exposure_graph_path,
        "posture_snapshot_path": config.posture_snapshot_path,
        "agentic_aivss_risk_scoring_pack_path": config.agentic_aivss_risk_scoring_pack_path,
        "app_intake_pack_path": config.app_intake_pack_path,
        "model_provider_routing_pack_path": config.model_provider_routing_pack_path,
        "catastrophic_risk_annex_path": config.catastrophic_risk_annex_path,
        "critical_infrastructure_pack_path": config.critical_infrastructure_pack_path,
        "incident_response_pack_path": config.incident_response_pack_path,
        "action_runtime_pack_path": config.action_runtime_pack_path,
        "agent_trust_fabric_pack_path": config.agent_trust_fabric_pack_path,
        "browser_agent_boundary_pack_path": config.browser_agent_boundary_pack_path,
        "measurement_probe_pack_path": config.measurement_probe_pack_path,
        "telemetry_contract_path": config.telemetry_contract_path,
        "soc_detection_pack_path": config.soc_detection_pack_path,
        "enterprise_trust_center_export_path": config.enterprise_trust_center_export_path,
        "secure_context_value_model_path": config.secure_context_value_model_path,
        "design_partner_pilot_pack_path": config.design_partner_pilot_pack_path,
        "buyer_diligence_brief_path": config.buyer_diligence_brief_path,
        "customer_proof_pack_path": config.customer_proof_pack_path,
        "evidence_contract_path": config.evidence_contract_path,
        "hosted_mcp_readiness_pack_path": config.hosted_mcp_readiness_pack_path,
        "upstream_mcp_server_count": len(config.upstream_mcp_servers),
        "upstream_mcp_servers": upstream_mcp.list_public(),
    }


@mcp.tool()
async def recipes_mcp_upstream_servers() -> dict[str, Any]:
    """List optional upstream MCP servers configured for this Security Recipes server."""
    servers = upstream_mcp.list_public()
    return {
        "count": len(servers),
        "servers": servers,
        "configured_by_default": False,
        "security_boundary": "No upstream MCP servers are enabled unless the operator configures them locally.",
    }


@mcp.tool()
async def recipes_mcp_upstream_tools(server_id: str) -> dict[str, Any]:
    """List tools exposed by a configured upstream MCP server and show local allow decisions."""
    try:
        return await upstream_mcp.list_tools(server_id)
    except Exception as exc:
        return {
            "server_id": server_id,
            "ok": False,
            "error": str(exc),
        }


@mcp.tool()
async def recipes_mcp_upstream_call(
    server_id: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call an allowed read-only tool on a configured upstream MCP server."""
    try:
        return await upstream_mcp.call_tool(server_id, tool_name, arguments=arguments)
    except Exception as exc:
        return {
            "ok": False,
            "server_id": server_id,
            "tool_name": tool_name,
            "error": str(exc),
        }


@mcp.tool()
async def recipes_mcp_upstream_context(
    query: str,
    server_ids: list[str] | None = None,
    max_chars: int = 24000,
) -> dict[str, Any]:
    """Collect bounded context from configured upstream MCP servers for a remediation query."""
    return await upstream_mcp.context_bundle(query=query, server_ids=server_ids, max_chars=max_chars)


@mcp.tool()
async def recipes_refresh(force: bool = False) -> dict[str, Any]:
    """Refresh the in-memory copy of recipes-index.json."""
    return await index.refresh(force=force)


@mcp.tool()
async def recipes_search(
    query: str,
    section: str | None = None,
    agent: str | None = None,
    tags: list[str] | None = None,
    facets: list[str] | None = None,
    min_quality: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Full-text search over security-recipes documents."""
    results = await index.search(
        query=query,
        section=section,
        agent=agent,
        tags=tags,
        facets=facets,
        min_quality=min_quality,
        limit=limit,
    )
    return {"query": query, "count": len(results), "results": results}


@mcp.tool()
async def recipes_list(
    section: str | None = None,
    agent: str | None = None,
    severity: str | None = None,
    tags: list[str] | None = None,
    facets: list[str] | None = None,
    min_quality: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List recipes with optional metadata filtering."""
    results = await index.list_docs(
        section=section,
        agent=agent,
        severity=severity,
        tags=tags,
        facets=facets,
        min_quality=min_quality,
        limit=limit,
    )
    return {"count": len(results), "results": results}


@mcp.tool()
async def recipes_get(slug_or_path: str) -> dict[str, Any]:
    """Get a full recipe record by slug or path."""
    doc = await index.get_doc(slug_or_path)
    if not doc:
        return {"found": False, "slug_or_path": slug_or_path}
    return {"found": True, "recipe": doc}


@mcp.tool()
async def recipes_quality_report(
    facet: str | None = None,
    tier: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Summarize recipe quality tiers and list recipes missing world-class signals."""
    return await index.quality_report(facet=facet, tier=tier, limit=limit)


@mcp.tool()
async def recipes_workflow_control_plane(workflow_id: str | None = None) -> dict[str, Any]:
    """Return workflow control-plane policy for agents, reviewers, and MCP gateways."""
    return control_plane.get(workflow_id=workflow_id)


@mcp.tool()
async def recipes_mcp_gateway_policy(workflow_id: str | None = None) -> dict[str, Any]:
    """Return generated MCP gateway policy for scoped tool access and runtime controls."""
    return gateway_policy.get(workflow_id=workflow_id)


@mcp.tool()
async def recipes_agentic_assurance_pack(
    control_id: str | None = None,
    workflow_id: str | None = None,
) -> dict[str, Any]:
    """Return enterprise assurance controls, workflow evidence, and AI/Agent BOM seed."""
    return assurance_pack.get(control_id=control_id, workflow_id=workflow_id)


@mcp.tool()
async def recipes_agent_identity_ledger(
    identity_id: str | None = None,
    workflow_id: str | None = None,
    agent_class: str | None = None,
) -> dict[str, Any]:
    """Return agent non-human identity, delegation, scope, and audit contracts."""
    return identity_ledger.get(identity_id=identity_id, workflow_id=workflow_id, agent_class=agent_class)


@mcp.tool()
async def recipes_agentic_entitlement_review_pack(
    entitlement_id: str | None = None,
    identity_id: str | None = None,
    workflow_id: str | None = None,
    namespace: str | None = None,
    access_mode: str | None = None,
    risk_tier: str | None = None,
) -> dict[str, Any]:
    """Return expiring agent entitlement leases, access reviews, and scope evidence."""
    return entitlement_review_pack.get(
        entitlement_id=entitlement_id,
        identity_id=identity_id,
        workflow_id=workflow_id,
        namespace=namespace,
        access_mode=access_mode,
        risk_tier=risk_tier,
    )


@mcp.tool()
async def recipes_agentic_approval_receipt_pack(
    approval_profile_id: str | None = None,
    workflow_id: str | None = None,
    action_class: str | None = None,
    risk_tier: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return scope-bound approval receipt profiles, workflow requirements, and evidence."""
    return approval_receipt_pack.get(
        approval_profile_id=approval_profile_id,
        workflow_id=workflow_id,
        action_class=action_class,
        risk_tier=risk_tier,
        decision=decision,
    )


@mcp.tool()
async def recipes_mcp_connector_trust_pack(
    connector_id: str | None = None,
    namespace: str | None = None,
    workflow_id: str | None = None,
) -> dict[str, Any]:
    """Return MCP connector trust tiers, controls, evidence, and workflow namespace coverage."""
    return connector_trust_pack.get(
        connector_id=connector_id,
        namespace=namespace,
        workflow_id=workflow_id,
    )


@mcp.tool()
async def recipes_mcp_connector_intake_pack(
    candidate_id: str | None = None,
    namespace: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return MCP connector intake decisions, risk findings, gaps, and promotion plans."""
    return connector_intake_pack.get(
        candidate_id=candidate_id,
        namespace=namespace,
        decision=decision,
    )


@mcp.tool()
async def recipes_mcp_stdio_launch_boundary_pack(
    launch_id: str | None = None,
    profile_id: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return MCP STDIO launch boundaries, profiles, decisions, and evidence."""
    return mcp_stdio_launch_boundary_pack.get(
        launch_id=launch_id,
        profile_id=profile_id,
        decision=decision,
    )


@mcp.tool()
async def recipes_mcp_authorization_conformance_pack(
    connector_id: str | None = None,
    namespace: str | None = None,
    workflow_id: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return MCP authorization conformance, scope-drift, and token-boundary evidence."""
    return authorization_conformance_pack.get(
        connector_id=connector_id,
        namespace=namespace,
        workflow_id=workflow_id,
        decision=decision,
    )


@mcp.tool()
async def recipes_mcp_elicitation_boundary_pack(
    profile_id: str | None = None,
    mode: str | None = None,
    decision: str | None = None,
    workflow_id: str | None = None,
    risk_tier: str | None = None,
) -> dict[str, Any]:
    """Return MCP form-mode and URL-mode elicitation boundary evidence."""
    return elicitation_boundary_pack.get(
        profile_id=profile_id,
        mode=mode,
        decision=decision,
        workflow_id=workflow_id,
        risk_tier=risk_tier,
    )


@mcp.tool()
async def recipes_mcp_tool_risk_contract(
    namespace: str | None = None,
    connector_id: str | None = None,
    workflow_id: str | None = None,
    risk_tier: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return MCP tool annotation, trust, and session-combination risk evidence."""
    return tool_risk_contract.get(
        namespace=namespace,
        connector_id=connector_id,
        workflow_id=workflow_id,
        risk_tier=risk_tier,
        decision=decision,
    )


@mcp.tool()
async def recipes_mcp_tool_surface_drift_pack(
    surface_id: str | None = None,
    namespace: str | None = None,
    tool_name: str | None = None,
    source_kind: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return pinned MCP tool descriptions, schemas, annotations, and drift evidence."""
    return tool_surface_drift_pack.get(
        surface_id=surface_id,
        namespace=namespace,
        tool_name=tool_name,
        source_kind=source_kind,
        decision=decision,
    )


@mcp.tool()
async def recipes_agentic_red_team_drill_pack(
    scenario_id: str | None = None,
    workflow_id: str | None = None,
    attack_family: str | None = None,
) -> dict[str, Any]:
    """Return adversarial drills for agentic remediation workflows and MCP controls."""
    return red_team_drill_pack.get(
        scenario_id=scenario_id,
        workflow_id=workflow_id,
        attack_family=attack_family,
    )


@mcp.tool()
async def recipes_agentic_red_team_replay_harness(
    replay_id: str | None = None,
    workflow_id: str | None = None,
    scenario_id: str | None = None,
    attack_family: str | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    """Return replay fixtures, expected decisions, and evidence gates for red-team drills."""
    return red_team_replay_harness.get(
        replay_id=replay_id,
        workflow_id=workflow_id,
        scenario_id=scenario_id,
        attack_family=attack_family,
        severity=severity,
    )


@mcp.tool()
async def recipes_agentic_readiness_scorecard(
    workflow_id: str | None = None,
    decision: str | None = None,
    minimum_score: int | None = None,
) -> dict[str, Any]:
    """Return generated scale, pilot, gate, or block decisions for agentic workflows."""
    return readiness_scorecard.get(
        workflow_id=workflow_id,
        decision=decision,
        minimum_score=minimum_score,
    )


@mcp.tool()
async def recipes_agent_capability_risk_register(
    workflow_id: str | None = None,
    risk_tier: str | None = None,
    decision: str | None = None,
    minimum_residual_score: int | None = None,
) -> dict[str, Any]:
    """Return capability-based residual risk scores for agentic workflows."""
    return capability_risk_register.get(
        workflow_id=workflow_id,
        risk_tier=risk_tier,
        decision=decision,
        minimum_residual_score=minimum_residual_score,
    )


@mcp.tool()
async def recipes_agent_memory_boundary_pack(
    memory_class_id: str | None = None,
    workflow_id: str | None = None,
    decision: str | None = None,
    persistent: bool | None = None,
) -> dict[str, Any]:
    """Return agent memory classes, workflow profiles, TTLs, and persistence decisions."""
    return agent_memory_boundary_pack.get(
        memory_class_id=memory_class_id,
        workflow_id=workflow_id,
        decision=decision,
        persistent=persistent,
    )


@mcp.tool()
async def recipes_agent_skill_supply_chain_pack(
    skill_id: str | None = None,
    platform: str | None = None,
    decision: str | None = None,
    risk_tier: str | None = None,
    minimum_score: int | None = None,
) -> dict[str, Any]:
    """Return agent skill provenance, permission, isolation, and supply-chain decisions."""
    return agent_skill_supply_chain_pack.get(
        skill_id=skill_id,
        platform=platform,
        decision=decision,
        risk_tier=risk_tier,
        minimum_score=minimum_score,
    )


@mcp.tool()
async def recipes_agent_handoff_boundary_pack(
    profile_id: str | None = None,
    workflow_id: str | None = None,
    protocol: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return agent handoff boundary profiles, protocol controls, and workflow maps."""
    return agent_handoff_boundary_pack.get(
        profile_id=profile_id,
        workflow_id=workflow_id,
        protocol=protocol,
        decision=decision,
    )


@mcp.tool()
async def recipes_a2a_agent_card_trust_profile(
    profile_id: str | None = None,
    decision: str | None = None,
    risk_tier: str | None = None,
) -> dict[str, Any]:
    """Return A2A Agent Card intake profiles, trust controls, and sample decisions."""
    return a2a_agent_card_trust_profile.get(
        profile_id=profile_id,
        decision=decision,
        risk_tier=risk_tier,
    )


@mcp.tool()
async def recipes_agentic_system_bom(
    component_type: str | None = None,
    workflow_id: str | None = None,
    agent_class: str | None = None,
    namespace: str | None = None,
) -> dict[str, Any]:
    """Return the Agentic System BOM for workflows, agents, identities, MCP tools, and evidence."""
    return agentic_system_bom.get(
        component_type=component_type,
        workflow_id=workflow_id,
        agent_class=agent_class,
        namespace=namespace,
    )


@mcp.tool()
async def recipes_agentic_run_receipt_pack(
    workflow_id: str | None = None,
    receipt_id: str | None = None,
    minimum_score: int | None = None,
) -> dict[str, Any]:
    """Return agent run receipt templates for identity, context, tools, egress, approval, and evidence."""
    return agentic_run_receipt_pack.get(
        workflow_id=workflow_id,
        receipt_id=receipt_id,
        minimum_score=minimum_score,
    )


@mcp.tool()
async def recipes_secure_context_trust_pack(
    source_id: str | None = None,
    workflow_id: str | None = None,
    trust_tier: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return context provenance, retrieval policy, source hashes, and workflow context packages."""
    return secure_context_trust_pack.get(
        source_id=source_id,
        workflow_id=workflow_id,
        trust_tier=trust_tier,
        decision=decision,
    )


@mcp.tool()
async def recipes_secure_context_attestation_pack(
    source_id: str | None = None,
    workflow_id: str | None = None,
    artifact_id: str | None = None,
    subject_type: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return secure-context attestation subjects, verification policy, and recertification state."""
    return secure_context_attestation_pack.get(
        source_id=source_id,
        workflow_id=workflow_id,
        artifact_id=artifact_id,
        subject_type=subject_type,
        status=status,
    )


@mcp.tool()
async def recipes_secure_context_lineage_ledger(
    source_id: str | None = None,
    workflow_id: str | None = None,
    decision: str | None = None,
    reuse_class: str | None = None,
    stage_id: str | None = None,
) -> dict[str, Any]:
    """Return context lineage, reuse policy, stage requirements, hashes, and workflow envelopes."""
    return secure_context_lineage_ledger.get(
        source_id=source_id,
        workflow_id=workflow_id,
        decision=decision,
        reuse_class=reuse_class,
        stage_id=stage_id,
    )


@mcp.tool()
async def recipes_secure_context_eval_pack(
    scenario_id: str | None = None,
    workflow_id: str | None = None,
    scenario_type: str | None = None,
    decision: str | None = None,
    minimum_score: int | None = None,
) -> dict[str, Any]:
    """Return scenario-backed secure-context evals for retrieval, attestation, egress, and handoffs."""
    return secure_context_eval_pack.get(
        scenario_id=scenario_id,
        workflow_id=workflow_id,
        scenario_type=scenario_type,
        decision=decision,
        minimum_score=minimum_score,
    )


@mcp.tool()
async def recipes_context_poisoning_guard_pack(
    source_id: str | None = None,
    decision: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    actionable_only: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    """Return context-poisoning scan results for registered secure-context sources."""
    return context_poisoning_guard_pack.get(
        source_id=source_id,
        decision=decision,
        severity=severity,
        rule_id=rule_id,
        actionable_only=actionable_only,
        limit=limit,
    )


@mcp.tool()
async def recipes_context_egress_boundary_pack(
    data_class: str | None = None,
    destination_class: str | None = None,
    source_id: str | None = None,
    workflow_id: str | None = None,
) -> dict[str, Any]:
    """Return context egress data classes, destination classes, and workflow boundary policy."""
    return context_egress_boundary_pack.get(
        data_class=data_class,
        destination_class=destination_class,
        source_id=source_id,
        workflow_id=workflow_id,
    )


@mcp.tool()
async def recipes_agentic_threat_radar(
    signal_id: str | None = None,
    priority: str | None = None,
    horizon: str | None = None,
    capability_id: str | None = None,
    minimum_score: int | None = None,
) -> dict[str, Any]:
    """Return current source-backed agentic AI threat signals and product priorities."""
    return threat_radar.get(
        signal_id=signal_id,
        priority=priority,
        horizon=horizon,
        capability_id=capability_id,
        minimum_score=minimum_score,
    )


@mcp.tool()
async def recipes_agentic_standards_crosswalk(
    standard_id: str | None = None,
    control_id: str | None = None,
    capability_id: str | None = None,
    source_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return standards-to-evidence mappings for agentic AI, MCP, and prompt-injection guidance."""
    return standards_crosswalk.get(
        standard_id=standard_id,
        control_id=control_id,
        capability_id=capability_id,
        source_id=source_id,
        status=status,
    )


@mcp.tool()
async def recipes_agentic_source_freshness_watch(
    watched_source_id: str | None = None,
    source_id: str | None = None,
    primary_watchlist_id: str | None = None,
    publisher_family: str | None = None,
    source_class_family: str | None = None,
    freshness_class: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return source-freshness and standards-drift evidence for SecurityRecipes."""
    return source_freshness_watch.get(
        watched_source_id=watched_source_id,
        source_id=source_id,
        primary_watchlist_id=primary_watchlist_id,
        publisher_family=publisher_family,
        source_class_family=source_class_family,
        freshness_class=freshness_class,
        decision=decision,
    )


@mcp.tool()
async def recipes_mcp_risk_coverage_pack(
    risk_id: str | None = None,
    standard_id: str | None = None,
    capability_id: str | None = None,
    source_id: str | None = None,
    risk_tier: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return OWASP MCP and agentic-skill risk coverage mapped to generated evidence."""
    return mcp_risk_coverage_pack.get(
        risk_id=risk_id,
        standard_id=standard_id,
        capability_id=capability_id,
        source_id=source_id,
        risk_tier=risk_tier,
        status=status,
    )


@mcp.tool()
async def recipes_agentic_protocol_conformance_pack(
    protocol_id: str | None = None,
    check_id: str | None = None,
    source_id: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return MCP/A2A protocol conformance evidence and buyer-ready drift controls."""
    return protocol_conformance_pack.get(
        protocol_id=protocol_id,
        check_id=check_id,
        source_id=source_id,
        decision=decision,
    )


@mcp.tool()
async def recipes_agentic_control_plane_blueprint(
    layer_id: str | None = None,
    question_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return the acquisition-ready agentic control plane architecture and buyer evidence map."""
    return control_plane_blueprint.get(
        layer_id=layer_id,
        question_id=question_id,
        status=status,
    )


@mcp.tool()
async def recipes_agentic_exposure_graph(
    path_id: str | None = None,
    workflow_id: str | None = None,
    identity_id: str | None = None,
    namespace: str | None = None,
    decision: str | None = None,
    path_class_id: str | None = None,
    minimum_score: int | None = None,
    node_id: str | None = None,
) -> dict[str, Any]:
    """Return risk-ranked agentic exposure paths across context, identities, MCP tools, and evidence."""
    return exposure_graph.get(
        path_id=path_id,
        workflow_id=workflow_id,
        identity_id=identity_id,
        namespace=namespace,
        decision=decision,
        path_class_id=path_class_id,
        minimum_score=minimum_score,
        node_id=node_id,
    )


@mcp.tool()
async def recipes_agentic_posture_snapshot(
    workflow_id: str | None = None,
    posture_decision: str | None = None,
    minimum_score: int | None = None,
    risk_factor_id: str | None = None,
    finding_id: str | None = None,
) -> dict[str, Any]:
    """Return the generated enterprise posture snapshot for agentic AI and MCP operations."""
    return posture_snapshot.get(
        workflow_id=workflow_id,
        posture_decision=posture_decision,
        minimum_score=minimum_score,
        risk_factor_id=risk_factor_id,
        finding_id=finding_id,
    )


@mcp.tool()
async def recipes_agentic_aivss_risk_scoring_pack(
    scenario_id: str | None = None,
    severity: str | None = None,
    runtime_default_decision: str | None = None,
    minimum_score: float | None = None,
    owner: str | None = None,
) -> dict[str, Any]:
    """Return AIVSS-aligned agentic risk scores, SLAs, evidence, and hosted MCP wedges."""
    return agentic_aivss_risk_scoring_pack.get(
        scenario_id=scenario_id,
        severity=severity,
        runtime_default_decision=runtime_default_decision,
        minimum_score=minimum_score,
        owner=owner,
    )


@mcp.tool()
async def recipes_agentic_app_intake_pack(
    app_id: str | None = None,
    decision: str | None = None,
    risk_tier: str | None = None,
    buyer_stage: str | None = None,
    minimum_score: int | None = None,
) -> dict[str, Any]:
    """Return generated agentic app launch-review profiles and decisions."""
    return app_intake_pack.get(
        app_id=app_id,
        decision=decision,
        risk_tier=risk_tier,
        buyer_stage=buyer_stage,
        minimum_score=minimum_score,
    )


@mcp.tool()
async def recipes_model_provider_routing_pack(
    provider_id: str | None = None,
    model_id: str | None = None,
    route_id: str | None = None,
    workflow_id: str | None = None,
    decision: str | None = None,
    risk_tier: str | None = None,
) -> dict[str, Any]:
    """Return model-provider route profiles, workflow mappings, and required evidence."""
    return model_provider_routing_pack.get(
        provider_id=provider_id,
        model_id=model_id,
        route_id=route_id,
        workflow_id=workflow_id,
        decision=decision,
        risk_tier=risk_tier,
    )


@mcp.tool()
async def recipes_agentic_catastrophic_risk_annex(
    scenario_id: str | None = None,
    control_id: str | None = None,
    buyer_view_id: str | None = None,
    impact_domain: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return the severe-risk annex for high-impact agentic AI runtime decisions."""
    return catastrophic_risk_annex.get(
        scenario_id=scenario_id,
        control_id=control_id,
        buyer_view_id=buyer_view_id,
        impact_domain=impact_domain,
        status=status,
    )


@mcp.tool()
async def recipes_critical_infrastructure_secure_context_pack(
    sector_id: str | None = None,
    control_id: str | None = None,
    buyer_view_id: str | None = None,
    decision: str | None = None,
    readiness_status: str | None = None,
) -> dict[str, Any]:
    """Return the generated critical-infrastructure secure-context profile."""
    return critical_infrastructure_pack.get(
        sector_id=sector_id,
        control_id=control_id,
        buyer_view_id=buyer_view_id,
        decision=decision,
        readiness_status=readiness_status,
    )


@mcp.tool()
async def recipes_agentic_incident_response_pack(
    incident_class_id: str | None = None,
    workflow_id: str | None = None,
    severity: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return agentic incident response classes, phases, workflow matrix, and evidence."""
    return incident_response_pack.get(
        incident_class_id=incident_class_id,
        workflow_id=workflow_id,
        severity=severity,
        decision=decision,
    )


@mcp.tool()
async def recipes_agentic_action_runtime_pack(
    action_class_id: str | None = None,
    workflow_id: str | None = None,
    risk_tier: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return action classes, workflow action envelopes, runtime policy, and evidence."""
    return action_runtime_pack.get(
        action_class_id=action_class_id,
        workflow_id=workflow_id,
        risk_tier=risk_tier,
        decision=decision,
    )


@mcp.tool()
async def recipes_agent_trust_fabric_pack(
    dimension_id: str | None = None,
    workflow_id: str | None = None,
    trust_tier: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return Agent Trust Fabric dimensions, workflow tiers, source evidence, and buyer proof."""
    return agent_trust_fabric_pack.get(
        dimension_id=dimension_id,
        workflow_id=workflow_id,
        trust_tier=trust_tier,
        status=status,
    )


@mcp.tool()
async def recipes_browser_agent_boundary_pack(
    workspace_class_id: str | None = None,
    task_profile_id: str | None = None,
    risk_tier: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return browser-agent workspace classes, task profiles, controls, and evidence."""
    return browser_agent_boundary_pack.get(
        workspace_class_id=workspace_class_id,
        task_profile_id=task_profile_id,
        risk_tier=risk_tier,
        decision=decision,
    )


@mcp.tool()
async def recipes_agentic_measurement_probe_pack(
    probe_id: str | None = None,
    workflow_id: str | None = None,
    decision: str | None = None,
    class_id: str | None = None,
    status: str | None = None,
    minimum_score: int | None = None,
) -> dict[str, Any]:
    """Return measurement probes for agentic workflow traceability and readiness."""
    return measurement_probe_pack.get(
        probe_id=probe_id,
        workflow_id=workflow_id,
        decision=decision,
        class_id=class_id,
        status=status,
        minimum_score=minimum_score,
    )


@mcp.tool()
async def recipes_agentic_telemetry_contract(
    workflow_id: str | None = None,
    signal_class_id: str | None = None,
    check_id: str | None = None,
    decision: str | None = None,
    required_attribute: str | None = None,
) -> dict[str, Any]:
    """Return the OpenTelemetry-aligned agentic telemetry and redaction contract."""
    return telemetry_contract.get(
        workflow_id=workflow_id,
        signal_class_id=signal_class_id,
        check_id=check_id,
        decision=decision,
        required_attribute=required_attribute,
    )


@mcp.tool()
async def recipes_agentic_soc_detection_pack(
    rule_id: str | None = None,
    workflow_id: str | None = None,
    severity: str | None = None,
    decision: str | None = None,
    event_class: str | None = None,
) -> dict[str, Any]:
    """Return SIEM-ready detections for agentic AI and MCP telemetry."""
    return soc_detection_pack.get(
        rule_id=rule_id,
        workflow_id=workflow_id,
        severity=severity,
        decision=decision,
        event_class=event_class,
    )


@mcp.tool()
async def recipes_enterprise_trust_center_export(
    section_id: str | None = None,
    pack_id: str | None = None,
    question_id: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return the bundled enterprise trust-center export for buyer and platform diligence."""
    return enterprise_trust_center_export.get(
        section_id=section_id,
        pack_id=pack_id,
        question_id=question_id,
        category=category,
        status=status,
    )


@mcp.tool()
async def recipes_secure_context_value_model(
    driver_id: str | None = None,
    segment_id: str | None = None,
    scenario_id: str | None = None,
    wedge_id: str | None = None,
    question_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return the secure context value model for buyer, ROI, and acquisition diligence."""
    return secure_context_value_model.get(
        driver_id=driver_id,
        segment_id=segment_id,
        scenario_id=scenario_id,
        wedge_id=wedge_id,
        question_id=question_id,
        status=status,
    )


@mcp.tool()
async def recipes_design_partner_pilot_pack(
    segment_id: str | None = None,
    phase_id: str | None = None,
    wedge_id: str | None = None,
    metric_id: str | None = None,
    question_id: str | None = None,
    risk_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return the design partner pilot motion for buyer proof and hosted MCP validation."""
    return design_partner_pilot_pack.get(
        segment_id=segment_id,
        phase_id=phase_id,
        wedge_id=wedge_id,
        metric_id=metric_id,
        question_id=question_id,
        risk_id=risk_id,
        status=status,
    )


@mcp.tool()
async def recipes_secure_context_buyer_diligence_brief(
    buyer_id: str | None = None,
    question_id: str | None = None,
    objection_id: str | None = None,
    bet_id: str | None = None,
    source_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return buyer and acquirer diligence evidence for the secure context layer."""
    return buyer_diligence_brief.get(
        buyer_id=buyer_id,
        question_id=question_id,
        objection_id=objection_id,
        bet_id=bet_id,
        source_id=source_id,
        status=status,
    )


@mcp.tool()
async def recipes_secure_context_customer_proof_pack(
    claim_id: str | None = None,
    event_id: str | None = None,
    metric_id: str | None = None,
    gate_id: str | None = None,
    risk_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return the customer proof contract for design partner and acquisition evidence."""
    return customer_proof_pack.get(
        claim_id=claim_id,
        event_id=event_id,
        metric_id=metric_id,
        gate_id=gate_id,
        risk_id=risk_id,
        status=status,
    )


@mcp.tool()
async def recipes_secure_context_evidence_contract(
    object_type_id: str | None = None,
    channel_id: str | None = None,
    endpoint_id: str | None = None,
    artifact_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return the secure context evidence API and release contract."""
    return evidence_contract.get(
        object_type_id=object_type_id,
        channel_id=channel_id,
        endpoint_id=endpoint_id,
        artifact_id=artifact_id,
        status=status,
    )


@mcp.tool()
async def recipes_hosted_mcp_readiness_pack(
    stage_id: str | None = None,
    control_id: str | None = None,
    gate_id: str | None = None,
    buyer_evidence_id: str | None = None,
    risk_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return the hosted MCP readiness plan for enterprise product rollout."""
    return hosted_mcp_readiness_pack.get(
        stage_id=stage_id,
        control_id=control_id,
        gate_id=gate_id,
        buyer_evidence_id=buyer_evidence_id,
        risk_id=risk_id,
        status=status,
    )


@mcp.tool()
async def recipes_match_finding(
    cve: str | None = None,
    package: str | None = None,
    ecosystem: str | None = None,
    rule_id: str | None = None,
    keywords: list[str] | None = None,
    facets: list[str] | None = None,
    min_quality: int | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    """Heuristic matcher that suggests best-fit recipes for a security finding."""
    parts = [cve, package, ecosystem, rule_id]
    if keywords:
        parts.extend(keywords)
    query = " ".join([p for p in parts if p])
    if not query:
        return {"query": "", "count": 0, "results": []}

    results = await index.search(query=query, facets=facets, min_quality=min_quality, limit=limit)
    max_score = max([r.get("score", 0.0) for r in results], default=0.0)

    shaped = []
    for r in results:
        raw_score = float(r.get("score", 0.0))
        confidence = round(raw_score / max_score, 3) if max_score > 0 else 0.0
        shaped.append({**r, "confidence": confidence})

    return {
        "query": query,
        "count": len(shaped),
        "results": shaped,
    }


def main() -> None:
    if _env_bool("RECIPES_MCP_EAGER_REFRESH", False):
        asyncio.run(index.refresh(force=False))
    run_mcp_server()


if __name__ == "__main__":
    main()
