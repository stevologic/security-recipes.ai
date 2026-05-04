#!/usr/bin/env python3
"""security-recipes.ai MCP server.

Exposes a read-only MCP tool surface backed by Hugo's recipes-index.json.
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
from urllib.parse import urlparse

import httpx
import tomli
from fastmcp import FastMCP

try:
    from scripts.evaluate_a2a_agent_card_trust_decision import evaluate_a2a_agent_card_trust_decision
    from scripts.evaluate_agentic_action_runtime_decision import evaluate_agentic_action_runtime_decision
    from scripts.evaluate_agentic_approval_receipt_decision import evaluate_agentic_approval_receipt_decision
    from scripts.evaluate_agentic_entitlement_decision import evaluate_agentic_entitlement_decision
    from scripts.evaluate_agentic_app_intake_decision import evaluate_agentic_app_intake_decision
    from scripts.evaluate_agentic_catastrophic_risk_decision import evaluate_agentic_catastrophic_risk_decision
    from scripts.evaluate_agentic_incident_response_decision import evaluate_agentic_incident_response_decision
    from scripts.evaluate_agentic_posture_decision import evaluate_agentic_posture_decision
    from scripts.evaluate_agentic_protocol_conformance_decision import evaluate_agentic_protocol_conformance_decision
    from scripts.evaluate_agentic_telemetry_event import evaluate_agentic_telemetry_event
    from scripts.evaluate_model_provider_routing_decision import evaluate_model_provider_routing_decision
    from scripts.evaluate_browser_agent_boundary_decision import evaluate_browser_agent_boundary_decision
    from scripts.evaluate_mcp_elicitation_boundary_decision import evaluate_mcp_elicitation_boundary_decision
    from scripts.evaluate_agent_skill_supply_chain_decision import evaluate_agent_skill_supply_chain_decision
    from scripts.evaluate_agent_handoff_boundary_decision import evaluate_agent_handoff_boundary_decision
    from scripts.evaluate_agent_memory_boundary_decision import evaluate_agent_memory_boundary_decision
    from scripts.evaluate_mcp_stdio_launch_decision import evaluate_mcp_stdio_launch_decision
    from scripts.evaluate_mcp_tool_risk_decision import evaluate_mcp_tool_risk_decision
    from scripts.evaluate_mcp_tool_surface_drift_decision import evaluate_mcp_tool_surface_drift_decision
    from scripts.evaluate_context_egress_decision import evaluate_context_egress_decision
    from scripts.evaluate_context_attestation_decision import evaluate_context_attestation_decision
    from scripts.evaluate_secure_context_lineage_decision import evaluate_secure_context_lineage_decision
    from scripts.evaluate_secure_context_eval_case import evaluate_secure_context_eval_case
    from scripts.evaluate_mcp_authorization_decision import evaluate_mcp_authorization_decision
    from scripts.evaluate_mcp_gateway_decision import evaluate_policy_decision
    from scripts.evaluate_secure_context_retrieval import evaluate_context_retrieval_decision
except ImportError:  # pragma: no cover - supports direct script-directory execution.
    from evaluate_a2a_agent_card_trust_decision import evaluate_a2a_agent_card_trust_decision
    from evaluate_agentic_action_runtime_decision import evaluate_agentic_action_runtime_decision
    from evaluate_agentic_approval_receipt_decision import evaluate_agentic_approval_receipt_decision
    from evaluate_agentic_entitlement_decision import evaluate_agentic_entitlement_decision
    from evaluate_agentic_app_intake_decision import evaluate_agentic_app_intake_decision
    from evaluate_agentic_catastrophic_risk_decision import evaluate_agentic_catastrophic_risk_decision
    from evaluate_agentic_incident_response_decision import evaluate_agentic_incident_response_decision
    from evaluate_agentic_posture_decision import evaluate_agentic_posture_decision
    from evaluate_agentic_protocol_conformance_decision import evaluate_agentic_protocol_conformance_decision
    from evaluate_agentic_telemetry_event import evaluate_agentic_telemetry_event
    from evaluate_model_provider_routing_decision import evaluate_model_provider_routing_decision
    from evaluate_browser_agent_boundary_decision import evaluate_browser_agent_boundary_decision
    from evaluate_mcp_elicitation_boundary_decision import evaluate_mcp_elicitation_boundary_decision
    from evaluate_agent_skill_supply_chain_decision import evaluate_agent_skill_supply_chain_decision
    from evaluate_agent_handoff_boundary_decision import evaluate_agent_handoff_boundary_decision
    from evaluate_agent_memory_boundary_decision import evaluate_agent_memory_boundary_decision
    from evaluate_mcp_stdio_launch_decision import evaluate_mcp_stdio_launch_decision
    from evaluate_mcp_tool_risk_decision import evaluate_mcp_tool_risk_decision
    from evaluate_mcp_tool_surface_drift_decision import evaluate_mcp_tool_surface_drift_decision
    from evaluate_context_egress_decision import evaluate_context_egress_decision
    from evaluate_context_attestation_decision import evaluate_context_attestation_decision
    from evaluate_secure_context_lineage_decision import evaluate_secure_context_lineage_decision
    from evaluate_secure_context_eval_case import evaluate_secure_context_eval_case
    from evaluate_mcp_authorization_decision import evaluate_mcp_authorization_decision
    from evaluate_mcp_gateway_decision import evaluate_policy_decision
    from evaluate_secure_context_retrieval import evaluate_context_retrieval_decision

DEFAULT_CONFIG_PATH = os.environ.get("RECIPES_MCP_CONFIG", "./mcp-server.toml")
DEFAULT_TRANSPORT = os.environ.get("RECIPES_MCP_TRANSPORT", "streamable-http")
DEFAULT_HOST = os.environ.get("RECIPES_MCP_HOST", "0.0.0.0")
DEFAULT_PORT = os.environ.get("RECIPES_MCP_PORT", "8000")
DEFAULT_PATH = os.environ.get("RECIPES_MCP_PATH")
DEFAULT_LOG_LEVEL = os.environ.get("RECIPES_MCP_LOG_LEVEL")


@dataclass
class ServerConfig:
    source_index_url: str = "https://security-recipes.ai/recipes-index.json"
    allowed_source_hosts: list[str] = field(default_factory=lambda: ["security-recipes.ai"])
    cache_ttl_seconds: int = 3600
    request_timeout_seconds: int = 15
    max_results_default: int = 8
    max_results_cap: int = 25
    # Public-facing URL for this MCP server (metadata only).
    server_public_base_url: str = "https://mcp.security-recipes.ai"
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
    enterprise_trust_center_export_path: str = os.environ.get(
        "RECIPES_MCP_ENTERPRISE_TRUST_CENTER_EXPORT_PATH",
        "./data/evidence/enterprise-trust-center-export.json",
    )
    catastrophic_risk_annex_path: str = os.environ.get(
        "RECIPES_MCP_CATASTROPHIC_RISK_ANNEX_PATH",
        "./data/evidence/agentic-catastrophic-risk-annex.json",
    )
    incident_response_pack_path: str = os.environ.get(
        "RECIPES_MCP_INCIDENT_RESPONSE_PACK_PATH",
        "./data/evidence/agentic-incident-response-pack.json",
    )
    action_runtime_pack_path: str = os.environ.get(
        "RECIPES_MCP_ACTION_RUNTIME_PACK_PATH",
        "./data/evidence/agentic-action-runtime-pack.json",
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
    app_intake_pack_path: str = os.environ.get(
        "RECIPES_MCP_APP_INTAKE_PACK_PATH",
        "./data/evidence/agentic-app-intake-pack.json",
    )
    model_provider_routing_pack_path: str = os.environ.get(
        "RECIPES_MCP_MODEL_PROVIDER_ROUTING_PACK_PATH",
        "./data/evidence/model-provider-routing-pack.json",
    )


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
        host = parsed.hostname
        if not host:
            raise ValueError("source_index_url must include a hostname")
        if host not in set(self.config.allowed_source_hosts):
            raise ValueError(
                f"source host '{host}' is not in allowed_source_hosts={self.config.allowed_source_hosts}"
            )

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

            timeout = httpx.Timeout(self.config.request_timeout_seconds)
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.get(self.config.source_index_url, headers=headers)

            if response.status_code == 304:
                self._fetched_at = time.time()
                return {
                    "status": "not_modified",
                    "fetched_at_unix": int(self._fetched_at),
                    "doc_count": len(self._docs),
                }

            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list) or not payload:
                raise ValueError("recipes-index payload must be a non-empty JSON array")

            required = {"slug", "title", "url", "content"}
            for idx, row in enumerate(payload[:20]):
                missing = sorted(required - set(row.keys()))
                if missing:
                    raise ValueError(f"row[{idx}] missing required fields: {missing}")

            self._docs = payload
            self._doc_by_slug = {str(doc.get("slug", "")).strip(): doc for doc in payload if doc.get("slug")}
            self._doc_by_path = {str(doc.get("path", "")).strip(): doc for doc in payload if doc.get("path")}
            self._fetched_at = time.time()
            self._etag = response.headers.get("ETag")

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
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        await self.ensure_fresh()
        docs = self._docs

        if section:
            docs = [d for d in docs if str(d.get("section", "")).lower() == section.lower()]
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

        cap = self.config.max_results_cap
        if limit is None:
            limit = self.config.max_results_default
        limit = max(1, min(limit, cap))
        return [self._shape_preview(d) for d in docs[:limit]]

    async def get_doc(self, slug_or_path: str) -> dict[str, Any] | None:
        await self.ensure_fresh()
        key = slug_or_path.strip()
        return self._doc_by_slug.get(key) or self._doc_by_path.get(key)

    async def search(
        self,
        query: str,
        section: str | None = None,
        agent: str | None = None,
        tags: list[str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        await self.ensure_fresh()
        terms = [t for t in re.split(r"\s+", query.lower().strip()) if t]
        if not terms:
            return []

        candidates: list[dict[str, Any]] = self._docs
        if section:
            candidates = [d for d in candidates if str(d.get("section", "")).lower() == section.lower()]
        if agent:
            candidates = [d for d in candidates if str(d.get("agent", "")).lower() == agent.lower()]
        if tags:
            tags_lower = {t.lower() for t in tags}
            candidates = [
                d
                for d in candidates
                if tags_lower.intersection({str(tag).lower() for tag in (d.get("tags") or [])})
            ]

        scored: list[tuple[float, dict[str, Any]]] = []
        for d in candidates:
            hay = " ".join(
                [
                    str(d.get("title", "")),
                    str(d.get("summary", "")),
                    str(d.get("content", ""))[:8000],
                    " ".join([str(x) for x in (d.get("tags") or [])]),
                    str(d.get("slug", "")),
                    str(d.get("path", "")),
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

    @staticmethod
    def _shape_preview(doc: dict[str, Any], score: float | None = None) -> dict[str, Any]:
        out = {
            "slug": doc.get("slug"),
            "title": doc.get("title"),
            "path": doc.get("path"),
            "url": doc.get("url"),
            "section": doc.get("section"),
            "agent": doc.get("agent"),
            "severity": doc.get("severity"),
            "tags": doc.get("tags") or [],
            "summary": doc.get("summary"),
            "last_updated": doc.get("last_updated"),
            "source_file": doc.get("source_file"),
        }
        if score is not None:
            out["score"] = round(score, 4)
        return out


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
        try:
            policy_pack = self._load()
        except Exception as exc:
            return {
                "allowed": False,
                "available": False,
                "decision": "deny",
                "error": f"failed to load MCP gateway policy pack: {exc}",
                "policy_path": str(self.path),
            }

        if policy_pack is None:
            return {
                "allowed": False,
                "available": False,
                "decision": "deny",
                "error": "MCP gateway policy pack is not present",
                "policy_path": str(self.path),
            }

        if not isinstance(policy_pack, dict):
            return {
                "allowed": False,
                "available": False,
                "decision": "deny",
                "error": "MCP gateway policy pack root must be an object",
                "policy_path": str(self.path),
            }

        return {
            "available": True,
            **evaluate_policy_decision(policy_pack, runtime_request),
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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agentic_entitlement_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agentic entitlement decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agentic_approval_receipt_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agentic approval receipt decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_mcp_stdio_launch_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate MCP STDIO launch decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_mcp_authorization_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate MCP authorization decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_mcp_elicitation_boundary_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate MCP elicitation boundary decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_mcp_tool_risk_decision(contract, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "contract_path": str(self.path),
                "error": f"failed to evaluate MCP tool-risk decision: {exc}",
            }
        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_mcp_tool_surface_drift_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate MCP tool-surface drift decision: {exc}",
                "pack_path": str(self.path),
            }
        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agent_skill_supply_chain_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agent skill decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agent_handoff_boundary_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agent handoff decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_a2a_agent_card_trust_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate A2A Agent Card trust decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agent_memory_boundary_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agent memory decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_context_retrieval_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate context retrieval decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_context_attestation_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate context attestation decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_secure_context_lineage_decision(ledger, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate secure context lineage decision: {exc}",
                "ledger_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_result: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_secure_context_eval_case(pack, runtime_result)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate secure context eval case: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_event: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agentic_posture_decision(snapshot, runtime_event)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agentic posture decision: {exc}",
                "snapshot_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agentic_app_intake_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agentic app intake decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_model_provider_routing_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate model provider routing decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agentic_catastrophic_risk_decision(annex, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate catastrophic-risk decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agentic_incident_response_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agentic incident response decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agentic_action_runtime_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agentic action runtime decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_browser_agent_boundary_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate browser-agent boundary decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_event: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agentic_telemetry_event(contract, runtime_event)
        except Exception as exc:
            return {
                "available": False,
                "contract_path": str(self.path),
                "error": f"failed to evaluate agentic telemetry event: {exc}",
            }
        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_context_egress_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate context egress decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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

    def evaluate(self, runtime_request: dict[str, Any]) -> dict[str, Any]:
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

        try:
            decision = evaluate_agentic_protocol_conformance_decision(pack, runtime_request)
        except Exception as exc:
            return {
                "available": False,
                "error": f"failed to evaluate agentic protocol conformance decision: {exc}",
                "pack_path": str(self.path),
            }

        decision["available"] = True
        return decision


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


def load_config(config_path: str) -> ServerConfig:
    path = Path(config_path)
    cfg = ServerConfig()
    if not path.exists():
        return cfg

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
    cfg.enterprise_trust_center_export_path = data.get(
        "enterprise_trust_center_export_path",
        cfg.enterprise_trust_center_export_path,
    )
    cfg.catastrophic_risk_annex_path = data.get(
        "catastrophic_risk_annex_path",
        cfg.catastrophic_risk_annex_path,
    )
    cfg.incident_response_pack_path = data.get(
        "incident_response_pack_path",
        cfg.incident_response_pack_path,
    )
    cfg.action_runtime_pack_path = data.get(
        "action_runtime_pack_path",
        cfg.action_runtime_pack_path,
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
    cfg.app_intake_pack_path = data.get(
        "app_intake_pack_path",
        cfg.app_intake_pack_path,
    )
    cfg.model_provider_routing_pack_path = data.get(
        "model_provider_routing_pack_path",
        cfg.model_provider_routing_pack_path,
    )
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
mcp_risk_coverage_pack = MCPRiskCoveragePack(config.mcp_risk_coverage_pack_path)
protocol_conformance_pack = AgenticProtocolConformancePack(config.protocol_conformance_pack_path)
control_plane_blueprint = AgenticControlPlaneBlueprint(config.control_plane_blueprint_path)
exposure_graph = AgenticExposureGraph(config.exposure_graph_path)
posture_snapshot = AgenticPostureSnapshot(config.posture_snapshot_path)
app_intake_pack = AgenticAppIntakePack(config.app_intake_pack_path)
model_provider_routing_pack = ModelProviderRoutingPack(config.model_provider_routing_pack_path)
catastrophic_risk_annex = AgenticCatastrophicRiskAnnex(config.catastrophic_risk_annex_path)
incident_response_pack = AgenticIncidentResponsePack(config.incident_response_pack_path)
action_runtime_pack = AgenticActionRuntimePack(config.action_runtime_pack_path)
browser_agent_boundary_pack = BrowserAgentBoundaryPack(config.browser_agent_boundary_pack_path)
measurement_probe_pack = AgenticMeasurementProbePack(config.measurement_probe_pack_path)
telemetry_contract = AgenticTelemetryContract(config.telemetry_contract_path)
enterprise_trust_center_export = EnterpriseTrustCenterExport(config.enterprise_trust_center_export_path)
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
        "mcp_risk_coverage_pack_path": config.mcp_risk_coverage_pack_path,
        "protocol_conformance_pack_path": config.protocol_conformance_pack_path,
        "control_plane_blueprint_path": config.control_plane_blueprint_path,
        "exposure_graph_path": config.exposure_graph_path,
        "posture_snapshot_path": config.posture_snapshot_path,
        "app_intake_pack_path": config.app_intake_pack_path,
        "model_provider_routing_pack_path": config.model_provider_routing_pack_path,
        "catastrophic_risk_annex_path": config.catastrophic_risk_annex_path,
        "incident_response_pack_path": config.incident_response_pack_path,
        "action_runtime_pack_path": config.action_runtime_pack_path,
        "browser_agent_boundary_pack_path": config.browser_agent_boundary_pack_path,
        "measurement_probe_pack_path": config.measurement_probe_pack_path,
        "telemetry_contract_path": config.telemetry_contract_path,
        "enterprise_trust_center_export_path": config.enterprise_trust_center_export_path,
    }


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
    limit: int | None = None,
) -> dict[str, Any]:
    """Full-text search over security-recipes documents."""
    results = await index.search(query=query, section=section, agent=agent, tags=tags, limit=limit)
    return {"query": query, "count": len(results), "results": results}


@mcp.tool()
async def recipes_list(
    section: str | None = None,
    agent: str | None = None,
    severity: str | None = None,
    tags: list[str] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List recipes with optional metadata filtering."""
    results = await index.list_docs(
        section=section,
        agent=agent,
        severity=severity,
        tags=tags,
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
async def recipes_workflow_control_plane(workflow_id: str | None = None) -> dict[str, Any]:
    """Return workflow control-plane policy for agents, reviewers, and MCP gateways."""
    return control_plane.get(workflow_id=workflow_id)


@mcp.tool()
async def recipes_mcp_gateway_policy(workflow_id: str | None = None) -> dict[str, Any]:
    """Return generated MCP gateway policy for scoped tool access and runtime controls."""
    return gateway_policy.get(workflow_id=workflow_id)


@mcp.tool()
async def recipes_evaluate_mcp_gateway_decision(
    workflow_id: str,
    agent_id: str,
    run_id: str,
    tool_namespace: str,
    tool_access_mode: str,
    gate_phase: str,
    branch_name: str | None = None,
    changed_paths: list[str] | None = None,
    diff_line_count: int | None = 0,
    human_approval_record: dict[str, Any] | None = None,
    runtime_kill_signal: str | None = None,
    agent_class: str | None = None,
    change_class: str | None = None,
) -> dict[str, Any]:
    """Evaluate one runtime MCP tool call against the generated gateway policy."""
    return gateway_policy.evaluate(
        {
            "agent_class": agent_class,
            "agent_id": agent_id,
            "branch_name": branch_name,
            "change_class": change_class,
            "changed_paths": changed_paths or [],
            "diff_line_count": diff_line_count or 0,
            "gate_phase": gate_phase,
            "human_approval_record": human_approval_record,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "tool_access_mode": tool_access_mode,
            "tool_namespace": tool_namespace,
            "workflow_id": workflow_id,
        }
    )


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
async def recipes_evaluate_agentic_entitlement_decision(
    identity_id: str,
    workflow_id: str,
    agent_class: str,
    namespace: str,
    requested_access_mode: str,
    lease_id: str,
    lease_status: str,
    lease_expires_at: str,
    review_status: str,
    authorization_decision: str,
    run_id: str,
    tenant_id: str,
    correlation_id: str,
    receipt_id: str,
    entitlement_id: str | None = None,
    policy_pack_hash: str | None = None,
    risk_acceptance_id: str | None = None,
    human_approval_record: dict[str, Any] | None = None,
    now: str | None = None,
    indicators: list[str] | None = None,
    contains_secret: bool = False,
    cross_tenant_entitlement: bool = False,
    identity_used_after_revocation: bool = False,
    repeated_denied_entitlement: bool = False,
    scope_escalation: bool = False,
    token_passthrough: bool = False,
) -> dict[str, Any]:
    """Return a deterministic allow, hold, deny, or kill decision for one agent entitlement use."""
    return entitlement_review_pack.evaluate(
        {
            "agent_class": agent_class,
            "authorization_decision": authorization_decision,
            "contains_secret": contains_secret,
            "correlation_id": correlation_id,
            "cross_tenant_entitlement": cross_tenant_entitlement,
            "entitlement_id": entitlement_id,
            "human_approval_record": human_approval_record,
            "identity_id": identity_id,
            "identity_used_after_revocation": identity_used_after_revocation,
            "indicators": indicators or [],
            "lease_expires_at": lease_expires_at,
            "lease_id": lease_id,
            "lease_status": lease_status,
            "namespace": namespace,
            "now": now,
            "policy_pack_hash": policy_pack_hash,
            "receipt_id": receipt_id,
            "repeated_denied_entitlement": repeated_denied_entitlement,
            "requested_access_mode": requested_access_mode,
            "review_status": review_status,
            "risk_acceptance_id": risk_acceptance_id,
            "run_id": run_id,
            "scope_escalation": scope_escalation,
            "tenant_id": tenant_id,
            "token_passthrough": token_passthrough,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_agentic_approval_receipt_decision(
    workflow_id: str,
    action_class: str,
    run_id: str,
    agent_id: str,
    identity_id: str,
    tenant_id: str,
    correlation_id: str,
    approval_id: str,
    approval_type: str,
    approval_status: str,
    approver_ids: list[str],
    approver_roles: list[str],
    requested_scope_hash: str,
    approved_scope_hash: str,
    issued_at: str,
    expires_at: str,
    receipt_id: str,
    policy_pack_hash: str,
    approval_profile_id: str | None = None,
    approval_source: str | None = None,
    requester_id: str | None = None,
    risk_acceptance_id: str | None = None,
    authorization_decision: str | None = None,
    now: str | None = None,
    indicators: list[str] | None = None,
    approval_after_execution: bool = False,
    approval_bypass_signal: bool = False,
    approval_reused_across_run: bool = False,
    contains_secret: bool = False,
    cross_tenant_approval_reuse: bool = False,
    requester_self_approved: bool = False,
    token_passthrough: bool = False,
) -> dict[str, Any]:
    """Return a deterministic allow, hold, deny, or kill decision for one approval receipt."""
    return approval_receipt_pack.evaluate(
        {
            "action_class": action_class,
            "agent_id": agent_id,
            "approval_after_execution": approval_after_execution,
            "approval_bypass_signal": approval_bypass_signal,
            "approval_id": approval_id,
            "approval_profile_id": approval_profile_id,
            "approval_reused_across_run": approval_reused_across_run,
            "approval_source": approval_source,
            "approval_status": approval_status,
            "approval_type": approval_type,
            "approved_scope_hash": approved_scope_hash,
            "approver_ids": approver_ids,
            "approver_roles": approver_roles,
            "authorization_decision": authorization_decision,
            "contains_secret": contains_secret,
            "correlation_id": correlation_id,
            "cross_tenant_approval_reuse": cross_tenant_approval_reuse,
            "expires_at": expires_at,
            "identity_id": identity_id,
            "indicators": indicators or [],
            "issued_at": issued_at,
            "now": now,
            "policy_pack_hash": policy_pack_hash,
            "receipt_id": receipt_id,
            "requested_scope_hash": requested_scope_hash,
            "requester_id": requester_id,
            "requester_self_approved": requester_self_approved,
            "risk_acceptance_id": risk_acceptance_id,
            "run_id": run_id,
            "tenant_id": tenant_id,
            "token_passthrough": token_passthrough,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_mcp_stdio_launch_decision(
    launch_id: str,
    command: str,
    command_args: list[str] | None = None,
    agent_id: str | None = None,
    run_id: str | None = None,
    client_id: str | None = None,
    correlation_id: str | None = None,
    package_name: str | None = None,
    package_version: str | None = None,
    package_hash: str | None = None,
    package_install_on_launch: bool = False,
    signature_present: bool = False,
    publisher_verified: bool = False,
    sandboxed: bool = False,
    network_egress: str | None = "allowlist",
    allowed_external_hosts: list[str] | None = None,
    allows_private_network: bool = False,
    filesystem_roots: list[str] | None = None,
    env_keys: list[str] | None = None,
    contains_secret: bool = False,
    env_contains_secret: bool = False,
    data_classes: list[str] | None = None,
    requested_capabilities: list[str] | None = None,
    run_as_root: bool = False,
    requests_privilege_escalation: bool = False,
    human_approval_record: dict[str, Any] | None = None,
    runtime_kill_signal: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic allow, hold, deny, or kill decision before spawning a STDIO MCP server."""
    return mcp_stdio_launch_boundary_pack.evaluate(
        {
            "agent_id": agent_id,
            "allowed_external_hosts": allowed_external_hosts or [],
            "allows_private_network": allows_private_network,
            "args": command_args or [],
            "client_id": client_id,
            "command": command,
            "contains_secret": contains_secret,
            "correlation_id": correlation_id,
            "data_classes": data_classes or [],
            "env_contains_secret": env_contains_secret,
            "env_keys": env_keys or [],
            "filesystem_roots": filesystem_roots or [],
            "human_approval_record": human_approval_record or {},
            "launch_id": launch_id,
            "network_egress": network_egress,
            "package_hash": package_hash,
            "package_install_on_launch": package_install_on_launch,
            "package_name": package_name,
            "package_version": package_version,
            "publisher_verified": publisher_verified,
            "requested_capabilities": requested_capabilities or [],
            "requests_privilege_escalation": requests_privilege_escalation,
            "run_as_root": run_as_root,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "sandboxed": sandboxed,
            "signature_present": signature_present,
        }
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
async def recipes_evaluate_mcp_authorization_decision(
    workflow_id: str,
    namespace: str,
    requested_access_mode: str,
    connector_id: str | None = None,
    agent_id: str | None = None,
    run_id: str | None = None,
    client_id: str | None = None,
    resource_indicator: str | None = None,
    token_audience: str | None = None,
    token_issuer: str | None = None,
    token_expires_at: str | None = None,
    token_scopes: list[str] | None = None,
    consent_record_id: str | None = None,
    session_id: str | None = None,
    correlation_id: str | None = None,
    gateway_policy_hash: str | None = None,
    token_passthrough: bool = False,
    contains_secret_scope: bool = False,
) -> dict[str, Any]:
    """Return a deterministic MCP authorization decision before a tool call is forwarded."""
    return authorization_conformance_pack.evaluate(
        {
            "agent_id": agent_id,
            "client_id": client_id,
            "connector_id": connector_id,
            "consent_record_id": consent_record_id,
            "contains_secret_scope": contains_secret_scope,
            "correlation_id": correlation_id,
            "gateway_policy_hash": gateway_policy_hash,
            "namespace": namespace,
            "requested_access_mode": requested_access_mode,
            "resource_indicator": resource_indicator,
            "run_id": run_id,
            "session_id": session_id,
            "token_audience": token_audience,
            "token_expires_at": token_expires_at,
            "token_issuer": token_issuer,
            "token_passthrough": token_passthrough,
            "token_scopes": token_scopes or [],
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_mcp_elicitation_boundary_decision(
    workflow_id: str,
    agent_id: str,
    run_id: str,
    server_id: str,
    elicitation_profile_id: str,
    elicitation_id: str,
    mode: str,
    connector_id: str | None = None,
    namespace: str | None = None,
    url: str | None = None,
    url_domain: str | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
    correlation_id: str | None = None,
    gateway_policy_hash: str | None = None,
    authorization_pack_hash: str | None = None,
    response_action: str | None = None,
    requested_data_classes: list[str] | None = None,
    response_schema_fields: list[str] | None = None,
    human_approval_record: dict[str, Any] | None = None,
    client_supports_mode: bool = False,
    server_identity_displayed: bool = False,
    user_can_decline: bool = False,
    user_can_review: bool = False,
    user_consent_recorded: bool = False,
    completion_notification_bound: bool = False,
    https_url: bool = False,
    url_allowlisted: bool = False,
    sensitive_information_requested: bool = False,
    credential_requested: bool = False,
    token_or_secret_transit: bool = False,
    preauthenticated_url: bool = False,
    url_contains_sensitive_data: bool = False,
    url_prefetched: bool = False,
    url_opened_without_consent: bool = False,
    phishing_or_open_redirect_signal: bool = False,
    untrusted_content_seen: bool = False,
    form_contains_clickable_url: bool = False,
    runtime_kill_signal: bool = False,
) -> dict[str, Any]:
    """Return a deterministic MCP elicitation allow, hold, deny, or kill decision."""
    return elicitation_boundary_pack.evaluate(
        {
            "agent_id": agent_id,
            "authorization_pack_hash": authorization_pack_hash,
            "client_supports_mode": client_supports_mode,
            "completion_notification_bound": completion_notification_bound,
            "connector_id": connector_id,
            "correlation_id": correlation_id,
            "credential_requested": credential_requested,
            "elicitation_id": elicitation_id,
            "elicitation_profile_id": elicitation_profile_id,
            "form_contains_clickable_url": form_contains_clickable_url,
            "gateway_policy_hash": gateway_policy_hash,
            "human_approval_record": human_approval_record or {},
            "https_url": https_url,
            "mode": mode,
            "namespace": namespace,
            "phishing_or_open_redirect_signal": phishing_or_open_redirect_signal,
            "preauthenticated_url": preauthenticated_url,
            "requested_data_classes": requested_data_classes or [],
            "response_action": response_action,
            "response_schema_fields": response_schema_fields or [],
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "sensitive_information_requested": sensitive_information_requested,
            "server_id": server_id,
            "server_identity_displayed": server_identity_displayed,
            "session_id": session_id,
            "token_or_secret_transit": token_or_secret_transit,
            "untrusted_content_seen": untrusted_content_seen,
            "url": url,
            "url_allowlisted": url_allowlisted,
            "url_contains_sensitive_data": url_contains_sensitive_data,
            "url_domain": url_domain,
            "url_opened_without_consent": url_opened_without_consent,
            "url_prefetched": url_prefetched,
            "user_can_decline": user_can_decline,
            "user_can_review": user_can_review,
            "user_consent_recorded": user_consent_recorded,
            "user_id": user_id,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_mcp_tool_risk_decision(
    workflow_id: str,
    namespace: str,
    tool_name: str,
    requested_access_mode: str,
    connector_id: str | None = None,
    agent_id: str | None = None,
    run_id: str | None = None,
    gate_phase: str | None = None,
    session_id: str | None = None,
    correlation_id: str | None = None,
    policy_pack_hash: str | None = None,
    authorization_pack_hash: str | None = None,
    annotation_source: str | None = None,
    annotations: dict[str, Any] | None = None,
    server_trusted: bool = False,
    session_reads_private_data: bool = False,
    session_sees_untrusted_content: bool = False,
    session_can_exfiltrate: bool = False,
    human_approval_record: dict[str, Any] | None = None,
    contains_secret: bool = False,
    tool_list_changed_after_approval: bool = False,
    private_network_destination: bool = False,
    runtime_kill_signal: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic MCP tool-risk decision before a tool call executes."""
    return tool_risk_contract.evaluate(
        {
            "agent_id": agent_id,
            "annotation_source": annotation_source,
            "annotations": annotations or {},
            "authorization_pack_hash": authorization_pack_hash,
            "connector_id": connector_id,
            "contains_secret": contains_secret,
            "correlation_id": correlation_id,
            "gate_phase": gate_phase,
            "human_approval_record": human_approval_record or {},
            "namespace": namespace,
            "policy_pack_hash": policy_pack_hash,
            "private_network_destination": private_network_destination,
            "requested_access_mode": requested_access_mode,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "server_trusted": server_trusted,
            "session_can_exfiltrate": session_can_exfiltrate,
            "session_id": session_id,
            "session_reads_private_data": session_reads_private_data,
            "session_sees_untrusted_content": session_sees_untrusted_content,
            "tool_list_changed_after_approval": tool_list_changed_after_approval,
            "tool_name": tool_name,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_mcp_tool_surface_drift_decision(
    namespace: str,
    tool_name: str,
    workflow_id: str | None = None,
    requested_access_mode: str | None = None,
    surface_id: str | None = None,
    description_sha256: str | None = None,
    input_schema_sha256: str | None = None,
    output_schema_sha256: str | None = None,
    annotations_sha256: str | None = None,
    surface_hash: str | None = None,
    annotations: dict[str, Any] | None = None,
    agent_id: str | None = None,
    run_id: str | None = None,
    session_id: str | None = None,
    tenant_id: str | None = None,
    correlation_id: str | None = None,
    added_capability_flags: list[str] | None = None,
    human_approval_record: dict[str, Any] | None = None,
    capability_expansion: bool = False,
    data_class_expansion: bool = False,
    external_system_expansion: bool = False,
    server_trust_downgrade: bool = False,
    tool_list_changed_after_approval: bool = False,
    tool_removed: bool = False,
    contains_secret: bool = False,
    private_network_destination: bool = False,
    approval_bypass_signal: bool = False,
    hidden_instruction_signal: bool = False,
    annotation_relaxes_controls: bool = False,
    runtime_kill_signal: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic drift decision before a changed MCP tool surface is trusted."""
    return tool_surface_drift_pack.evaluate(
        {
            "added_capability_flags": added_capability_flags or [],
            "agent_id": agent_id,
            "annotation_relaxes_controls": annotation_relaxes_controls,
            "annotations": annotations or {},
            "annotations_sha256": annotations_sha256,
            "approval_bypass_signal": approval_bypass_signal,
            "capability_expansion": capability_expansion,
            "contains_secret": contains_secret,
            "correlation_id": correlation_id,
            "data_class_expansion": data_class_expansion,
            "description_sha256": description_sha256,
            "external_system_expansion": external_system_expansion,
            "hidden_instruction_signal": hidden_instruction_signal,
            "human_approval_record": human_approval_record or {},
            "input_schema_sha256": input_schema_sha256,
            "namespace": namespace,
            "output_schema_sha256": output_schema_sha256,
            "private_network_destination": private_network_destination,
            "requested_access_mode": requested_access_mode,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "server_trust_downgrade": server_trust_downgrade,
            "session_id": session_id,
            "surface_hash": surface_hash,
            "surface_id": surface_id,
            "tenant_id": tenant_id,
            "tool_list_changed_after_approval": tool_list_changed_after_approval,
            "tool_name": tool_name,
            "tool_removed": tool_removed,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_agent_memory_decision(
    workflow_id: str,
    memory_class_id: str,
    operation: str,
    agent_id: str | None = None,
    run_id: str | None = None,
    tenant_id: str | None = None,
    source_id: str | None = None,
    provenance_hash: str | None = None,
    requested_ttl_days: int | None = None,
    data_class: str | None = None,
    data_classes: list[str] | None = None,
    contains_secret: bool = False,
    contains_unredacted_pii: bool = False,
    human_approval_record: dict[str, Any] | None = None,
    runtime_kill_signal: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic memory read, write, delete, replay, or reindex decision."""
    return agent_memory_boundary_pack.evaluate(
        {
            "agent_id": agent_id,
            "contains_secret": contains_secret,
            "contains_unredacted_pii": contains_unredacted_pii,
            "data_class": data_class,
            "data_classes": data_classes or [],
            "human_approval_record": human_approval_record,
            "memory_class_id": memory_class_id,
            "operation": operation,
            "provenance_hash": provenance_hash,
            "requested_ttl_days": requested_ttl_days,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "source_id": source_id,
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_agent_skill_decision(
    skill_id: str,
    operation: str,
    workflow_id: str | None = None,
    platform: str | None = None,
    agent_id: str | None = None,
    run_id: str | None = None,
    package_hash: str | None = None,
    signature_present: bool = False,
    verified_publisher: bool = False,
    registry_verified: bool = False,
    sandboxed: bool = False,
    requested_permissions: dict[str, Any] | None = None,
    network_egress_domains: list[str] | None = None,
    human_approval_record: dict[str, Any] | None = None,
    runtime_kill_signal: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic install, update, enable, or run decision for an agent skill."""
    return agent_skill_supply_chain_pack.evaluate(
        {
            "agent_id": agent_id,
            "human_approval_record": human_approval_record,
            "network_egress_domains": network_egress_domains or [],
            "operation": operation,
            "package_hash": package_hash,
            "platform": platform,
            "registry_verified": registry_verified,
            "requested_permissions": requested_permissions or {},
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "sandboxed": sandboxed,
            "signature_present": signature_present,
            "skill_id": skill_id,
            "verified_publisher": verified_publisher,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_agent_handoff_decision(
    workflow_id: str,
    handoff_profile_id: str,
    protocol: str,
    target_agent_class: str | None = None,
    source_agent_id: str | None = None,
    run_id: str | None = None,
    correlation_id: str | None = None,
    target_trust_tier: str = "first_party",
    payload_fields: list[str] | None = None,
    data_classes: list[str] | None = None,
    requested_capabilities: list[str] | None = None,
    authentication_schemes: list[str] | None = None,
    agent_card_signed: bool = False,
    contains_secret: bool = False,
    resource_indicator: str | None = None,
    token_audience: str | None = None,
    human_approval_record: dict[str, Any] | None = None,
    runtime_kill_signal: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic allow, hold, deny, or kill decision for an agent handoff."""
    return agent_handoff_boundary_pack.evaluate(
        {
            "agent_card_signed": agent_card_signed,
            "authentication_schemes": authentication_schemes or [],
            "contains_secret": contains_secret,
            "correlation_id": correlation_id,
            "data_classes": data_classes or [],
            "handoff_profile_id": handoff_profile_id,
            "human_approval_record": human_approval_record or {},
            "payload_fields": payload_fields or [],
            "protocol": protocol,
            "requested_capabilities": requested_capabilities or [],
            "resource_indicator": resource_indicator,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "source_agent_id": source_agent_id,
            "target_agent_class": target_agent_class,
            "target_trust_tier": target_trust_tier,
            "token_audience": token_audience,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_a2a_agent_card_trust_decision(
    agent_card: dict[str, Any],
    profile_id: str,
    production: bool = False,
    expected_domain: str | None = None,
    declared_controls: list[str] | None = None,
    approved_skill_ids: list[str] | None = None,
    tenant_id: str | None = None,
    run_id: str | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic allow, pilot, hold, deny, or kill decision for an A2A Agent Card."""
    return a2a_agent_card_trust_profile.evaluate(
        {
            "agent_card": agent_card,
            "approved_skill_ids": approved_skill_ids or [],
            "correlation_id": correlation_id,
            "declared_controls": declared_controls or [],
            "expected_domain": expected_domain,
            "production": production,
            "profile_id": profile_id,
            "run_id": run_id,
            "tenant_id": tenant_id,
        }
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
async def recipes_evaluate_context_retrieval_decision(
    workflow_id: str,
    source_id: str,
    retrieval_mode: str,
    agent_id: str | None = None,
    run_id: str | None = None,
    requested_path: str | None = None,
    context_hash: str | None = None,
    tenant_id: str | None = None,
    data_class: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic allow, hold, deny, or kill decision before context is returned."""
    return secure_context_trust_pack.evaluate(
        {
            "agent_id": agent_id,
            "context_hash": context_hash,
            "data_class": data_class,
            "requested_path": requested_path,
            "retrieval_mode": retrieval_mode,
            "run_id": run_id,
            "source_id": source_id,
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_context_attestation_decision(
    subject_type: str,
    environment: str = "open_reference",
    source_id: str | None = None,
    workflow_id: str | None = None,
    artifact_id: str | None = None,
    subject_hash: str | None = None,
    data_class: str | None = None,
    signature_bundle_present: bool = False,
    transparency_log_verified: bool = False,
) -> dict[str, Any]:
    """Return a deterministic attestation decision before context is trusted for an agent."""
    return secure_context_attestation_pack.evaluate(
        {
            "artifact_id": artifact_id,
            "data_class": data_class,
            "environment": environment,
            "signature_bundle_present": signature_bundle_present,
            "source_id": source_id,
            "subject_hash": subject_hash,
            "subject_type": subject_type,
            "transparency_log_verified": transparency_log_verified,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_secure_context_lineage_decision(
    workflow_id: str,
    run_id: str,
    agent_id: str,
    tenant_id: str,
    correlation_id: str,
    trace_id: str,
    context_package_hash: str,
    context_retrieval_decision: str,
    attestation_decision: str,
    poisoning_scan_state: str,
    model_route_id: str,
    model_route_decision: str,
    egress_decision: str,
    handoff_decision: str,
    telemetry_event_id: str,
    telemetry_decision: str,
    receipt_id: str,
    source_ids: list[str] | None = None,
    source_hashes: list[str] | None = None,
    reuse_class: str = "same_run_context_replay",
    destination_class: str | None = None,
    target_tenant_id: str | None = None,
    contains_secret: bool = False,
    context_hash_mismatch: bool = False,
    identity_used_after_revocation: bool = False,
    prohibited_data_class: bool = False,
    token_passthrough: bool = False,
    runtime_kill_signal: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic allow, hold, deny, or kill decision for context lineage and reuse."""
    return secure_context_lineage_ledger.evaluate(
        {
            "agent_id": agent_id,
            "attestation_decision": attestation_decision,
            "contains_secret": contains_secret,
            "context_hash_mismatch": context_hash_mismatch,
            "context_package_hash": context_package_hash,
            "context_retrieval_decision": context_retrieval_decision,
            "correlation_id": correlation_id,
            "destination_class": destination_class,
            "egress_decision": egress_decision,
            "handoff_decision": handoff_decision,
            "identity_used_after_revocation": identity_used_after_revocation,
            "model_route_decision": model_route_decision,
            "model_route_id": model_route_id,
            "poisoning_scan_state": poisoning_scan_state,
            "prohibited_data_class": prohibited_data_class,
            "receipt_id": receipt_id,
            "reuse_class": reuse_class,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "source_hashes": source_hashes or [],
            "source_ids": source_ids or [],
            "target_tenant_id": target_tenant_id,
            "telemetry_decision": telemetry_decision,
            "telemetry_event_id": telemetry_event_id,
            "tenant_id": tenant_id,
            "token_passthrough": token_passthrough,
            "trace_id": trace_id,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_secure_context_eval_case(
    scenario_id: str,
    agent_id: str | None = None,
    run_id: str | None = None,
    answer_text: str | None = None,
    citations: list[dict[str, Any]] | None = None,
    observed_decisions: dict[str, Any] | None = None,
    handoff_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate one observed answer against the generated secure-context eval contract."""
    return secure_context_eval_pack.evaluate(
        {
            "agent_id": agent_id,
            "answer_text": answer_text,
            "citations": citations or [],
            "handoff_payload": handoff_payload or {},
            "observed_decisions": observed_decisions or {},
            "run_id": run_id,
            "scenario_id": scenario_id,
        }
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
async def recipes_evaluate_context_egress_decision(
    workflow_id: str,
    destination_class: str,
    data_class: str | None = None,
    source_id: str | None = None,
    mcp_namespace: str | None = None,
    tenant_id: str | None = None,
    destination_trust_tier: str | None = None,
    contains_secret: bool = False,
    contains_unredacted_pii: bool = False,
    dpa_in_place: bool = False,
    zero_data_retention: bool = False,
    residency_region: str | None = None,
    required_region: str | None = None,
    human_approval_record: dict[str, Any] | None = None,
    egress_path: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic allow, hold, deny, or kill decision before context egress."""
    return context_egress_boundary_pack.evaluate(
        {
            "contains_secret": contains_secret,
            "contains_unredacted_pii": contains_unredacted_pii,
            "data_class": data_class,
            "destination_class": destination_class,
            "destination_trust_tier": destination_trust_tier,
            "dpa_in_place": dpa_in_place,
            "egress_path": egress_path,
            "human_approval_record": human_approval_record,
            "mcp_namespace": mcp_namespace,
            "residency_region": residency_region,
            "required_region": required_region,
            "source_id": source_id,
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
            "zero_data_retention": zero_data_retention,
        }
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
async def recipes_evaluate_agentic_protocol_conformance_decision(
    protocol_id: str,
    workflow_id: str | None = None,
    agent_id: str | None = None,
    run_id: str | None = None,
    transport: str | None = "streamable-http",
    protocol_version_observed: str | None = None,
    resource_indicator_present: bool = False,
    token_audience_bound: bool = False,
    pkce_verified: bool = False,
    client_metadata_reviewed: bool = False,
    token_passthrough: bool = False,
    tool_annotations_trusted: bool = False,
    tool_surface_pinned: bool = False,
    schema_drift_detected: bool = False,
    private_data_access: bool = False,
    open_world_tool: bool = False,
    external_egress: bool = False,
    agent_card_present: bool = False,
    agent_card_signed: bool = False,
    extended_card_authenticated: bool = False,
    provider_identity_verified: bool = False,
    https_transport: bool = False,
    a2a_version_header: bool = False,
    untrusted_content_seen: bool = False,
    contains_secret: bool = False,
    runtime_kill_signal: bool = False,
    session_id: str | None = None,
    correlation_id: str | None = None,
    gateway_policy_hash: str | None = None,
    human_approval_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a deterministic protocol allow, hold, deny, or kill decision."""
    return protocol_conformance_pack.evaluate(
        {
            "a2a_version_header": a2a_version_header,
            "agent_card_present": agent_card_present,
            "agent_card_signed": agent_card_signed,
            "agent_id": agent_id,
            "client_metadata_reviewed": client_metadata_reviewed,
            "contains_secret": contains_secret,
            "correlation_id": correlation_id,
            "extended_card_authenticated": extended_card_authenticated,
            "external_egress": external_egress,
            "gateway_policy_hash": gateway_policy_hash,
            "human_approval_record": human_approval_record or {},
            "https_transport": https_transport,
            "open_world_tool": open_world_tool,
            "pkce_verified": pkce_verified,
            "private_data_access": private_data_access,
            "protocol_id": protocol_id,
            "protocol_version_observed": protocol_version_observed,
            "provider_identity_verified": provider_identity_verified,
            "resource_indicator_present": resource_indicator_present,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "schema_drift_detected": schema_drift_detected,
            "session_id": session_id,
            "token_audience_bound": token_audience_bound,
            "token_passthrough": token_passthrough,
            "tool_annotations_trusted": tool_annotations_trusted,
            "tool_surface_pinned": tool_surface_pinned,
            "transport": transport,
            "untrusted_content_seen": untrusted_content_seen,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_agentic_posture_decision(
    workflow_id: str,
    agent_id: str | None = None,
    mcp_namespace: str | None = None,
    risk_factor: str | None = None,
    autonomy_level: str = "bounded",
    indirect_prompt_injection_risk: str = "unknown",
    connector_status: str | None = None,
    human_approval_present: bool = False,
    contains_secret: bool = False,
    session_exfiltration_path: bool = False,
    unregistered_agent: bool = False,
) -> dict[str, Any]:
    """Return a deterministic posture decision before an agent crosses a high-risk path."""
    return posture_snapshot.evaluate(
        {
            "agent_id": agent_id,
            "autonomy_level": autonomy_level,
            "connector_status": connector_status,
            "contains_secret": contains_secret,
            "human_approval_present": human_approval_present,
            "indirect_prompt_injection_risk": indirect_prompt_injection_risk,
            "mcp_namespace": mcp_namespace,
            "risk_factor": risk_factor,
            "session_exfiltration_path": session_exfiltration_path,
            "unregistered_agent": unregistered_agent,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_agentic_app_intake_decision(
    app_id: str,
    owner: str | None = None,
    business_purpose: str | None = None,
    autonomy_level: str | None = None,
    deployment_environment: str | None = None,
    data_classes: list[str] | None = None,
    mcp_namespaces: list[str] | None = None,
    mcp_access_modes: list[str] | None = None,
    control_evidence: list[str] | None = None,
    requested_high_impact_actions: list[str] | None = None,
    indirect_prompt_injection_risk: str | None = None,
    telemetry_decision: str | None = None,
    egress_decision: str | None = None,
    authorization_decision: str | None = None,
    external_write: bool = False,
    production_write: bool = False,
    destructive_or_irreversible: bool = False,
    memory_persistence: str | None = None,
    a2a_or_remote_agent: bool = False,
    untrusted_input: bool = False,
    startup_or_package_install: bool = False,
    human_approval_record: dict[str, Any] | None = None,
    runtime_kill_signal: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic launch or expansion decision for an agentic app."""
    return app_intake_pack.evaluate(
        {
            "a2a_or_remote_agent": a2a_or_remote_agent,
            "app_id": app_id,
            "authorization_decision": authorization_decision,
            "autonomy_level": autonomy_level,
            "business_purpose": business_purpose,
            "control_evidence": control_evidence or [],
            "data_classes": data_classes or [],
            "deployment_environment": deployment_environment,
            "destructive_or_irreversible": destructive_or_irreversible,
            "egress_decision": egress_decision,
            "external_write": external_write,
            "human_approval_record": human_approval_record or {},
            "indirect_prompt_injection_risk": indirect_prompt_injection_risk,
            "mcp_access_modes": mcp_access_modes or [],
            "mcp_namespaces": mcp_namespaces or [],
            "memory_persistence": memory_persistence,
            "owner": owner,
            "production_write": production_write,
            "requested_high_impact_actions": requested_high_impact_actions or [],
            "runtime_kill_signal": runtime_kill_signal,
            "startup_or_package_install": startup_or_package_install,
            "telemetry_decision": telemetry_decision,
            "untrusted_input": untrusted_input,
        }
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
async def recipes_evaluate_model_provider_routing_decision(
    workflow_id: str,
    provider_id: str,
    model_id: str,
    route_class: str,
    route_id: str | None = None,
    data_classes: list[str] | None = None,
    autonomy_level: str = "assisted",
    tenant_id: str | None = None,
    tenant_region: str | None = None,
    provider_region: str | None = None,
    endpoint_url: str | None = None,
    egress_decision: str | None = None,
    zero_data_retention: bool = False,
    training_opt_out: bool = False,
    dpa_in_place: bool = False,
    enterprise_contract: bool = False,
    mcp_gateway_enforced: bool = False,
    tool_guardrails_enforced: bool = False,
    output_guardrails_enforced: bool = False,
    telemetry_redacted: bool = False,
    run_receipt_attached: bool = False,
    human_approval_record: dict[str, Any] | None = None,
    contains_secret: bool = False,
    contains_unredacted_pii: bool = False,
    cross_tenant_context: bool = False,
    untrusted_input: bool = False,
    tool_call_started: bool = False,
    high_impact_action: bool = False,
    runtime_kill_signal: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic model-provider route decision before a model call starts."""
    return model_provider_routing_pack.evaluate(
        {
            "autonomy_level": autonomy_level,
            "contains_secret": contains_secret,
            "contains_unredacted_pii": contains_unredacted_pii,
            "cross_tenant_context": cross_tenant_context,
            "data_classes": data_classes or [],
            "dpa_in_place": dpa_in_place,
            "egress_decision": egress_decision,
            "endpoint_url": endpoint_url,
            "enterprise_contract": enterprise_contract,
            "high_impact_action": high_impact_action,
            "human_approval_record": human_approval_record or {},
            "mcp_gateway_enforced": mcp_gateway_enforced,
            "model_id": model_id,
            "output_guardrails_enforced": output_guardrails_enforced,
            "provider_id": provider_id,
            "provider_region": provider_region,
            "route_class": route_class,
            "route_id": route_id,
            "run_receipt_attached": run_receipt_attached,
            "runtime_kill_signal": runtime_kill_signal,
            "telemetry_redacted": telemetry_redacted,
            "tenant_id": tenant_id,
            "tenant_region": tenant_region,
            "tool_call_started": tool_call_started,
            "tool_guardrails_enforced": tool_guardrails_enforced,
            "training_opt_out": training_opt_out,
            "untrusted_input": untrusted_input,
            "workflow_id": workflow_id,
            "zero_data_retention": zero_data_retention,
        }
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
async def recipes_evaluate_agentic_catastrophic_risk_decision(
    workflow_id: str,
    action_class: str,
    agent_id: str | None = None,
    run_id: str | None = None,
    identity_id: str | None = None,
    tenant_id: str | None = None,
    impact_domain: str | None = None,
    policy_pack_hash: str | None = None,
    authorization_decision: str | None = None,
    context_package_hash: str | None = None,
    egress_decision: str | None = None,
    handoff_decision: str | None = None,
    readiness_decision: str | None = None,
    human_approval_record: dict[str, Any] | None = None,
    risk_acceptance_id: str | None = None,
    receipt_id: str | None = None,
    correlation_id: str | None = None,
    residual_risk_tier: str | None = None,
    runtime_kill_signal: str | None = None,
    observed_loop_count: int = 0,
    max_loop_count: int = 3,
    affects_prod: bool = False,
    affects_many_tenants: bool = False,
    can_move_funds: bool = False,
    can_modify_identity: bool = False,
    can_delete_data: bool = False,
    can_deploy: bool = False,
    writes_public_corpus: bool = False,
    handles_secrets: bool = False,
    handles_unredacted_pii: bool = False,
    external_side_effect: bool = False,
) -> dict[str, Any]:
    """Return a deterministic allow, hold, deny, or kill decision for high-impact autonomy."""
    return catastrophic_risk_annex.evaluate(
        {
            "action_class": action_class,
            "affects_many_tenants": affects_many_tenants,
            "affects_prod": affects_prod,
            "agent_id": agent_id,
            "authorization_decision": authorization_decision,
            "can_delete_data": can_delete_data,
            "can_deploy": can_deploy,
            "can_modify_identity": can_modify_identity,
            "can_move_funds": can_move_funds,
            "context_package_hash": context_package_hash,
            "correlation_id": correlation_id,
            "egress_decision": egress_decision,
            "external_side_effect": external_side_effect,
            "handoff_decision": handoff_decision,
            "handles_secrets": handles_secrets,
            "handles_unredacted_pii": handles_unredacted_pii,
            "human_approval_record": human_approval_record,
            "identity_id": identity_id,
            "impact_domain": impact_domain,
            "max_loop_count": max_loop_count,
            "observed_loop_count": observed_loop_count,
            "policy_pack_hash": policy_pack_hash,
            "readiness_decision": readiness_decision,
            "receipt_id": receipt_id,
            "residual_risk_tier": residual_risk_tier,
            "risk_acceptance_id": risk_acceptance_id,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
            "writes_public_corpus": writes_public_corpus,
        }
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
async def recipes_evaluate_agentic_incident_response_decision(
    incident_id: str,
    workflow_id: str,
    run_id: str,
    agent_id: str,
    identity_id: str,
    tenant_id: str,
    correlation_id: str,
    incident_class_id: str,
    severity_signal: str | None = None,
    source_event_ids: list[str] | None = None,
    receipt_id: str | None = None,
    context_source_ids: list[str] | None = None,
    context_source_hashes: list[str] | None = None,
    mcp_namespaces: list[str] | None = None,
    authorization_decisions: list[str] | None = None,
    egress_decisions: list[str] | None = None,
    handoff_decisions: list[str] | None = None,
    affected_data_classes: list[str] | None = None,
    indicators: list[str] | None = None,
    containment_action_ids: list[str] | None = None,
    replay_case_ids: list[str] | None = None,
    customer_impact_state: str | None = None,
    externalized_context: bool = False,
    production_write: bool = False,
    token_passthrough: bool = False,
    identity_used_after_revocation: bool = False,
    customer_impact_confirmed: bool = False,
    runtime_kill_signal: str | None = None,
    human_approval_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a deterministic monitor, triage, hold, contain, or kill decision for an agentic incident."""
    return incident_response_pack.evaluate(
        {
            "affected_data_classes": affected_data_classes or [],
            "agent_id": agent_id,
            "authorization_decisions": authorization_decisions or [],
            "containment_action_ids": containment_action_ids or [],
            "context_source_hashes": context_source_hashes or [],
            "context_source_ids": context_source_ids or [],
            "correlation_id": correlation_id,
            "customer_impact_confirmed": customer_impact_confirmed,
            "customer_impact_state": customer_impact_state,
            "egress_decisions": egress_decisions or [],
            "externalized_context": externalized_context,
            "handoff_decisions": handoff_decisions or [],
            "human_approval_record": human_approval_record,
            "identity_id": identity_id,
            "identity_used_after_revocation": identity_used_after_revocation,
            "incident_class_id": incident_class_id,
            "incident_id": incident_id,
            "indicators": indicators or [],
            "mcp_namespaces": mcp_namespaces or [],
            "production_write": production_write,
            "receipt_id": receipt_id,
            "replay_case_ids": replay_case_ids or [],
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "severity_signal": severity_signal,
            "source_event_ids": source_event_ids or [],
            "tenant_id": tenant_id,
            "token_passthrough": token_passthrough,
            "workflow_id": workflow_id,
        }
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
async def recipes_evaluate_agentic_action_runtime_decision(
    workflow_id: str,
    action_class: str,
    run_id: str,
    agent_id: str,
    identity_id: str,
    tenant_id: str,
    correlation_id: str,
    intent_summary: str,
    policy_pack_hash: str,
    authorization_decision: str,
    receipt_id: str,
    context_package_hash: str | None = None,
    egress_decision: str | None = None,
    handoff_decision: str | None = None,
    telemetry_decision: str | None = None,
    catastrophic_risk_decision: str | None = None,
    telemetry_event_id: str | None = None,
    human_approval_record: dict[str, Any] | None = None,
    risk_acceptance_id: str | None = None,
    runtime_kill_signal: str | None = None,
    indicators: list[str] | None = None,
    mcp_namespaces: list[str] | None = None,
    requested_capabilities: list[str] | None = None,
    changed_paths: list[str] | None = None,
    data_classes: list[str] | None = None,
    affects_prod: bool = False,
    affects_many_tenants: bool = False,
    can_delete_data: bool = False,
    can_deploy: bool = False,
    can_modify_identity: bool = False,
    can_move_funds: bool = False,
    contains_secret: bool = False,
    external_side_effect: bool = False,
    identity_used_after_revocation: bool = False,
    persistent_memory_write: bool = False,
    repeated_denied_action: bool = False,
    skill_or_tool_install: bool = False,
    token_passthrough: bool = False,
    writes_public_corpus: bool = False,
) -> dict[str, Any]:
    """Return a deterministic allow, hold, deny, or kill decision before an agent action executes."""
    return action_runtime_pack.evaluate(
        {
            "action_class": action_class,
            "affects_many_tenants": affects_many_tenants,
            "affects_prod": affects_prod,
            "agent_id": agent_id,
            "authorization_decision": authorization_decision,
            "can_delete_data": can_delete_data,
            "can_deploy": can_deploy,
            "can_modify_identity": can_modify_identity,
            "can_move_funds": can_move_funds,
            "catastrophic_risk_decision": catastrophic_risk_decision,
            "changed_paths": changed_paths or [],
            "contains_secret": contains_secret,
            "context_package_hash": context_package_hash,
            "correlation_id": correlation_id,
            "data_classes": data_classes or [],
            "egress_decision": egress_decision,
            "external_side_effect": external_side_effect,
            "handoff_decision": handoff_decision,
            "human_approval_record": human_approval_record,
            "identity_id": identity_id,
            "identity_used_after_revocation": identity_used_after_revocation,
            "indicators": indicators or [],
            "intent_summary": intent_summary,
            "mcp_namespaces": mcp_namespaces or [],
            "persistent_memory_write": persistent_memory_write,
            "policy_pack_hash": policy_pack_hash,
            "receipt_id": receipt_id,
            "repeated_denied_action": repeated_denied_action,
            "requested_capabilities": requested_capabilities or [],
            "risk_acceptance_id": risk_acceptance_id,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "skill_or_tool_install": skill_or_tool_install,
            "telemetry_decision": telemetry_decision,
            "telemetry_event_id": telemetry_event_id,
            "tenant_id": tenant_id,
            "token_passthrough": token_passthrough,
            "workflow_id": workflow_id,
            "writes_public_corpus": writes_public_corpus,
        }
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
async def recipes_evaluate_browser_agent_boundary_decision(
    workspace_class_id: str,
    task_profile_id: str,
    session_id: str,
    run_id: str,
    agent_id: str,
    tenant_id: str,
    user_intent: str,
    target_origin: str,
    content_trust_level: str,
    auth_state: str,
    isolation_mode: str,
    action_classes: list[str],
    data_classes: list[str],
    network_egress_policy: str,
    browser_storage_policy: str,
    approval_state: str,
    telemetry_event_id: str,
    receipt_id: str,
    controls: list[str] | None = None,
    indicators: list[str] | None = None,
    human_approval_record: dict[str, Any] | None = None,
    runtime_kill_signal: str | None = None,
    admin_console_write: bool = False,
    ambient_cookies_available: bool = False,
    contains_secret: bool = False,
    cross_origin_egress: bool = False,
    dom_credential_visible: bool = False,
    downloads_file: bool = False,
    executes_code: bool = False,
    external_side_effect: bool = False,
    hidden_instruction_detected: bool = False,
    localhost_access: bool = False,
    localhost_probe: bool = False,
    local_storage_token: bool = False,
    payment_or_purchase: bool = False,
    persistent_memory_write: bool = False,
    prompt_injection_signal: bool = False,
    sends_external_message: bool = False,
    uses_personal_profile: bool = False,
) -> dict[str, Any]:
    """Return a deterministic browser-agent workspace allow, hold, deny, or kill decision."""
    return browser_agent_boundary_pack.evaluate(
        {
            "action_classes": action_classes,
            "admin_console_write": admin_console_write,
            "agent_id": agent_id,
            "ambient_cookies_available": ambient_cookies_available,
            "approval_state": approval_state,
            "auth_state": auth_state,
            "browser_storage_policy": browser_storage_policy,
            "contains_secret": contains_secret,
            "content_trust_level": content_trust_level,
            "controls": controls or [],
            "cross_origin_egress": cross_origin_egress,
            "data_classes": data_classes,
            "dom_credential_visible": dom_credential_visible,
            "downloads_file": downloads_file,
            "executes_code": executes_code,
            "external_side_effect": external_side_effect,
            "hidden_instruction_detected": hidden_instruction_detected,
            "human_approval_record": human_approval_record,
            "indicators": indicators or [],
            "isolation_mode": isolation_mode,
            "localhost_access": localhost_access,
            "localhost_probe": localhost_probe,
            "local_storage_token": local_storage_token,
            "network_egress_policy": network_egress_policy,
            "payment_or_purchase": payment_or_purchase,
            "persistent_memory_write": persistent_memory_write,
            "prompt_injection_signal": prompt_injection_signal,
            "receipt_id": receipt_id,
            "run_id": run_id,
            "runtime_kill_signal": runtime_kill_signal,
            "sends_external_message": sends_external_message,
            "session_id": session_id,
            "target_origin": target_origin,
            "task_profile_id": task_profile_id,
            "telemetry_event_id": telemetry_event_id,
            "tenant_id": tenant_id,
            "user_intent": user_intent,
            "uses_personal_profile": uses_personal_profile,
            "workspace_class_id": workspace_class_id,
        }
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
async def recipes_evaluate_agentic_telemetry_event(
    workflow_id: str,
    event_class: str,
    attributes: dict[str, Any],
    argument_capture: str = "absent",
    result_capture: str = "absent",
    contains_secret: bool = False,
) -> dict[str, Any]:
    """Return a telemetry_ready, hold, deny, or kill decision for one runtime trace event."""
    return telemetry_contract.evaluate(
        {
            "argument_capture": argument_capture,
            "attributes": attributes,
            "contains_secret": contains_secret,
            "event_class": event_class,
            "result_capture": result_capture,
            "workflow_id": workflow_id,
        }
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
async def recipes_match_finding(
    cve: str | None = None,
    package: str | None = None,
    ecosystem: str | None = None,
    rule_id: str | None = None,
    keywords: list[str] | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    """Heuristic matcher that suggests best-fit recipes for a security finding."""
    parts = [cve, package, ecosystem, rule_id]
    if keywords:
        parts.extend(keywords)
    query = " ".join([p for p in parts if p])
    if not query:
        return {"query": "", "count": 0, "results": []}

    results = await index.search(query=query, limit=limit)
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
    # Validate config and do an eager refresh to fail fast if misconfigured.
    asyncio.run(index.refresh(force=False))
    run_mcp_server()


if __name__ == "__main__":
    main()
