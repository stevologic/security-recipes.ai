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
    from scripts.evaluate_agent_skill_supply_chain_decision import evaluate_agent_skill_supply_chain_decision
    from scripts.evaluate_agent_memory_boundary_decision import evaluate_agent_memory_boundary_decision
    from scripts.evaluate_context_egress_decision import evaluate_context_egress_decision
    from scripts.evaluate_mcp_authorization_decision import evaluate_mcp_authorization_decision
    from scripts.evaluate_mcp_gateway_decision import evaluate_policy_decision
    from scripts.evaluate_secure_context_retrieval import evaluate_context_retrieval_decision
except ImportError:  # pragma: no cover - supports direct script-directory execution.
    from evaluate_agent_skill_supply_chain_decision import evaluate_agent_skill_supply_chain_decision
    from evaluate_agent_memory_boundary_decision import evaluate_agent_memory_boundary_decision
    from evaluate_context_egress_decision import evaluate_context_egress_decision
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
    connector_trust_pack_path: str = os.environ.get(
        "RECIPES_MCP_CONNECTOR_TRUST_PACK_PATH",
        "./data/evidence/mcp-connector-trust-pack.json",
    )
    connector_intake_pack_path: str = os.environ.get(
        "RECIPES_MCP_CONNECTOR_INTAKE_PACK_PATH",
        "./data/evidence/mcp-connector-intake-pack.json",
    )
    authorization_conformance_pack_path: str = os.environ.get(
        "RECIPES_MCP_AUTHORIZATION_CONFORMANCE_PACK_PATH",
        "./data/evidence/mcp-authorization-conformance-pack.json",
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
    measurement_probe_pack_path: str = os.environ.get(
        "RECIPES_MCP_MEASUREMENT_PROBE_PACK_PATH",
        "./data/evidence/agentic-measurement-probe-pack.json",
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
    cfg.connector_trust_pack_path = data.get(
        "connector_trust_pack_path",
        cfg.connector_trust_pack_path,
    )
    cfg.connector_intake_pack_path = data.get(
        "connector_intake_pack_path",
        cfg.connector_intake_pack_path,
    )
    cfg.authorization_conformance_pack_path = data.get(
        "authorization_conformance_pack_path",
        cfg.authorization_conformance_pack_path,
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
    cfg.context_poisoning_guard_pack_path = data.get(
        "context_poisoning_guard_pack_path",
        cfg.context_poisoning_guard_pack_path,
    )
    cfg.context_egress_boundary_pack_path = data.get(
        "context_egress_boundary_pack_path",
        cfg.context_egress_boundary_pack_path,
    )
    cfg.threat_radar_path = data.get("threat_radar_path", cfg.threat_radar_path)
    cfg.measurement_probe_pack_path = data.get(
        "measurement_probe_pack_path",
        cfg.measurement_probe_pack_path,
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
connector_trust_pack = MCPConnectorTrustPack(config.connector_trust_pack_path)
connector_intake_pack = MCPConnectorIntakePack(config.connector_intake_pack_path)
authorization_conformance_pack = MCPAuthorizationConformancePack(config.authorization_conformance_pack_path)
red_team_drill_pack = AgenticRedTeamDrillPack(config.red_team_drill_pack_path)
readiness_scorecard = AgenticReadinessScorecard(config.readiness_scorecard_path)
capability_risk_register = AgentCapabilityRiskRegister(config.capability_risk_register_path)
agent_memory_boundary_pack = AgentMemoryBoundaryPack(config.agent_memory_boundary_pack_path)
agent_skill_supply_chain_pack = AgentSkillSupplyChainPack(config.agent_skill_supply_chain_pack_path)
agentic_system_bom = AgenticSystemBOM(config.agentic_system_bom_path)
agentic_run_receipt_pack = AgenticRunReceiptPack(config.agentic_run_receipt_pack_path)
secure_context_trust_pack = SecureContextTrustPack(config.secure_context_trust_pack_path)
context_poisoning_guard_pack = ContextPoisoningGuardPack(config.context_poisoning_guard_pack_path)
context_egress_boundary_pack = ContextEgressBoundaryPack(config.context_egress_boundary_pack_path)
threat_radar = AgenticThreatRadar(config.threat_radar_path)
measurement_probe_pack = AgenticMeasurementProbePack(config.measurement_probe_pack_path)
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
        "connector_trust_pack_path": config.connector_trust_pack_path,
        "connector_intake_pack_path": config.connector_intake_pack_path,
        "authorization_conformance_pack_path": config.authorization_conformance_pack_path,
        "red_team_drill_pack_path": config.red_team_drill_pack_path,
        "readiness_scorecard_path": config.readiness_scorecard_path,
        "capability_risk_register_path": config.capability_risk_register_path,
        "agent_memory_boundary_pack_path": config.agent_memory_boundary_pack_path,
        "agent_skill_supply_chain_pack_path": config.agent_skill_supply_chain_pack_path,
        "agentic_system_bom_path": config.agentic_system_bom_path,
        "agentic_run_receipt_pack_path": config.agentic_run_receipt_pack_path,
        "secure_context_trust_pack_path": config.secure_context_trust_pack_path,
        "context_poisoning_guard_pack_path": config.context_poisoning_guard_pack_path,
        "context_egress_boundary_pack_path": config.context_egress_boundary_pack_path,
        "threat_radar_path": config.threat_radar_path,
        "measurement_probe_pack_path": config.measurement_probe_pack_path,
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
