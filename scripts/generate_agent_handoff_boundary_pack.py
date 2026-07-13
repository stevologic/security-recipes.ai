#!/usr/bin/env python3
"""Generate the SecurityRecipes agent handoff boundary pack.

The pack sits between secure context retrieval and multi-agent
coordination. It turns A2A/MCP/provider-native handoffs into a
machine-readable decision surface: what may cross, which protocols are
approved, which fields are forbidden, when approval is needed, and what
evidence proves the boundary is current.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_MODEL = Path("data/assurance/agent-handoff-boundary-model.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_IDENTITY_LEDGER = Path("data/evidence/agent-identity-delegation-ledger.json")
DEFAULT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_EGRESS_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_THREAT_RADAR = Path("data/evidence/agentic-threat-radar.json")
DEFAULT_OUTPUT = Path("data/evidence/agent-handoff-boundary-pack.json")

REQUIRED_DECISIONS = {
    "allow_metadata_handoff",
    "allow_cited_evidence_handoff",
    "allow_approved_handoff",
    "hold_for_redaction_or_approval",
    "deny_untrusted_agent_handoff",
    "deny_unregistered_handoff",
    "kill_session_on_secret_handoff",
}
REQUIRED_PROTOCOLS = {
    "mcp_tool_call",
    "a2a_task_delegation",
    "provider_native_subagent",
    "human_approval_bridge",
}
REQUIRED_PROFILES = {
    "metadata-only",
    "cited-evidence",
    "approval-gated",
    "prohibited-context",
}


class AgentHandoffBoundaryPackError(RuntimeError):
    """Raised when the handoff boundary pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgentHandoffBoundaryPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AgentHandoffBoundaryPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AgentHandoffBoundaryPackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentHandoffBoundaryPackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AgentHandoffBoundaryPackError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def index_by(rows: Any, key: str) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get(key)): row
        for row in rows
        if isinstance(row, dict) and row.get(key)
    }


def validate_model(model: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(model.get("schema_version") == "1.0", failures, "model schema_version must be 1.0")
    require(len(str(model.get("intent", ""))) >= 100, failures, "model intent must explain the product goal")

    standards = as_list(model.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include current agent, MCP, A2A, and security references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"{standard_id}: duplicated standard id")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 50, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(model.get("decision_contract"), "decision_contract")
    require(contract.get("default_state") == "deny_unregistered_handoff", failures, "decision_contract must fail closed")
    decisions = {
        str(item.get("decision"))
        for item in as_list(contract.get("decisions"), "decision_contract.decisions")
        if isinstance(item, dict)
    }
    require(REQUIRED_DECISIONS.issubset(decisions), failures, "decision_contract must declare every runtime decision")
    require(len(as_list(contract.get("runtime_fields"), "decision_contract.runtime_fields")) >= 12, failures, "runtime_fields are incomplete")
    require(len(as_list(contract.get("prohibited_payload_fields"), "decision_contract.prohibited_payload_fields")) >= 8, failures, "prohibited payload fields are incomplete")
    require(len(as_list(contract.get("high_impact_capabilities"), "decision_contract.high_impact_capabilities")) >= 5, failures, "high-impact capabilities are incomplete")

    protocols = as_list(model.get("protocol_surfaces"), "protocol_surfaces")
    protocol_ids = {str(item.get("id")) for item in protocols if isinstance(item, dict)}
    require(REQUIRED_PROTOCOLS.issubset(protocol_ids), failures, "protocol_surfaces must include MCP, A2A, provider-native, and human approval bridges")
    for idx, protocol in enumerate(protocols):
        item = as_dict(protocol, f"protocol_surfaces[{idx}]")
        protocol_id = str(item.get("id", "")).strip()
        require(bool(protocol_id), failures, f"protocol_surfaces[{idx}].id is required")
        require(len(as_list(item.get("required_controls"), f"{protocol_id}.required_controls")) >= 3, failures, f"{protocol_id}: required_controls are incomplete")
        require(bool(as_list(item.get("allowed_target_trust_tiers"), f"{protocol_id}.allowed_target_trust_tiers")), failures, f"{protocol_id}: target trust tiers are required")

    profiles = as_list(model.get("handoff_profiles"), "handoff_profiles")
    profile_ids = {str(item.get("id")) for item in profiles if isinstance(item, dict)}
    require(REQUIRED_PROFILES.issubset(profile_ids), failures, "handoff_profiles must include metadata, evidence, approval, and prohibited profiles")
    for idx, profile in enumerate(profiles):
        item = as_dict(profile, f"handoff_profiles[{idx}]")
        profile_id = str(item.get("id", "")).strip()
        require(bool(profile_id), failures, f"handoff_profiles[{idx}].id is required")
        if profile_id != "prohibited-context":
            require(bool(as_list(item.get("allowed_protocols"), f"{profile_id}.allowed_protocols")), failures, f"{profile_id}: allowed_protocols are required")
            require(bool(as_list(item.get("required_payload_fields"), f"{profile_id}.required_payload_fields")), failures, f"{profile_id}: required payload fields are required")
            require(bool(as_list(item.get("allowed_payload_fields"), f"{profile_id}.allowed_payload_fields")), failures, f"{profile_id}: allowed payload fields are required")
            require(bool(as_list(item.get("allowed_data_classes"), f"{profile_id}.allowed_data_classes")), failures, f"{profile_id}: allowed data classes are required")
    return failures


def validate_source_packs(
    *,
    manifest: dict[str, Any],
    identity_ledger: dict[str, Any],
    trust_pack: dict[str, Any],
    egress_pack: dict[str, Any],
    threat_radar: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    require(manifest.get("schema_version") == "1.0", failures, "workflow manifest schema_version must be 1.0")
    require(identity_ledger.get("schema_version") == "1.0", failures, "identity ledger schema_version must be 1.0")
    require(trust_pack.get("schema_version") == "1.0", failures, "secure context trust pack schema_version must be 1.0")
    require(egress_pack.get("schema_version") == "1.0", failures, "context egress pack schema_version must be 1.0")
    require(threat_radar.get("schema_version") == "1.0", failures, "threat radar schema_version must be 1.0")
    require(bool(manifest.get("workflows")), failures, "workflow manifest must include workflows")
    require(bool(identity_ledger.get("agent_identities")), failures, "identity ledger must include agent identities")
    require(bool(trust_pack.get("workflow_context_map")), failures, "trust pack must include workflow_context_map")
    require(bool(egress_pack.get("workflow_egress_map")), failures, "egress pack must include workflow_egress_map")
    require(bool(threat_radar.get("threat_signals")), failures, "threat radar must include threat_signals")
    return failures


def build_protocol_surfaces(model: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for protocol in as_list(model.get("protocol_surfaces"), "protocol_surfaces"):
        if not isinstance(protocol, dict):
            continue
        rows.append(
            {
                "allowed_target_trust_tiers": protocol.get("allowed_target_trust_tiers", []),
                "description": protocol.get("description"),
                "protocol_hash": stable_hash(protocol),
                "protocol_id": protocol.get("id"),
                "required_controls": protocol.get("required_controls", []),
                "title": protocol.get("title"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("protocol_id")))


def profile_decision(profile_id: str) -> str:
    if profile_id == "metadata-only":
        return "allow_metadata_handoff"
    if profile_id == "cited-evidence":
        return "allow_cited_evidence_handoff"
    if profile_id == "approval-gated":
        return "allow_approved_handoff"
    return "kill_session_on_secret_handoff"


def build_handoff_profiles(model: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for profile in as_list(model.get("handoff_profiles"), "handoff_profiles"):
        if not isinstance(profile, dict):
            continue
        profile_id = str(profile.get("id"))
        rows.append(
            {
                "allowed_data_classes": profile.get("allowed_data_classes", []),
                "allowed_payload_fields": profile.get("allowed_payload_fields", []),
                "allowed_protocols": profile.get("allowed_protocols", []),
                "default_decision": profile_decision(profile_id),
                "description": profile.get("description"),
                "profile_hash": stable_hash(profile),
                "profile_id": profile_id,
                "required_controls": profile.get("required_controls", []),
                "required_payload_fields": profile.get("required_payload_fields", []),
                "risk_tier": profile.get("risk_tier"),
                "title": profile.get("title"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("profile_id")))


def build_workflow_handoff_map(
    *,
    manifest: dict[str, Any],
    identity_ledger: dict[str, Any],
    trust_pack: dict[str, Any],
    egress_pack: dict[str, Any],
) -> list[dict[str, Any]]:
    context_by_workflow = index_by(trust_pack.get("workflow_context_map"), "workflow_id")
    egress_by_workflow = index_by(egress_pack.get("workflow_egress_map"), "workflow_id")
    identities_by_workflow: dict[str, list[dict[str, Any]]] = {}
    for identity in identity_ledger.get("agent_identities", []) or []:
        if not isinstance(identity, dict):
            continue
        workflow_id = str(identity.get("workflow_id") or "")
        if not workflow_id:
            continue
        identities_by_workflow.setdefault(workflow_id, []).append(identity)

    rows: list[dict[str, Any]] = []
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        if not isinstance(workflow, dict):
            continue
        workflow_id = str(workflow.get("id"))
        identities = identities_by_workflow.get(workflow_id, [])
        context_package = context_by_workflow.get(workflow_id, {})
        egress_policy = egress_by_workflow.get(workflow_id, {})
        profiles = ["metadata-only", "cited-evidence"]
        if any(
            str(namespace.get("access_mode") or namespace.get("access")) == "approval_required"
            for namespace in workflow.get("mcp_context", []) or []
            if isinstance(namespace, dict)
        ):
            profiles.append("approval-gated")
        rows.append(
            {
                "agent_classes": sorted({str(identity.get("agent_class")) for identity in identities if identity.get("agent_class")}),
                "approved_profile_ids": profiles,
                "context_package_hash": context_package.get("context_package_hash"),
                "default_decision": "deny_unregistered_handoff",
                "egress_policy_hash": egress_policy.get("egress_policy_hash") or egress_policy.get("policy_hash") or egress_policy.get("workflow_egress_hash"),
                "identity_ids": [identity.get("identity_id") for identity in identities if identity.get("identity_id")],
                "maturity_stage": workflow.get("maturity_stage"),
                "public_path": workflow.get("public_path"),
                "required_runtime_evidence": [
                    "workflow_id",
                    "run_id",
                    "source_agent_id",
                    "target_agent_class",
                    "handoff_profile_id",
                    "protocol",
                    "payload_fields",
                    "source_hashes",
                    "correlation_id"
                ],
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return sorted(rows, key=lambda row: str(row.get("workflow_id")))


def build_threat_signal_coverage(threat_radar: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for signal in threat_radar.get("threat_signals", []) or []:
        if not isinstance(signal, dict):
            continue
        mapped = {str(item) for item in signal.get("mapped_capability_ids", []) or []}
        if {
            "agent-handoff-boundary-pack",
            "agent-identity-ledger",
            "context-egress-boundary",
            "secure-context-trust-pack",
            "mcp-authorization-conformance",
        } & mapped:
            rows.append(
                {
                    "priority": signal.get("priority"),
                    "signal_id": signal.get("id"),
                    "strategic_score": signal.get("strategic_score"),
                    "title": signal.get("title"),
                }
            )
    return sorted(rows, key=lambda row: str(row.get("signal_id")))


def build_pack(
    *,
    model: dict[str, Any],
    manifest: dict[str, Any],
    identity_ledger: dict[str, Any],
    trust_pack: dict[str, Any],
    egress_pack: dict[str, Any],
    threat_radar: dict[str, Any],
    paths: dict[str, Path],
    refs: dict[str, Path],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    protocol_rows = build_protocol_surfaces(model)
    profile_rows = build_handoff_profiles(model)
    workflow_rows = build_workflow_handoff_map(
        manifest=manifest,
        identity_ledger=identity_ledger,
        trust_pack=trust_pack,
        egress_pack=egress_pack,
    )
    risk_counts = Counter(str(profile.get("risk_tier")) for profile in profile_rows)
    profile_decision_counts = Counter(str(profile.get("default_decision")) for profile in profile_rows)

    return {
        "schema_version": PACK_SCHEMA_VERSION,
        "generated_at": generated_at or str(model.get("last_reviewed", "")),
        "intent": model.get("intent"),
        "positioning": model.get("positioning", {}),
        "standards_alignment": model.get("standards_alignment", []),
        "decision_contract": model.get("decision_contract", {}),
        "protocol_surfaces": protocol_rows,
        "handoff_profiles": profile_rows,
        "workflow_handoff_map": workflow_rows,
        "handoff_boundary_summary": {
            "default_state": model.get("decision_contract", {}).get("default_state"),
            "failure_count": len(failures),
            "profile_count": len(profile_rows),
            "profile_decision_counts": dict(sorted(profile_decision_counts.items())),
            "protocol_count": len(protocol_rows),
            "risk_tier_counts": dict(sorted(risk_counts.items())),
            "workflow_count": len(workflow_rows),
        },
        "enterprise_adoption_packet": model.get("enterprise_adoption_packet", {}),
        "threat_signal_coverage": build_threat_signal_coverage(threat_radar),
        "source_artifacts": {
            name: {
                "path": normalize_path(refs[name]),
                "sha256": sha256_file(paths[name]),
            }
            for name in sorted(paths)
        },
        "residual_risks": [
            {
                "risk": "The open pack cannot prove a customer remote agent actually enforces its advertised Agent Card.",
                "treatment": "Production deployments should add signed Agent Cards, tenant-side allowlists, gateway telemetry, and replayable handoff receipts."
            },
            {
                "risk": "A metadata-only handoff can still be misinterpreted by a capable remote agent.",
                "treatment": "Keep handoff payloads structured, preserve source hashes, attach policy decisions, and run agent-specific eval replay before trust-tier promotion."
            },
            {
                "risk": "A2A, MCP, and provider-native orchestration can compose into longer chains than one gateway can inspect.",
                "treatment": "Propagate correlation IDs, require per-hop boundary decisions, and deny handoffs that omit prior hop evidence."
            }
        ],
        "failures": failures,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--identity-ledger", type=Path, default=DEFAULT_IDENTITY_LEDGER)
    parser.add_argument("--trust-pack", type=Path, default=DEFAULT_TRUST_PACK)
    parser.add_argument("--egress-pack", type=Path, default=DEFAULT_EGRESS_PACK)
    parser.add_argument("--threat-radar", type=Path, default=DEFAULT_THREAT_RADAR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in handoff pack is stale.")
    parser.add_argument(
        "--update-if-stale",
        action="store_true",
        help="With --check, refresh the generated pack instead of failing when only the output is stale.",
    )
    return parser.parse_args()


def should_update_stale_output(args: argparse.Namespace) -> bool:
    return bool(args.update_if_stale) and bool(args.check)


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    model_path = resolve(repo_root, args.model)
    manifest_path = resolve(repo_root, args.manifest)
    identity_path = resolve(repo_root, args.identity_ledger)
    trust_path = resolve(repo_root, args.trust_pack)
    egress_path = resolve(repo_root, args.egress_pack)
    threat_path = resolve(repo_root, args.threat_radar)
    output_path = resolve(repo_root, args.output)

    try:
        model = load_json(model_path)
        manifest = load_json(manifest_path)
        identity_ledger = load_json(identity_path)
        trust_pack = load_json(trust_path)
        egress_pack = load_json(egress_path)
        threat_radar = load_json(threat_path)
        failures = [
            *validate_model(model),
            *validate_source_packs(
                manifest=manifest,
                identity_ledger=identity_ledger,
                trust_pack=trust_pack,
                egress_pack=egress_pack,
                threat_radar=threat_radar,
            ),
        ]
        pack = build_pack(
            model=model,
            manifest=manifest,
            identity_ledger=identity_ledger,
            trust_pack=trust_pack,
            egress_pack=egress_pack,
            threat_radar=threat_radar,
            paths={
                "agent_handoff_boundary_model": model_path,
                "agent_identity_ledger": identity_path,
                "agentic_threat_radar": threat_path,
                "context_egress_boundary_pack": egress_path,
                "secure_context_trust_pack": trust_path,
                "workflow_manifest": manifest_path,
            },
            refs={
                "agent_handoff_boundary_model": args.model,
                "agent_identity_ledger": args.identity_ledger,
                "agentic_threat_radar": args.threat_radar,
                "context_egress_boundary_pack": args.egress_pack,
                "secure_context_trust_pack": args.trust_pack,
                "workflow_manifest": args.manifest,
            },
            generated_at=args.generated_at,
            failures=failures,
        )
    except AgentHandoffBoundaryPackError as exc:
        print(f"agent handoff boundary pack error: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if not output_path.exists():
            if should_update_stale_output(args):
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(rendered, encoding="utf-8")
            else:
                print(f"{output_path} does not exist", file=sys.stderr)
                return 1
        existing = output_path.read_text(encoding="utf-8")
        if existing != rendered:
            if should_update_stale_output(args):
                output_path.write_text(rendered, encoding="utf-8")
            else:
                print(f"{output_path} is stale; regenerate agent handoff boundary pack", file=sys.stderr)
                return 1
        if failures:
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        print(f"Validated agent handoff boundary pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Wrote agent handoff boundary pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
