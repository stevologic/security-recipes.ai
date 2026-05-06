#!/usr/bin/env python3
"""Generate the SecurityRecipes hosted MCP readiness pack.

The pack turns the current open evidence corpus into a concrete hosted
MCP product-readiness plan. It is deliberately conservative: the public
repo proves the reference layer, while tenant isolation, private evidence
ingestion, signed receipts, metering, and operational SLOs remain explicit
runtime gates before production hosted claims are credible.
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
DEFAULT_PROFILE = Path("data/assurance/hosted-mcp-readiness-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/hosted-mcp-readiness-pack.json")
DEFAULT_SOURCE_PACKS: dict[str, Path] = {
    "agentic_app_intake_pack": Path("data/evidence/agentic-app-intake-pack.json"),
    "agentic_run_receipt_pack": Path("data/evidence/agentic-run-receipt-pack.json"),
    "agentic_soc_detection_pack": Path("data/evidence/agentic-soc-detection-pack.json"),
    "agentic_source_freshness_watch": Path("data/evidence/agentic-source-freshness-watch.json"),
    "agentic_telemetry_contract": Path("data/evidence/agentic-telemetry-contract.json"),
    "context_egress_boundary_pack": Path("data/evidence/context-egress-boundary-pack.json"),
    "enterprise_trust_center_export": Path("data/evidence/enterprise-trust-center-export.json"),
    "mcp_authorization_conformance_pack": Path("data/evidence/mcp-authorization-conformance-pack.json"),
    "mcp_connector_intake_pack": Path("data/evidence/mcp-connector-intake-pack.json"),
    "mcp_connector_trust_pack": Path("data/evidence/mcp-connector-trust-pack.json"),
    "mcp_stdio_launch_boundary_pack": Path("data/evidence/mcp-stdio-launch-boundary-pack.json"),
    "mcp_tool_surface_drift_pack": Path("data/evidence/mcp-tool-surface-drift-pack.json"),
    "secure_context_customer_proof_pack": Path("data/evidence/secure-context-customer-proof-pack.json"),
    "secure_context_lineage_ledger": Path("data/evidence/secure-context-lineage-ledger.json"),
}


class HostedMcpReadinessError(RuntimeError):
    """Raised when the hosted MCP readiness pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HostedMcpReadinessError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise HostedMcpReadinessError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise HostedMcpReadinessError(f"{path} root must be a JSON object")
    return payload


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HostedMcpReadinessError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise HostedMcpReadinessError(f"{label} must be a list")
    return value


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pack_reported_failure_count(pack: dict[str, Any] | None) -> int:
    if not isinstance(pack, dict):
        return 1
    failures = pack.get("failures")
    if isinstance(failures, list):
        return len(failures)
    for key in ("failure_count", "source_pack_failure_count", "reported_failure_count"):
        value = pack.get(key)
        if isinstance(value, int):
            return value
    summary = pack.get("summary")
    if isinstance(summary, dict) and isinstance(summary.get("failure_count"), int):
        return int(summary["failure_count"])
    for summary_key in (
        "customer_proof_summary",
        "telemetry_summary",
        "authorization_summary",
        "source_freshness_summary",
        "trust_center_summary",
    ):
        summary = pack.get(summary_key)
        if isinstance(summary, dict) and isinstance(summary.get("failure_count"), int):
            return int(summary["failure_count"])
    return 0


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain hosted MCP readiness")

    source_refs = as_list(profile.get("source_references"), "source_references")
    require(len(source_refs) >= 8, failures, "source_references must include current MCP, OWASP, CSA, NIST, CISA, and telemetry sources")
    source_classes: set[str] = set()
    source_ids: set[str] = set()
    for idx, source in enumerate(source_refs):
        item = as_dict(source, f"source_references[{idx}]")
        source_id = str(item.get("id", "")).strip()
        require(bool(source_id), failures, f"source_references[{idx}].id is required")
        require(source_id not in source_ids, failures, f"{source_id}: duplicate source id")
        source_ids.add(source_id)
        source_classes.add(str(item.get("source_class", "")).strip())
        require(str(item.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(str(item.get("publisher", "")).strip(), failures, f"{source_id}: publisher is required")
        require(len(str(item.get("why_it_matters", ""))) >= 70, failures, f"{source_id}: why_it_matters must be specific")
    for required_class in {
        "government_framework",
        "government_guidance",
        "industry_standard",
        "protocol_specification",
        "telemetry_standard",
    }:
        require(required_class in source_classes, failures, f"source_references must include {required_class}")

    contract = as_dict(profile.get("readiness_contract"), "readiness_contract")
    require(
        contract.get("default_state") == "not_hosted_production_ready_until_tenant_runtime_controls_are_implemented",
        failures,
        "readiness_contract.default_state must block hosted production claims",
    )
    required_pack_keys = {str(key) for key in as_list(contract.get("required_source_pack_keys"), "required_source_pack_keys")}
    unknown_pack_keys = sorted(required_pack_keys - set(DEFAULT_SOURCE_PACKS))
    require(not unknown_pack_keys, failures, f"unknown required source pack keys: {unknown_pack_keys}")
    require(
        len(required_pack_keys) >= int(contract.get("minimum_source_packs") or 0),
        failures,
        "required_source_pack_keys below minimum_source_packs",
    )
    for key in required_pack_keys:
        path = DEFAULT_SOURCE_PACKS[key]
        require(resolve(repo_root, path).exists(), failures, f"{key}: source pack path does not exist: {path}")
    valid_states = {str(item) for item in as_list(contract.get("valid_implementation_states"), "valid_implementation_states")}
    valid_decisions = {str(item) for item in as_list(contract.get("valid_default_decisions"), "valid_default_decisions")}
    require(len(valid_states) >= 4, failures, "valid_implementation_states must enumerate reference, design-partner, hosted, and blocked states")
    require(len(valid_decisions) >= 5, failures, "valid_default_decisions must enumerate allow, hold, deny, and kill decisions")
    require(len(as_list(contract.get("hosted_boundaries"), "hosted_boundaries")) >= 8, failures, "hosted_boundaries must cover tenant, context, MCP, telemetry, billing, and export boundaries")

    evidence_sources = as_list(profile.get("evidence_sources"), "evidence_sources")
    evidence_keys: set[str] = set()
    for idx, evidence in enumerate(evidence_sources):
        item = as_dict(evidence, f"evidence_sources[{idx}]")
        key = str(item.get("key", "")).strip()
        evidence_keys.add(key)
        require(key in DEFAULT_SOURCE_PACKS, failures, f"{key}: unknown evidence source key")
        expected = DEFAULT_SOURCE_PACKS.get(key)
        path = Path(str(item.get("path", "")))
        require(path == expected, failures, f"{key}: evidence source path must match generator default")
        require(resolve(repo_root, path).exists(), failures, f"{key}: evidence source path does not exist: {path}")
        require(len(str(item.get("readiness_role", ""))) >= 70, failures, f"{key}: readiness_role must be specific")
    require(not sorted(required_pack_keys - evidence_keys), failures, f"evidence_sources missing required packs: {sorted(required_pack_keys - evidence_keys)}")

    controls = as_list(profile.get("readiness_controls"), "readiness_controls")
    require(len(controls) >= int(contract.get("minimum_controls") or 0), failures, "readiness_controls below minimum")
    control_ids: set[str] = set()
    for idx, control in enumerate(controls):
        item = as_dict(control, f"readiness_controls[{idx}]")
        control_id = str(item.get("id", "")).strip()
        require(bool(control_id), failures, f"readiness_controls[{idx}].id is required")
        require(control_id not in control_ids, failures, f"{control_id}: duplicate control id")
        control_ids.add(control_id)
        packs = {str(key) for key in as_list(item.get("evidence_pack_keys"), f"{control_id}.evidence_pack_keys")}
        require(not sorted(packs - required_pack_keys), failures, f"{control_id}: unknown evidence pack keys {sorted(packs - required_pack_keys)}")
        require(len(as_list(item.get("runtime_signals"), f"{control_id}.runtime_signals")) >= 3, failures, f"{control_id}: runtime_signals are incomplete")
        require(str(item.get("implementation_state")) in valid_states, failures, f"{control_id}: invalid implementation_state")
        require(str(item.get("default_decision")) in valid_decisions, failures, f"{control_id}: invalid default_decision")
        require(len(str(item.get("buyer_claim", ""))) >= 70, failures, f"{control_id}: buyer_claim must be specific")

    stages = as_list(profile.get("readiness_stages"), "readiness_stages")
    require(len(stages) >= int(contract.get("minimum_stages") or 0), failures, "readiness_stages below minimum")
    stage_ids: set[str] = set()
    for idx, stage in enumerate(stages):
        item = as_dict(stage, f"readiness_stages[{idx}]")
        stage_id = str(item.get("id", "")).strip()
        require(bool(stage_id), failures, f"readiness_stages[{idx}].id is required")
        require(stage_id not in stage_ids, failures, f"{stage_id}: duplicate stage id")
        stage_ids.add(stage_id)
        required_controls = {str(key) for key in as_list(item.get("required_control_ids"), f"{stage_id}.required_control_ids")}
        require(not sorted(required_controls - control_ids), failures, f"{stage_id}: unknown required_control_ids {sorted(required_controls - control_ids)}")
        require(str(item.get("current_state")) in valid_states, failures, f"{stage_id}: invalid current_state")
        require(len(str(item.get("commercial_value", ""))) >= 70, failures, f"{stage_id}: commercial_value must be specific")
        require(len(str(item.get("blocked_until", ""))) >= 50, failures, f"{stage_id}: blocked_until must be specific")

    gates = as_list(profile.get("rollout_gates"), "rollout_gates")
    require(len(gates) >= int(contract.get("minimum_rollout_gates") or 0), failures, "rollout_gates below minimum")
    for idx, gate in enumerate(gates):
        item = as_dict(gate, f"rollout_gates[{idx}]")
        gate_id = str(item.get("id", "")).strip()
        linked = {str(key) for key in as_list(item.get("linked_control_ids"), f"{gate_id}.linked_control_ids")}
        require(bool(gate_id), failures, f"rollout_gates[{idx}].id is required")
        require(not sorted(linked - control_ids), failures, f"{gate_id}: unknown linked_control_ids {sorted(linked - control_ids)}")
        require(str(item.get("gate_state")) in valid_states, failures, f"{gate_id}: invalid gate_state")
        require(len(str(item.get("what_passes", ""))) >= 70, failures, f"{gate_id}: what_passes must be specific")

    buyer_items = as_list(profile.get("buyer_evidence_items"), "buyer_evidence_items")
    require(len(buyer_items) >= int(contract.get("minimum_buyer_evidence_items") or 0), failures, "buyer_evidence_items below minimum")
    for idx, evidence in enumerate(buyer_items):
        item = as_dict(evidence, f"buyer_evidence_items[{idx}]")
        evidence_id = str(item.get("id", "")).strip()
        linked = {str(key) for key in as_list(item.get("linked_control_ids"), f"{evidence_id}.linked_control_ids")}
        require(bool(evidence_id), failures, f"buyer_evidence_items[{idx}].id is required")
        require(not sorted(linked - control_ids), failures, f"{evidence_id}: unknown linked_control_ids {sorted(linked - control_ids)}")
        require(str(item.get("status")) in valid_states, failures, f"{evidence_id}: invalid status")
        require(len(str(item.get("required_artifact", ""))) >= 70, failures, f"{evidence_id}: required_artifact must be specific")

    packaging = as_dict(profile.get("commercial_packaging"), "commercial_packaging")
    require(len(as_list(packaging.get("enterprise_plans"), "commercial_packaging.enterprise_plans")) >= 3, failures, "commercial_packaging.enterprise_plans must include at least three plans")
    require(len(str(packaging.get("acquirer_value", ""))) >= 100, failures, "commercial_packaging.acquirer_value must be specific")

    risks = as_list(profile.get("risk_register"), "risk_register")
    require(len(risks) >= 5, failures, "risk_register must include hosted MCP risks")
    for idx, risk in enumerate(risks):
        item = as_dict(risk, f"risk_register[{idx}]")
        require(str(item.get("id", "")).strip(), failures, f"risk_register[{idx}].id is required")
        require(len(str(item.get("mitigation", ""))) >= 70, failures, f"{item.get('id')}: mitigation must be specific")

    require(len(as_list(profile.get("next_90_days"), "next_90_days")) >= 4, failures, "next_90_days must include concrete next steps")
    return failures


def load_source_packs(profile: dict[str, Any], repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    failures: list[str] = []
    packs: dict[str, dict[str, Any]] = {}
    required_keys = {
        str(key)
        for key in profile.get("readiness_contract", {}).get("required_source_pack_keys", [])
    }
    for key in sorted(required_keys):
        ref = DEFAULT_SOURCE_PACKS.get(key)
        if ref is None:
            failures.append(f"{key}: no default source pack path")
            continue
        try:
            packs[key] = load_json(resolve(repo_root, ref))
        except HostedMcpReadinessError as exc:
            failures.append(f"{key}: {exc}")
    return packs, failures


def evidence_source_by_key(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_list(profile.get("evidence_sources"), "evidence_sources")
    return {
        str(row.get("key")): row
        for row in rows
        if isinstance(row, dict) and row.get("key")
    }


def source_pack_index(
    profile: dict[str, Any],
    source_packs: dict[str, dict[str, Any]],
    repo_root: Path,
) -> list[dict[str, Any]]:
    sources = evidence_source_by_key(profile)
    rows: list[dict[str, Any]] = []
    required_keys = [
        str(key)
        for key in profile.get("readiness_contract", {}).get("required_source_pack_keys", [])
    ]
    for key in sorted(required_keys):
        ref = DEFAULT_SOURCE_PACKS[key]
        path = resolve(repo_root, ref)
        pack = source_packs.get(key)
        evidence = sources.get(key, {})
        rows.append(
            {
                "generated_at": pack.get("generated_at") if isinstance(pack, dict) else None,
                "key": key,
                "last_reviewed": pack.get("last_reviewed") if isinstance(pack, dict) else None,
                "path": normalize_path(ref),
                "ready": isinstance(pack, dict),
                "reported_failure_count": pack_reported_failure_count(pack),
                "schema_version": pack.get("schema_version") if isinstance(pack, dict) else None,
                "sha256": sha256_file(path) if path.exists() else None,
                "title": evidence.get("title", key),
            }
        )
    return rows


def annotate_controls(profile: dict[str, Any], source_packs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    controls = as_list(profile.get("readiness_controls"), "readiness_controls")
    annotated: list[dict[str, Any]] = []
    for control in controls:
        item = dict(as_dict(control, "readiness_control"))
        pack_keys = [str(key) for key in item.get("evidence_pack_keys", [])]
        item["source_pack_status"] = [
            {
                "key": key,
                "ready": key in source_packs,
                "reported_failure_count": pack_reported_failure_count(source_packs.get(key)),
            }
            for key in pack_keys
        ]
        item["source_packs_ready"] = all(row["ready"] for row in item["source_pack_status"])
        item["status"] = item.get("implementation_state")
        annotated.append(item)
    return annotated


def annotate_stages(profile: dict[str, Any], controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    controls_by_id = {str(control.get("id")): control for control in controls}
    stages = as_list(profile.get("readiness_stages"), "readiness_stages")
    annotated: list[dict[str, Any]] = []
    for stage in stages:
        item = dict(as_dict(stage, "readiness_stage"))
        required_ids = [str(control_id) for control_id in item.get("required_control_ids", [])]
        linked_controls = [controls_by_id[control_id] for control_id in required_ids if control_id in controls_by_id]
        states = Counter(str(control.get("implementation_state")) for control in linked_controls)
        item["control_state_counts"] = dict(sorted(states.items()))
        item["linked_control_count"] = len(linked_controls)
        item["source_packs_ready"] = all(control.get("source_packs_ready") for control in linked_controls)
        if states.get("hosted_runtime_required") or states.get("blocked_until_customer_private_controls_exist"):
            item["status"] = "hosted_runtime_required"
        elif states.get("design_partner_runtime_required"):
            item["status"] = "design_partner_runtime_required"
        else:
            item["status"] = "reference_evidence_ready"
        return_controls = []
        for control in linked_controls:
            return_controls.append(
                {
                    "control_family": control.get("control_family"),
                    "default_decision": control.get("default_decision"),
                    "id": control.get("id"),
                    "implementation_state": control.get("implementation_state"),
                    "priority": control.get("priority"),
                    "title": control.get("title"),
                }
            )
        item["required_controls"] = return_controls
        annotated.append(item)
    return annotated


def annotate_rollout_gates(profile: dict[str, Any], controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    controls_by_id = {str(control.get("id")): control for control in controls}
    gates = as_list(profile.get("rollout_gates"), "rollout_gates")
    annotated: list[dict[str, Any]] = []
    for gate in gates:
        item = dict(as_dict(gate, "rollout_gate"))
        linked_ids = [str(control_id) for control_id in item.get("linked_control_ids", [])]
        item["linked_controls"] = [
            {
                "id": controls_by_id[control_id].get("id"),
                "implementation_state": controls_by_id[control_id].get("implementation_state"),
                "priority": controls_by_id[control_id].get("priority"),
                "title": controls_by_id[control_id].get("title"),
            }
            for control_id in linked_ids
            if control_id in controls_by_id
        ]
        item["status"] = item.get("gate_state")
        annotated.append(item)
    return annotated


def annotate_buyer_evidence(profile: dict[str, Any], controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    controls_by_id = {str(control.get("id")): control for control in controls}
    items = as_list(profile.get("buyer_evidence_items"), "buyer_evidence_items")
    annotated: list[dict[str, Any]] = []
    for evidence in items:
        item = dict(as_dict(evidence, "buyer_evidence_item"))
        linked_ids = [str(control_id) for control_id in item.get("linked_control_ids", [])]
        item["linked_controls"] = [
            {
                "control_family": controls_by_id[control_id].get("control_family"),
                "id": controls_by_id[control_id].get("id"),
                "implementation_state": controls_by_id[control_id].get("implementation_state"),
                "title": controls_by_id[control_id].get("title"),
            }
            for control_id in linked_ids
            if control_id in controls_by_id
        ]
        annotated.append(item)
    return annotated


def source_artifacts(
    profile_path: Path,
    profile_ref: Path,
    pack_index: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(profile_path),
        },
        "source_packs": [
            {
                "key": row.get("key"),
                "path": row.get("path"),
                "sha256": row.get("sha256"),
            }
            for row in pack_index
        ],
    }


def build_summary(
    profile: dict[str, Any],
    controls: list[dict[str, Any]],
    stages: list[dict[str, Any]],
    gates: list[dict[str, Any]],
    buyer_items: list[dict[str, Any]],
    pack_index: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    state_counts = Counter(str(control.get("implementation_state")) for control in controls)
    gate_counts = Counter(str(gate.get("gate_state")) for gate in gates)
    critical_runtime_gaps = [
        {
            "default_decision": control.get("default_decision"),
            "id": control.get("id"),
            "implementation_state": control.get("implementation_state"),
            "priority": control.get("priority"),
            "title": control.get("title"),
        }
        for control in controls
        if control.get("priority") == "critical"
        and control.get("implementation_state") != "reference_evidence_ready"
    ]
    reported_source_pack_issues = sum(int(row.get("reported_failure_count") or 0) for row in pack_index)
    source_pack_ready_count = sum(1 for row in pack_index if row.get("ready"))
    hosted_runtime_required_count = sum(
        1
        for control in controls
        if control.get("implementation_state") in {
            "blocked_until_customer_private_controls_exist",
            "design_partner_runtime_required",
            "hosted_runtime_required",
        }
    )
    return {
        "buyer_evidence_count": len(buyer_items),
        "contract_status": "hosted_mcp_readiness_contract_ready" if not failures else "hosted_mcp_readiness_contract_has_failures",
        "control_count": len(controls),
        "control_state_counts": dict(sorted(state_counts.items())),
        "critical_runtime_gaps": critical_runtime_gaps,
        "default_state": profile.get("readiness_contract", {}).get("default_state"),
        "failure_count": len(failures),
        "gate_state_counts": dict(sorted(gate_counts.items())),
        "hosted_runtime_required_count": hosted_runtime_required_count,
        "open_reference_ready": state_counts.get("reference_evidence_ready", 0) >= 1,
        "production_ready": False,
        "product_readiness_decision": "hold_for_hosted_runtime_implementation",
        "reported_source_pack_issue_count": reported_source_pack_issues,
        "rollout_gate_count": len(gates),
        "source_pack_count": len(pack_index),
        "source_pack_ready_count": source_pack_ready_count,
        "stage_count": len(stages),
    }


def build_pack(
    profile: dict[str, Any],
    profile_path: Path,
    profile_ref: Path,
    repo_root: Path,
    source_packs: dict[str, dict[str, Any]],
    failures: list[str],
    generated_at: str | None,
) -> dict[str, Any]:
    pack_index = source_pack_index(profile, source_packs, repo_root)
    controls = annotate_controls(profile, source_packs)
    stages = annotate_stages(profile, controls)
    gates = annotate_rollout_gates(profile, controls)
    buyer_items = annotate_buyer_evidence(profile, controls)
    summary = build_summary(profile, controls, stages, gates, buyer_items, pack_index, failures)
    return {
        "buyer_evidence_items": buyer_items,
        "commercial_packaging": profile.get("commercial_packaging", {}),
        "evidence_sources": profile.get("evidence_sources", []),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "hosted_mcp_readiness_pack_id": "security-recipes-hosted-mcp-readiness-pack",
        "hosted_mcp_readiness_summary": summary,
        "last_reviewed": profile.get("last_reviewed"),
        "next_90_days": profile.get("next_90_days", []),
        "positioning": profile.get("positioning", {}),
        "readiness_contract": profile.get("readiness_contract", {}),
        "readiness_controls": controls,
        "readiness_stages": stages,
        "risk_register": profile.get("risk_register", []),
        "rollout_gates": gates,
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts(profile_path, profile_ref, pack_index),
        "source_pack_index": pack_index,
        "source_references": profile.get("source_references", []),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Validate that the generated output is current")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path.cwd()
    profile_ref = args.profile
    output_ref = args.output
    profile_path = resolve(repo_root, profile_ref)
    output_path = resolve(repo_root, output_ref)

    try:
        profile = load_json(profile_path)
        failures = validate_profile(profile, repo_root)
        source_packs, source_failures = load_source_packs(profile, repo_root)
        failures.extend(source_failures)
        pack = build_pack(
            profile=profile,
            profile_path=profile_path,
            profile_ref=profile_ref,
            repo_root=repo_root,
            source_packs=source_packs,
            failures=failures,
            generated_at=args.generated_at,
        )
    except HostedMcpReadinessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("hosted MCP readiness pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        if not output_path.exists():
            print(f"{output_path} is missing; run scripts/generate_hosted_mcp_readiness_pack.py", file=sys.stderr)
            return 1
        current = output_path.read_text(encoding="utf-8")
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_hosted_mcp_readiness_pack.py", file=sys.stderr)
            return 1
        print(f"{output_path} is current")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("generated hosted MCP readiness pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
