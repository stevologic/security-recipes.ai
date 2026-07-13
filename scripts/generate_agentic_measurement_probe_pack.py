#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic measurement probe pack.

The probe pack turns the "secure context layer for agentic AI" claim
into a measurable artifact. It joins workflow scope, MCP gateway policy,
authorization conformance, secure context, poisoning scans, egress,
memory boundaries, red-team drills, readiness, capability risk, run
receipts, and threat radar into repeatable checks that AI platform and
GRC teams can use before workflow expansion.
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
DEFAULT_PROFILE = Path("data/assurance/agentic-measurement-probe-profile.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_GATEWAY_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_AUTHORIZATION_PACK = Path("data/evidence/mcp-authorization-conformance-pack.json")
DEFAULT_CONTEXT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_POISONING_GUARD_PACK = Path("data/evidence/context-poisoning-guard-pack.json")
DEFAULT_EGRESS_BOUNDARY_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_MEMORY_BOUNDARY_PACK = Path("data/evidence/agent-memory-boundary-pack.json")
DEFAULT_RED_TEAM_PACK = Path("data/evidence/agentic-red-team-drill-pack.json")
DEFAULT_READINESS_SCORECARD = Path("data/evidence/agentic-readiness-scorecard.json")
DEFAULT_CAPABILITY_RISK_REGISTER = Path("data/evidence/agent-capability-risk-register.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_THREAT_RADAR = Path("data/evidence/agentic-threat-radar.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-measurement-probe-pack.json")

REQUIRED_PROBE_CLASSES = {
    "context_integrity",
    "tool_authorization",
    "identity_delegation",
    "egress_boundary",
    "memory_boundary",
    "red_team_replay",
    "run_receipt_integrity",
    "readiness_decision",
    "threat_radar_alignment",
}
REQUIRED_SOURCE_PACKS = {
    "workflow_manifest",
    "gateway_policy",
    "mcp_authorization_conformance",
    "secure_context_trust_pack",
    "context_poisoning_guard_pack",
    "context_egress_boundary_pack",
    "agent_memory_boundary_pack",
    "agentic_red_team_drill_pack",
    "agentic_readiness_scorecard",
    "agent_capability_risk_register",
    "agentic_run_receipt_pack",
    "agentic_threat_radar",
}
PASSING_STATUSES = {"pass", "observe"}


class MeasurementProbeError(RuntimeError):
    """Raised when the measurement probe pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MeasurementProbeError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise MeasurementProbeError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MeasurementProbeError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise MeasurementProbeError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MeasurementProbeError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def index_by(rows: list[Any], key: str, label: str) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = as_dict(row, label)
        item_key = str(item.get(key, "")).strip()
        if item_key:
            output[item_key] = item
    return output


def workflow_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(as_list(manifest.get("workflows"), "manifest.workflows"), "id", "workflow")


def policy_by_workflow(policy_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(
        as_list(policy_pack.get("workflow_policies"), "gateway_policy.workflow_policies"),
        "workflow_id",
        "workflow_policy",
    )


def rows_by_workflow(pack: dict[str, Any], field: str, label: str) -> dict[str, dict[str, Any]]:
    return index_by(as_list(pack.get(field), f"{label}.{field}"), "workflow_id", label)


def signal_by_id(threat_radar: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(
        as_list(threat_radar.get("threat_signals"), "threat_radar.threat_signals"),
        "id",
        "threat_signal",
    )


def count_failures(payloads: dict[str, dict[str, Any]]) -> int:
    count = 0
    for payload in payloads.values():
        failures = payload.get("failures")
        if isinstance(failures, list):
            count += len(failures)
    return count


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 80, failures, "profile intent must explain the product goal")

    standards = as_list(profile.get("standards_alignment"), "profile.standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include current AI and MCP references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"standards_alignment[{idx}].id duplicates {standard_id}")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 50, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("probe_contract"), "profile.probe_contract")
    require(contract.get("default_state") == "unverified_until_probe_passes", failures, "probe default_state must fail closed")
    required_source_packs = {str(item) for item in as_list(contract.get("required_source_packs"), "probe_contract.required_source_packs")}
    missing_source_packs = sorted(REQUIRED_SOURCE_PACKS - required_source_packs)
    require(not missing_source_packs, failures, f"probe_contract missing source packs: {missing_source_packs}")
    runtime_fields = as_list(contract.get("required_runtime_fields"), "probe_contract.required_runtime_fields")
    require(len(runtime_fields) >= 10, failures, "probe_contract must require runtime trace fields")

    classes = as_list(profile.get("probe_classes"), "profile.probe_classes")
    class_ids: set[str] = set()
    for idx, probe_class in enumerate(classes):
        item = as_dict(probe_class, f"probe_classes[{idx}]")
        class_id = str(item.get("id", "")).strip()
        class_ids.add(class_id)
        require(class_id in REQUIRED_PROBE_CLASSES, failures, f"unknown probe class: {class_id}")
        require(len(str(item.get("question", ""))) >= 40, failures, f"{class_id}: question must be specific")
    require(REQUIRED_PROBE_CLASSES.issubset(class_ids), failures, "profile must define all required probe classes")

    probes = as_list(profile.get("probes"), "profile.probes")
    require(len(probes) >= int(contract.get("minimum_probes_per_workflow", 8)), failures, "profile must define enough probes")
    probe_ids: set[str] = set()
    for idx, probe in enumerate(probes):
        item = as_dict(probe, f"probes[{idx}]")
        probe_id = str(item.get("id", "")).strip()
        class_id = str(item.get("class_id", "")).strip()
        probe_ids.add(probe_id)
        require(bool(probe_id), failures, f"probes[{idx}].id is required")
        require(class_id in class_ids, failures, f"{probe_id}: class_id is unknown")
        require(int(item.get("weight", 0)) > 0, failures, f"{probe_id}: weight must be positive")
        require(len(as_list(item.get("mapped_signal_ids"), f"{probe_id}.mapped_signal_ids")) >= 2, failures, f"{probe_id}: mapped_signal_ids are required")
        require(len(as_list(item.get("evidence_inputs"), f"{probe_id}.evidence_inputs")) >= 1, failures, f"{probe_id}: evidence_inputs are required")
        require(len(as_list(item.get("pass_conditions"), f"{probe_id}.pass_conditions")) >= 3, failures, f"{probe_id}: pass_conditions must include at least three items")
        require(len(as_list(item.get("failure_actions"), f"{probe_id}.failure_actions")) >= 2, failures, f"{probe_id}: failure_actions must include at least two items")
    require(len(probe_ids) == len(probes), failures, "probe IDs must be unique")
    return failures


def validate_sources(
    *,
    manifest: dict[str, Any],
    gateway_policy: dict[str, Any],
    authorization_pack: dict[str, Any],
    context_trust_pack: dict[str, Any],
    egress_boundary_pack: dict[str, Any],
    memory_boundary_pack: dict[str, Any],
    red_team_pack: dict[str, Any],
    readiness_scorecard: dict[str, Any],
    capability_risk_register: dict[str, Any],
    run_receipt_pack: dict[str, Any],
    threat_radar: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    source_payloads = {
        "gateway policy": gateway_policy,
        "authorization pack": authorization_pack,
        "secure context trust pack": context_trust_pack,
        "egress boundary pack": egress_boundary_pack,
        "memory boundary pack": memory_boundary_pack,
        "red-team pack": red_team_pack,
        "readiness scorecard": readiness_scorecard,
        "capability risk register": capability_risk_register,
        "run receipt pack": run_receipt_pack,
        "threat radar": threat_radar,
    }
    require(manifest.get("schema_version") == "1.0", failures, "workflow manifest schema_version must be 1.0")
    for label, payload in source_payloads.items():
        require(payload.get("schema_version") == "1.0", failures, f"{label} schema_version must be 1.0")
    require(count_failures(source_payloads) == 0, failures, "all generated source packs must have zero failures")
    require(gateway_policy.get("decision_contract", {}).get("default_decision") == "deny", failures, "gateway policy must default to deny")

    workflows = set(workflow_by_id(manifest))
    require(bool(workflows), failures, "workflow manifest must include workflows")
    workflow_sources = {
        "gateway policy": set(policy_by_workflow(gateway_policy)),
        "authorization map": set(rows_by_workflow(authorization_pack, "workflow_authorization_map", "authorization_pack")),
        "secure context map": set(rows_by_workflow(context_trust_pack, "workflow_context_map", "context_trust_pack")),
        "egress map": set(rows_by_workflow(egress_boundary_pack, "workflow_egress_map", "egress_boundary_pack")),
        "memory profile": set(rows_by_workflow(memory_boundary_pack, "workflow_memory_profiles", "memory_boundary_pack")),
        "red-team drills": set(rows_by_workflow(red_team_pack, "workflow_drills", "red_team_pack")),
        "readiness scorecard": set(rows_by_workflow(readiness_scorecard, "workflow_readiness", "readiness_scorecard")),
        "capability risk register": set(rows_by_workflow(capability_risk_register, "workflow_capability_risks", "capability_risk_register")),
        "run receipts": set(rows_by_workflow(run_receipt_pack, "workflow_receipt_templates", "run_receipt_pack")),
    }
    for label, source_workflows in workflow_sources.items():
        require(workflows == source_workflows, failures, f"{label} workflows must match manifest")
    return failures


def status_row(status: str, evidence: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    return {
        "evidence": evidence,
        "notes": notes,
        "status": status,
    }


def evaluate_probe(
    probe: dict[str, Any],
    workflow_id: str,
    sources: dict[str, Any],
) -> dict[str, Any]:
    class_id = str(probe.get("class_id"))
    context_row = sources["context_by_workflow"].get(workflow_id)
    policy_row = sources["policy_by_workflow"].get(workflow_id)
    auth_row = sources["authorization_by_workflow"].get(workflow_id)
    egress_row = sources["egress_by_workflow"].get(workflow_id)
    memory_row = sources["memory_by_workflow"].get(workflow_id)
    red_team_row = sources["red_team_by_workflow"].get(workflow_id)
    readiness_row = sources["readiness_by_workflow"].get(workflow_id)
    risk_row = sources["risk_by_workflow"].get(workflow_id)
    receipt_row = sources["receipt_by_workflow"].get(workflow_id)
    threat_signals = sources["signals_by_id"]

    if class_id == "context_integrity":
        status = "pass" if context_row and sources["poisoning_guard_pack"].get("source_results") else "fail"
        return status_row(
            status,
            {
                "context_package_hash": context_row.get("context_package_hash") if context_row else None,
                "context_source_count": context_row.get("context_source_count") if context_row else 0,
                "poisoning_source_result_count": len(sources["poisoning_guard_pack"].get("source_results", []) or []),
            },
            ["Retrieved text is measured as evidence, not authority."],
        )

    if class_id == "tool_authorization":
        namespaces = auth_row.get("namespaces", []) if auth_row else []
        decisions = {str(item.get("authorization_decision")) for item in namespaces if isinstance(item, dict)}
        status = "pass" if policy_row and auth_row and decisions and all("approve" in item for item in decisions) else "fail"
        return status_row(
            status,
            {
                "authorization_policy_hash": auth_row.get("authorization_policy_hash") if auth_row else None,
                "gateway_default_decision": sources["gateway_policy"].get("decision_contract", {}).get("default_decision"),
                "namespace_count": len(namespaces),
            },
            ["MCP calls must pass both gateway policy and authorization conformance checks."],
        )

    if class_id == "identity_delegation":
        event_classes = {
            str(event.get("event_class"))
            for event in receipt_row.get("event_manifest", [])
            if isinstance(event, dict)
        } if receipt_row else set()
        identity_ids = receipt_row.get("identity_ids", []) if receipt_row else []
        status = "pass" if identity_ids and "identity_revoked" in event_classes else "fail"
        return status_row(
            status,
            {
                "identity_count": len(identity_ids),
                "identity_revocation_required": "identity_revoked" in event_classes,
                "readiness_identity_count": readiness_row.get("identity_count") if readiness_row else 0,
            },
            ["Agent actions must be attributable to scoped non-human identities."],
        )

    if class_id == "egress_boundary":
        namespace_policies = egress_row.get("namespace_policies", []) if egress_row else []
        prohibited = [
            destination
            for policy in namespace_policies
            if isinstance(policy, dict)
            for destination in policy.get("prohibited_destination_classes", []) or []
        ]
        status = "pass" if egress_row and namespace_policies and "securityrecipes_public_corpus" in prohibited else "fail"
        return status_row(
            status,
            {
                "egress_policy_hash": egress_row.get("egress_policy_hash") if egress_row else None,
                "namespace_policy_count": len(namespace_policies),
                "prohibited_destination_count": len(set(prohibited)),
            },
            ["Context movement is measured before it reaches model, MCP, telemetry, or public boundaries."],
        )

    if class_id == "memory_boundary":
        status = "pass" if memory_row and memory_row.get("kill_memory_class_ids") and memory_row.get("hold_memory_class_ids") else "fail"
        return status_row(
            status,
            {
                "memory_profile_hash": memory_row.get("memory_profile_hash") if memory_row else None,
                "hold_memory_class_ids": memory_row.get("hold_memory_class_ids", []) if memory_row else [],
                "kill_memory_class_ids": memory_row.get("kill_memory_class_ids", []) if memory_row else [],
            },
            ["Persistent memory is treated as a gated data boundary."],
        )

    if class_id == "red_team_replay":
        drills = red_team_row.get("drills", []) if red_team_row else []
        severities = {str(drill.get("severity")) for drill in drills if isinstance(drill, dict)}
        status = "pass" if len(drills) >= 5 and severities.intersection({"critical", "high"}) else "fail"
        return status_row(
            status,
            {
                "drill_count": len(drills),
                "severity_coverage": sorted(severities),
                "attack_families": sorted({str(drill.get("attack_family")) for drill in drills if isinstance(drill, dict)}),
            },
            ["Probe results should feed quarterly replay and connector promotion gates."],
        )

    if class_id == "run_receipt_integrity":
        event_count = int(receipt_row.get("required_event_class_count") or 0) if receipt_row else 0
        criteria = receipt_row.get("receipt_acceptance_criteria", []) if receipt_row else []
        status = "pass" if event_count >= 10 and len(criteria) >= 8 else "fail"
        return status_row(
            status,
            {
                "receipt_id": receipt_row.get("receipt_id") if receipt_row else None,
                "required_event_class_count": event_count,
                "acceptance_criteria_count": len(criteria),
            },
            ["A trusted agent run needs a sealed receipt, not a natural-language success claim."],
        )

    if class_id == "readiness_decision":
        score = int(readiness_row.get("score") or 0) if readiness_row else 0
        blockers = readiness_row.get("blockers", []) if readiness_row else []
        residual = int(risk_row.get("residual_risk_score") or 0) if risk_row else 0
        status = "pass" if score >= 78 and not blockers and risk_row else "fail"
        return status_row(
            status,
            {
                "readiness_decision": readiness_row.get("decision") if readiness_row else None,
                "readiness_score": score,
                "risk_tier": risk_row.get("risk_tier") if risk_row else None,
                "residual_risk_score": residual,
            },
            ["Capability risk and readiness must be reviewed together before scale."],
        )

    if class_id == "threat_radar_alignment":
        mapped_ids = [str(item) for item in probe.get("mapped_signal_ids", []) or []]
        mapped = [threat_signals[item] for item in mapped_ids if item in threat_signals]
        priority_counts = Counter(str(signal.get("priority")) for signal in mapped)
        status = "pass" if len(mapped) == len(mapped_ids) and (priority_counts["critical"] or priority_counts["high"]) else "fail"
        return status_row(
            status,
            {
                "mapped_signal_count": len(mapped),
                "priority_counts": dict(sorted(priority_counts.items())),
                "source_reference_count": sources["threat_radar"].get("threat_radar_summary", {}).get("source_reference_count"),
            },
            ["Threat alignment keeps probes anchored to current industry signals."],
        )

    return status_row("fail", {"class_id": class_id}, ["Unknown probe class."])


def probe_result(
    probe: dict[str, Any],
    workflow: dict[str, Any],
    sources: dict[str, Any],
) -> dict[str, Any]:
    workflow_id = str(workflow.get("id"))
    result = evaluate_probe(probe, workflow_id, sources)
    status = str(result.get("status"))
    weight = int(probe.get("weight") or 0)
    earned = weight if status in PASSING_STATUSES else 0
    return {
        "class_id": probe.get("class_id"),
        "earned_weight": earned,
        "evidence": result.get("evidence", {}),
        "evidence_inputs": probe.get("evidence_inputs", []),
        "failure_actions": probe.get("failure_actions", []),
        "mapped_signal_ids": probe.get("mapped_signal_ids", []),
        "notes": result.get("notes", []),
        "pass_conditions": probe.get("pass_conditions", []),
        "probe_id": probe.get("id"),
        "status": status,
        "title": probe.get("title"),
        "weight": weight,
        "workflow_id": workflow_id,
    }


def workflow_probe_row(
    *,
    workflow: dict[str, Any],
    probes: list[dict[str, Any]],
    sources: dict[str, Any],
    minimum_pass_score: int,
) -> dict[str, Any]:
    workflow_id = str(workflow.get("id"))
    probe_rows = [probe_result(probe, workflow, sources) for probe in probes]
    total_weight = sum(int(row.get("weight") or 0) for row in probe_rows)
    earned_weight = sum(int(row.get("earned_weight") or 0) for row in probe_rows)
    score = round((earned_weight / total_weight) * 100) if total_weight else 0
    failed = [row for row in probe_rows if row.get("status") not in PASSING_STATUSES]
    readiness_row = sources["readiness_by_workflow"].get(workflow_id, {})
    risk_row = sources["risk_by_workflow"].get(workflow_id, {})

    if failed:
        decision = "manual_gate"
    elif score >= minimum_pass_score:
        decision = "measurement_ready"
    else:
        decision = "manual_gate"

    return {
        "decision": decision,
        "earned_weight": earned_weight,
        "failed_probe_count": len(failed),
        "maturity_stage": workflow.get("maturity_stage"),
        "mcp_namespaces": [
            context.get("namespace")
            for context in workflow.get("mcp_context", []) or []
            if isinstance(context, dict) and context.get("namespace")
        ],
        "owner": workflow.get("owner"),
        "probe_count": len(probe_rows),
        "probe_results": probe_rows,
        "public_path": workflow.get("public_path"),
        "readiness_decision": readiness_row.get("decision"),
        "readiness_score": readiness_row.get("score"),
        "risk_tier": risk_row.get("risk_tier"),
        "score": score,
        "status": workflow.get("status"),
        "title": workflow.get("title"),
        "total_weight": total_weight,
        "workflow_id": workflow_id,
    }


def build_source_artifacts(paths: dict[str, Path], refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    return {
        key: {
            "path": normalize_path(refs[key]),
            "sha256": sha256_file(paths[key]),
        }
        for key in sorted(paths)
    }


def build_summary(workflow_rows: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    decisions = Counter(str(row.get("decision")) for row in workflow_rows)
    probe_statuses = Counter(
        str(probe.get("status"))
        for workflow in workflow_rows
        for probe in workflow.get("probe_results", [])
    )
    class_statuses: dict[str, Counter[str]] = {}
    for workflow in workflow_rows:
        for probe in workflow.get("probe_results", []):
            class_id = str(probe.get("class_id"))
            class_statuses.setdefault(class_id, Counter())[str(probe.get("status"))] += 1

    return {
        "average_score": round(
            sum(int(row.get("score") or 0) for row in workflow_rows) / len(workflow_rows),
            2,
        ) if workflow_rows else 0,
        "decision_counts": dict(sorted(decisions.items())),
        "failure_count": len(failures),
        "probe_class_status_counts": {
            key: dict(sorted(value.items()))
            for key, value in sorted(class_statuses.items())
        },
        "probe_status_counts": dict(sorted(probe_statuses.items())),
        "total_probe_results": sum(len(row.get("probe_results", [])) for row in workflow_rows),
        "workflow_count": len(workflow_rows),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    source_payloads: dict[str, dict[str, Any]],
    source_paths: dict[str, Path],
    source_refs: dict[str, Path],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    manifest = source_payloads["workflow_manifest"]
    gateway_policy = source_payloads["gateway_policy"]
    threat_radar = source_payloads["agentic_threat_radar"]
    sources = {
        "authorization_by_workflow": rows_by_workflow(source_payloads["mcp_authorization_conformance"], "workflow_authorization_map", "authorization_pack"),
        "context_by_workflow": rows_by_workflow(source_payloads["secure_context_trust_pack"], "workflow_context_map", "context_trust_pack"),
        "egress_by_workflow": rows_by_workflow(source_payloads["context_egress_boundary_pack"], "workflow_egress_map", "egress_boundary_pack"),
        "gateway_policy": gateway_policy,
        "memory_by_workflow": rows_by_workflow(source_payloads["agent_memory_boundary_pack"], "workflow_memory_profiles", "memory_boundary_pack"),
        "policy_by_workflow": policy_by_workflow(gateway_policy),
        "poisoning_guard_pack": source_payloads["context_poisoning_guard_pack"],
        "readiness_by_workflow": rows_by_workflow(source_payloads["agentic_readiness_scorecard"], "workflow_readiness", "readiness_scorecard"),
        "receipt_by_workflow": rows_by_workflow(source_payloads["agentic_run_receipt_pack"], "workflow_receipt_templates", "run_receipt_pack"),
        "red_team_by_workflow": rows_by_workflow(source_payloads["agentic_red_team_drill_pack"], "workflow_drills", "red_team_pack"),
        "risk_by_workflow": rows_by_workflow(source_payloads["agent_capability_risk_register"], "workflow_capability_risks", "capability_risk_register"),
        "signals_by_id": signal_by_id(threat_radar),
        "threat_radar": threat_radar,
    }
    probes = [as_dict(item, "profile.probe") for item in as_list(profile.get("probes"), "profile.probes")]
    minimum_pass_score = int(profile.get("probe_contract", {}).get("minimum_pass_score") or 85)
    workflow_rows = [
        workflow_probe_row(
            workflow=workflow,
            probes=probes,
            sources=sources,
            minimum_pass_score=minimum_pass_score,
        )
        for workflow in workflow_by_id(manifest).values()
    ]
    workflow_rows.sort(key=lambda row: str(row.get("workflow_id")))

    return {
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "measurement_probe_summary": build_summary(workflow_rows, failures),
        "positioning": profile.get("positioning", {}),
        "probe_classes": profile.get("probe_classes", []),
        "probe_contract": profile.get("probe_contract", {}),
        "probes": probes,
        "residual_risks": [
            {
                "risk": "Generated probes verify source-controlled evidence, not a customer's live runtime trace.",
                "treatment": "Hosted deployments must ingest tenant runtime events and compare them to this probe contract."
            },
            {
                "risk": "A passing probe does not guarantee model behavior under every future prompt, model, or connector change.",
                "treatment": "Re-run probes after model, tool, policy, context, memory, or workflow drift."
            },
            {
                "risk": "Judges and verifiers can fail if they are not grounded in the declared evidence pack.",
                "treatment": "Use deterministic checks for policy, hashes, and event completeness before model-graded evaluations."
            }
        ],
        "schema_version": PACK_SCHEMA_VERSION,
        "selected_feature": {
            "id": "agentic-measurement-probe-pack",
            "implementation": [
                "Probe profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Generated evidence pack under data/evidence.",
                "Human-readable docs page under security-remediation.",
                "MCP tool exposure through recipes_agentic_measurement_probe_pack."
            ],
            "reason": "NIST's 2026 agentic measurement probe direction creates a clear enterprise opportunity: make SecurityRecipes the measurable context, policy, and traceability layer for agentic AI."
        },
        "source_artifacts": build_source_artifacts(source_paths, source_refs),
        "standards_alignment": profile.get("standards_alignment", []),
        "workflow_probes": workflow_rows,
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--gateway-policy", type=Path, default=DEFAULT_GATEWAY_POLICY)
    parser.add_argument("--authorization-pack", type=Path, default=DEFAULT_AUTHORIZATION_PACK)
    parser.add_argument("--context-trust-pack", type=Path, default=DEFAULT_CONTEXT_TRUST_PACK)
    parser.add_argument("--poisoning-guard-pack", type=Path, default=DEFAULT_POISONING_GUARD_PACK)
    parser.add_argument("--egress-boundary-pack", type=Path, default=DEFAULT_EGRESS_BOUNDARY_PACK)
    parser.add_argument("--memory-boundary-pack", type=Path, default=DEFAULT_MEMORY_BOUNDARY_PACK)
    parser.add_argument("--red-team-pack", type=Path, default=DEFAULT_RED_TEAM_PACK)
    parser.add_argument("--readiness-scorecard", type=Path, default=DEFAULT_READINESS_SCORECARD)
    parser.add_argument("--capability-risk-register", type=Path, default=DEFAULT_CAPABILITY_RISK_REGISTER)
    parser.add_argument("--run-receipt-pack", type=Path, default=DEFAULT_RUN_RECEIPT_PACK)
    parser.add_argument("--threat-radar", type=Path, default=DEFAULT_THREAT_RADAR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in probe pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "agent_capability_risk_register": args.capability_risk_register,
        "agent_memory_boundary_pack": args.memory_boundary_pack,
        "agentic_readiness_scorecard": args.readiness_scorecard,
        "agentic_red_team_drill_pack": args.red_team_pack,
        "agentic_run_receipt_pack": args.run_receipt_pack,
        "agentic_threat_radar": args.threat_radar,
        "context_egress_boundary_pack": args.egress_boundary_pack,
        "context_poisoning_guard_pack": args.poisoning_guard_pack,
        "gateway_policy": args.gateway_policy,
        "mcp_authorization_conformance": args.authorization_pack,
        "profile": args.profile,
        "secure_context_trust_pack": args.context_trust_pack,
        "workflow_manifest": args.manifest,
    }
    paths = {key: resolve(repo_root, path) for key, path in refs.items()}
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["profile"])
        source_payloads = {
            key: load_json(path)
            for key, path in paths.items()
            if key != "profile"
        }
        failures = validate_profile(profile)
        failures.extend(
            validate_sources(
                manifest=source_payloads["workflow_manifest"],
                gateway_policy=source_payloads["gateway_policy"],
                authorization_pack=source_payloads["mcp_authorization_conformance"],
                context_trust_pack=source_payloads["secure_context_trust_pack"],
                egress_boundary_pack=source_payloads["context_egress_boundary_pack"],
                memory_boundary_pack=source_payloads["agent_memory_boundary_pack"],
                red_team_pack=source_payloads["agentic_red_team_drill_pack"],
                readiness_scorecard=source_payloads["agentic_readiness_scorecard"],
                capability_risk_register=source_payloads["agent_capability_risk_register"],
                run_receipt_pack=source_payloads["agentic_run_receipt_pack"],
                threat_radar=source_payloads["agentic_threat_radar"],
            )
        )
        all_payloads = {"profile": profile, **source_payloads}
        pack = build_pack(
            profile=profile,
            source_payloads=all_payloads,
            source_paths=paths,
            source_refs=refs,
            generated_at=args.generated_at,
            failures=failures,
        )
    except MeasurementProbeError as exc:
        print(f"agentic measurement probe generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("agentic measurement probe validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(
                f"{output_path} is stale; run scripts/generate_agentic_measurement_probe_pack.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated agentic measurement probe pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")
    if failures:
        print("Generated agentic measurement probe pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic measurement probe pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
