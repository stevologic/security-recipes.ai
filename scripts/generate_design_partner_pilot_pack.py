#!/usr/bin/env python3
"""Generate the SecurityRecipes design partner pilot pack.

The pack turns the secure context layer into a concrete enterprise pilot
motion: which buyer segment is being tested, which paid wedge is being
validated, which evidence packs support the motion, and which telemetry
must replace assumption-based ROI before renewal or acquisition claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/design-partner-pilot-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/design-partner-pilot-pack.json")

SOURCE_PACKS: dict[str, Path] = {
    "agentic_app_intake_pack": Path("data/evidence/agentic-app-intake-pack.json"),
    "agentic_incident_response_pack": Path("data/evidence/agentic-incident-response-pack.json"),
    "agentic_protocol_conformance_pack": Path("data/evidence/agentic-protocol-conformance-pack.json"),
    "agentic_readiness_scorecard": Path("data/evidence/agentic-readiness-scorecard.json"),
    "agentic_run_receipt_pack": Path("data/evidence/agentic-run-receipt-pack.json"),
    "agentic_telemetry_contract": Path("data/evidence/agentic-telemetry-contract.json"),
    "enterprise_trust_center_export": Path("data/evidence/enterprise-trust-center-export.json"),
    "mcp_authorization_conformance_pack": Path("data/evidence/mcp-authorization-conformance-pack.json"),
    "mcp_connector_intake_pack": Path("data/evidence/mcp-connector-intake-pack.json"),
    "mcp_tool_surface_drift_pack": Path("data/evidence/mcp-tool-surface-drift-pack.json"),
    "secure_context_eval_pack": Path("data/evidence/secure-context-eval-pack.json"),
    "secure_context_value_model": Path("data/evidence/secure-context-value-model.json"),
}


class DesignPartnerPilotPackError(RuntimeError):
    """Raised when the design partner pilot pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DesignPartnerPilotPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise DesignPartnerPilotPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise DesignPartnerPilotPackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DesignPartnerPilotPackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise DesignPartnerPilotPackError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def validate_pack_keys(keys: list[Any], label: str, failures: list[str]) -> set[str]:
    resolved = {str(key) for key in keys}
    unknown = sorted(resolved - set(SOURCE_PACKS))
    require(not unknown, failures, f"{label} contains unknown source pack keys: {unknown}")
    return resolved


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must describe the pilot goal")

    sources = as_list(profile.get("source_references"), "source_references")
    require(len(sources) >= 7, failures, "source_references must include current MCP, NIST, OWASP, and CISA sources")
    source_ids: set[str] = set()
    source_classes: set[str] = set()
    for idx, source in enumerate(sources):
        item = as_dict(source, f"source_references[{idx}]")
        source_id = str(item.get("id", "")).strip()
        require(bool(source_id), failures, f"source_references[{idx}].id is required")
        require(source_id not in source_ids, failures, f"{source_id}: duplicate source id")
        source_ids.add(source_id)
        source_classes.add(str(item.get("source_class", "")).strip())
        require(str(item.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(str(item.get("publisher", "")).strip(), failures, f"{source_id}: publisher is required")
        require(len(str(item.get("why_it_matters", ""))) >= 70, failures, f"{source_id}: why_it_matters must be specific")
    for required_class in {"protocol_specification", "government_framework", "industry_standard"}:
        require(required_class in source_classes, failures, f"source_references must include {required_class}")

    contract = as_dict(profile.get("pilot_contract"), "pilot_contract")
    require(
        contract.get("default_state") == "not_sales_ready_until_design_partner_evidence_is_bound",
        failures,
        "pilot_contract.default_state must keep sales claims evidence-gated",
    )
    required_source_keys = validate_pack_keys(
        as_list(contract.get("required_source_pack_keys"), "pilot_contract.required_source_pack_keys"),
        "pilot_contract.required_source_pack_keys",
        failures,
    )
    for key in required_source_keys:
        require(resolve(repo_root, SOURCE_PACKS[key]).exists(), failures, f"{key}: source pack does not exist")
    require(len(as_list(contract.get("required_mcp_tools"), "pilot_contract.required_mcp_tools")) >= 10, failures, "required_mcp_tools are incomplete")
    require(len(as_list(contract.get("required_runtime_fields"), "pilot_contract.required_runtime_fields")) >= 16, failures, "required_runtime_fields are incomplete")
    require(len(as_list(contract.get("hard_gates"), "pilot_contract.hard_gates")) >= 6, failures, "hard_gates are incomplete")

    wedges = as_list(profile.get("monetization_wedges"), "monetization_wedges")
    require(len(wedges) >= int(contract.get("minimum_monetization_wedges") or 0), failures, "monetization_wedges below minimum")
    wedge_ids: set[str] = set()
    for idx, wedge in enumerate(wedges):
        item = as_dict(wedge, f"monetization_wedges[{idx}]")
        wedge_id = str(item.get("id", "")).strip()
        require(bool(wedge_id), failures, f"monetization_wedges[{idx}].id is required")
        require(wedge_id not in wedge_ids, failures, f"{wedge_id}: duplicate wedge id")
        wedge_ids.add(wedge_id)
        validate_pack_keys(as_list(item.get("linked_evidence_pack_keys"), f"{wedge_id}.linked_evidence_pack_keys"), f"{wedge_id}.linked_evidence_pack_keys", failures)
        require(len(as_list(item.get("required_telemetry_fields"), f"{wedge_id}.required_telemetry_fields")) >= 3, failures, f"{wedge_id}: telemetry fields are incomplete")
        require(len(str(item.get("proof_needed", ""))) >= 60, failures, f"{wedge_id}: proof_needed must be specific")

    buyers = as_list(profile.get("buyer_segments"), "buyer_segments")
    require(len(buyers) >= int(contract.get("minimum_buyer_segments") or 0), failures, "buyer_segments below minimum")
    buyer_ids: set[str] = set()
    for idx, buyer in enumerate(buyers):
        item = as_dict(buyer, f"buyer_segments[{idx}]")
        buyer_id = str(item.get("id", "")).strip()
        require(bool(buyer_id), failures, f"buyer_segments[{idx}].id is required")
        require(buyer_id not in buyer_ids, failures, f"{buyer_id}: duplicate buyer id")
        buyer_ids.add(buyer_id)
        primary = {str(wedge_id) for wedge_id in as_list(item.get("primary_wedge_ids"), f"{buyer_id}.primary_wedge_ids")}
        require(not sorted(primary - wedge_ids), failures, f"{buyer_id}: unknown primary_wedge_ids")
        require(len(str(item.get("proof_needed", ""))) >= 60, failures, f"{buyer_id}: proof_needed must be specific")

    phases = as_list(profile.get("pilot_phases"), "pilot_phases")
    require(len(phases) >= int(contract.get("minimum_pilot_phases") or 0), failures, "pilot_phases below minimum")
    phase_ids: set[str] = set()
    for idx, phase in enumerate(phases):
        item = as_dict(phase, f"pilot_phases[{idx}]")
        phase_id = str(item.get("id", "")).strip()
        require(bool(phase_id), failures, f"pilot_phases[{idx}].id is required")
        require(phase_id not in phase_ids, failures, f"{phase_id}: duplicate phase id")
        phase_ids.add(phase_id)
        require(int(item.get("minimum_duration_days") or 0) > 0, failures, f"{phase_id}: minimum_duration_days must be positive")
        validate_pack_keys(as_list(item.get("required_evidence_pack_keys"), f"{phase_id}.required_evidence_pack_keys"), f"{phase_id}.required_evidence_pack_keys", failures)
        require(len(as_list(item.get("required_mcp_tools"), f"{phase_id}.required_mcp_tools")) >= 2, failures, f"{phase_id}: required_mcp_tools are incomplete")
        require(len(as_list(item.get("exit_criteria"), f"{phase_id}.exit_criteria")) >= 3, failures, f"{phase_id}: exit_criteria are incomplete")
        require(len(as_list(item.get("kill_or_hold_signals"), f"{phase_id}.kill_or_hold_signals")) >= 2, failures, f"{phase_id}: kill_or_hold_signals are incomplete")

    metrics = as_list(profile.get("success_metrics"), "success_metrics")
    require(len(metrics) >= int(contract.get("minimum_success_metrics") or 0), failures, "success_metrics below minimum")
    metric_ids: set[str] = set()
    for idx, metric in enumerate(metrics):
        item = as_dict(metric, f"success_metrics[{idx}]")
        metric_id = str(item.get("id", "")).strip()
        require(bool(metric_id), failures, f"success_metrics[{idx}].id is required")
        require(metric_id not in metric_ids, failures, f"{metric_id}: duplicate metric id")
        metric_ids.add(metric_id)
        require(str(item.get("target", "")).strip(), failures, f"{metric_id}: target is required")
        require(str(item.get("telemetry_field", "")).strip(), failures, f"{metric_id}: telemetry_field is required")
        require(str(item.get("owner", "")).strip(), failures, f"{metric_id}: owner is required")

    questions = as_list(profile.get("diligence_questions"), "diligence_questions")
    require(len(questions) >= int(contract.get("minimum_diligence_questions") or 0), failures, "diligence_questions below minimum")
    for idx, question in enumerate(questions):
        item = as_dict(question, f"diligence_questions[{idx}]")
        require(str(item.get("id", "")).strip(), failures, f"diligence_questions[{idx}].id is required")
        require(len(str(item.get("question", ""))) >= 35, failures, f"diligence_questions[{idx}].question is too short")
        require(len(str(item.get("answer", ""))) >= 100, failures, f"diligence_questions[{idx}].answer is too short")

    risks = as_list(profile.get("risk_register"), "risk_register")
    require(len(risks) >= 6, failures, "risk_register must include at least six risks")
    for idx, risk in enumerate(risks):
        item = as_dict(risk, f"risk_register[{idx}]")
        require(str(item.get("id", "")).strip(), failures, f"risk_register[{idx}].id is required")
        require(str(item.get("decision", "")).strip(), failures, f"risk_register[{idx}].decision is required")
        require(len(str(item.get("mitigation", ""))) >= 60, failures, f"risk_register[{idx}].mitigation must be specific")

    telemetry = as_dict(profile.get("telemetry_requirements"), "telemetry_requirements")
    require(telemetry.get("redaction_required") is True, failures, "telemetry_requirements.redaction_required must be true")
    require(len(as_list(telemetry.get("minimum_events"), "telemetry_requirements.minimum_events")) >= 8, failures, "minimum telemetry events are incomplete")
    require(len(as_list(telemetry.get("do_not_capture"), "telemetry_requirements.do_not_capture")) >= 5, failures, "do_not_capture must list sensitive classes")

    pricing = as_dict(profile.get("pricing_guardrails"), "pricing_guardrails")
    require(pricing.get("status") == "guardrails_not_public_list_prices", failures, "pricing guardrails must not be represented as list prices")

    return failures


def load_source_packs(repo_root: Path, keys: set[str]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for key in keys:
        path = resolve(repo_root, SOURCE_PACKS[key])
        try:
            packs[key] = load_json(path)
        except DesignPartnerPilotPackError as exc:
            failures.append(f"{key}: {exc}")
    return packs, failures


def pack_failure_count(pack: dict[str, Any] | None) -> int:
    if not isinstance(pack, dict):
        return 1
    failures = pack.get("failures")
    if isinstance(failures, list):
        return len(failures)
    failure_count = pack.get("failure_count")
    if isinstance(failure_count, int):
        return failure_count
    for summary_key in ["export_summary", "value_model_summary", "pilot_summary"]:
        summary = pack.get(summary_key)
        if isinstance(summary, dict) and isinstance(summary.get("failure_count"), int):
            return int(summary["failure_count"])
    return 0


def pack_summary(pack: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(pack, dict):
        return None
    for key, value in pack.items():
        if key.endswith("_summary") and isinstance(value, dict):
            return {"key": key, "value": value}
    return None


def source_pack_index(repo_root: Path, keys: set[str], packs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in sorted(keys):
        ref = SOURCE_PACKS[key]
        path = resolve(repo_root, ref)
        pack = packs.get(key)
        failure_count = pack_failure_count(pack)
        rows.append(
            {
                "available": path.exists() and isinstance(pack, dict),
                "failure_count": failure_count,
                "key": key,
                "path": normalize_path(ref),
                "schema_version": pack.get("schema_version") if isinstance(pack, dict) else None,
                "sha256": sha256_file(path) if path.exists() else None,
                "status": "ready" if path.exists() and failure_count == 0 else "needs_attention",
                "summary": pack_summary(pack),
            }
        )
    return rows


def source_status_by_key(index: list[dict[str, Any]]) -> dict[str, str]:
    return {str(item.get("key")): str(item.get("status")) for item in index}


def all_sources_ready(keys: list[Any], statuses: dict[str, str]) -> bool:
    return all(statuses.get(str(key)) == "ready" for key in keys)


def enrich_phases(profile: dict[str, Any], statuses: dict[str, str]) -> list[dict[str, Any]]:
    phases = []
    for phase in as_list(profile.get("pilot_phases"), "pilot_phases"):
        item = dict(as_dict(phase, "pilot_phase"))
        keys = [str(key) for key in item.get("required_evidence_pack_keys", [])]
        item["source_pack_status"] = {key: statuses.get(key, "missing") for key in keys}
        item["status"] = "ready" if all_sources_ready(keys, statuses) else "needs_evidence"
        item["phase_hash"] = stable_hash(item)
        phases.append(item)
    return phases


def enrich_wedges(profile: dict[str, Any], statuses: dict[str, str]) -> list[dict[str, Any]]:
    wedges = []
    for wedge in as_list(profile.get("monetization_wedges"), "monetization_wedges"):
        item = dict(as_dict(wedge, "monetization_wedge"))
        keys = [str(key) for key in item.get("linked_evidence_pack_keys", [])]
        telemetry = [str(field) for field in item.get("required_telemetry_fields", [])]
        item["source_pack_status"] = {key: statuses.get(key, "missing") for key in keys}
        item["status"] = "ready_for_design_partner_test" if all_sources_ready(keys, statuses) else "needs_evidence"
        item["telemetry_contract"] = {
            "required_field_count": len(telemetry),
            "required_fields": telemetry,
            "proof_state": "customer_telemetry_required",
        }
        item["wedge_hash"] = stable_hash(item)
        wedges.append(item)
    return wedges


def enrich_metrics(profile: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = []
    for metric in as_list(profile.get("success_metrics"), "success_metrics"):
        item = dict(as_dict(metric, "success_metric"))
        item["status"] = "needs_customer_telemetry"
        item["metric_hash"] = stable_hash(item)
        metrics.append(item)
    return metrics


def readiness_score(
    *,
    source_index: list[dict[str, Any]],
    phases: list[dict[str, Any]],
    wedges: list[dict[str, Any]],
    metrics: list[dict[str, Any]],
    hard_gate_count: int,
) -> dict[str, Any]:
    source_total = max(len(source_index), 1)
    source_ready = sum(1 for item in source_index if item.get("status") == "ready")
    phase_total = max(len(phases), 1)
    phase_ready = sum(1 for item in phases if item.get("status") == "ready")
    wedge_total = max(len(wedges), 1)
    wedge_ready = sum(1 for item in wedges if item.get("status") == "ready_for_design_partner_test")
    metric_total = max(len(metrics), 1)
    metric_defined = sum(1 for item in metrics if item.get("telemetry_field") and item.get("target"))

    raw_score = round(
        (source_ready / source_total) * 35
        + (phase_ready / phase_total) * 20
        + (wedge_ready / wedge_total) * 20
        + (metric_defined / metric_total) * 15
        + min(hard_gate_count / 6, 1) * 10,
        1,
    )
    score: int | float = int(raw_score) if raw_score == int(raw_score) else raw_score
    if source_ready < source_total:
        decision = "hold_for_source_pack_attention"
    elif score >= 90:
        decision = "ready_for_design_partner_outreach"
    elif score >= 75:
        decision = "ready_for_controlled_pilot"
    elif score >= 50:
        decision = "hold_for_productization"
    else:
        decision = "block_until_pilot_foundation_exists"

    return {
        "decision": decision,
        "phase_ready_count": phase_ready,
        "phase_total": phase_total,
        "score": score,
        "source_pack_ready_count": source_ready,
        "source_pack_total": source_total,
        "wedge_ready_count": wedge_ready,
        "wedge_total": wedge_total,
    }


def source_artifacts(
    *,
    repo_root: Path,
    profile_path: Path,
    required_keys: set[str],
) -> dict[str, Any]:
    artifacts: dict[str, Any] = {
        "profile": {
            "path": normalize_path(profile_path),
            "sha256": sha256_file(resolve(repo_root, profile_path)),
        },
        "source_packs": {},
    }
    for key in sorted(required_keys):
        path = resolve(repo_root, SOURCE_PACKS[key])
        artifacts["source_packs"][key] = {
            "path": normalize_path(SOURCE_PACKS[key]),
            "sha256": sha256_file(path) if path.exists() else None,
        }
    return artifacts


def build_pack(profile: dict[str, Any], repo_root: Path, profile_path: Path) -> dict[str, Any]:
    contract = as_dict(profile.get("pilot_contract"), "pilot_contract")
    required_keys = {str(key) for key in as_list(contract.get("required_source_pack_keys"), "required_source_pack_keys")}

    validation_failures = validate_profile(profile, repo_root)
    packs, load_failures = load_source_packs(repo_root, required_keys)
    source_index = source_pack_index(repo_root, required_keys, packs)
    statuses = source_status_by_key(source_index)
    phases = enrich_phases(profile, statuses)
    wedges = enrich_wedges(profile, statuses)
    metrics = enrich_metrics(profile)
    hard_gates = as_list(contract.get("hard_gates"), "pilot_contract.hard_gates")
    readiness = readiness_score(
        source_index=source_index,
        phases=phases,
        wedges=wedges,
        metrics=metrics,
        hard_gate_count=len(hard_gates),
    )
    failures = validation_failures + load_failures

    return {
        "schema_version": PACK_SCHEMA_VERSION,
        "generated_at": profile.get("last_reviewed"),
        "design_partner_pilot_pack_id": "security-recipes-design-partner-pilot-pack",
        "positioning": profile.get("positioning"),
        "pilot_summary": {
            "buyer_segment_count": len(profile.get("buyer_segments", []) or []),
            "decision": readiness["decision"],
            "failure_count": len(failures),
            "monetization_wedge_count": len(wedges),
            "pilot_phase_count": len(phases),
            "readiness_score": readiness["score"],
            "source_pack_ready_count": readiness["source_pack_ready_count"],
            "source_pack_total": readiness["source_pack_total"],
            "success_metric_count": len(metrics),
        },
        "pilot_contract": contract,
        "readiness": readiness,
        "source_references": profile.get("source_references", []),
        "source_pack_index": source_index,
        "buyer_segments": profile.get("buyer_segments", []),
        "pilot_phases": phases,
        "success_metrics": metrics,
        "monetization_wedges": wedges,
        "pricing_guardrails": profile.get("pricing_guardrails", {}),
        "telemetry_requirements": profile.get("telemetry_requirements", {}),
        "diligence_questions": profile.get("diligence_questions", []),
        "risk_register": profile.get("risk_register", []),
        "source_artifacts": source_artifacts(repo_root=repo_root, profile_path=profile_path, required_keys=required_keys),
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if the checked-in pack is stale")
    args = parser.parse_args()

    repo_root = Path.cwd()
    profile_path = args.profile
    output_path = args.output

    try:
        profile = load_json(resolve(repo_root, profile_path))
        pack = build_pack(profile, repo_root, profile_path)
    except DesignPartnerPilotPackError as exc:
        print(f"design partner pilot pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if pack.get("failures"):
            print("design partner pilot pack validation failed:", file=sys.stderr)
            for failure in pack["failures"]:
                print(f"- {failure}", file=sys.stderr)
            return 1
        if not output_path.exists():
            print(f"{output_path} is missing; run scripts/generate_design_partner_pilot_pack.py", file=sys.stderr)
            return 1
        current = output_path.read_text(encoding="utf-8")
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_design_partner_pilot_pack.py", file=sys.stderr)
            return 1
        print(f"Validated design partner pilot pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if pack.get("failures"):
        print("Generated design partner pilot pack with validation failures:", file=sys.stderr)
        for failure in pack["failures"]:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated design partner pilot pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
