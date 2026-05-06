#!/usr/bin/env python3
"""Generate the SecurityRecipes secure context value model.

The value model turns existing evidence packs into a conservative
business-case artifact for enterprise pilots, hosted MCP packaging, and
acquisition diligence. It is intentionally assumption-based: customer
runtime telemetry should replace the default assumptions in a paid
deployment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


MODEL_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/secure-context-value-model-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/secure-context-value-model.json")
DEFAULT_SOURCE_PACKS: dict[str, Path] = {
    "agentic_control_plane_blueprint": Path("data/evidence/agentic-control-plane-blueprint.json"),
    "agentic_protocol_conformance_pack": Path("data/evidence/agentic-protocol-conformance-pack.json"),
    "agentic_readiness_scorecard": Path("data/evidence/agentic-readiness-scorecard.json"),
    "agentic_standards_crosswalk": Path("data/evidence/agentic-standards-crosswalk.json"),
    "agentic_system_bom": Path("data/evidence/agentic-system-bom.json"),
    "agentic_threat_radar": Path("data/evidence/agentic-threat-radar.json"),
    "enterprise_trust_center_export": Path("data/evidence/enterprise-trust-center-export.json"),
    "mcp_risk_coverage_pack": Path("data/evidence/mcp-risk-coverage-pack.json"),
}


class SecureContextValueModelError(RuntimeError):
    """Raised when the value model cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SecureContextValueModelError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SecureContextValueModelError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecureContextValueModelError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SecureContextValueModelError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SecureContextValueModelError(f"{label} must be a list")
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


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == MODEL_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the value model")

    sources = as_list(profile.get("source_references"), "source_references")
    require(len(sources) >= 6, failures, "source_references must include current MCP, NIST, OWASP, and CISA sources")
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
        require(len(str(item.get("why_it_matters", ""))) >= 60, failures, f"{source_id}: why_it_matters must be specific")
    for required_class in {"protocol_specification", "government_framework", "industry_standard"}:
        require(required_class in source_classes, failures, f"source_references must include {required_class}")

    contract = as_dict(profile.get("value_contract"), "value_contract")
    require(
        contract.get("default_state") == "assumption_based_until_customer_runtime_data_is_bound",
        failures,
        "value_contract.default_state must label the model as assumption-based",
    )
    required_pack_keys = {str(item) for item in as_list(contract.get("required_source_pack_keys"), "required_source_pack_keys")}
    missing_source_refs = sorted(required_pack_keys - set(DEFAULT_SOURCE_PACKS))
    require(not missing_source_refs, failures, f"required source pack keys are unknown: {missing_source_refs}")
    for key in required_pack_keys:
        require(resolve(repo_root, DEFAULT_SOURCE_PACKS[key]).exists(), failures, f"{key}: source pack path does not exist: {DEFAULT_SOURCE_PACKS[key]}")
    require(len(as_list(contract.get("required_mcp_tools"), "required_mcp_tools")) >= 5, failures, "required_mcp_tools are incomplete")
    require(len(as_list(contract.get("buyer_success_criteria"), "buyer_success_criteria")) >= 5, failures, "buyer_success_criteria are required")

    value_drivers = as_list(profile.get("value_drivers"), "value_drivers")
    require(len(value_drivers) >= int(contract.get("minimum_value_drivers") or 0), failures, "value_drivers below minimum")
    driver_ids: set[str] = set()
    for idx, driver in enumerate(value_drivers):
        item = as_dict(driver, f"value_drivers[{idx}]")
        driver_id = str(item.get("id", "")).strip()
        require(bool(driver_id), failures, f"value_drivers[{idx}].id is required")
        require(driver_id not in driver_ids, failures, f"{driver_id}: duplicate value driver id")
        driver_ids.add(driver_id)
        for key in as_list(item.get("evidence_pack_keys"), f"{driver_id}.evidence_pack_keys"):
            require(str(key) in DEFAULT_SOURCE_PACKS, failures, f"{driver_id}: unknown evidence_pack_key {key}")
        require(len(str(item.get("why_acquirer_cares", ""))) >= 60, failures, f"{driver_id}: why_acquirer_cares must be specific")

    buyers = as_list(profile.get("buyer_segments"), "buyer_segments")
    require(len(buyers) >= int(contract.get("minimum_buyer_segments") or 0), failures, "buyer_segments below minimum")
    for idx, buyer in enumerate(buyers):
        item = as_dict(buyer, f"buyer_segments[{idx}]")
        buyer_id = str(item.get("id", "")).strip()
        require(bool(buyer_id), failures, f"buyer_segments[{idx}].id is required")
        for driver_id in as_list(item.get("primary_wedge_ids"), f"{buyer_id}.primary_wedge_ids"):
            require(str(driver_id) in driver_ids, failures, f"{buyer_id}: unknown primary_wedge_id {driver_id}")
        require(len(str(item.get("proof_needed", ""))) >= 50, failures, f"{buyer_id}: proof_needed must be specific")

    scenarios = as_list(profile.get("adoption_scenarios"), "adoption_scenarios")
    require(len(scenarios) >= int(contract.get("minimum_adoption_scenarios") or 0), failures, "adoption_scenarios below minimum")
    for idx, scenario in enumerate(scenarios):
        item = as_dict(scenario, f"adoption_scenarios[{idx}]")
        scenario_id = str(item.get("id", "")).strip()
        assumptions = as_dict(item.get("assumptions"), f"{scenario_id}.assumptions")
        for field in [
            "runs_per_month",
            "avoided_engineer_hours_per_run",
            "automation_success_rate",
            "reviewer_hours_per_run",
            "loaded_hourly_cost_usd",
            "annual_platform_cost_usd",
            "implementation_cost_usd",
        ]:
            require(field in assumptions, failures, f"{scenario_id}: missing assumption {field}")
        rate = float(assumptions.get("automation_success_rate") or 0)
        require(0 < rate <= 1, failures, f"{scenario_id}: automation_success_rate must be 0-1")

    questions = as_list(profile.get("diligence_questions"), "diligence_questions")
    require(len(questions) >= int(contract.get("minimum_diligence_questions") or 0), failures, "diligence_questions below minimum")
    for idx, question in enumerate(questions):
        item = as_dict(question, f"diligence_questions[{idx}]")
        require(str(item.get("id", "")).strip(), failures, f"diligence_questions[{idx}].id is required")
        require(len(str(item.get("question", ""))) >= 35, failures, f"diligence_questions[{idx}].question is too short")
        require(len(str(item.get("answer", ""))) >= 80, failures, f"diligence_questions[{idx}].answer is too short")

    wedges = as_list(profile.get("monetization_wedges"), "monetization_wedges")
    require(len(wedges) >= 4, failures, "monetization_wedges must name paid product surfaces")
    return failures


def load_source_packs(repo_root: Path, required_keys: set[str]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for key in required_keys:
        path = resolve(repo_root, DEFAULT_SOURCE_PACKS[key])
        try:
            packs[key] = load_json(path)
        except SecureContextValueModelError as exc:
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
    summary = pack.get("export_summary")
    if isinstance(summary, dict) and isinstance(summary.get("failure_count"), int):
        return int(summary["failure_count"])
    return 0


def pack_summary(pack: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(pack, dict):
        return None
    for key, value in pack.items():
        if key.endswith("_summary") and isinstance(value, dict):
            return {"key": key, "value": value}
    for key in ["export_summary", "protocol_conformance_summary", "crosswalk_summary"]:
        value = pack.get(key)
        if isinstance(value, dict):
            return {"key": key, "value": value}
    return None


def source_pack_index(
    *,
    repo_root: Path,
    required_keys: set[str],
    packs: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for key in sorted(required_keys):
        ref = DEFAULT_SOURCE_PACKS[key]
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


def scenario_economics(scenario: dict[str, Any]) -> dict[str, Any]:
    assumptions = scenario.get("assumptions", {})
    runs = float(assumptions.get("runs_per_month") or 0)
    avoided_hours = float(assumptions.get("avoided_engineer_hours_per_run") or 0)
    success_rate = float(assumptions.get("automation_success_rate") or 0)
    reviewer_hours = float(assumptions.get("reviewer_hours_per_run") or 0)
    hourly_cost = float(assumptions.get("loaded_hourly_cost_usd") or 0)
    annual_platform_cost = float(assumptions.get("annual_platform_cost_usd") or 0)
    implementation_cost = float(assumptions.get("implementation_cost_usd") or 0)

    monthly_avoided_hours = runs * avoided_hours * success_rate
    monthly_review_hours = runs * reviewer_hours
    annual_gross_value = monthly_avoided_hours * hourly_cost * 12
    annual_review_cost = monthly_review_hours * hourly_cost * 12
    annual_net_value = annual_gross_value - annual_review_cost - annual_platform_cost
    first_year_net_after_implementation = annual_net_value - implementation_cost
    monthly_net_value = annual_net_value / 12 if annual_net_value else 0
    payback_months = round(implementation_cost / monthly_net_value, 1) if monthly_net_value > 0 else None
    roi_multiple = round(first_year_net_after_implementation / implementation_cost, 2) if implementation_cost > 0 else None

    def rounded_metric(value: float) -> float | int:
        rounded = round(value, 2)
        return int(rounded) if float(rounded).is_integer() else rounded

    return {
        "annual_gross_value_usd": round(annual_gross_value),
        "annual_net_value_usd": round(annual_net_value),
        "annual_platform_cost_usd": round(annual_platform_cost),
        "annual_review_cost_usd": round(annual_review_cost),
        "assumption_hash": stable_hash(assumptions),
        "first_year_net_after_implementation_usd": round(first_year_net_after_implementation),
        "implementation_cost_usd": round(implementation_cost),
        "model_limitations": [
            "This is not a revenue forecast.",
            "Replace default assumptions with customer telemetry before using it in a commercial proposal.",
            "Excluded benefits include incident avoidance, audit acceleration, and reduced procurement friction unless separately measured."
        ],
        "monthly_avoided_engineer_hours": rounded_metric(monthly_avoided_hours),
        "monthly_review_hours": rounded_metric(monthly_review_hours),
        "payback_months": payback_months,
        "roi_multiple_first_year_after_implementation": roi_multiple,
    }


def build_value_drivers(profile: dict[str, Any], pack_index: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packs_by_key = {str(row.get("key")): row for row in pack_index}
    rows = []
    for driver in profile.get("value_drivers", []) or []:
        if not isinstance(driver, dict):
            continue
        evidence_keys = [str(key) for key in driver.get("evidence_pack_keys", []) or []]
        evidence = [packs_by_key[key] for key in evidence_keys if key in packs_by_key]
        rows.append(
            {
                **driver,
                "evidence_pack_status": evidence,
                "ready_evidence_count": sum(1 for row in evidence if row.get("status") == "ready"),
                "status": "ready" if evidence and all(row.get("status") == "ready" for row in evidence) else "needs_attention",
                "total_evidence_count": len(evidence_keys),
            }
        )
    return rows


def build_scenarios(profile: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for scenario in profile.get("adoption_scenarios", []) or []:
        if isinstance(scenario, dict):
            rows.append({**scenario, "economics": scenario_economics(scenario)})
    return rows


def summarize_existing_evidence(packs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    trust_center = packs.get("enterprise_trust_center_export", {})
    export_summary = trust_center.get("export_summary") if isinstance(trust_center, dict) else {}
    blueprint = packs.get("agentic_control_plane_blueprint", {})
    readiness = packs.get("agentic_readiness_scorecard", {})
    protocol = packs.get("agentic_protocol_conformance_pack", {})
    threat = packs.get("agentic_threat_radar", {})
    standards = packs.get("agentic_standards_crosswalk", {})
    return {
        "control_plane_acquisition_readiness": blueprint.get("acquisition_readiness") if isinstance(blueprint, dict) else None,
        "readiness_summary": readiness.get("readiness_summary") if isinstance(readiness, dict) else None,
        "protocol_conformance_summary": protocol.get("protocol_conformance_summary") if isinstance(protocol, dict) else None,
        "threat_radar_summary": threat.get("threat_radar_summary") if isinstance(threat, dict) else None,
        "standards_crosswalk_summary": standards.get("crosswalk_summary") if isinstance(standards, dict) else None,
        "trust_center_summary": export_summary if isinstance(export_summary, dict) else None,
    }


def value_summary(
    *,
    drivers: list[dict[str, Any]],
    scenarios: list[dict[str, Any]],
    pack_index: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    driver_status = Counter(str(driver.get("status")) for driver in drivers)
    pack_status = Counter(str(pack.get("status")) for pack in pack_index)
    net_values = [
        int(scenario.get("economics", {}).get("annual_net_value_usd") or 0)
        for scenario in scenarios
    ]
    return {
        "annual_net_value_range_usd": {
            "max": max(net_values) if net_values else 0,
            "min": min(net_values) if net_values else 0,
        },
        "default_state": "assumption_based_until_customer_runtime_data_is_bound",
        "failure_count": len(failures),
        "ready_source_pack_count": pack_status.get("ready", 0),
        "scenario_count": len(scenarios),
        "source_pack_count": len(pack_index),
        "source_pack_status_counts": dict(sorted(pack_status.items())),
        "status": "value_model_ready" if not failures and pack_status.get("needs_attention", 0) == 0 else "needs_attention_before_value_model",
        "value_driver_count": len(drivers),
        "value_driver_status_counts": dict(sorted(driver_status.items())),
    }


def source_artifacts(
    *,
    profile_path: Path,
    profile_ref: Path,
    pack_index: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "secure_context_value_model_profile": {
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


def build_pack(
    *,
    profile: dict[str, Any],
    profile_path: Path,
    profile_ref: Path,
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
    packs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    required_keys = {str(item) for item in profile.get("value_contract", {}).get("required_source_pack_keys", [])}
    pack_index = source_pack_index(repo_root=repo_root, required_keys=required_keys, packs=packs)
    drivers = build_value_drivers(profile, pack_index)
    scenarios = build_scenarios(profile)
    return {
        "buyer_segments": profile.get("buyer_segments", []),
        "diligence_questions": profile.get("diligence_questions", []),
        "evidence_rollup": summarize_existing_evidence(packs),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "monetization_wedges": profile.get("monetization_wedges", []),
        "positioning": profile.get("positioning", {}),
        "schema_version": MODEL_SCHEMA_VERSION,
        "secure_context_value_model_id": "security-recipes-secure-context-value-model",
        "source_artifacts": source_artifacts(profile_path=profile_path, profile_ref=profile_ref, pack_index=pack_index),
        "source_pack_index": pack_index,
        "source_references": profile.get("source_references", []),
        "value_contract": profile.get("value_contract", {}),
        "value_drivers": drivers,
        "value_model_summary": value_summary(drivers=drivers, scenarios=scenarios, pack_index=pack_index, failures=failures),
        "adoption_scenarios": scenarios,
        "acquisition_readiness": {
            "current_signal": "credible_open_core_foundation_with_hosted_mcp_gap",
            "credible_exit_condition": "Reach three to five design partners using hosted MCP governance with signed receipts, customer-private context, live connector drift monitoring, and measurable renewal value.",
            "not_yet_proven": [
                "Recurring revenue",
                "Hosted multi-tenant enforcement",
                "Customer-private evidence ingestion",
                "Retention and expansion metrics",
                "Operational SLAs"
            ],
            "why_10_20m_is_plausible_after_execution": "A buyer gets a standards-backed secure context layer between agents, MCP tools, identity, telemetry, and evidence, plus an open corpus that lowers adoption friction."
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in value model is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        failures = validate_profile(profile, repo_root)
        required_keys = {str(item) for item in profile.get("value_contract", {}).get("required_source_pack_keys", [])}
        packs, pack_failures = load_source_packs(repo_root, required_keys)
        failures.extend(pack_failures)
        pack = build_pack(
            profile=profile,
            profile_path=profile_path,
            profile_ref=args.profile,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
            packs=packs,
        )
        for row in pack.get("source_pack_index", []):
            if isinstance(row, dict) and row.get("status") != "ready":
                failures.append(f"{row.get('key')}: source pack is not ready")
    except SecureContextValueModelError as exc:
        print(f"secure context value model generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("secure context value model validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_secure_context_value_model.py", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_secure_context_value_model.py", file=sys.stderr)
            return 1
        print(f"Validated secure context value model: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated secure context value model with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated secure context value model: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
