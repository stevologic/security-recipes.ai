#!/usr/bin/env python3
"""Generate the SecurityRecipes critical-infrastructure secure-context pack.

The pack turns NIST's 2026 critical-infrastructure AI direction plus
existing SecurityRecipes evidence into a buyer-readable, MCP-readable
readiness layer for high-stakes agentic AI and MCP pilots.
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
DEFAULT_PROFILE = Path("data/assurance/critical-infrastructure-secure-context-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/critical-infrastructure-secure-context-pack.json")
VALID_DECISIONS = {
    "allow_ci_read_only_context",
    "allow_ci_supervised_action",
    "hold_for_ci_safety_case",
    "deny_untrusted_ci_context",
    "kill_session_on_ci_hazard_signal",
}


class CriticalInfrastructurePackError(RuntimeError):
    """Raised when the critical-infrastructure pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CriticalInfrastructurePackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise CriticalInfrastructurePackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CriticalInfrastructurePackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CriticalInfrastructurePackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CriticalInfrastructurePackError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def source_pack_rows(profile: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, row in enumerate(as_list(profile.get("evidence_sources"), "evidence_sources")):
        item = as_dict(row, f"evidence_sources[{idx}]")
        pack_id = str(item.get("id", "")).strip()
        if pack_id in seen:
            raise CriticalInfrastructurePackError(f"duplicate evidence source id: {pack_id}")
        seen.add(pack_id)
        rows.append(item)
    return rows


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the critical-infrastructure goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 8, failures, "standards_alignment must include current AI, MCP, OWASP, NIST, and CISA references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicate standard id")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("readiness_contract"), "readiness_contract")
    require(
        contract.get("default_state") == "not_ci_ready_until_secure_context_controls_are_evidence_bound_and_operator_reviewed",
        failures,
        "readiness_contract.default_state must fail closed",
    )
    decisions = {str(item) for item in as_list(contract.get("allowed_decisions"), "readiness_contract.allowed_decisions")}
    require(decisions == VALID_DECISIONS, failures, "readiness_contract.allowed_decisions must match evaluator decisions")
    require(len(as_list(contract.get("required_runtime_evidence"), "readiness_contract.required_runtime_evidence")) >= 15, failures, "runtime evidence fields are incomplete")
    require(len(as_list(contract.get("hazard_flags"), "readiness_contract.hazard_flags")) >= 10, failures, "hazard flags are incomplete")

    sources = source_pack_rows(profile)
    require(len(sources) >= int(contract.get("minimum_evidence_packs") or 0), failures, "evidence_sources below critical-infrastructure minimum")
    source_ids = {str(source.get("id")) for source in sources}
    for source in sources:
        pack_id = str(source.get("id"))
        path = Path(str(source.get("path", "")))
        require(bool(pack_id), failures, "evidence source id is required")
        require(bool(str(source.get("title", "")).strip()), failures, f"{pack_id}: title is required")
        require(bool(str(source.get("path", "")).strip()), failures, f"{pack_id}: path is required")
        require(resolve(repo_root, path).exists(), failures, f"{pack_id}: path does not exist: {path}")
        require(bool(as_list(source.get("mcp_tools"), f"{pack_id}.mcp_tools")), failures, f"{pack_id}: mcp_tools are required")
        require(len(str(source.get("proof_role", ""))) >= 50, failures, f"{pack_id}: proof_role must be specific")

    controls = as_list(profile.get("control_objectives"), "control_objectives")
    require(len(controls) >= int(contract.get("minimum_control_objectives") or 0), failures, "control_objectives below minimum")
    control_ids: set[str] = set()
    for idx, control in enumerate(controls):
        item = as_dict(control, f"control_objectives[{idx}]")
        control_id = str(item.get("id", "")).strip()
        require(bool(control_id), failures, f"control_objectives[{idx}].id is required")
        require(control_id not in control_ids, failures, f"{control_id}: duplicate control id")
        control_ids.add(control_id)
        require(len(str(item.get("control_objective", ""))) >= 100, failures, f"{control_id}: control_objective must be specific")
        evidence_ids = {str(pack_id) for pack_id in as_list(item.get("evidence_pack_ids"), f"{control_id}.evidence_pack_ids")}
        require(not sorted(evidence_ids - source_ids), failures, f"{control_id}: unknown evidence_pack_ids: {sorted(evidence_ids - source_ids)}")
        require(bool(as_list(item.get("mcp_tools"), f"{control_id}.mcp_tools")), failures, f"{control_id}: mcp_tools are required")

    sectors = as_list(profile.get("sector_profiles"), "sector_profiles")
    require(len(sectors) >= int(contract.get("minimum_sector_profiles") or 0), failures, "sector_profiles below minimum")
    sector_ids: set[str] = set()
    for idx, sector in enumerate(sectors):
        item = as_dict(sector, f"sector_profiles[{idx}]")
        sector_id = str(item.get("id", "")).strip()
        require(bool(sector_id), failures, f"sector_profiles[{idx}].id is required")
        require(sector_id not in sector_ids, failures, f"{sector_id}: duplicate sector id")
        sector_ids.add(sector_id)
        required_controls = {str(control_id) for control_id in as_list(item.get("required_control_ids"), f"{sector_id}.required_control_ids")}
        require(not sorted(required_controls - control_ids), failures, f"{sector_id}: unknown required_control_ids: {sorted(required_controls - control_ids)}")
        require(str(item.get("default_decision")) in VALID_DECISIONS, failures, f"{sector_id}: invalid default_decision")
        require(len(str(item.get("operator_evidence_needed", ""))) >= 70, failures, f"{sector_id}: operator_evidence_needed must be specific")

    for idx, lane in enumerate(as_list(profile.get("rollout_lanes"), "rollout_lanes")):
        item = as_dict(lane, f"rollout_lanes[{idx}]")
        require(str(item.get("decision")) in VALID_DECISIONS, failures, f"{item.get('id')}: invalid lane decision")
        require(len(str(item.get("entry_criteria", ""))) >= 50, failures, f"{item.get('id')}: entry_criteria must be specific")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer_views must cover operator, platform, and acquisition")
    for idx, view in enumerate(buyer_views):
        item = as_dict(view, f"buyer_views[{idx}]")
        view_id = str(item.get("id", "")).strip()
        required_controls = {str(control_id) for control_id in as_list(item.get("required_control_ids"), f"{view_id}.required_control_ids")}
        require(not sorted(required_controls - control_ids), failures, f"{view_id}: unknown required_control_ids: {sorted(required_controls - control_ids)}")
        require(len(str(item.get("answer_contract", ""))) >= 80, failures, f"{view_id}: answer_contract must be specific")

    return failures


def load_source_packs(profile: dict[str, Any], repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source in source_pack_rows(profile):
        pack_id = str(source.get("id"))
        try:
            packs[pack_id] = load_json(resolve(repo_root, Path(str(source.get("path")))))
        except CriticalInfrastructurePackError as exc:
            failures.append(f"{pack_id}: {exc}")
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
    for value in pack.values():
        if isinstance(value, dict) and isinstance(value.get("failure_count"), int):
            return int(value["failure_count"])
    return 0


def pack_summary(pack: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(pack, dict):
        return None
    for key, value in pack.items():
        if key.endswith("_summary") and isinstance(value, dict):
            return {"key": key, "value": value}
    for key in ["annex_summary", "readiness_summary", "source_artifacts"]:
        value = pack.get(key)
        if isinstance(value, dict):
            return {"key": key, "value": value}
    return None


def build_evidence_index(profile: dict[str, Any], packs: dict[str, dict[str, Any]], repo_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in source_pack_rows(profile):
        pack_id = str(source.get("id"))
        ref = Path(str(source.get("path")))
        path = resolve(repo_root, ref)
        pack = packs.get(pack_id)
        failure_count = pack_failure_count(pack)
        rows.append(
            {
                "available": path.exists() and isinstance(pack, dict),
                "failure_count": failure_count,
                "id": pack_id,
                "mcp_tools": source.get("mcp_tools", []),
                "path": normalize_path(ref),
                "proof_role": source.get("proof_role"),
                "schema_version": pack.get("schema_version") if isinstance(pack, dict) else None,
                "sha256": sha256_file(path) if path.exists() else None,
                "status": "ready" if path.exists() and failure_count == 0 else "needs_attention",
                "summary": pack_summary(pack),
                "title": source.get("title"),
            }
        )
    return rows


def build_control_objectives(profile: dict[str, Any], evidence_index: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence_by_id = {str(row.get("id")): row for row in evidence_index}
    rows: list[dict[str, Any]] = []
    for control in profile.get("control_objectives", []) or []:
        if not isinstance(control, dict):
            continue
        evidence_ids = [str(item) for item in control.get("evidence_pack_ids", []) or []]
        evidence = [evidence_by_id[pack_id] for pack_id in evidence_ids if pack_id in evidence_by_id]
        ready_count = sum(1 for row in evidence if row.get("status") == "ready")
        rows.append(
            {
                **control,
                "evidence_paths": [row.get("path") for row in evidence],
                "ready_evidence_count": ready_count,
                "status": "ready" if ready_count == len(evidence_ids) else "needs_attention",
                "total_evidence_count": len(evidence_ids),
            }
        )
    return rows


def build_sector_profiles(profile: dict[str, Any], controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    control_by_id = {str(row.get("id")): row for row in controls}
    rows: list[dict[str, Any]] = []
    for sector in profile.get("sector_profiles", []) or []:
        if not isinstance(sector, dict):
            continue
        required_ids = [str(item) for item in sector.get("required_control_ids", []) or []]
        selected = [control_by_id[control_id] for control_id in required_ids if control_id in control_by_id]
        ready_count = sum(1 for control in selected if control.get("status") == "ready")
        status = "ready_for_read_only_pilot" if ready_count == len(required_ids) else "needs_evidence_attention"
        rows.append(
            {
                **sector,
                "control_evidence_paths": sorted({path for control in selected for path in control.get("evidence_paths", [])}),
                "controls": [
                    {
                        "id": control.get("id"),
                        "status": control.get("status"),
                        "title": control.get("title"),
                    }
                    for control in selected
                ],
                "ready_control_count": ready_count,
                "readiness_status": status,
                "total_control_count": len(required_ids),
            }
        )
    return rows


def build_rollout_lanes(profile: dict[str, Any], sectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ready_sector_count = sum(1 for sector in sectors if sector.get("readiness_status") == "ready_for_read_only_pilot")
    rows: list[dict[str, Any]] = []
    for lane in profile.get("rollout_lanes", []) or []:
        if not isinstance(lane, dict):
            continue
        rows.append(
            {
                **lane,
                "ready_sector_count": ready_sector_count,
                "sector_count": len(sectors),
                "status": "ready" if lane.get("decision") == "allow_ci_read_only_context" and ready_sector_count else "operator_review_required",
            }
        )
    return rows


def build_buyer_views(profile: dict[str, Any], controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    control_by_id = {str(row.get("id")): row for row in controls}
    rows: list[dict[str, Any]] = []
    for view in profile.get("buyer_views", []) or []:
        if not isinstance(view, dict):
            continue
        required_ids = [str(item) for item in view.get("required_control_ids", []) or []]
        selected = [control_by_id[control_id] for control_id in required_ids if control_id in control_by_id]
        rows.append(
            {
                **view,
                "controls": [
                    {
                        "id": control.get("id"),
                        "mcp_tools": control.get("mcp_tools", []),
                        "status": control.get("status"),
                        "title": control.get("title"),
                    }
                    for control in selected
                ],
                "ready_control_count": sum(1 for control in selected if control.get("status") == "ready"),
            }
        )
    return rows


def build_summary(
    evidence_index: list[dict[str, Any]],
    controls: list[dict[str, Any]],
    sectors: list[dict[str, Any]],
    lanes: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    evidence_status = Counter(str(row.get("status")) for row in evidence_index)
    control_status = Counter(str(row.get("status")) for row in controls)
    sector_status = Counter(str(row.get("readiness_status")) for row in sectors)
    lane_status = Counter(str(row.get("status")) for row in lanes)
    mcp_tools = sorted({str(tool) for row in evidence_index for tool in row.get("mcp_tools", [])})
    ready = not failures and evidence_status.get("needs_attention", 0) == 0 and control_status.get("needs_attention", 0) == 0
    return {
        "control_count": len(controls),
        "control_status_counts": dict(sorted(control_status.items())),
        "distinct_mcp_tool_count": len(mcp_tools),
        "evidence_pack_count": len(evidence_index),
        "evidence_status_counts": dict(sorted(evidence_status.items())),
        "failure_count": len(failures),
        "lane_count": len(lanes),
        "lane_status_counts": dict(sorted(lane_status.items())),
        "ready_sector_count": sector_status.get("ready_for_read_only_pilot", 0),
        "sector_count": len(sectors),
        "sector_status_counts": dict(sorted(sector_status.items())),
        "status": "critical_infrastructure_secure_context_ready" if ready else "needs_attention_before_ci_review",
    }


def source_artifacts(profile_path: Path, profile_ref: Path, evidence_index: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "critical_infrastructure_secure_context_profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(profile_path),
        },
        "evidence_packs": [
            {
                "id": row.get("id"),
                "path": row.get("path"),
                "sha256": row.get("sha256"),
            }
            for row in evidence_index
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
    evidence_index = build_evidence_index(profile, packs, repo_root)
    controls = build_control_objectives(profile, evidence_index)
    sectors = build_sector_profiles(profile, controls)
    lanes = build_rollout_lanes(profile, sectors)
    buyer_views = build_buyer_views(profile, controls)
    return {
        "buyer_views": buyer_views,
        "commercialization_path": profile.get("commercialization_path", {}),
        "control_objectives": controls,
        "critical_infrastructure_summary": build_summary(evidence_index, controls, sectors, lanes, failures),
        "evidence_index": evidence_index,
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "readiness_contract": profile.get("readiness_contract", {}),
        "rollout_lanes": lanes,
        "schema_version": PACK_SCHEMA_VERSION,
        "sector_profiles": sectors,
        "source_artifacts": source_artifacts(profile_path, profile_ref, evidence_index),
        "standards_alignment": profile.get("standards_alignment", []),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in critical-infrastructure pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        failures = validate_profile(profile, repo_root)
        packs, pack_failures = load_source_packs(profile, repo_root)
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
        for row in pack.get("evidence_index", []):
            if isinstance(row, dict) and row.get("status") != "ready":
                failures.append(f"{row.get('id')}: evidence source is not ready")
    except CriticalInfrastructurePackError as exc:
        print(f"critical-infrastructure secure-context pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("critical-infrastructure secure-context validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_critical_infrastructure_secure_context_pack.py", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_critical_infrastructure_secure_context_pack.py", file=sys.stderr)
            return 1
        print(f"Validated critical-infrastructure secure-context pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated critical-infrastructure secure-context pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated critical-infrastructure secure-context pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
