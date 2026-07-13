#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic catastrophic-risk annex.

The annex is the severe-risk assurance layer for the secure context
control plane. It maps current agentic AI risk guidance to generated
evidence packs, high-impact scenarios, runtime decisions, and buyer
diligence views.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ANNEX_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-catastrophic-risk-annex.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-catastrophic-risk-annex.json")
VALID_DECISIONS = {
    "allow_bounded_agent_action",
    "allow_reviewed_high_impact_action",
    "hold_for_catastrophic_risk_review",
    "deny_unbounded_autonomy",
    "kill_session_on_catastrophic_signal",
}


class CatastrophicRiskAnnexError(RuntimeError):
    """Raised when the catastrophic-risk annex cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CatastrophicRiskAnnexError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise CatastrophicRiskAnnexError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CatastrophicRiskAnnexError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatastrophicRiskAnnexError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CatastrophicRiskAnnexError(f"{label} must be a list")
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
    for idx, source in enumerate(as_list(profile.get("source_pack_catalog"), "source_pack_catalog")):
        item = as_dict(source, f"source_pack_catalog[{idx}]")
        source_id = str(item.get("id", "")).strip()
        if source_id in seen:
            raise CatastrophicRiskAnnexError(f"duplicate source pack id: {source_id}")
        seen.add(source_id)
        rows.append(item)
    return rows


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == ANNEX_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the annex goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include current severe-risk references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicate standard id")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("annex_contract"), "annex_contract")
    require(
        contract.get("default_state") == "blocked_until_high_impact_autonomy_has_explicit_evidence_and_review",
        failures,
        "annex_contract.default_state must fail closed",
    )
    require(len(as_list(contract.get("board_level_success_criteria"), "annex_contract.board_level_success_criteria")) >= 5, failures, "board success criteria are required")
    require(len(as_list(contract.get("required_runtime_evidence"), "annex_contract.required_runtime_evidence")) >= 12, failures, "runtime evidence fields are incomplete")

    runtime_contract = as_dict(profile.get("runtime_decision_contract"), "runtime_decision_contract")
    require(bool(as_list(runtime_contract.get("high_impact_action_classes"), "runtime_decision_contract.high_impact_action_classes")), failures, "high-impact action classes are required")
    require(bool(as_list(runtime_contract.get("catastrophic_flags"), "runtime_decision_contract.catastrophic_flags")), failures, "catastrophic flags are required")
    for decision_key in ["allow_decisions", "hold_decisions", "deny_decisions", "kill_decisions"]:
        decisions = as_list(runtime_contract.get(decision_key), f"runtime_decision_contract.{decision_key}")
        require(bool(decisions), failures, f"{decision_key} must not be empty")
        for decision in decisions:
            require(str(decision) in VALID_DECISIONS, failures, f"unknown runtime decision: {decision}")

    sources = source_pack_rows(profile)
    minimum_source_packs = int(contract.get("minimum_source_packs") or 0)
    require(len(sources) >= minimum_source_packs, failures, "source_pack_catalog below annex minimum")
    source_ids = {str(source.get("id")) for source in sources}
    for source in sources:
        source_id = str(source.get("id"))
        path = Path(str(source.get("path", "")))
        require(bool(source_id), failures, "source pack id is required")
        require(bool(str(source.get("title", "")).strip()), failures, f"{source_id}: title is required")
        require(bool(str(source.get("path", "")).strip()), failures, f"{source_id}: path is required")
        require(resolve(repo_root, path).exists(), failures, f"{source_id}: path does not exist: {path}")
        require(bool(as_list(source.get("mcp_tools"), f"{source_id}.mcp_tools")), failures, f"{source_id}: mcp_tools are required")

    scenarios = as_list(profile.get("catastrophic_scenarios"), "catastrophic_scenarios")
    require(len(scenarios) >= int(contract.get("minimum_scenarios") or 0), failures, "catastrophic_scenarios below annex minimum")
    scenario_ids: set[str] = set()
    for idx, scenario in enumerate(scenarios):
        item = as_dict(scenario, f"catastrophic_scenarios[{idx}]")
        scenario_id = str(item.get("id", "")).strip()
        require(bool(scenario_id), failures, f"catastrophic_scenarios[{idx}].id is required")
        require(scenario_id not in scenario_ids, failures, f"{scenario_id}: duplicate scenario id")
        scenario_ids.add(scenario_id)
        require(len(str(item.get("board_question", ""))) >= 70, failures, f"{scenario_id}: board_question must be specific")
        required_packs = {str(pack_id) for pack_id in as_list(item.get("required_pack_ids"), f"{scenario_id}.required_pack_ids")}
        require(len(required_packs) >= 3, failures, f"{scenario_id}: at least three required packs are needed")
        require(not sorted(required_packs - source_ids), failures, f"{scenario_id}: unknown required_pack_ids: {sorted(required_packs - source_ids)}")
        require(bool(as_list(item.get("required_mcp_tools"), f"{scenario_id}.required_mcp_tools")), failures, f"{scenario_id}: required_mcp_tools are required")
        require(str(item.get("default_decision")) in VALID_DECISIONS, failures, f"{scenario_id}: default_decision is invalid")
        require(len(str(item.get("promotion_gate", ""))) >= 70, failures, f"{scenario_id}: promotion_gate must be specific")

    controls = as_list(profile.get("annex_controls"), "annex_controls")
    require(len(controls) >= int(contract.get("minimum_controls") or 0), failures, "annex_controls below annex minimum")
    control_ids: set[str] = set()
    for idx, control in enumerate(controls):
        item = as_dict(control, f"annex_controls[{idx}]")
        control_id = str(item.get("id", "")).strip()
        require(bool(control_id), failures, f"annex_controls[{idx}].id is required")
        require(control_id not in control_ids, failures, f"{control_id}: duplicate control id")
        control_ids.add(control_id)
        require(len(str(item.get("control_objective", ""))) >= 80, failures, f"{control_id}: control_objective must be specific")
        control_scenarios = {str(scenario_id) for scenario_id in as_list(item.get("scenario_ids"), f"{control_id}.scenario_ids")}
        require(not sorted(control_scenarios - scenario_ids), failures, f"{control_id}: unknown scenario_ids: {sorted(control_scenarios - scenario_ids)}")
        control_packs = {str(pack_id) for pack_id in as_list(item.get("evidence_pack_ids"), f"{control_id}.evidence_pack_ids")}
        require(not sorted(control_packs - source_ids), failures, f"{control_id}: unknown evidence_pack_ids: {sorted(control_packs - source_ids)}")
        require(bool(as_list(item.get("mcp_tools"), f"{control_id}.mcp_tools")), failures, f"{control_id}: mcp_tools are required")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer_views must include board, platform, and diligence views")
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
        path = resolve(repo_root, Path(str(source.get("path"))))
        try:
            packs[pack_id] = load_json(path)
        except CatastrophicRiskAnnexError as exc:
            failures.append(f"{pack_id}: {exc}")
    return packs, failures


def pack_failure_count(pack: dict[str, Any] | None) -> int:
    if not isinstance(pack, dict):
        return 1
    failures = pack.get("failures")
    if isinstance(failures, list):
        return len(failures)
    for key in [
        "failure_count",
        "policy_summary",
        "readiness_summary",
        "red_team_summary",
        "measurement_probe_summary",
        "receipt_summary",
        "authorization_summary",
    ]:
        value = pack.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, dict) and isinstance(value.get("failure_count"), int):
            return int(value.get("failure_count"))
    return 0


def pack_summary(pack: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(pack, dict):
        return None
    for key in [
        "acquisition_readiness",
        "assurance_summary",
        "authorization_summary",
        "capability_risk_summary",
        "egress_boundary_summary",
        "handoff_boundary_summary",
        "identity_summary",
        "measurement_probe_summary",
        "memory_boundary_summary",
        "policy_summary",
        "readiness_summary",
        "receipt_summary",
        "red_team_summary",
        "skill_supply_chain_summary",
        "workflow_summary",
    ]:
        value = pack.get(key)
        if isinstance(value, dict):
            return {"key": key, "value": value}
    return None


def build_source_pack_index(
    profile: dict[str, Any],
    packs: dict[str, dict[str, Any]],
    repo_root: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in source_pack_rows(profile):
        pack_id = str(source.get("id"))
        rel_path = Path(str(source.get("path")))
        path = resolve(repo_root, rel_path)
        pack = packs.get(pack_id)
        failure_count = pack_failure_count(pack)
        rows.append(
            {
                "available": path.exists() and isinstance(pack, dict),
                "failure_count": failure_count,
                "id": pack_id,
                "mcp_tools": source.get("mcp_tools", []),
                "path": normalize_path(rel_path),
                "schema_version": pack.get("schema_version") if isinstance(pack, dict) else None,
                "sha256": sha256_file(path) if path.exists() else None,
                "status": "ready" if path.exists() and failure_count == 0 else "needs_attention",
                "summary": pack_summary(pack),
                "title": source.get("title"),
            }
        )
    return rows


def build_scenarios(profile: dict[str, Any], pack_index: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packs_by_id = {str(pack.get("id")): pack for pack in pack_index}
    rows: list[dict[str, Any]] = []
    for scenario in as_list(profile.get("catastrophic_scenarios"), "catastrophic_scenarios"):
        item = as_dict(scenario, "catastrophic_scenario")
        required_pack_ids = [str(pack_id) for pack_id in item.get("required_pack_ids", [])]
        evidence = [packs_by_id[pack_id] for pack_id in required_pack_ids if pack_id in packs_by_id]
        ready_count = sum(1 for pack in evidence if pack.get("status") == "ready")
        rows.append(
            {
                "board_question": item.get("board_question"),
                "buyer_value": item.get("buyer_value"),
                "default_decision": item.get("default_decision"),
                "evidence_coverage_score": round((ready_count / max(len(required_pack_ids), 1)) * 100, 2),
                "evidence_paths": [pack.get("path") for pack in evidence],
                "id": item.get("id"),
                "impact_domain": item.get("impact_domain"),
                "promotion_gate": item.get("promotion_gate"),
                "ready_evidence_count": ready_count,
                "required_mcp_tools": item.get("required_mcp_tools", []),
                "required_pack_ids": required_pack_ids,
                "status": "ready" if ready_count == len(required_pack_ids) else "needs_attention",
                "title": item.get("title"),
                "trigger_action_classes": item.get("trigger_action_classes", []),
            }
        )
    return rows


def build_controls(profile: dict[str, Any], pack_index: list[dict[str, Any]], scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packs_by_id = {str(pack.get("id")): pack for pack in pack_index}
    scenarios_by_id = {str(scenario.get("id")): scenario for scenario in scenarios}
    rows: list[dict[str, Any]] = []
    for control in as_list(profile.get("annex_controls"), "annex_controls"):
        item = as_dict(control, "annex_control")
        evidence_ids = [str(pack_id) for pack_id in item.get("evidence_pack_ids", [])]
        evidence = [packs_by_id[pack_id] for pack_id in evidence_ids if pack_id in packs_by_id]
        scenario_ids = [str(scenario_id) for scenario_id in item.get("scenario_ids", [])]
        ready_count = sum(1 for pack in evidence if pack.get("status") == "ready")
        rows.append(
            {
                "control_objective": item.get("control_objective"),
                "diligence_question": item.get("diligence_question"),
                "evidence_paths": [pack.get("path") for pack in evidence],
                "evidence_pack_ids": evidence_ids,
                "id": item.get("id"),
                "mcp_tools": item.get("mcp_tools", []),
                "ready_evidence_count": ready_count,
                "scenario_ids": scenario_ids,
                "scenarios": [
                    {
                        "default_decision": scenarios_by_id[scenario_id].get("default_decision"),
                        "id": scenario_id,
                        "impact_domain": scenarios_by_id[scenario_id].get("impact_domain"),
                        "title": scenarios_by_id[scenario_id].get("title"),
                    }
                    for scenario_id in scenario_ids
                    if scenario_id in scenarios_by_id
                ],
                "status": "ready" if ready_count == len(evidence_ids) else "needs_attention",
                "title": item.get("title"),
            }
        )
    return rows


def build_buyer_views(profile: dict[str, Any], controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    controls_by_id = {str(control.get("id")): control for control in controls}
    rows: list[dict[str, Any]] = []
    for view in as_list(profile.get("buyer_views"), "buyer_views"):
        item = as_dict(view, "buyer_view")
        required_control_ids = [str(control_id) for control_id in item.get("required_control_ids", [])]
        selected = [controls_by_id[control_id] for control_id in required_control_ids if control_id in controls_by_id]
        rows.append(
            {
                "answer_contract": item.get("answer_contract"),
                "control_count": len(selected),
                "controls": selected,
                "id": item.get("id"),
                "question": item.get("question"),
                "required_control_ids": required_control_ids,
                "title": item.get("title"),
            }
        )
    return rows


def build_summary(
    profile: dict[str, Any],
    pack_index: list[dict[str, Any]],
    scenarios: list[dict[str, Any]],
    controls: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    scenario_status = Counter(str(scenario.get("status")) for scenario in scenarios)
    control_status = Counter(str(control.get("status")) for control in controls)
    pack_status = Counter(str(pack.get("status")) for pack in pack_index)
    decision_counts = Counter(str(scenario.get("default_decision")) for scenario in scenarios)
    mcp_tools = sorted(
        {
            str(tool)
            for source in source_pack_rows(profile)
            for tool in source.get("mcp_tools", [])
        }
        | {
            str(tool)
            for scenario in scenarios
            for tool in scenario.get("required_mcp_tools", [])
        }
    )
    ready = not failures and scenario_status.get("needs_attention", 0) == 0 and control_status.get("needs_attention", 0) == 0
    return {
        "control_count": len(controls),
        "control_status_counts": dict(sorted(control_status.items())),
        "default_decision_counts": dict(sorted(decision_counts.items())),
        "distinct_mcp_tool_count": len(mcp_tools),
        "failure_count": len(failures),
        "high_impact_action_class_count": len(profile.get("runtime_decision_contract", {}).get("high_impact_action_classes", []) or []),
        "ready_source_pack_count": pack_status.get("ready", 0),
        "scenario_count": len(scenarios),
        "scenario_status_counts": dict(sorted(scenario_status.items())),
        "source_pack_count": len(pack_index),
        "source_pack_status_counts": dict(sorted(pack_status.items())),
        "status": "catastrophic_risk_annex_ready" if ready else "needs_attention_before_high_impact_autonomy",
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
    pack_index = build_source_pack_index(profile, packs, repo_root)
    scenarios = build_scenarios(profile, pack_index)
    controls = build_controls(profile, pack_index, scenarios)
    return {
        "annex_contract": profile.get("annex_contract", {}),
        "annex_controls": controls,
        "annex_summary": build_summary(profile, pack_index, scenarios, controls, failures),
        "buyer_views": build_buyer_views(profile, controls),
        "catastrophic_scenarios": scenarios,
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": {
            "board_level_claim": "SecurityRecipes exposes a testable catastrophic-risk annex for agentic AI: high-impact action classes, default decisions, kill signals, source evidence, and MCP tools are machine-readable before agents act.",
            "default_questions_answered": [
                "Which severe scenarios are in scope?",
                "Which actions require human approval and risk acceptance?",
                "Which runtime signals kill a session?",
                "Which evidence packs and MCP tools prove readiness?",
                "Which gaps block high-impact autonomy?"
            ],
            "recommended_first_use": "Attach this annex to board AI risk review, AI platform intake, high-impact MCP tool approval, procurement security review, and acquisition diligence.",
            "sales_motion": "Lead with open severe-risk evidence, then sell hosted approval receipts, runtime kill policy, customer-specific risk acceptance, replay, and trust-center exports."
        },
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "runtime_decision_contract": profile.get("runtime_decision_contract", {}),
        "schema_version": ANNEX_SCHEMA_VERSION,
        "source_artifacts": {
            "annex_profile": {
                "path": normalize_path(profile_ref),
                "sha256": sha256_file(profile_path),
            },
            "source_packs": pack_index,
        },
        "standards_alignment": profile.get("standards_alignment", []),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in catastrophic-risk annex is stale.")
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
    except CatastrophicRiskAnnexError as exc:
        print(f"agentic catastrophic-risk annex generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("agentic catastrophic-risk annex validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(f"{output_path} is stale; run scripts/generate_agentic_catastrophic_risk_annex.py", file=sys.stderr)
            return 1
        print(f"Validated agentic catastrophic-risk annex: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agentic catastrophic-risk annex with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic catastrophic-risk annex: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
