#!/usr/bin/env python3
"""Generate the SecurityRecipes secure context buyer diligence brief.

The brief compresses the existing control-plane, trust-center, value,
pilot, source-freshness, protocol, authorization, telemetry, receipt,
app-intake, and posture evidence into one buyer-facing packet. It is
designed for enterprise review, VC diligence, and acquisition
conversations where the first question is not "do you have artifacts?"
but "which artifacts answer the reviewer's objections?"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


BRIEF_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/secure-context-buyer-diligence-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/secure-context-buyer-diligence-brief.json")


class BuyerDiligenceBriefError(RuntimeError):
    """Raised when the buyer diligence brief cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BuyerDiligenceBriefError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise BuyerDiligenceBriefError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise BuyerDiligenceBriefError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BuyerDiligenceBriefError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise BuyerDiligenceBriefError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def source_pack_rows(profile: dict[str, Any]) -> list[dict[str, Any]]:
    rows = as_list(profile.get("source_packs"), "source_packs")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, row in enumerate(rows):
        item = as_dict(row, f"source_packs[{idx}]")
        key = str(item.get("key", "")).strip()
        if key in seen:
            raise BuyerDiligenceBriefError(f"source_packs duplicate key: {key}")
        seen.add(key)
        output.append(item)
    return output


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == BRIEF_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the diligence goal")

    sources = as_list(profile.get("source_references"), "source_references")
    require(len(sources) >= 8, failures, "source_references must include current AI, MCP, A2A, telemetry, government, and industry references")
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
    for required_class in {
        "frontier_platform_guidance",
        "government_framework",
        "industry_standard",
        "protocol_specification",
        "telemetry_standard",
    }:
        require(required_class in source_classes, failures, f"source_references must include {required_class}")

    features = as_list(profile.get("features_assessed"), "features_assessed")
    require(len(features) >= 3, failures, "features_assessed must document alternatives considered")
    selected_features = [
        feature
        for feature in features
        if isinstance(feature, dict) and feature.get("decision") == "selected"
    ]
    require(
        any(feature.get("id") == "buyer-diligence-brief" for feature in selected_features),
        failures,
        "features_assessed must mark buyer-diligence-brief as the selected feature",
    )
    for idx, feature in enumerate(features):
        item = as_dict(feature, f"features_assessed[{idx}]")
        require(bool(str(item.get("decision", "")).strip()), failures, f"features_assessed[{idx}].decision is required")
        require(len(str(item.get("assessment", ""))) >= 70, failures, f"features_assessed[{idx}].assessment must be specific")

    contract = as_dict(profile.get("diligence_contract"), "diligence_contract")
    require(
        contract.get("default_state") == "reference_evidence_ready_customer_runtime_proof_required",
        failures,
        "diligence_contract.default_state must separate reference evidence from customer proof",
    )
    require(len(as_list(contract.get("buyer_success_criteria"), "buyer_success_criteria")) >= 5, failures, "buyer_success_criteria are required")
    require(len(as_list(contract.get("required_mcp_tools"), "required_mcp_tools")) >= 10, failures, "required_mcp_tools are incomplete")

    packs = source_pack_rows(profile)
    minimum_packs = int(contract.get("minimum_source_packs") or 0)
    require(len(packs) >= minimum_packs, failures, "source_packs below buyer diligence minimum")
    pack_keys = {str(pack.get("key")) for pack in packs}
    required_keys = {str(key) for key in as_list(contract.get("required_source_pack_keys"), "required_source_pack_keys")}
    require(not sorted(required_keys - pack_keys), failures, f"required source packs are missing: {sorted(required_keys - pack_keys)}")
    for pack in packs:
        key = str(pack.get("key", "")).strip()
        path = Path(str(pack.get("path", "")))
        require(bool(key), failures, "source pack key is required")
        require(bool(str(pack.get("title", "")).strip()), failures, f"{key}: title is required")
        require(bool(str(pack.get("proof_role", "")).strip()), failures, f"{key}: proof_role is required")
        require(resolve(repo_root, path).exists(), failures, f"{key}: path does not exist: {path}")
        require(bool(as_list(pack.get("mcp_tools"), f"{key}.mcp_tools")), failures, f"{key}: mcp_tools are required")

    buyers = as_list(profile.get("buyer_briefs"), "buyer_briefs")
    require(len(buyers) >= int(contract.get("minimum_buyer_briefs") or 0), failures, "buyer_briefs below diligence minimum")
    buyer_ids: set[str] = set()
    for idx, buyer in enumerate(buyers):
        item = as_dict(buyer, f"buyer_briefs[{idx}]")
        buyer_id = str(item.get("id", "")).strip()
        require(bool(buyer_id), failures, f"buyer_briefs[{idx}].id is required")
        require(buyer_id not in buyer_ids, failures, f"{buyer_id}: duplicate buyer id")
        buyer_ids.add(buyer_id)
        show_first = {str(key) for key in as_list(item.get("show_first_pack_keys"), f"{buyer_id}.show_first_pack_keys")}
        require(not sorted(show_first - pack_keys), failures, f"{buyer_id}: unknown show_first_pack_keys {sorted(show_first - pack_keys)}")
        require(len(str(item.get("short_pitch", ""))) >= 100, failures, f"{buyer_id}: short_pitch must be specific")
        require(len(str(item.get("customer_evidence_needed", ""))) >= 60, failures, f"{buyer_id}: customer_evidence_needed must be specific")

    questions = as_list(profile.get("enterprise_questions"), "enterprise_questions")
    require(len(questions) >= int(contract.get("minimum_enterprise_questions") or 0), failures, "enterprise_questions below diligence minimum")
    question_ids: set[str] = set()
    for idx, question in enumerate(questions):
        item = as_dict(question, f"enterprise_questions[{idx}]")
        question_id = str(item.get("id", "")).strip()
        require(bool(question_id), failures, f"enterprise_questions[{idx}].id is required")
        require(question_id not in question_ids, failures, f"{question_id}: duplicate question id")
        question_ids.add(question_id)
        evidence = {str(key) for key in as_list(item.get("evidence_pack_keys"), f"{question_id}.evidence_pack_keys")}
        require(not sorted(evidence - pack_keys), failures, f"{question_id}: unknown evidence_pack_keys {sorted(evidence - pack_keys)}")
        require(len(str(item.get("question", ""))) >= 40, failures, f"{question_id}: question must be specific")
        require(len(str(item.get("short_answer", ""))) >= 100, failures, f"{question_id}: short_answer must be specific")
        require(bool(as_list(item.get("mcp_tools"), f"{question_id}.mcp_tools")), failures, f"{question_id}: mcp_tools are required")

    objections = as_list(profile.get("objection_handlers"), "objection_handlers")
    require(len(objections) >= int(contract.get("minimum_objection_handlers") or 0), failures, "objection_handlers below diligence minimum")
    for idx, objection in enumerate(objections):
        item = as_dict(objection, f"objection_handlers[{idx}]")
        objection_id = str(item.get("id", "")).strip()
        evidence = {str(key) for key in as_list(item.get("evidence_pack_keys"), f"{objection_id}.evidence_pack_keys")}
        require(bool(objection_id), failures, f"objection_handlers[{idx}].id is required")
        require(not sorted(evidence - pack_keys), failures, f"{objection_id}: unknown evidence_pack_keys {sorted(evidence - pack_keys)}")
        require(len(str(item.get("answer", ""))) >= 120, failures, f"{objection_id}: answer must be specific")
        require(len(str(item.get("next_proof", ""))) >= 50, failures, f"{objection_id}: next_proof must be specific")

    bets = as_list(profile.get("industry_bets"), "industry_bets")
    require(len(bets) >= 3, failures, "industry_bets must describe current market theses")
    for idx, bet in enumerate(bets):
        item = as_dict(bet, f"industry_bets[{idx}]")
        bet_id = str(item.get("id", "")).strip()
        refs = {str(source_id) for source_id in as_list(item.get("source_reference_ids"), f"{bet_id}.source_reference_ids")}
        require(bool(bet_id), failures, f"industry_bets[{idx}].id is required")
        require(not sorted(refs - source_ids), failures, f"{bet_id}: unknown source_reference_ids {sorted(refs - source_ids)}")
        require(len(str(item.get("monetizable_surface", ""))) >= 50, failures, f"{bet_id}: monetizable_surface must be specific")

    next_steps = as_list(profile.get("deal_room_next_steps"), "deal_room_next_steps")
    require(len(next_steps) >= 3, failures, "deal_room_next_steps must name the next proof points")
    return failures


def load_packs(profile: dict[str, Any], repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source in source_pack_rows(profile):
        key = str(source.get("key"))
        path = resolve(repo_root, Path(str(source.get("path"))))
        try:
            packs[key] = load_json(path)
        except BuyerDiligenceBriefError as exc:
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
    for key in ["export_summary", "value_model_summary", "pilot_summary", "brief_summary"]:
        summary = pack.get(key)
        if isinstance(summary, dict) and isinstance(summary.get("failure_count"), int):
            return int(summary["failure_count"])
    return 0


def pack_summary(pack: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(pack, dict):
        return None
    for key, value in pack.items():
        if key.endswith("_summary") and isinstance(value, dict):
            return {"key": key, "value": value}
    for key in ["export_summary", "value_model_summary", "pilot_summary", "posture_summary"]:
        value = pack.get(key)
        if isinstance(value, dict):
            return {"key": key, "value": value}
    return None


def build_pack_index(profile: dict[str, Any], packs: dict[str, dict[str, Any]], repo_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in source_pack_rows(profile):
        key = str(source.get("key"))
        ref = Path(str(source.get("path")))
        path = resolve(repo_root, ref)
        pack = packs.get(key)
        failure_count = pack_failure_count(pack)
        rows.append(
            {
                "available": path.exists() and isinstance(pack, dict),
                "failure_count": failure_count,
                "key": key,
                "mcp_tools": source.get("mcp_tools", []),
                "path": normalize_path(ref),
                "proof_role": source.get("proof_role"),
                "required": bool(source.get("required", True)),
                "schema_version": pack.get("schema_version") if isinstance(pack, dict) else None,
                "sha256": sha256_file(path) if path.exists() else None,
                "status": "ready" if path.exists() and failure_count == 0 else "needs_attention",
                "summary": pack_summary(pack),
                "title": source.get("title"),
            }
        )
    return rows


def evidence_status(pack_keys: list[str], packs_by_key: dict[str, dict[str, Any]]) -> dict[str, Any]:
    evidence = [packs_by_key[key] for key in pack_keys if key in packs_by_key]
    missing = [key for key in pack_keys if key not in packs_by_key]
    ready_count = sum(1 for row in evidence if row.get("status") == "ready")
    return {
        "evidence_paths": [row.get("path") for row in evidence],
        "missing_pack_keys": missing,
        "ready_evidence_count": ready_count,
        "status": "reference_evidence_ready" if not missing and ready_count == len(pack_keys) else "needs_source_pack_attention",
        "total_evidence_count": len(pack_keys),
    }


def build_buyer_briefs(profile: dict[str, Any], pack_index: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packs_by_key = {str(row.get("key")): row for row in pack_index}
    rows: list[dict[str, Any]] = []
    for buyer in profile.get("buyer_briefs", []) or []:
        if not isinstance(buyer, dict):
            continue
        pack_keys = [str(key) for key in buyer.get("show_first_pack_keys", []) or []]
        rows.append({**buyer, "evidence_status": evidence_status(pack_keys, packs_by_key)})
    return rows


def build_questions(profile: dict[str, Any], pack_index: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packs_by_key = {str(row.get("key")): row for row in pack_index}
    rows: list[dict[str, Any]] = []
    for question in profile.get("enterprise_questions", []) or []:
        if not isinstance(question, dict):
            continue
        pack_keys = [str(key) for key in question.get("evidence_pack_keys", []) or []]
        rows.append({**question, "evidence_status": evidence_status(pack_keys, packs_by_key)})
    return rows


def build_objections(profile: dict[str, Any], pack_index: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packs_by_key = {str(row.get("key")): row for row in pack_index}
    rows: list[dict[str, Any]] = []
    for objection in profile.get("objection_handlers", []) or []:
        if not isinstance(objection, dict):
            continue
        pack_keys = [str(key) for key in objection.get("evidence_pack_keys", []) or []]
        rows.append({**objection, "evidence_status": evidence_status(pack_keys, packs_by_key)})
    return rows


def source_reference_index(profile: dict[str, Any]) -> list[dict[str, Any]]:
    bets = profile.get("industry_bets", []) or []
    rows: list[dict[str, Any]] = []
    for source in profile.get("source_references", []) or []:
        if not isinstance(source, dict):
            continue
        source_id = str(source.get("id"))
        rows.append(
            {
                **source,
                "industry_bet_ids": [
                    str(bet.get("id"))
                    for bet in bets
                    if isinstance(bet, dict) and source_id in {str(item) for item in bet.get("source_reference_ids", []) or []}
                ],
            }
        )
    return rows


def evidence_rollup(packs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "agentic_app_intake_pack": pack_summary(packs.get("agentic_app_intake_pack")),
        "agentic_control_plane_blueprint": pack_summary(packs.get("agentic_control_plane_blueprint")),
        "agentic_posture_snapshot": pack_summary(packs.get("agentic_posture_snapshot")),
        "agentic_protocol_conformance_pack": pack_summary(packs.get("agentic_protocol_conformance_pack")),
        "agentic_source_freshness_watch": pack_summary(packs.get("agentic_source_freshness_watch")),
        "agentic_telemetry_contract": pack_summary(packs.get("agentic_telemetry_contract")),
        "critical_infrastructure_secure_context_pack": pack_summary(packs.get("critical_infrastructure_secure_context_pack")),
        "design_partner_pilot_pack": pack_summary(packs.get("design_partner_pilot_pack")),
        "enterprise_trust_center_export": pack_summary(packs.get("enterprise_trust_center_export")),
        "mcp_authorization_conformance_pack": pack_summary(packs.get("mcp_authorization_conformance_pack")),
        "secure_context_value_model": pack_summary(packs.get("secure_context_value_model")),
    }


def build_brief_summary(
    *,
    pack_index: list[dict[str, Any]],
    buyer_briefs: list[dict[str, Any]],
    questions: list[dict[str, Any]],
    objections: list[dict[str, Any]],
    failures: list[str],
    source_reference_count: int,
) -> dict[str, Any]:
    pack_status = Counter(str(row.get("status")) for row in pack_index)
    question_status = Counter(str(row.get("evidence_status", {}).get("status")) for row in questions)
    objection_status = Counter(str(row.get("evidence_status", {}).get("status")) for row in objections)
    return {
        "buyer_brief_count": len(buyer_briefs),
        "default_state": "reference_evidence_ready_customer_runtime_proof_required",
        "enterprise_question_count": len(questions),
        "failure_count": len(failures),
        "objection_handler_count": len(objections),
        "pack_count": len(pack_index),
        "pack_status_counts": dict(sorted(pack_status.items())),
        "question_status_counts": dict(sorted(question_status.items())),
        "objection_status_counts": dict(sorted(objection_status.items())),
        "ready_source_pack_count": pack_status.get("ready", 0),
        "source_reference_count": source_reference_count,
        "status": "buyer_diligence_brief_ready" if not failures and pack_status.get("needs_attention", 0) == 0 else "needs_attention_before_buyer_diligence",
    }


def source_artifacts(profile_path: Path, profile_ref: Path, pack_index: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "secure_context_buyer_diligence_profile": {
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


def build_brief(
    *,
    profile: dict[str, Any],
    profile_path: Path,
    profile_ref: Path,
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
    packs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    pack_index = build_pack_index(profile, packs, repo_root)
    buyers = build_buyer_briefs(profile, pack_index)
    questions = build_questions(profile, pack_index)
    objections = build_objections(profile, pack_index)
    return {
        "brief_summary": build_brief_summary(
            pack_index=pack_index,
            buyer_briefs=buyers,
            questions=questions,
            objections=objections,
            failures=failures,
            source_reference_count=len(profile.get("source_references", []) or []),
        ),
        "buyer_briefs": buyers,
        "deal_room_next_steps": profile.get("deal_room_next_steps", []),
        "diligence_contract": profile.get("diligence_contract", {}),
        "enterprise_questions": questions,
        "evidence_rollup": evidence_rollup(packs),
        "failures": failures,
        "features_assessed": profile.get("features_assessed", []),
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "industry_bets": profile.get("industry_bets", []),
        "intent": profile.get("intent"),
        "objection_handlers": objections,
        "pack_index": pack_index,
        "positioning": profile.get("positioning", {}),
        "schema_version": BRIEF_SCHEMA_VERSION,
        "secure_context_buyer_diligence_brief_id": "security-recipes-secure-context-buyer-diligence-brief",
        "source_artifacts": source_artifacts(profile_path, profile_ref, pack_index),
        "source_references": source_reference_index(profile),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in buyer diligence brief is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        failures = validate_profile(profile, repo_root)
        packs, pack_failures = load_packs(profile, repo_root)
        failures.extend(pack_failures)
        brief = build_brief(
            profile=profile,
            profile_path=profile_path,
            profile_ref=args.profile,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
            packs=packs,
        )
        for row in brief.get("pack_index", []):
            if isinstance(row, dict) and row.get("required") and row.get("status") != "ready":
                failures.append(
                    f"{row.get('key')}: required buyer diligence evidence is not ready "
                    f"(available={row.get('available')}, failure_count={row.get('failure_count')})"
                )
    except BuyerDiligenceBriefError as exc:
        print(f"buyer diligence brief generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(brief)
    if args.check:
        if failures:
            print("buyer diligence brief validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_secure_context_buyer_diligence_brief.py", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_secure_context_buyer_diligence_brief.py", file=sys.stderr)
            return 1
        print(f"Validated buyer diligence brief: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated buyer diligence brief with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated buyer diligence brief: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
