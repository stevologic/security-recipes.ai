#!/usr/bin/env python3
"""Generate the SecurityRecipes enterprise trust-center export.

The export bundles the repo's generated evidence packs into one
machine-readable diligence packet. It is deliberately read-only and
deterministic so CI can prove the trust-center view did not drift from
the underlying control-plane, MCP, identity, context, eval, and threat
artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


EXPORT_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/enterprise-trust-center-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/enterprise-trust-center-export.json")

SUMMARY_KEYS = [
    "acquisition_readiness",
    "agent_card_trust_summary",
    "annex_summary",
    "assurance_summary",
    "attestation_summary",
    "authorization_summary",
    "bom_summary",
    "capability_risk_summary",
    "connector_intake_summary",
    "connector_trust_summary",
    "control_plane_summary",
    "egress_boundary_summary",
    "entitlement_review_summary",
    "eval_summary",
    "exposure_graph_summary",
    "guard_summary",
    "handoff_boundary_summary",
    "identity_summary",
    "incident_response_summary",
    "launch_boundary_summary",
    "measurement_probe_summary",
    "memory_boundary_summary",
    "policy_summary",
    "readiness_summary",
    "receipt_summary",
    "red_team_summary",
    "skill_supply_chain_summary",
    "crosswalk_summary",
    "threat_radar_summary",
    "telemetry_summary",
    "workflow_summary",
]


class TrustCenterExportError(RuntimeError):
    """Raised when the trust-center export cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TrustCenterExportError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise TrustCenterExportError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise TrustCenterExportError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TrustCenterExportError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise TrustCenterExportError(f"{label} must be a list")
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
    rows = as_list(profile.get("required_packs"), "required_packs")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, row in enumerate(rows):
        item = as_dict(row, f"required_packs[{idx}]")
        pack_id = str(item.get("id", "")).strip()
        if pack_id in seen:
            raise TrustCenterExportError(f"required_packs duplicate id: {pack_id}")
        seen.add(pack_id)
        output.append(item)
    return output


def sections(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return [as_dict(section, "section") for section in as_list(profile.get("sections"), "sections")]


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == EXPORT_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the export goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 8, failures, "standards_alignment must include current AI agent, MCP, A2A, eval, and AI security references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicate standard id")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 50, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("trust_center_contract"), "trust_center_contract")
    require(
        contract.get("default_state") == "not_trust_center_ready_until_all_required_packs_are_present_and_failure_free",
        failures,
        "trust_center_contract.default_state must fail closed",
    )
    require(len(as_list(contract.get("required_runtime_evidence"), "trust_center_contract.required_runtime_evidence")) >= 12, failures, "runtime evidence fields are incomplete")
    require(len(as_list(contract.get("buyer_success_criteria"), "trust_center_contract.buyer_success_criteria")) >= 5, failures, "buyer success criteria are required")

    packs = source_pack_rows(profile)
    minimum_packs = int(contract.get("minimum_required_packs") or 0)
    require(len(packs) >= minimum_packs, failures, "required_packs below trust-center minimum")
    pack_ids = {str(pack.get("id")) for pack in packs}
    for pack in packs:
        pack_id = str(pack.get("id"))
        pack_path = Path(str(pack.get("path", "")))
        require(bool(pack_id), failures, "required pack id is required")
        require(bool(str(pack.get("title", "")).strip()), failures, f"{pack_id}: title is required")
        require(bool(str(pack.get("category", "")).strip()), failures, f"{pack_id}: category is required")
        require(bool(str(pack.get("path", "")).strip()), failures, f"{pack_id}: path is required")
        require(resolve(repo_root, pack_path).exists(), failures, f"{pack_id}: path does not exist: {pack_path}")
        require(bool(as_list(pack.get("mcp_tools"), f"{pack_id}.mcp_tools")), failures, f"{pack_id}: mcp_tools are required")

    section_rows = sections(profile)
    minimum_sections = int(contract.get("minimum_sections") or 0)
    require(len(section_rows) >= minimum_sections, failures, "sections below trust-center minimum")
    question_count = 0
    for section in section_rows:
        section_id = str(section.get("id", "")).strip()
        evidence_ids = {str(item) for item in as_list(section.get("evidence_pack_ids"), f"{section_id}.evidence_pack_ids")}
        missing = sorted(evidence_ids - pack_ids)
        require(not missing, failures, f"{section_id}: unknown evidence_pack_ids: {missing}")
        require(len(str(section.get("claim", ""))) >= 80, failures, f"{section_id}: claim must be specific")
        questions = as_list(section.get("due_diligence_questions"), f"{section_id}.due_diligence_questions")
        require(len(questions) >= 2, failures, f"{section_id}: at least two diligence questions are required")
        question_count += len(questions)
        for idx, question in enumerate(questions):
            item = as_dict(question, f"{section_id}.due_diligence_questions[{idx}]")
            require(str(item.get("id", "")).strip(), failures, f"{section_id}: question id is required")
            require(len(str(item.get("question", ""))) >= 40, failures, f"{section_id}: question must be specific")
            require(len(str(item.get("answer", ""))) >= 80, failures, f"{section_id}: answer must be specific")

    require(
        question_count >= int(contract.get("minimum_due_diligence_questions") or 0),
        failures,
        "due diligence question count below trust-center minimum",
    )
    return failures


def load_packs(profile: dict[str, Any], repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source in source_pack_rows(profile):
        pack_id = str(source.get("id"))
        path = resolve(repo_root, Path(str(source.get("path"))))
        try:
            packs[pack_id] = load_json(path)
        except TrustCenterExportError as exc:
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
    return 0


def pack_summary(pack: dict[str, Any]) -> dict[str, Any] | None:
    for key in SUMMARY_KEYS:
        value = pack.get(key)
        if isinstance(value, dict):
            return {"key": key, "value": value}
    return None


def build_pack_index(
    profile: dict[str, Any],
    packs: dict[str, dict[str, Any]],
    repo_root: Path,
) -> list[dict[str, Any]]:
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
                "category": source.get("category"),
                "failure_count": failure_count,
                "id": pack_id,
                "mcp_tools": source.get("mcp_tools", []),
                "path": normalize_path(ref),
                "required": bool(source.get("required", True)),
                "schema_version": pack.get("schema_version") if isinstance(pack, dict) else None,
                "sha256": sha256_file(path) if path.exists() else None,
                "status": "ready" if path.exists() and failure_count == 0 else "needs_attention",
                "summary": pack_summary(pack) if isinstance(pack, dict) else None,
                "title": source.get("title"),
            }
        )
    return rows


def build_sections(profile: dict[str, Any], pack_index: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packs_by_id = {str(pack.get("id")): pack for pack in pack_index}
    rows: list[dict[str, Any]] = []
    for section in sections(profile):
        evidence_ids = [str(item) for item in section.get("evidence_pack_ids", [])]
        evidence = [packs_by_id[pack_id] for pack_id in evidence_ids if pack_id in packs_by_id]
        ready_count = sum(1 for pack in evidence if pack.get("status") == "ready")
        section_tools = sorted({str(tool) for pack in evidence for tool in pack.get("mcp_tools", [])})
        questions = [
            {
                "answer": question.get("answer"),
                "evidence_pack_ids": evidence_ids,
                "evidence_paths": [pack.get("path") for pack in evidence],
                "id": question.get("id"),
                "mcp_tools": section_tools,
                "question": question.get("question"),
                "section_id": section.get("id"),
            }
            for question in section.get("due_diligence_questions", [])
            if isinstance(question, dict)
        ]
        rows.append(
            {
                "claim": section.get("claim"),
                "evidence_pack_ids": evidence_ids,
                "evidence_paths": [pack.get("path") for pack in evidence],
                "id": section.get("id"),
                "mcp_tools": section_tools,
                "question_count": len(questions),
                "questions": questions,
                "ready_evidence_count": ready_count,
                "status": "ready" if ready_count == len(evidence_ids) else "needs_attention",
                "title": section.get("title"),
                "total_evidence_count": len(evidence_ids),
            }
        )
    return rows


def build_diligence_questions(section_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for section in section_rows:
        rows.extend(section.get("questions", []))
    return sorted(rows, key=lambda row: str(row.get("id")))


def source_artifacts(
    profile_path: Path,
    profile_ref: Path,
    pack_index: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "enterprise_trust_center_profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(profile_path),
        },
        "evidence_packs": [
            {
                "id": pack.get("id"),
                "path": pack.get("path"),
                "sha256": pack.get("sha256"),
            }
            for pack in pack_index
        ],
    }


def build_export_summary(
    profile: dict[str, Any],
    pack_index: list[dict[str, Any]],
    section_rows: list[dict[str, Any]],
    packs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    status_counts = Counter(str(pack.get("status")) for pack in pack_index)
    categories = Counter(str(pack.get("category")) for pack in pack_index)
    section_status_counts = Counter(str(section.get("status")) for section in section_rows)
    mcp_tools = sorted({str(tool) for pack in pack_index for tool in pack.get("mcp_tools", [])})

    blueprint = packs.get("agentic-control-plane-blueprint", {})
    crosswalk = packs.get("agentic-standards-crosswalk", {})
    readiness = packs.get("agentic-readiness-scorecard", {})
    radar = packs.get("agentic-threat-radar", {})
    agent_card_trust = packs.get("a2a-agent-card-trust-profile", {})
    bom = packs.get("agentic-system-bom", {})
    incident_response = packs.get("agentic-incident-response-pack", {})
    exposure_graph = packs.get("agentic-exposure-graph", {})
    telemetry = packs.get("agentic-telemetry-contract", {})
    entitlement_review = packs.get("agentic-entitlement-review-pack", {})

    return {
        "agent_card_trust_summary": agent_card_trust.get("agent_card_trust_summary") if isinstance(agent_card_trust, dict) else None,
        "bom_summary": bom.get("bom_summary") if isinstance(bom, dict) else None,
        "category_counts": dict(sorted(categories.items())),
        "control_plane_acquisition_readiness": blueprint.get("acquisition_readiness") if isinstance(blueprint, dict) else None,
        "crosswalk_summary": crosswalk.get("crosswalk_summary") if isinstance(crosswalk, dict) else None,
        "default_state": profile.get("trust_center_contract", {}).get("default_state"),
        "distinct_mcp_tool_count": len(mcp_tools),
        "entitlement_review_summary": entitlement_review.get("entitlement_review_summary") if isinstance(entitlement_review, dict) else None,
        "failure_count": sum(int(pack.get("failure_count") or 0) for pack in pack_index),
        "exposure_graph_summary": exposure_graph.get("exposure_graph_summary") if isinstance(exposure_graph, dict) else None,
        "incident_response_summary": incident_response.get("incident_response_summary") if isinstance(incident_response, dict) else None,
        "pack_count": len(pack_index),
        "pack_status_counts": dict(sorted(status_counts.items())),
        "question_count": sum(int(section.get("question_count") or 0) for section in section_rows),
        "readiness_summary": readiness.get("readiness_summary") if isinstance(readiness, dict) else None,
        "section_count": len(section_rows),
        "section_status_counts": dict(sorted(section_status_counts.items())),
        "status": "trust_center_ready" if status_counts.get("needs_attention", 0) == 0 and section_status_counts.get("needs_attention", 0) == 0 else "needs_attention_before_trust_center",
        "threat_radar_summary": radar.get("threat_radar_summary") if isinstance(radar, dict) else None,
        "telemetry_summary": telemetry.get("telemetry_summary") if isinstance(telemetry, dict) else None,
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
    pack_index = build_pack_index(profile, packs, repo_root)
    section_rows = build_sections(profile, pack_index)
    diligence = build_diligence_questions(section_rows)
    return {
        "commercialization_path": profile.get("commercialization_path", {}),
        "diligence_questions": diligence,
        "enterprise_trust_center_export_id": "security-recipes-enterprise-trust-center-export",
        "executive_readout": profile.get("executive_readout", {}),
        "export_summary": build_export_summary(profile, pack_index, section_rows, packs),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "pack_index": pack_index,
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The open export proves the reference control package, not a live customer's runtime enforcement.",
                "treatment": "Bind the same export shape to customer traces, gateway logs, identity-provider records, approval systems, and signed context releases."
            },
            {
                "risk": "A generated trust-center packet can become stale after model, connector, policy, context, or workflow drift.",
                "treatment": "Regenerate the export after every evidence-pack refresh and make hosted drift alerts part of the paid control plane."
            },
            {
                "risk": "Some production guarantees require external evidence that this public repository cannot hold.",
                "treatment": "Use customer-private evidence ingestion for tickets, logs, approvals, connector metadata, source-host reviews, and runtime receipts."
            }
        ],
        "runtime_evidence_contract": profile.get("trust_center_contract", {}).get("required_runtime_evidence", []),
        "schema_version": EXPORT_SCHEMA_VERSION,
        "source_artifacts": source_artifacts(profile_path, profile_ref, pack_index),
        "standards_alignment": profile.get("standards_alignment", []),
        "trust_center_contract": profile.get("trust_center_contract", {}),
        "trust_center_sections": section_rows,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in trust-center export is stale.")
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
        pack = build_pack(
            profile=profile,
            profile_path=profile_path,
            profile_ref=args.profile,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
            packs=packs,
        )
        for row in pack.get("pack_index", []):
            if isinstance(row, dict) and row.get("required") and row.get("status") != "ready":
                failures.append(
                    f"{row.get('id')}: required trust-center evidence is not ready "
                    f"(available={row.get('available')}, failure_count={row.get('failure_count')})"
                )
    except TrustCenterExportError as exc:
        print(f"enterprise trust-center export generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("enterprise trust-center export validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_enterprise_trust_center_export.py", file=sys.stderr)
            return 1
        print(f"Validated enterprise trust-center export: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")

    if failures:
        print("Generated enterprise trust-center export with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated enterprise trust-center export: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
