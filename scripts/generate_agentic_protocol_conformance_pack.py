#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic protocol conformance pack.

The pack turns fast-moving MCP, A2A, NIST, OWASP, and frontier-lab
guidance into deterministic conformance evidence. It is deliberately
source-backed and CI-friendly so protocol drift becomes visible before
secure context, tool authority, or remote-agent delegation reaches
production.
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
DEFAULT_PROFILE = Path("data/assurance/agentic-protocol-conformance-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-protocol-conformance-pack.json")
DEFAULT_SOURCE_PACKS: dict[str, Path] = {
    "a2a_agent_card_trust_profile": Path("data/evidence/a2a-agent-card-trust-profile.json"),
    "agent_handoff_boundary_pack": Path("data/evidence/agent-handoff-boundary-pack.json"),
    "agent_identity_ledger": Path("data/evidence/agent-identity-delegation-ledger.json"),
    "agentic_control_plane_blueprint": Path("data/evidence/agentic-control-plane-blueprint.json"),
    "agentic_red_team_drill_pack": Path("data/evidence/agentic-red-team-drill-pack.json"),
    "agentic_run_receipt_pack": Path("data/evidence/agentic-run-receipt-pack.json"),
    "context_egress_boundary_pack": Path("data/evidence/context-egress-boundary-pack.json"),
    "context_poisoning_guard_pack": Path("data/evidence/context-poisoning-guard-pack.json"),
    "enterprise_trust_center_export": Path("data/evidence/enterprise-trust-center-export.json"),
    "mcp_authorization_conformance_pack": Path("data/evidence/mcp-authorization-conformance-pack.json"),
    "mcp_connector_intake_pack": Path("data/evidence/mcp-connector-intake-pack.json"),
    "mcp_tool_risk_contract": Path("data/evidence/mcp-tool-risk-contract.json"),
    "mcp_tool_surface_drift_pack": Path("data/evidence/mcp-tool-surface-drift-pack.json"),
    "secure_context_eval_pack": Path("data/evidence/secure-context-eval-pack.json"),
    "standards_crosswalk": Path("data/evidence/agentic-standards-crosswalk.json"),
}


class ProtocolConformanceError(RuntimeError):
    """Raised when the conformance pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProtocolConformanceError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ProtocolConformanceError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ProtocolConformanceError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolConformanceError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProtocolConformanceError(f"{label} must be a list")
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


def output_path_allowed(path: str, output_ref: Path) -> bool:
    return Path(path).as_posix() == output_ref.as_posix()


def validate_profile(profile: dict[str, Any], repo_root: Path, output_ref: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain protocol conformance")

    contract = as_dict(profile.get("conformance_contract"), "conformance_contract")
    require(contract.get("default_state") == "hold_for_protocol_evidence", failures, "default_state must hold for evidence")
    required_protocol_ids = {str(item) for item in as_list(contract.get("required_protocol_ids"), "required_protocol_ids")}
    require(len(as_list(contract.get("required_runtime_attributes"), "required_runtime_attributes")) >= 12, failures, "runtime attributes are incomplete")
    require(len(as_list(contract.get("valid_runtime_decisions"), "valid_runtime_decisions")) >= 6, failures, "runtime decisions are incomplete")

    sources = as_list(profile.get("source_references"), "source_references")
    require(len(sources) >= 8, failures, "source_references must include current protocol, government, industry, and lab guidance")
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
        require(str(item.get("published", "")).strip(), failures, f"{source_id}: published is required")
        require(len(str(item.get("why_it_matters", ""))) >= 50, failures, f"{source_id}: why_it_matters must be specific")
    for required_class in {"protocol_specification", "government_framework", "industry_standard", "frontier_lab_guidance"}:
        require(required_class in source_classes, failures, f"source_references must include {required_class}")

    protocols = as_list(profile.get("protocol_profiles"), "protocol_profiles")
    require(len(protocols) >= int(contract.get("minimum_protocol_profiles") or 0), failures, "protocol profile count below minimum")
    protocol_ids: set[str] = set()
    control_count = 0
    for idx, protocol in enumerate(protocols):
        item = as_dict(protocol, f"protocol_profiles[{idx}]")
        protocol_id = str(item.get("id", "")).strip()
        require(bool(protocol_id), failures, f"protocol_profiles[{idx}].id is required")
        require(protocol_id not in protocol_ids, failures, f"{protocol_id}: duplicate protocol id")
        protocol_ids.add(protocol_id)
        require(len(str(item.get("commercial_value", ""))) >= 60, failures, f"{protocol_id}: commercial_value must be specific")
        for source_id in as_list(item.get("source_ids"), f"{protocol_id}.source_ids"):
            require(str(source_id) in source_ids, failures, f"{protocol_id}: unknown source_id {source_id}")
        checks = as_list(item.get("conformance_checks"), f"{protocol_id}.conformance_checks")
        control_count += len(checks)
        require(len(checks) >= 3, failures, f"{protocol_id}: at least three conformance checks are required")
        check_ids: set[str] = set()
        for check_idx, check in enumerate(checks):
            row = as_dict(check, f"{protocol_id}.conformance_checks[{check_idx}]")
            check_id = str(row.get("id", "")).strip()
            require(bool(check_id), failures, f"{protocol_id}: check id is required")
            require(check_id not in check_ids, failures, f"{protocol_id}: duplicate check id {check_id}")
            check_ids.add(check_id)
            require(len(str(row.get("requirement", ""))) >= 60, failures, f"{protocol_id}.{check_id}: requirement must be specific")
            require(bool(as_list(row.get("source_pack_keys"), f"{protocol_id}.{check_id}.source_pack_keys")), failures, f"{protocol_id}.{check_id}: source_pack_keys are required")
            paths = as_list(row.get("evidence_paths"), f"{protocol_id}.{check_id}.evidence_paths")
            require(bool(paths), failures, f"{protocol_id}.{check_id}: evidence_paths are required")
            for raw_path in paths:
                path = str(raw_path)
                if output_path_allowed(path, output_ref):
                    continue
                require(resolve(repo_root, Path(path)).exists(), failures, f"{protocol_id}.{check_id}: evidence path does not exist: {path}")
            require(len(as_list(row.get("required_runtime_attributes"), f"{protocol_id}.{check_id}.required_runtime_attributes")) >= 2, failures, f"{protocol_id}.{check_id}: runtime attributes are incomplete")
            require(str(row.get("fail_closed_decision", "")).strip(), failures, f"{protocol_id}.{check_id}: fail_closed_decision is required")
            require(len(str(row.get("buyer_question", ""))) >= 45, failures, f"{protocol_id}.{check_id}: buyer_question must be specific")

    missing_protocols = sorted(required_protocol_ids - protocol_ids)
    require(not missing_protocols, failures, f"required protocol profiles are missing: {missing_protocols}")
    require(control_count >= int(contract.get("minimum_control_checks") or 0), failures, "control check count below minimum")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer_views must include platform, procurement, and diligence views")
    for idx, view in enumerate(buyer_views):
        item = as_dict(view, f"buyer_views[{idx}]")
        view_id = str(item.get("id", "")).strip()
        require(bool(view_id), failures, f"buyer_views[{idx}].id is required")
        for protocol_id in as_list(item.get("required_protocol_ids"), f"{view_id}.required_protocol_ids"):
            require(str(protocol_id) in protocol_ids, failures, f"{view_id}: unknown protocol id {protocol_id}")
        require(len(str(item.get("answer_contract", ""))) >= 70, failures, f"{view_id}: answer_contract must be specific")
    return failures


def validate_source_packs(source_packs: dict[str, dict[str, Any]], required_keys: set[str]) -> list[str]:
    failures: list[str] = []
    missing_keys = sorted(required_keys - set(source_packs))
    require(not missing_keys, failures, f"source pack keys are missing: {missing_keys}")
    for key in required_keys:
        pack = source_packs.get(key)
        if not isinstance(pack, dict):
            failures.append(f"{key}: source pack is missing or invalid")
            continue
        require(pack.get("schema_version") == PACK_SCHEMA_VERSION, failures, f"{key}: schema_version must be 1.0")
    return failures


def required_source_pack_keys(profile: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for protocol in profile.get("protocol_profiles", []) or []:
        if not isinstance(protocol, dict):
            continue
        for check in protocol.get("conformance_checks", []) or []:
            if isinstance(check, dict):
                keys.update(str(key) for key in check.get("source_pack_keys", []) or [])
    return keys


def source_pack_status(key: str, source_packs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    pack = source_packs.get(key, {})
    failures = pack.get("failures") if isinstance(pack.get("failures"), list) else []
    summary_keys = [
        field
        for field, value in pack.items()
        if field.endswith("_summary") and isinstance(value, dict)
    ]
    summaries = {
        field: pack.get(field)
        for field in sorted(summary_keys)
    }
    return {
        "failure_count": len(failures),
        "schema_version": pack.get("schema_version"),
        "status": "ready" if pack.get("schema_version") == PACK_SCHEMA_VERSION and not failures else "needs_attention",
        "summaries": summaries,
    }


def build_check(
    *,
    protocol_id: str,
    check: dict[str, Any],
    source_packs: dict[str, dict[str, Any]],
    source_refs: dict[str, Path],
    repo_root: Path,
    output_ref: Path,
) -> dict[str, Any]:
    source_pack_keys = [str(key) for key in check.get("source_pack_keys", []) or []]
    missing_source_pack_keys = [key for key in source_pack_keys if key not in source_packs]
    source_pack_failures = [
        key
        for key in source_pack_keys
        if source_pack_status(key, source_packs).get("status") != "ready"
    ]
    missing_evidence_paths = []
    for raw_path in check.get("evidence_paths", []) or []:
        path = str(raw_path)
        if output_path_allowed(path, output_ref):
            continue
        if not resolve(repo_root, Path(path)).exists():
            missing_evidence_paths.append(path)
    status = "ready" if not missing_source_pack_keys and not source_pack_failures and not missing_evidence_paths else "needs_attention"
    return {
        "buyer_question": check.get("buyer_question"),
        "check_hash": stable_hash(
            {
                "evidence_paths": check.get("evidence_paths", []),
                "id": check.get("id"),
                "protocol_id": protocol_id,
                "requirement": check.get("requirement"),
                "source_pack_keys": source_pack_keys,
            }
        ),
        "evidence_paths": check.get("evidence_paths", []),
        "fail_closed_decision": check.get("fail_closed_decision"),
        "id": check.get("id"),
        "missing_evidence_paths": missing_evidence_paths,
        "missing_source_pack_keys": missing_source_pack_keys,
        "protocol_id": protocol_id,
        "required_runtime_attributes": check.get("required_runtime_attributes", []),
        "requirement": check.get("requirement"),
        "source_pack_keys": source_pack_keys,
        "source_pack_status": {
            key: {
                "path": normalize_path(source_refs[key]),
                **source_pack_status(key, source_packs),
            }
            for key in source_pack_keys
            if key in source_refs
        },
        "status": status,
        "title": check.get("title"),
    }


def build_protocol(
    *,
    protocol: dict[str, Any],
    checks: list[dict[str, Any]],
    sources_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    ready = [check for check in checks if check.get("status") == "ready"]
    gaps = [
        {
            "check_id": check.get("id"),
            "fail_closed_decision": check.get("fail_closed_decision"),
            "missing_evidence_paths": check.get("missing_evidence_paths", []),
            "missing_source_pack_keys": check.get("missing_source_pack_keys", []),
            "title": check.get("title"),
        }
        for check in checks
        if check.get("status") != "ready"
    ]
    return {
        "commercial_value": protocol.get("commercial_value"),
        "conformance_check_count": len(checks),
        "conformance_checks": checks,
        "current_versions": protocol.get("current_versions", []),
        "effective_decision": "ready_for_enterprise_conformance" if len(ready) == len(checks) else "hold_for_protocol_evidence",
        "id": protocol.get("id"),
        "readiness_score": round((len(ready) / max(len(checks), 1)) * 100, 2),
        "ready_check_count": len(ready),
        "source_ids": protocol.get("source_ids", []),
        "sources": [
            {
                "id": sources_by_id[str(source_id)].get("id"),
                "name": sources_by_id[str(source_id)].get("name"),
                "published": sources_by_id[str(source_id)].get("published"),
                "publisher": sources_by_id[str(source_id)].get("publisher"),
                "source_class": sources_by_id[str(source_id)].get("source_class"),
                "url": sources_by_id[str(source_id)].get("url"),
            }
            for source_id in protocol.get("source_ids", []) or []
            if str(source_id) in sources_by_id
        ],
        "status_gaps": gaps,
        "title": protocol.get("title"),
    }


def source_artifacts(
    *,
    profile_path: Path,
    profile_ref: Path,
    source_paths: dict[str, Path],
    source_refs: dict[str, Path],
) -> dict[str, Any]:
    return {
        "agentic_protocol_conformance_profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(profile_path),
        },
        "source_packs": {
            key: {
                "path": normalize_path(source_refs[key]),
                "sha256": sha256_file(source_paths[key]),
            }
            for key in sorted(source_paths)
        },
    }


def build_summary(protocols: list[dict[str, Any]], checks: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    protocol_counts = Counter(str(protocol.get("effective_decision")) for protocol in protocols)
    check_counts = Counter(str(check.get("status")) for check in checks)
    return {
        "control_check_count": len(checks),
        "control_status_counts": dict(sorted(check_counts.items())),
        "failure_count": len(failures),
        "protocol_decision_counts": dict(sorted(protocol_counts.items())),
        "protocol_profile_count": len(protocols),
        "ready_control_check_count": sum(1 for check in checks if check.get("status") == "ready"),
        "ready_protocol_profile_count": sum(
            1 for protocol in protocols if protocol.get("effective_decision") == "ready_for_enterprise_conformance"
        ),
        "status": "protocol_conformance_ready" if not failures and check_counts.get("needs_attention", 0) == 0 else "needs_attention_before_enterprise_review",
    }


def build_buyer_views(profile: dict[str, Any], protocols: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(protocol.get("id")): protocol for protocol in protocols}
    views = []
    for view in profile.get("buyer_views", []) or []:
        if not isinstance(view, dict):
            continue
        selected = [
            by_id[str(protocol_id)]
            for protocol_id in view.get("required_protocol_ids", []) or []
            if str(protocol_id) in by_id
        ]
        views.append(
            {
                "answer_contract": view.get("answer_contract"),
                "id": view.get("id"),
                "question": view.get("question"),
                "required_protocol_ids": view.get("required_protocol_ids", []),
                "protocols": selected,
                "title": view.get("title"),
            }
        )
    return views


def build_pack(
    *,
    profile: dict[str, Any],
    profile_path: Path,
    profile_ref: Path,
    source_packs: dict[str, dict[str, Any]],
    source_paths: dict[str, Path],
    source_refs: dict[str, Path],
    repo_root: Path,
    output_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    sources_by_id = {
        str(source.get("id")): source
        for source in profile.get("source_references", []) or []
        if isinstance(source, dict) and source.get("id")
    }
    all_checks: list[dict[str, Any]] = []
    protocols: list[dict[str, Any]] = []
    for protocol in profile.get("protocol_profiles", []) or []:
        if not isinstance(protocol, dict):
            continue
        checks = [
            build_check(
                protocol_id=str(protocol.get("id")),
                check=check,
                source_packs=source_packs,
                source_refs=source_refs,
                repo_root=repo_root,
                output_ref=output_ref,
            )
            for check in protocol.get("conformance_checks", []) or []
            if isinstance(check, dict)
        ]
        all_checks.extend(checks)
        protocols.append(build_protocol(protocol=protocol, checks=checks, sources_by_id=sources_by_id))

    return {
        "buyer_views": build_buyer_views(profile, protocols),
        "commercialization_path": {
            "open_layer": "Publish protocol conformance as open evidence so teams can evaluate MCP, A2A, and agent boundary risk with a shared vocabulary.",
            "enterprise_layer": "Sell hosted MCP/A2A protocol drift monitoring, live metadata checks, signed tool-surface baselines, Agent Card verification, conformance APIs, and trust-center exports.",
            "acquirer_value": "A model lab, AI platform vendor, or security company gets a standards-backed protocol control plane that sits directly between agents, tools, context, and remote-agent networks."
        },
        "conformance_contract": profile.get("conformance_contract", {}),
        "control_checks": all_checks,
        "enterprise_adoption_packet": {
            "board_level_claim": "SecurityRecipes treats MCP and A2A as governable enterprise protocol surfaces with generated evidence and deterministic runtime decisions.",
            "default_questions_answered": [
                "Which protocol versions and guidance are tracked?",
                "Which generated packs prove MCP authorization, tool safety, A2A Agent Card trust, handoff, identity, and egress controls?",
                "Which runtime fields must be present before protocol-mediated context or authority moves?",
                "Which protocol drift conditions force hold, deny, or kill-session decisions?",
                "How does the open knowledge layer become a hosted MCP/A2A conformance product?"
            ],
            "recommended_first_use": "Attach this pack to AI platform protocol review, MCP gateway intake, A2A pilot review, procurement security questionnaires, and acquisition diligence.",
            "sales_motion": "Lead with open protocol conformance evidence, then sell hosted live checks, drift alerts, signed receipts, fleet reporting, and private customer policy mapping."
        },
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "protocol_conformance_pack_id": "security-recipes-agentic-protocol-conformance",
        "protocol_conformance_summary": build_summary(protocols, all_checks, failures),
        "protocol_profiles": protocols,
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts(
            profile_path=profile_path,
            profile_ref=profile_ref,
            source_paths=source_paths,
            source_refs=source_refs,
        ),
        "source_references": profile.get("source_references", []),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in protocol conformance pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)
    source_refs = dict(DEFAULT_SOURCE_PACKS)
    source_paths = {key: resolve(repo_root, path) for key, path in source_refs.items()}

    try:
        profile = load_json(profile_path)
        required_keys = required_source_pack_keys(profile)
        source_packs = {
            key: load_json(path)
            for key, path in source_paths.items()
            if key in required_keys
        }
        failures = [
            *validate_profile(profile, repo_root, args.output),
            *validate_source_packs(source_packs, required_keys),
        ]
        pack = build_pack(
            profile=profile,
            profile_path=profile_path,
            profile_ref=args.profile,
            source_packs=source_packs,
            source_paths={key: source_paths[key] for key in required_keys if key in source_paths},
            source_refs={key: source_refs[key] for key in required_keys if key in source_refs},
            repo_root=repo_root,
            output_ref=args.output,
            generated_at=args.generated_at,
            failures=failures,
        )
    except ProtocolConformanceError as exc:
        print(f"agentic protocol conformance pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("agentic protocol conformance pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_protocol_conformance_pack.py", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(f"{output_path} is stale; run scripts/generate_agentic_protocol_conformance_pack.py", file=sys.stderr)
            return 1
        print(f"Validated agentic protocol conformance pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")
    if failures:
        print("Generated agentic protocol conformance pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic protocol conformance pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
