#!/usr/bin/env python3
"""Generate the SecurityRecipes MCP elicitation boundary pack.

The pack turns MCP form-mode and URL-mode elicitation guidance into a
machine-readable enterprise control layer. It is intentionally
deterministic so CI can detect drift between the source profile, runtime
decision model, and generated evidence.
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
DEFAULT_PROFILE = Path("data/assurance/mcp-elicitation-boundary-profile.json")
DEFAULT_AUTHORIZATION_PACK = Path("data/evidence/mcp-authorization-conformance-pack.json")
DEFAULT_EGRESS_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_TOOL_RISK_PACK = Path("data/evidence/mcp-tool-risk-contract.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_OUTPUT = Path("data/evidence/mcp-elicitation-boundary-pack.json")

VALID_MODES = {"form", "url"}
VALID_RISK_TIERS = {"low", "medium", "high", "critical"}
VALID_DECISIONS = {
    "allow_elicitation_with_receipt",
    "hold_for_elicitation_evidence",
    "deny_sensitive_form_elicitation",
    "deny_untrusted_elicitation_url",
    "deny_token_or_secret_transit",
    "kill_session_on_elicitation_abuse",
}
RISK_SCORE = {"low": 25, "medium": 45, "high": 70, "critical": 95}


class ElicitationBoundaryPackError(RuntimeError):
    """Raised when the elicitation boundary pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ElicitationBoundaryPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ElicitationBoundaryPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ElicitationBoundaryPackError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ElicitationBoundaryPackError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ElicitationBoundaryPackError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the product goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 8, failures, "standards_alignment must include current MCP, AI, and security references")
    source_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        source_id = str(item.get("id", "")).strip()
        require(bool(source_id), failures, f"standards_alignment[{idx}].id is required")
        require(source_id not in source_ids, failures, f"{source_id}: duplicate source id")
        source_ids.add(source_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 70, failures, f"{source_id}: coverage must be specific")

    contract = as_dict(profile.get("boundary_contract"), "boundary_contract")
    require(
        contract.get("default_decision") == "hold_for_elicitation_evidence",
        failures,
        "boundary_contract.default_decision must hold for missing evidence",
    )
    valid_runtime_decisions = {str(item) for item in as_list(contract.get("valid_runtime_decisions"), "valid_runtime_decisions")}
    require(VALID_DECISIONS <= valid_runtime_decisions, failures, "boundary_contract.valid_runtime_decisions is incomplete")
    require(len(as_list(contract.get("required_runtime_attributes"), "required_runtime_attributes")) >= 15, failures, "runtime attributes must include identity, mode, URL, and receipt fields")
    require(len(as_list(contract.get("sensitive_data_classes"), "sensitive_data_classes")) >= 8, failures, "sensitive data classes are required")
    implemented_controls = {str(item) for item in as_list(contract.get("implemented_controls"), "implemented_controls")}
    require(len(implemented_controls) >= 12, failures, "implemented_controls must define the baseline enforcement model")

    controls = as_list(profile.get("control_checks"), "control_checks")
    require(len(controls) >= 12, failures, "control_checks must cover form, URL, identity, consent, and receipt controls")
    control_ids: set[str] = set()
    for idx, control in enumerate(controls):
        item = as_dict(control, f"control_checks[{idx}]")
        control_id = str(item.get("id", "")).strip()
        require(control_id not in control_ids, failures, f"{control_id}: duplicate control id")
        control_ids.add(control_id)
        require(control_id in implemented_controls, failures, f"{control_id}: control is not listed in implemented_controls")
        require(str(item.get("severity")) in {"medium", "high", "critical"}, failures, f"{control_id}: severity is invalid")
        require(len(str(item.get("control_reason", ""))) >= 50, failures, f"{control_id}: control_reason must be specific")

    profiles = as_list(profile.get("elicitation_profiles"), "elicitation_profiles")
    require(len(profiles) >= 6, failures, "elicitation_profiles must include allowed and prohibited form and URL cases")
    profile_ids: set[str] = set()
    for idx, elicitation_profile in enumerate(profiles):
        item = as_dict(elicitation_profile, f"elicitation_profiles[{idx}]")
        profile_id = str(item.get("id", "")).strip()
        require(bool(profile_id), failures, f"elicitation_profiles[{idx}].id is required")
        require(profile_id not in profile_ids, failures, f"{profile_id}: duplicate profile id")
        profile_ids.add(profile_id)
        require(str(item.get("mode")) in VALID_MODES, failures, f"{profile_id}: mode must be form or url")
        require(str(item.get("risk_tier")) in VALID_RISK_TIERS, failures, f"{profile_id}: risk_tier is invalid")
        require(str(item.get("default_decision")) in VALID_DECISIONS, failures, f"{profile_id}: default_decision is invalid")
        require(len(str(item.get("buyer_value", ""))) >= 60, failures, f"{profile_id}: buyer_value must be specific")
        require(len(as_list(item.get("required_controls"), f"{profile_id}.required_controls")) >= 3, failures, f"{profile_id}: required_controls are required")
        require(len(as_list(item.get("source_ids"), f"{profile_id}.source_ids")) >= 3, failures, f"{profile_id}: source_ids are required")
        for source_id in item.get("source_ids", []) or []:
            require(str(source_id) in source_ids, failures, f"{profile_id}: unknown source_id {source_id}")
        for control_id in item.get("required_controls", []) or []:
            require(str(control_id) in control_ids, failures, f"{profile_id}: unknown control {control_id}")
        if item.get("mode") == "url":
            require(
                "url" in as_list(item.get("required_runtime_attributes"), f"{profile_id}.required_runtime_attributes"),
                failures,
                f"{profile_id}: URL mode profiles must require url runtime evidence",
            )

    workflow_rules = as_list(profile.get("workflow_rules"), "workflow_rules")
    require(len(workflow_rules) >= 3, failures, "workflow_rules must include production workflow mappings")
    for idx, workflow in enumerate(workflow_rules):
        item = as_dict(workflow, f"workflow_rules[{idx}]")
        workflow_id = str(item.get("workflow_id", "")).strip()
        require(bool(workflow_id), failures, f"workflow_rules[{idx}].workflow_id is required")
        allowed_profiles = as_list(item.get("allowed_profile_ids"), f"{workflow_id}.allowed_profile_ids")
        require(bool(allowed_profiles), failures, f"{workflow_id}: allowed_profile_ids are required")
        for profile_id in allowed_profiles:
            require(str(profile_id) in profile_ids, failures, f"{workflow_id}: unknown profile_id {profile_id}")
        for profile_id in as_list(item.get("approval_required_for"), f"{workflow_id}.approval_required_for"):
            require(str(profile_id) in profile_ids, failures, f"{workflow_id}: unknown approval profile_id {profile_id}")

    questions = as_list(profile.get("buyer_due_diligence_questions"), "buyer_due_diligence_questions")
    require(len(questions) >= 4, failures, "buyer_due_diligence_questions must cover sensitive data, URL safety, auth separation, and receipts")
    return failures


def validate_source_packs(source_packs: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for pack_id, pack in source_packs.items():
        require(isinstance(pack, dict), failures, f"{pack_id} must be a JSON object")
        require(bool(pack.get("schema_version")), failures, f"{pack_id} must include schema_version")
    return failures


def source_artifacts(source_paths: dict[str, Path], source_refs: dict[str, Path]) -> dict[str, Any]:
    return {
        key: {
            "path": normalize_path(source_refs[key]),
            "sha256": sha256_file(source_paths[key]),
        }
        for key in sorted(source_paths)
    }


def source_pack_summaries(source_packs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "agentic_run_receipt_pack": source_packs.get("agentic_run_receipt_pack", {}).get("run_receipt_summary"),
        "context_egress_boundary_pack": source_packs.get("context_egress_boundary_pack", {}).get("egress_boundary_summary"),
        "mcp_authorization_conformance_pack": source_packs.get("mcp_authorization_conformance_pack", {}).get("authorization_summary"),
        "mcp_gateway_policy": source_packs.get("mcp_gateway_policy", {}).get("policy_summary"),
        "mcp_tool_risk_contract": source_packs.get("mcp_tool_risk_contract", {}).get("tool_risk_summary"),
        "workflow_manifest": {
            "workflow_count": len(source_packs.get("workflow_manifest", {}).get("workflows", []) or []),
            "schema_version": source_packs.get("workflow_manifest", {}).get("schema_version"),
        },
    }


def profile_status(profile: dict[str, Any], implemented_controls: set[str]) -> tuple[str, list[str]]:
    gaps = sorted({str(control) for control in profile.get("required_controls", []) or []} - implemented_controls)
    default_decision = str(profile.get("default_decision"))
    if default_decision.startswith("deny_"):
        return default_decision, gaps
    if gaps:
        return "hold_for_elicitation_evidence", gaps
    return default_decision, gaps


def risk_score(profile: dict[str, Any]) -> int:
    score = RISK_SCORE.get(str(profile.get("risk_tier")), 50)
    if profile.get("mode") == "url":
        score += 5
    if str(profile.get("default_decision", "")).startswith("deny_"):
        score += 5
    return min(score, 100)


def build_profiles(profile: dict[str, Any]) -> list[dict[str, Any]]:
    implemented_controls = {str(item) for item in profile.get("boundary_contract", {}).get("implemented_controls", []) or []}
    rows: list[dict[str, Any]] = []
    for item in profile.get("elicitation_profiles", []) or []:
        if not isinstance(item, dict):
            continue
        decision, gaps = profile_status(item, implemented_controls)
        rows.append(
            {
                "allowed_data_classes": item.get("allowed_data_classes", []),
                "allowed_url_domains": item.get("allowed_url_domains", []),
                "buyer_value": item.get("buyer_value"),
                "computed_decision": decision,
                "control_gaps": gaps,
                "default_decision": item.get("default_decision"),
                "id": item.get("id"),
                "mode": item.get("mode"),
                "prohibited_data_classes": item.get("prohibited_data_classes", []),
                "request_class": item.get("request_class"),
                "required_controls": item.get("required_controls", []),
                "required_runtime_attributes": item.get("required_runtime_attributes", []),
                "risk_score": risk_score(item),
                "risk_tier": item.get("risk_tier"),
                "source_ids": item.get("source_ids", []),
                "title": item.get("title"),
                "workflow_ids": item.get("workflow_ids", []),
            }
        )
    return sorted(rows, key=lambda row: (-int(row.get("risk_score") or 0), str(row.get("id"))))


def build_workflow_map(profile: dict[str, Any], profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    profile_by_id = {str(item.get("id")): item for item in profiles}
    rows: list[dict[str, Any]] = []
    for workflow in profile.get("workflow_rules", []) or []:
        if not isinstance(workflow, dict):
            continue
        allowed = [
            profile_by_id[str(profile_id)]
            for profile_id in workflow.get("allowed_profile_ids", []) or []
            if str(profile_id) in profile_by_id
        ]
        rows.append(
            {
                "allowed_profile_ids": workflow.get("allowed_profile_ids", []),
                "allowed_profiles": [
                    {
                        "computed_decision": item.get("computed_decision"),
                        "id": item.get("id"),
                        "mode": item.get("mode"),
                        "risk_tier": item.get("risk_tier"),
                        "title": item.get("title"),
                    }
                    for item in allowed
                ],
                "approval_required_for": workflow.get("approval_required_for", []),
                "evidence_expectation": workflow.get("evidence_expectation"),
                "title": workflow.get("title"),
                "workflow_id": workflow.get("workflow_id"),
            }
        )
    return rows


def build_summary(profiles: list[dict[str, Any]], workflow_map: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    mode_counts = Counter(str(profile.get("mode")) for profile in profiles)
    decision_counts = Counter(str(profile.get("computed_decision")) for profile in profiles)
    risk_counts = Counter(str(profile.get("risk_tier")) for profile in profiles)
    return {
        "allowed_profile_count": sum(1 for profile in profiles if str(profile.get("computed_decision")) == "allow_elicitation_with_receipt"),
        "critical_or_high_profile_count": sum(1 for profile in profiles if profile.get("risk_tier") in {"critical", "high"}),
        "decision_counts": dict(sorted(decision_counts.items())),
        "failure_count": len(failures),
        "mode_counts": dict(sorted(mode_counts.items())),
        "profile_count": len(profiles),
        "risk_tier_counts": dict(sorted(risk_counts.items())),
        "status": "elicitation_boundary_ready" if not failures else "needs_attention_before_enterprise_use",
        "workflow_rule_count": len(workflow_map),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    profile_path: Path,
    profile_ref: Path,
    source_paths: dict[str, Path],
    source_refs: dict[str, Path],
    source_packs: dict[str, dict[str, Any]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    profiles = build_profiles(profile)
    workflow_map = build_workflow_map(profile, profiles)
    source_paths_with_profile = {"mcp_elicitation_boundary_profile": profile_path, **source_paths}
    source_refs_with_profile = {"mcp_elicitation_boundary_profile": profile_ref, **source_refs}
    return {
        "boundary_contract": profile.get("boundary_contract", {}),
        "buyer_due_diligence_questions": profile.get("buyer_due_diligence_questions", []),
        "commercialization_path": {
            "open_layer": "Publish form-mode and URL-mode elicitation rules as open evidence so MCP clients can adopt a clear safe-by-default pattern.",
            "enterprise_layer": "Sell hosted domain allowlists, consent receipt storage, connector setup flows, phishing telemetry, policy APIs, and customer-specific elicitation replay.",
            "acquirer_value": "A strategic acquirer gets a production MCP safety primitive for the point where agents ask humans for data or route them to external authorization flows."
        },
        "control_checks": profile.get("control_checks", []),
        "elicitation_boundary_pack_id": "security-recipes-mcp-elicitation-boundary",
        "elicitation_boundary_summary": build_summary(profiles, workflow_map, failures),
        "elicitation_profiles": profiles,
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "runtime_evidence_contract": {
            "required_receipt_fields": profile.get("boundary_contract", {}).get("required_receipt_fields", []),
            "safe_url_requirements": profile.get("boundary_contract", {}).get("safe_url_requirements", []),
            "sensitive_data_classes": profile.get("boundary_contract", {}).get("sensitive_data_classes", []),
            "valid_runtime_decisions": profile.get("boundary_contract", {}).get("valid_runtime_decisions", []),
        },
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts(source_paths_with_profile, source_refs_with_profile),
        "source_pack_summaries": source_pack_summaries(source_packs),
        "standards_alignment": profile.get("standards_alignment", []),
        "workflow_elicitation_map": workflow_map,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--authorization-pack", type=Path, default=DEFAULT_AUTHORIZATION_PACK)
    parser.add_argument("--egress-pack", type=Path, default=DEFAULT_EGRESS_PACK)
    parser.add_argument("--tool-risk-pack", type=Path, default=DEFAULT_TOOL_RISK_PACK)
    parser.add_argument("--run-receipt-pack", type=Path, default=DEFAULT_RUN_RECEIPT_PACK)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in elicitation boundary pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)
    source_paths = {
        "agentic_run_receipt_pack": resolve(repo_root, args.run_receipt_pack),
        "context_egress_boundary_pack": resolve(repo_root, args.egress_pack),
        "mcp_authorization_conformance_pack": resolve(repo_root, args.authorization_pack),
        "mcp_gateway_policy": resolve(repo_root, args.policy),
        "mcp_tool_risk_contract": resolve(repo_root, args.tool_risk_pack),
        "workflow_manifest": resolve(repo_root, args.manifest),
    }
    source_refs = {
        "agentic_run_receipt_pack": args.run_receipt_pack,
        "context_egress_boundary_pack": args.egress_pack,
        "mcp_authorization_conformance_pack": args.authorization_pack,
        "mcp_gateway_policy": args.policy,
        "mcp_tool_risk_contract": args.tool_risk_pack,
        "workflow_manifest": args.manifest,
    }

    try:
        profile = load_json(profile_path)
        source_packs = {key: load_json(path) for key, path in source_paths.items()}
        failures = validate_profile(profile)
        failures.extend(validate_source_packs(source_packs))
        pack = build_pack(
            profile=profile,
            profile_path=profile_path,
            profile_ref=args.profile,
            source_paths=source_paths,
            source_refs=source_refs,
            source_packs=source_packs,
            generated_at=args.generated_at,
            failures=failures,
        )
    except ElicitationBoundaryPackError as exc:
        print(f"MCP elicitation boundary pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("MCP elicitation boundary pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_mcp_elicitation_boundary_pack.py", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(f"{output_path} is stale; run scripts/generate_mcp_elicitation_boundary_pack.py", file=sys.stderr)
            return 1
        print(f"Validated MCP elicitation boundary pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")
    if failures:
        print("Generated MCP elicitation boundary pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated MCP elicitation boundary pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
