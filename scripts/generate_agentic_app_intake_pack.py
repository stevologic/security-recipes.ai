#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic app intake gate.

The intake gate is the launch-review layer for agentic applications. It
turns declared autonomy, data, MCP authority, memory, handoffs,
guardrails, telemetry, and approval evidence into deterministic decisions
before a new app, agent host, or production MCP rollout expands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-app-intake-profile.json")
DEFAULT_WORKFLOW_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POSTURE_SNAPSHOT = Path("data/evidence/agentic-posture-snapshot.json")
DEFAULT_TOOL_RISK_CONTRACT = Path("data/evidence/mcp-tool-risk-contract.json")
DEFAULT_AUTHORIZATION_PACK = Path("data/evidence/mcp-authorization-conformance-pack.json")
DEFAULT_EGRESS_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_EVAL_PACK = Path("data/evidence/secure-context-eval-pack.json")
DEFAULT_TELEMETRY_CONTRACT = Path("data/evidence/agentic-telemetry-contract.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_SKILL_PACK = Path("data/evidence/agent-skill-supply-chain-pack.json")
DEFAULT_INCIDENT_RESPONSE_PACK = Path("data/evidence/agentic-incident-response-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-app-intake-pack.json")

VALID_AUTONOMY_LEVELS = {"assisted", "bounded_agent", "autonomous", "multi_agent_coordinator"}
SECRET_DATA_CLASSES = {
    "api_secret",
    "browser_password",
    "live_signing_material",
    "private_key",
    "production_credential",
    "raw_access_token",
    "seed_phrase",
}
REGULATED_DATA_CLASSES = {
    "customer_pii",
    "regulated_financial_data",
    "tenant_private_data",
    "support_ticket_history",
}
WRITE_MODES = {"write_branch", "write_ticket"}
APPROVAL_MODES = {"approval_required"}


class AppIntakeError(RuntimeError):
    """Raised when the agentic app intake pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AppIntakeError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AppIntakeError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AppIntakeError(f"{path} root must be an object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AppIntakeError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AppIntakeError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the launch-review goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 9, failures, "standards_alignment must include current AI, MCP, and security references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"{standard_id}: duplicate standards id")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 70, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("decision_contract"), "decision_contract")
    require(
        contract.get("default_decision") == "hold_for_agentic_app_security_review",
        failures,
        "decision contract must fail closed by default",
    )
    require(len(as_list(contract.get("required_runtime_attributes"), "required_runtime_attributes")) >= 14, failures, "runtime attributes are incomplete")
    require(len(as_list(contract.get("control_evidence_keys"), "control_evidence_keys")) >= 8, failures, "control evidence keys are incomplete")

    scoring = as_dict(profile.get("scoring_model"), "scoring_model")
    weights = as_dict(scoring.get("risk_weights"), "scoring_model.risk_weights")
    credits = as_dict(scoring.get("control_credits"), "scoring_model.control_credits")
    require(len(weights) >= 20, failures, "risk weights must cover autonomy, data, tools, memory, and evidence")
    require(int(credits.get("max_credit") or 0) > 0, failures, "control credit max_credit must be positive")

    profiles = as_list(profile.get("intake_profiles"), "intake_profiles")
    require(len(profiles) >= 4, failures, "at least four intake profiles are required")
    seen_app_ids: set[str] = set()
    for idx, app in enumerate(profiles):
        item = as_dict(app, f"intake_profiles[{idx}]")
        app_id = str(item.get("app_id", "")).strip()
        require(bool(app_id), failures, f"intake_profiles[{idx}].app_id is required")
        require(app_id not in seen_app_ids, failures, f"{app_id}: duplicate app_id")
        seen_app_ids.add(app_id)
        require(str(item.get("autonomy_level")) in VALID_AUTONOMY_LEVELS, failures, f"{app_id}: autonomy_level is invalid")
        require(bool(as_list(item.get("data_classes"), f"{app_id}.data_classes")), failures, f"{app_id}: data_classes are required")
        require(bool(as_list(item.get("mcp_namespaces"), f"{app_id}.mcp_namespaces")), failures, f"{app_id}: mcp_namespaces are required")
        require(bool(as_list(item.get("mcp_access_modes"), f"{app_id}.mcp_access_modes")), failures, f"{app_id}: mcp_access_modes are required")
        require(isinstance(item.get("control_evidence"), list), failures, f"{app_id}: control_evidence must be a list")
    return failures


def validate_sources(sources: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for key, payload in sources.items():
        require(payload.get("schema_version") == SCHEMA_VERSION, failures, f"{key} schema_version must be 1.0")
        source_failures = payload.get("failures")
        if isinstance(source_failures, list) and source_failures:
            failures.append(f"{key} has failures: {len(source_failures)}")
    return failures


def has_any(values: list[Any], candidates: set[str]) -> bool:
    return bool({str(value) for value in values} & candidates)


def add_factor(factors: list[dict[str, Any]], total: int, factor_id: str, points: int, evidence: str) -> int:
    if points <= 0:
        return total
    factors.append({"evidence": evidence, "id": factor_id, "points": points})
    return total + points


def risk_points(app: dict[str, Any], weights: dict[str, Any]) -> tuple[int, list[dict[str, Any]], bool]:
    factors: list[dict[str, Any]] = []
    raw = 0

    autonomy_level = str(app.get("autonomy_level"))
    raw = add_factor(factors, raw, f"autonomy_{autonomy_level}", int(weights.get(f"autonomy_{autonomy_level}", 0)), f"autonomy_level={autonomy_level}")

    data_classes = [str(item) for item in app.get("data_classes", []) or []]
    if has_any(data_classes, SECRET_DATA_CLASSES):
        raw = add_factor(factors, raw, "data_secret_or_signer", int(weights.get("data_secret_or_signer", 0)), "app can touch secret, credential, or signer data classes")
    elif has_any(data_classes, REGULATED_DATA_CLASSES):
        raw = add_factor(factors, raw, "data_regulated", int(weights.get("data_regulated", 0)), "app can touch regulated or tenant-private data")
    elif any("confidential" in item or "private" in item for item in data_classes):
        raw = add_factor(factors, raw, "data_confidential", int(weights.get("data_confidential", 0)), "app can touch confidential or private data")
    elif any("internal" in item or "repository" in item or "finding" in item for item in data_classes):
        raw = add_factor(factors, raw, "data_internal", int(weights.get("data_internal", 0)), "app can touch internal operational data")

    if app.get("untrusted_input"):
        raw = add_factor(factors, raw, "untrusted_input", int(weights.get("untrusted_input", 0)), "app ingests untrusted user, web, ticket, advisory, scanner, or document content")
    if str(app.get("indirect_prompt_injection_risk")) == "high":
        raw = add_factor(factors, raw, "high_indirect_prompt_injection_risk", int(weights.get("high_indirect_prompt_injection_risk", 0)), "app has high indirect prompt injection exposure")

    modes = {str(item) for item in app.get("mcp_access_modes", []) or []}
    if "read" in modes:
        raw = add_factor(factors, raw, "mcp_read", int(weights.get("mcp_read", 0)), "app uses MCP read namespaces")
    if modes & WRITE_MODES:
        raw = add_factor(factors, raw, "mcp_write", int(weights.get("mcp_write", 0)), "app uses MCP write namespaces")
    if modes & APPROVAL_MODES:
        raw = add_factor(factors, raw, "mcp_approval_required", int(weights.get("mcp_approval_required", 0)), "app uses approval-required MCP namespaces")
    if app.get("remote_mcp"):
        raw = add_factor(factors, raw, "remote_mcp", int(weights.get("remote_mcp", 0)), "app uses remote MCP transport or hosted MCP surface")
    if app.get("external_write"):
        raw = add_factor(factors, raw, "external_write", int(weights.get("external_write", 0)), "app can write to an external communication or ticketing surface")
    if app.get("production_write"):
        raw = add_factor(factors, raw, "production_write", int(weights.get("production_write", 0)), "app can affect production state")
    if app.get("destructive_or_irreversible"):
        raw = add_factor(factors, raw, "destructive_or_irreversible", int(weights.get("destructive_or_irreversible", 0)), "app can trigger destructive or irreversible effects")
    if str(app.get("memory_persistence")) not in {"", "none", "append_only_receipts"}:
        raw = add_factor(factors, raw, "persistent_memory", int(weights.get("persistent_memory", 0)), "app uses persistent memory beyond append-only run receipts")
    if app.get("a2a_or_remote_agent"):
        raw = add_factor(factors, raw, "a2a_or_remote_agent", int(weights.get("a2a_or_remote_agent", 0)), "app delegates to A2A or remote agents")
    if app.get("startup_or_package_install"):
        raw = add_factor(factors, raw, "startup_or_package_install", int(weights.get("startup_or_package_install", 0)), "app installs or launches packages at runtime")

    evidence = {str(item) for item in app.get("control_evidence", []) or []}
    missing = {
        "secure_context_eval_pack": "missing_guardrail_eval",
        "agentic_telemetry_contract": "missing_telemetry",
        "agentic_run_receipt_pack": "missing_run_receipts",
        "mcp_authorization_conformance": "missing_authz_binding",
        "context_egress_boundary": "missing_egress_boundary",
        "human_approval_path": "missing_human_approval_path",
    }
    for evidence_key, factor_id in missing.items():
        if evidence_key not in evidence:
            raw = add_factor(factors, raw, factor_id, int(weights.get(factor_id, 0)), f"missing control evidence: {evidence_key}")

    lethal = (
        has_any(data_classes, SECRET_DATA_CLASSES)
        and bool(app.get("external_write") or app.get("production_write") or app.get("destructive_or_irreversible"))
    )
    return raw, factors, lethal


def credit_points(app: dict[str, Any], credits: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    evidence = {str(item) for item in app.get("control_evidence", []) or []}
    rows: list[dict[str, Any]] = []
    total = 0
    for key, value in credits.items():
        if key == "max_credit":
            continue
        if key in evidence or (key == "isolated_runtime" and app.get("deployment_environment") in {"open_reference", "enterprise_pilot"}):
            points = int(value)
            rows.append({"evidence": key, "id": key, "points": points})
            total += points
    total = min(int(credits.get("max_credit") or total), total)
    return total, rows


def decision_for(profile: dict[str, Any], residual_score: int, lethal: bool) -> str:
    if lethal:
        return "deny_until_controls_exist"
    thresholds = profile.get("decision_contract", {}).get("score_thresholds", {})
    if residual_score <= int(thresholds.get("approve_reference_launch_max", 19)):
        return "approve_reference_launch"
    if residual_score <= int(thresholds.get("approve_guarded_pilot_max", 39)):
        return "approve_guarded_pilot"
    if residual_score <= int(thresholds.get("hold_for_review_max", 64)):
        return "hold_for_agentic_app_security_review"
    return "deny_until_controls_exist"


def risk_tier(residual_score: int) -> str:
    if residual_score <= 19:
        return "low"
    if residual_score <= 39:
        return "medium"
    if residual_score <= 64:
        return "high"
    return "critical"


def next_actions(row: dict[str, Any]) -> list[str]:
    decision = str(row.get("decision"))
    actions: list[str] = []
    if row.get("lethal_secret_or_signer_path"):
        actions.append("Remove secret, signer, production credential, or irreversible action access from the app before any launch.")
    if decision == "approve_reference_launch":
        actions.append("Keep the launch read-only and regenerate evidence when context, tools, or MCP metadata change.")
    elif decision == "approve_guarded_pilot":
        actions.append("Run only in a guarded pilot with human approval, telemetry, egress decisions, and run receipts enabled.")
    elif decision == "hold_for_agentic_app_security_review":
        actions.append("Complete architecture review for autonomy, XPIA exposure, MCP tool combinations, memory, and external writes.")
    else:
        actions.append("Block launch until missing controls and high-impact authority are redesigned.")
    missing = row.get("missing_control_evidence") or []
    if missing:
        actions.append("Add missing control evidence: " + ", ".join(missing) + ".")
    return actions


def source_snapshot(sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    posture = sources.get("agentic_posture_snapshot", {})
    tool_risk = sources.get("mcp_tool_risk_contract", {})
    return {
        "agentic_posture_decision": posture.get("posture_summary", {}).get("decision"),
        "agentic_posture_score": posture.get("posture_summary", {}).get("posture_score"),
        "lethal_tool_combination_workflows": tool_risk.get("tool_risk_summary", {}).get("lethal_combination_workflow_count"),
        "registered_workflows": sources.get("workflow_manifest", {}).get("workflows") and len(sources["workflow_manifest"].get("workflows", [])),
        "telemetry_signal_classes": sources.get("agentic_telemetry_contract", {}).get("telemetry_summary", {}).get("signal_class_count"),
    }


def build_rows(profile: dict[str, Any]) -> list[dict[str, Any]]:
    weights = profile.get("scoring_model", {}).get("risk_weights", {})
    credits = profile.get("scoring_model", {}).get("control_credits", {})
    rows: list[dict[str, Any]] = []
    required = {str(item) for item in profile.get("decision_contract", {}).get("control_evidence_keys", []) or []}
    for app in profile.get("intake_profiles", []) or []:
        if not isinstance(app, dict):
            continue
        raw_score, factors, lethal = risk_points(app, weights)
        credit_score, credit_rows = credit_points(app, credits)
        residual_score = max(0, raw_score - credit_score)
        decision = decision_for(profile, residual_score, lethal)
        evidence = {str(item) for item in app.get("control_evidence", []) or []}
        missing = sorted(required - evidence)
        row = {
            "app_id": app.get("app_id"),
            "a2a_or_remote_agent": app.get("a2a_or_remote_agent"),
            "autonomy_level": app.get("autonomy_level"),
            "business_purpose": app.get("business_purpose"),
            "buyer_stage": app.get("buyer_stage"),
            "control_credit": credit_score,
            "control_credits": credit_rows,
            "control_evidence": app.get("control_evidence", []),
            "data_classes": app.get("data_classes", []),
            "decision": decision,
            "deployment_environment": app.get("deployment_environment"),
            "destructive_or_irreversible": app.get("destructive_or_irreversible"),
            "external_write": app.get("external_write"),
            "indirect_prompt_injection_risk": app.get("indirect_prompt_injection_risk"),
            "lethal_secret_or_signer_path": lethal,
            "mcp_access_modes": app.get("mcp_access_modes", []),
            "mcp_namespaces": app.get("mcp_namespaces", []),
            "memory_persistence": app.get("memory_persistence"),
            "missing_control_evidence": missing,
            "owner": app.get("owner"),
            "production_write": app.get("production_write"),
            "raw_risk_score": raw_score,
            "recommended_controls": app.get("recommended_controls", []),
            "residual_risk_score": residual_score,
            "risk_factors": factors,
            "risk_tier": risk_tier(residual_score),
            "startup_or_package_install": app.get("startup_or_package_install"),
            "title": app.get("title"),
            "untrusted_input": app.get("untrusted_input"),
        }
        row["next_actions"] = next_actions(row)
        rows.append(row)
    return sorted(rows, key=lambda row: (-int(row.get("residual_risk_score") or 0), str(row.get("app_id"))))


def build_source_artifacts(repo_root: Path, refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    artifacts: dict[str, dict[str, str]] = {}
    for key, ref in sorted(refs.items()):
        path = resolve(repo_root, ref)
        artifacts[key] = {
            "path": normalize_path(ref),
            "sha256": sha256_file(path),
        }
    return artifacts


def build_pack(
    *,
    profile: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    source_artifacts: dict[str, dict[str, str]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    rows = build_rows(profile)
    decision_counts = Counter(str(row.get("decision")) for row in rows)
    tier_counts = Counter(str(row.get("risk_tier")) for row in rows)
    return {
        "app_intake_profiles": rows,
        "app_intake_summary": {
            "app_count": len(rows),
            "critical_or_high_count": sum(1 for row in rows if row.get("risk_tier") in {"high", "critical"}),
            "decision_counts": dict(sorted(decision_counts.items())),
            "failure_count": len(failures),
            "lethal_secret_or_signer_path_count": sum(1 for row in rows if row.get("lethal_secret_or_signer_path")),
            "risk_tier_counts": dict(sorted(tier_counts.items())),
            "source_snapshot": source_snapshot(sources),
        },
        "decision_contract": profile.get("decision_contract", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "evaluator_contract": {
            "allow_decisions": [
                "approve_reference_launch",
                "approve_guarded_pilot"
            ],
            "default_decision": profile.get("decision_contract", {}).get("default_decision"),
            "required_runtime_attributes": profile.get("decision_contract", {}).get("required_runtime_attributes", []),
            "runtime_kill_signals": profile.get("decision_contract", {}).get("runtime_kill_signals", []),
        },
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The open pack models declared sample applications, not a customer's live agent inventory.",
                "treatment": "Hosted deployments should ingest app manifests, MCP gateway logs, IAM issuance events, tool-list diffs, approval records, and telemetry traces."
            },
            {
                "risk": "Launch posture can drift after model, prompt, skill, tool, memory, or MCP metadata changes.",
                "treatment": "Regenerate the pack in CI and require runtime evaluation whenever app capabilities or control evidence change."
            },
            {
                "risk": "An approved pilot can still be unsafe if humans approve broad actions without context.",
                "treatment": "Use typed approvals, two-key review for high-impact classes, policy receipts, and session kill signals."
            }
        ],
        "schema_version": SCHEMA_VERSION,
        "scoring_model": profile.get("scoring_model", {}),
        "selected_feature": {
            "id": "agentic-app-intake-gate",
            "implementation": [
                "Launch-review profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Runtime evaluator for launch and production expansion decisions.",
                "Generated evidence pack under data/evidence.",
                "Human-readable docs page and MCP tool exposure."
            ],
            "reason": "Enterprise buyers need one easy, evidence-backed launch gate before agentic apps gain MCP tools, private context, memory, A2A handoffs, or production authority."
        },
        "source_artifacts": source_artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
    }


def validate_pack(pack: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(pack.get("schema_version") == SCHEMA_VERSION, failures, "pack schema_version must be 1.0")
    rows = as_list(pack.get("app_intake_profiles"), "app_intake_profiles")
    summary = as_dict(pack.get("app_intake_summary"), "app_intake_summary")
    require(summary.get("app_count") == len(rows), failures, "app_intake_summary.app_count is stale")
    require(summary.get("lethal_secret_or_signer_path_count") == sum(1 for row in rows if isinstance(row, dict) and row.get("lethal_secret_or_signer_path")), failures, "lethal path count is stale")
    valid_decisions = set(pack.get("decision_contract", {}).get("valid_decisions", []) or [])
    for row in rows:
        item = as_dict(row, "app_intake_profiles row")
        app_id = str(item.get("app_id"))
        require(item.get("decision") in valid_decisions, failures, f"{app_id}: invalid decision")
        require(int(item.get("residual_risk_score", -1)) == max(0, int(item.get("raw_risk_score", 0)) - int(item.get("control_credit", 0))), failures, f"{app_id}: residual risk score is stale")
        require(bool(item.get("next_actions")), failures, f"{app_id}: next_actions are required")
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--workflow-manifest", type=Path, default=DEFAULT_WORKFLOW_MANIFEST)
    parser.add_argument("--posture-snapshot", type=Path, default=DEFAULT_POSTURE_SNAPSHOT)
    parser.add_argument("--tool-risk-contract", type=Path, default=DEFAULT_TOOL_RISK_CONTRACT)
    parser.add_argument("--authorization-pack", type=Path, default=DEFAULT_AUTHORIZATION_PACK)
    parser.add_argument("--egress-pack", type=Path, default=DEFAULT_EGRESS_PACK)
    parser.add_argument("--eval-pack", type=Path, default=DEFAULT_EVAL_PACK)
    parser.add_argument("--telemetry-contract", type=Path, default=DEFAULT_TELEMETRY_CONTRACT)
    parser.add_argument("--run-receipt-pack", type=Path, default=DEFAULT_RUN_RECEIPT_PACK)
    parser.add_argument("--skill-pack", type=Path, default=DEFAULT_SKILL_PACK)
    parser.add_argument("--incident-response-pack", type=Path, default=DEFAULT_INCIDENT_RESPONSE_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in app intake pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "agent_skill_supply_chain_pack": args.skill_pack,
        "agentic_app_intake_profile": args.profile,
        "agentic_incident_response_pack": args.incident_response_pack,
        "agentic_posture_snapshot": args.posture_snapshot,
        "agentic_run_receipt_pack": args.run_receipt_pack,
        "agentic_telemetry_contract": args.telemetry_contract,
        "context_egress_boundary_pack": args.egress_pack,
        "mcp_authorization_conformance_pack": args.authorization_pack,
        "mcp_tool_risk_contract": args.tool_risk_contract,
        "secure_context_eval_pack": args.eval_pack,
        "workflow_manifest": args.workflow_manifest,
    }
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(resolve(repo_root, args.profile))
        sources = {
            key: load_json(resolve(repo_root, ref))
            for key, ref in refs.items()
            if key != "agentic_app_intake_profile"
        }
        failures = [*validate_profile(profile), *validate_sources(sources)]
        pack = build_pack(
            profile=profile,
            sources=sources,
            source_artifacts=build_source_artifacts(repo_root, refs),
            generated_at=args.generated_at,
            failures=failures,
        )
        failures.extend(validate_pack(pack))
        pack["failures"] = failures
        pack["app_intake_summary"]["failure_count"] = len(failures)
    except AppIntakeError as exc:
        print(f"agentic app intake pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("agentic app intake pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_app_intake_pack.py", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_app_intake_pack.py", file=sys.stderr)
            return 1
        print(f"Validated agentic app intake pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated agentic app intake pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic app intake pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
