#!/usr/bin/env python3
"""Generate the SecurityRecipes browser-agent workspace boundary pack.

The pack turns a browser-agent safety thesis into deterministic evidence:
workspace classes, task profiles, controls, source references, residual
risk, buyer questions, and runtime decision defaults for browser or
desktop agents that operate over untrusted web, email, document, local
developer, and admin-console surfaces.
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
DEFAULT_PROFILE = Path("data/assurance/browser-agent-boundary-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/browser-agent-boundary-pack.json")
DEFAULT_SOURCE_REFS = {
    "agentic_action_runtime_pack": Path("data/evidence/agentic-action-runtime-pack.json"),
    "agentic_app_intake_pack": Path("data/evidence/agentic-app-intake-pack.json"),
    "agentic_incident_response_pack": Path("data/evidence/agentic-incident-response-pack.json"),
    "agentic_telemetry_contract": Path("data/evidence/agentic-telemetry-contract.json"),
    "context_egress_boundary_pack": Path("data/evidence/context-egress-boundary-pack.json"),
    "secure_context_trust_pack": Path("data/evidence/secure-context-trust-pack.json"),
    "threat_radar": Path("data/evidence/agentic-threat-radar.json"),
    "browser_agent_readme": Path("README.browser-agents.md"),
}


class BrowserAgentBoundaryError(RuntimeError):
    """Raised when the browser-agent boundary pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BrowserAgentBoundaryError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise BrowserAgentBoundaryError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise BrowserAgentBoundaryError(f"{path} root must be a JSON object")
    return payload


def maybe_load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file() or path.suffix.lower() != ".json":
        return None
    return load_json(path)


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrowserAgentBoundaryError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise BrowserAgentBoundaryError(f"{label} must be a list")
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


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the browser-agent boundary goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 8, failures, "standards_alignment must include current browser-agent, agent, MCP, and AI security references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicate standard id")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 70, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("boundary_contract"), "boundary_contract")
    require(
        contract.get("default_state") == "browser_authority_untrusted_until_isolated_scoped_user_confirmed_and_receipt_bound",
        failures,
        "boundary_contract.default_state must fail closed",
    )
    valid_decisions = {str(item) for item in as_list(contract.get("valid_decisions"), "boundary_contract.valid_decisions")}
    require(len(valid_decisions) >= 5, failures, "valid_decisions must include allow, hold, deny, and kill states")
    required_controls = {str(item) for item in as_list(contract.get("required_control_keys"), "boundary_contract.required_control_keys")}
    require(len(required_controls) >= 10, failures, "required_control_keys must cover browser authority controls")
    require(
        len(as_list(contract.get("required_runtime_attributes"), "boundary_contract.required_runtime_attributes")) >= 16,
        failures,
        "required_runtime_attributes are incomplete",
    )

    workspaces = as_list(profile.get("workspace_classes"), "workspace_classes")
    tasks = as_list(profile.get("task_profiles"), "task_profiles")
    require(len(workspaces) >= int(contract.get("minimum_workspace_classes") or 0), failures, "workspace class count below minimum")
    require(len(tasks) >= int(contract.get("minimum_task_profiles") or 0), failures, "task profile count below minimum")

    workspace_ids: set[str] = set()
    for idx, workspace in enumerate(workspaces):
        item = as_dict(workspace, f"workspace_classes[{idx}]")
        workspace_id = str(item.get("id", "")).strip()
        require(bool(workspace_id), failures, f"workspace_classes[{idx}].id is required")
        require(workspace_id not in workspace_ids, failures, f"{workspace_id}: duplicate workspace id")
        workspace_ids.add(workspace_id)
        require(str(item.get("default_decision")) in valid_decisions, failures, f"{workspace_id}: invalid default_decision")
        require(str(item.get("risk_tier")) in {"low", "medium", "high", "critical"}, failures, f"{workspace_id}: invalid risk_tier")
        require(int(item.get("base_risk_score") or 0) > 0, failures, f"{workspace_id}: base_risk_score must be positive")
        workspace_controls = {str(control) for control in as_list(item.get("required_controls"), f"{workspace_id}.required_controls")}
        require(bool(workspace_controls), failures, f"{workspace_id}: required_controls are required")
        require(not sorted(workspace_controls - required_controls), failures, f"{workspace_id}: unknown required controls {sorted(workspace_controls - required_controls)}")
        require(bool(as_list(item.get("prohibited_conditions"), f"{workspace_id}.prohibited_conditions")), failures, f"{workspace_id}: prohibited_conditions are required")

    task_ids: set[str] = set()
    for idx, task in enumerate(tasks):
        item = as_dict(task, f"task_profiles[{idx}]")
        task_id = str(item.get("id", "")).strip()
        require(bool(task_id), failures, f"task_profiles[{idx}].id is required")
        require(task_id not in task_ids, failures, f"{task_id}: duplicate task id")
        task_ids.add(task_id)
        require(str(item.get("default_decision")) in valid_decisions, failures, f"{task_id}: invalid default_decision")
        allowed_workspace_ids = {str(workspace_id) for workspace_id in as_list(item.get("allowed_workspace_class_ids"), f"{task_id}.allowed_workspace_class_ids")}
        unknown_workspaces = sorted(allowed_workspace_ids - workspace_ids)
        require(not unknown_workspaces, failures, f"{task_id}: unknown workspace classes {unknown_workspaces}")
        task_controls = {str(control) for control in as_list(item.get("required_controls"), f"{task_id}.required_controls")}
        unknown_controls = sorted(task_controls - required_controls)
        require(not unknown_controls, failures, f"{task_id}: unknown required controls {unknown_controls}")
        require(bool(as_list(item.get("allowed_action_classes"), f"{task_id}.allowed_action_classes")), failures, f"{task_id}: allowed_action_classes are required")

    credits = as_dict(profile.get("control_credit_model"), "control_credit_model")
    require(int(credits.get("max_credit") or 0) > 0, failures, "control_credit_model.max_credit must be positive")
    weights = as_dict(profile.get("runtime_risk_weights"), "runtime_risk_weights")
    require(len(weights) >= 12, failures, "runtime_risk_weights must cover browser-agent runtime signals")

    return failures


def control_credit(profile: dict[str, Any], controls: list[Any]) -> int:
    model = profile.get("control_credit_model") if isinstance(profile.get("control_credit_model"), dict) else {}
    total = sum(int(model.get(str(control), 0)) for control in controls)
    return min(int(model.get("max_credit") or total), total)


def workspace_decision(default_decision: str, residual_score: int, risk_tier: str) -> str:
    if default_decision.startswith("deny"):
        return default_decision
    if residual_score >= 70 or risk_tier == "critical":
        return "hold_for_browser_workspace_review"
    if default_decision == "allow_isolated_browser_task" and residual_score <= 25:
        return "allow_isolated_browser_task"
    if residual_score <= 45:
        return "hold_for_user_confirmation"
    return "hold_for_browser_workspace_review"


def workspace_rows(profile: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for workspace in profile.get("workspace_classes", []) or []:
        if not isinstance(workspace, dict):
            continue
        controls = [str(control) for control in workspace.get("required_controls", []) or []]
        credit = control_credit(profile, controls)
        base = int(workspace.get("base_risk_score") or 0)
        residual = max(0, base - credit)
        decision = workspace_decision(
            str(workspace.get("default_decision")),
            residual,
            str(workspace.get("risk_tier")),
        )
        rows.append(
            {
                "allowed_action_classes": workspace.get("allowed_action_classes", []),
                "allowed_content_trust_levels": workspace.get("allowed_content_trust_levels", []),
                "base_risk_score": base,
                "commercial_value": workspace.get("commercial_value"),
                "control_credit": credit,
                "default_decision": workspace.get("default_decision"),
                "description": workspace.get("description"),
                "effective_decision": decision,
                "id": workspace.get("id"),
                "prohibited_conditions": workspace.get("prohibited_conditions", []),
                "required_controls": controls,
                "residual_risk_score": residual,
                "risk_tier": workspace.get("risk_tier"),
                "title": workspace.get("title"),
            }
        )
    return sorted(rows, key=lambda row: (-int(row.get("residual_risk_score") or 0), str(row.get("id"))))


def task_rows(profile: dict[str, Any], workspace_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for task in profile.get("task_profiles", []) or []:
        if not isinstance(task, dict):
            continue
        workspace_ids = [str(item) for item in task.get("allowed_workspace_class_ids", []) or []]
        workspace_decisions = [
            workspace_by_id[workspace_id].get("effective_decision")
            for workspace_id in workspace_ids
            if workspace_id in workspace_by_id
        ]
        max_residual = max(
            [int(workspace_by_id[workspace_id].get("residual_risk_score") or 0) for workspace_id in workspace_ids if workspace_id in workspace_by_id]
            or [0]
        )
        task_default = str(task.get("default_decision"))
        if any(str(decision).startswith("deny") for decision in workspace_decisions) and task_default.startswith("deny"):
            effective = "deny_ambient_browser_authority"
        elif max_residual >= 70:
            effective = "hold_for_browser_workspace_review"
        else:
            effective = task_default
        rows.append(
            {
                "allowed_action_classes": task.get("allowed_action_classes", []),
                "allowed_workspace_class_ids": workspace_ids,
                "default_decision": task.get("default_decision"),
                "description": task.get("description"),
                "effective_decision": effective,
                "id": task.get("id"),
                "max_workspace_residual_risk_score": max_residual,
                "required_controls": task.get("required_controls", []),
                "title": task.get("title"),
                "workspace_decisions": dict(zip(workspace_ids, workspace_decisions, strict=False)),
            }
        )
    return sorted(rows, key=lambda row: (str(row.get("effective_decision")), str(row.get("id"))))


def source_summary(name: str, payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    for key in [
        "action_runtime_summary",
        "app_intake_summary",
        "egress_boundary_summary",
        "incident_response_summary",
        "telemetry_summary",
        "threat_radar_summary",
        "context_trust_summary",
    ]:
        if isinstance(payload.get(key), dict):
            return {"key": key, "source": name, "value": payload[key]}
    return {"key": "schema_version", "source": name, "value": {"schema_version": payload.get("schema_version")}}


def build_source_artifacts(repo_root: Path, profile_ref: Path, source_refs: dict[str, Path]) -> dict[str, Any]:
    rows: dict[str, Any] = {
        "browser_agent_boundary_profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(resolve(repo_root, profile_ref)),
        }
    }
    for name, ref in sorted(source_refs.items()):
        path = resolve(repo_root, ref)
        rows[name] = {
            "available": path.exists() and path.is_file(),
            "path": normalize_path(ref),
            "sha256": sha256_file(path) if path.exists() and path.is_file() else None,
        }
    return rows


def build_pack(
    *,
    profile: dict[str, Any],
    repo_root: Path,
    profile_ref: Path,
    source_refs: dict[str, Path],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    workspaces = workspace_rows(profile)
    workspace_by_id = {str(row.get("id")): row for row in workspaces}
    tasks = task_rows(profile, workspace_by_id)
    decision_counts = Counter(str(row.get("effective_decision")) for row in workspaces)
    task_decision_counts = Counter(str(row.get("effective_decision")) for row in tasks)
    tier_counts = Counter(str(row.get("risk_tier")) for row in workspaces)
    source_payloads = {name: maybe_load_json(resolve(repo_root, ref)) for name, ref in source_refs.items()}
    source_summaries = {
        name: summary
        for name, summary in ((name, source_summary(name, payload)) for name, payload in source_payloads.items())
        if summary is not None
    }

    return {
        "boundary_contract": profile.get("boundary_contract", {}),
        "browser_agent_boundary_summary": {
            "critical_or_high_workspace_count": sum(1 for row in workspaces if row.get("risk_tier") in {"critical", "high"}),
            "decision_counts": dict(sorted(decision_counts.items())),
            "failure_count": len(failures),
            "source_summary_count": len(source_summaries),
            "status": "browser_boundary_ready" if not failures else "needs_attention",
            "task_count": len(tasks),
            "task_decision_counts": dict(sorted(task_decision_counts.items())),
            "workspace_count": len(workspaces),
            "workspace_risk_tier_counts": dict(sorted(tier_counts.items())),
        },
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The open boundary models workspace and task classes, not a live browser isolation implementation.",
                "treatment": "Hosted deployments should bind decisions to browser isolation logs, origin policy, agent workspace identity, approval receipts, and telemetry events."
            },
            {
                "risk": "Prompt-injection detection is imperfect, especially when attacks look like ordinary social engineering.",
                "treatment": "Constrain source-to-sink combinations: untrusted content plus external send, credential use, localhost access, downloads, admin writes, or payment actions should hold, deny, or kill."
            },
            {
                "risk": "Browser profile state can drift when extensions, tokens, cookies, local storage, or saved credentials change.",
                "treatment": "Prefer dedicated agent profiles, scoped storage, short-lived tokens, storage inspection, and recertification before recurring browser-agent schedules run."
            }
        ],
        "runtime_risk_weights": profile.get("runtime_risk_weights", {}),
        "schema_version": SCHEMA_VERSION,
        "selected_feature": {
            "id": "browser-agent-workspace-boundary",
            "implementation": [
                "Boundary profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Runtime evaluator for browser-agent sessions.",
                "Generated evidence pack under data/evidence.",
                "Human-readable docs page and MCP tool exposure."
            ],
            "reason": "Browser agents are becoming the most sensitive agent surface because untrusted content, logged-in user sessions, local storage, downloads, localhost, and external actions collide in one workspace."
        },
        "source_artifacts": build_source_artifacts(repo_root, profile_ref, source_refs),
        "source_summaries": source_summaries,
        "standards_alignment": profile.get("standards_alignment", []),
        "task_profiles": tasks,
        "workspace_classes": workspaces,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in browser-agent boundary pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        failures = validate_profile(profile)
        pack = build_pack(
            profile=profile,
            repo_root=repo_root,
            profile_ref=args.profile,
            source_refs=DEFAULT_SOURCE_REFS,
            generated_at=args.generated_at,
            failures=failures,
        )
    except BrowserAgentBoundaryError as exc:
        print(f"browser-agent boundary pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("browser-agent boundary pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_browser_agent_boundary_pack.py", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_browser_agent_boundary_pack.py", file=sys.stderr)
            return 1
        print(f"Validated browser-agent boundary pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated browser-agent boundary pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated browser-agent boundary pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
