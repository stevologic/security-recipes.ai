#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic assurance pack.

The workflow manifest and MCP gateway policy prove that agentic
remediation is scoped. The assurance control map explains why that scope
matters to enterprise buyers and auditors. This script joins those
artifacts into a single machine-readable trust pack.

The output is deterministic by default so CI can run with --check and
fail when the checked-in assurance pack drifts from source controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_CONTROL_MAP = Path("data/assurance/agentic-assurance-control-map.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_REPORT = Path("data/evidence/workflow-control-plane-report.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-assurance-pack.json")

CONTROL_ID_RE = re.compile(r"^SR-AI-\d{2}$")
WORKFLOW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")


class AssurancePackError(RuntimeError):
    """Raised when the assurance pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AssurancePackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AssurancePackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AssurancePackError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AssurancePackError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AssurancePackError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def sha256_file(path: Path) -> str:
    # Hash canonical UTF-8 text so evidence hashes are stable across
    # Windows CRLF and GitHub Actions Ubuntu LF checkouts.
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def validate_control_map(control_map: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(control_map.get("schema_version") == "1.0", failures, "control map schema_version must be 1.0")
    require(len(str(control_map.get("intent", ""))) >= 60, failures, "control map intent must explain the product goal")

    standards = as_list(control_map.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include at least six references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        label = f"standards_alignment[{idx}]"
        if not isinstance(standard, dict):
            failures.append(f"{label} must be an object")
            continue
        standard_id = str(standard.get("id", "")).strip()
        require(bool(standard_id), failures, f"{label}.id is required")
        require(standard_id not in standard_ids, failures, f"{label}.id duplicates {standard_id}")
        standard_ids.add(standard_id)
        require(str(standard.get("url", "")).startswith("https://"), failures, f"{label}.url must be https")

    artifacts = as_list(control_map.get("evidence_artifacts"), "evidence_artifacts")
    artifact_ids: set[str] = set()
    for idx, artifact in enumerate(artifacts):
        label = f"evidence_artifacts[{idx}]"
        if not isinstance(artifact, dict):
            failures.append(f"{label} must be an object")
            continue
        artifact_id = str(artifact.get("id", "")).strip()
        require(bool(artifact_id), failures, f"{label}.id is required")
        require(artifact_id not in artifact_ids, failures, f"{label}.id duplicates {artifact_id}")
        artifact_ids.add(artifact_id)
        availability = str(artifact.get("availability", "")).strip()
        require(
            availability in {"source-controlled", "generated", "external"},
            failures,
            f"{label}.availability is invalid",
        )
        artifact_path = artifact.get("path")
        if availability in {"source-controlled", "generated"}:
            require(bool(artifact_path), failures, f"{label}.path is required for {availability} artifacts")
            if artifact_path:
                require((repo_root / str(artifact_path)).exists(), failures, f"{label}.path does not exist: {artifact_path}")

    required = as_dict(control_map.get("required_workflow_controls"), "required_workflow_controls")
    gate_phases = set(as_list(required.get("gate_phases"), "required_workflow_controls.gate_phases"))
    require(len(gate_phases) >= 6, failures, "required_workflow_controls.gate_phases must include all lifecycle gates")

    controls = as_list(control_map.get("controls"), "controls")
    require(len(controls) >= 6, failures, "controls must include at least six assurance controls")
    control_ids: set[str] = set()
    for idx, control in enumerate(controls):
        label = f"controls[{idx}]"
        if not isinstance(control, dict):
            failures.append(f"{label} must be an object")
            continue
        control_id = str(control.get("id", "")).strip()
        require(bool(CONTROL_ID_RE.match(control_id)), failures, f"{label}.id must match SR-AI-##")
        require(control_id not in control_ids, failures, f"{label}.id duplicates {control_id}")
        control_ids.add(control_id)
        require(str(control.get("title", "")).strip(), failures, f"{label}.title is required")
        require(len(str(control.get("objective", ""))) >= 40, failures, f"{label}.objective must be specific")

        for artifact_id in as_list(control.get("evidence_sources"), f"{label}.evidence_sources"):
            require(str(artifact_id) in artifact_ids, failures, f"{label}.evidence_sources references unknown artifact {artifact_id}")

        mappings = as_list(control.get("framework_mappings"), f"{label}.framework_mappings")
        require(mappings, failures, f"{label}.framework_mappings must not be empty")
        for map_idx, mapping in enumerate(mappings):
            map_label = f"{label}.framework_mappings[{map_idx}]"
            if not isinstance(mapping, dict):
                failures.append(f"{map_label} must be an object")
                continue
            mapped_standard = str(mapping.get("standard_id", "")).strip()
            require(mapped_standard in standard_ids, failures, f"{map_label}.standard_id is unknown: {mapped_standard}")
            require(str(mapping.get("control", "")).strip(), failures, f"{map_label}.control is required")

    return failures


def validate_manifest_policy(
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path,
    control_map: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    required = as_dict(control_map.get("required_workflow_controls"), "required_workflow_controls")
    required_phases = set(as_list(required.get("gate_phases"), "required_workflow_controls.gate_phases"))
    min_evidence = int(required.get("minimum_evidence_records", 3))
    min_kpis = int(required.get("minimum_kpis", 3))

    workflows = as_list(manifest.get("workflows"), "manifest.workflows")
    workflow_ids: set[str] = set()
    for idx, workflow in enumerate(workflows):
        label = f"manifest.workflows[{idx}]"
        if not isinstance(workflow, dict):
            failures.append(f"{label} must be an object")
            continue
        workflow_id = str(workflow.get("id", "")).strip()
        require(bool(WORKFLOW_ID_RE.match(workflow_id)), failures, f"{label}.id must be kebab-case")
        require(workflow_id not in workflow_ids, failures, f"{label}.id duplicates {workflow_id}")
        workflow_ids.add(workflow_id)

        gates = workflow.get("gates") if isinstance(workflow.get("gates"), dict) else {}
        require(required_phases.issubset(set(gates.keys())), failures, f"{workflow_id}: gates missing required phases")
        require(len(workflow.get("evidence", []) or []) >= min_evidence, failures, f"{workflow_id}: insufficient evidence records")
        require(len(workflow.get("kpis", []) or []) >= min_kpis, failures, f"{workflow_id}: insufficient KPI records")
        require(bool(workflow.get("kill_signals")), failures, f"{workflow_id}: kill_signals are required")

    policy_source = as_dict(policy_pack.get("source_manifest"), "policy_pack.source_manifest")
    require(
        policy_source.get("sha256") == sha256_file(manifest_path),
        failures,
        "gateway policy source_manifest.sha256 does not match workflow manifest",
    )

    policies = as_list(policy_pack.get("workflow_policies"), "policy_pack.workflow_policies")
    policy_ids = {
        str(policy.get("workflow_id"))
        for policy in policies
        if isinstance(policy, dict) and policy.get("workflow_id")
    }
    require(policy_ids == workflow_ids, failures, "gateway policy workflow IDs must match manifest workflow IDs")

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        workflow_id = str(policy.get("workflow_id"))
        require(policy.get("default_decision") == "deny", failures, f"{workflow_id}: default gateway decision must be deny")
        tool_access = policy.get("tool_access") if isinstance(policy.get("tool_access"), dict) else {}
        require(tool_access.get("denied_by_default") is True, failures, f"{workflow_id}: tool access must be denied by default")
        runtime = policy.get("runtime_controls") if isinstance(policy.get("runtime_controls"), dict) else {}
        require(runtime.get("session_disablement_required") is True, failures, f"{workflow_id}: session disablement is required")

    require(report.get("failure_count") == 0, failures, "control-plane report must have zero failures")
    require(report.get("workflow_count") == len(workflow_ids), failures, "control-plane report workflow_count is stale")

    return failures


def artifact_lookup(control_map: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(artifact.get("id")): artifact
        for artifact in control_map.get("evidence_artifacts", [])
        if isinstance(artifact, dict) and artifact.get("id")
    }


def build_controls(control_map: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = artifact_lookup(control_map)
    controls: list[dict[str, Any]] = []
    for control in as_list(control_map.get("controls"), "controls"):
        if not isinstance(control, dict):
            continue
        controls.append(
            {
                "ai_easy_default": control.get("ai_easy_default"),
                "buyer_value": control.get("buyer_value"),
                "evidence_sources": [
                    {
                        "availability": artifacts.get(str(source_id), {}).get("availability"),
                        "id": source_id,
                        "path": artifacts.get(str(source_id), {}).get("path"),
                        "title": artifacts.get(str(source_id), {}).get("title"),
                    }
                    for source_id in control.get("evidence_sources", [])
                ],
                "framework_mappings": control.get("framework_mappings", []),
                "id": control.get("id"),
                "objective": control.get("objective"),
                "product_surface": control.get("product_surface", []),
                "title": control.get("title"),
            }
        )
    return controls


def workflow_policy_by_id(policy_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(policy.get("workflow_id")): policy
        for policy in policy_pack.get("workflow_policies", [])
        if isinstance(policy, dict) and policy.get("workflow_id")
    }


def build_workflow_assurance(
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    control_ids: list[str],
) -> list[dict[str, Any]]:
    policies = workflow_policy_by_id(policy_pack)
    output: list[dict[str, Any]] = []
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        if not isinstance(workflow, dict):
            continue
        workflow_id = str(workflow.get("id"))
        policy = policies.get(workflow_id, {})
        owner = workflow.get("owner") if isinstance(workflow.get("owner"), dict) else {}
        gates = workflow.get("gates") if isinstance(workflow.get("gates"), dict) else {}
        tool_access = policy.get("tool_access") if isinstance(policy.get("tool_access"), dict) else {}
        scopes = tool_access.get("allowed_mcp_scopes") if isinstance(tool_access.get("allowed_mcp_scopes"), list) else []

        output.append(
            {
                "applicable_control_ids": control_ids,
                "default_agents": workflow.get("default_agents", []),
                "evidence_records": [
                    {
                        "id": item.get("id"),
                        "owner": item.get("evidence_owner"),
                        "retention": item.get("retention"),
                        "source": item.get("source"),
                    }
                    for item in workflow.get("evidence", [])
                    if isinstance(item, dict)
                ],
                "gate_phases": [
                    {
                        "phase": phase,
                        "rule_count": len(rules) if isinstance(rules, list) else 0,
                    }
                    for phase, rules in gates.items()
                ],
                "gateway_decisions": sorted(
                    {
                        str(scope.get("decision"))
                        for scope in scopes
                        if isinstance(scope, dict) and scope.get("decision")
                    }
                    | {"deny", "kill_session"}
                ),
                "kpis": workflow.get("kpis", []),
                "kill_signal_count": len(workflow.get("kill_signals", []) or []),
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": [
                    item.get("namespace")
                    for item in workflow.get("mcp_context", [])
                    if isinstance(item, dict)
                ],
                "owner": {
                    "accountable_team": owner.get("accountable_team"),
                    "escalation": owner.get("escalation"),
                    "reviewer_pools": owner.get("reviewer_pools", []),
                },
                "public_path": workflow.get("public_path"),
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return output


def build_agent_bom_seed(manifest: dict[str, Any], policy_pack: dict[str, Any]) -> dict[str, Any]:
    policies = workflow_policy_by_id(policy_pack)
    agent_classes = sorted(
        {
            str(agent)
            for workflow in manifest.get("workflows", [])
            if isinstance(workflow, dict)
            for agent in workflow.get("default_agents", [])
        }
    )
    mcp_namespaces = sorted(
        {
            str(context.get("namespace"))
            for workflow in manifest.get("workflows", [])
            if isinstance(workflow, dict)
            for context in workflow.get("mcp_context", [])
            if isinstance(context, dict) and context.get("namespace")
        }
    )
    policy_decisions = sorted(
        {
            str(scope.get("decision"))
            for policy in policies.values()
            for scope in (
                policy.get("tool_access", {}).get("allowed_mcp_scopes", [])
                if isinstance(policy.get("tool_access"), dict)
                else []
            )
            if isinstance(scope, dict) and scope.get("decision")
        }
        | {"deny", "kill_session"}
    )
    return {
        "agent_classes": agent_classes,
        "mcp_namespaces": mcp_namespaces,
        "policy_decisions": policy_decisions,
        "prompt_asset_roots": [
            "content/prompt-library",
            "content/security-remediation",
            "data/control-plane",
            "data/policy"
        ],
        "workflow_count": len(policies),
    }


def build_pack(
    *,
    control_map: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    report: dict[str, Any],
    control_map_path: Path,
    manifest_path: Path,
    policy_path: Path,
    report_path: Path,
    control_map_ref: Path,
    manifest_ref: Path,
    policy_ref: Path,
    report_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    controls = build_controls(control_map)
    control_ids = [str(control.get("id")) for control in controls]
    workflows = build_workflow_assurance(manifest, policy_pack, control_ids)
    external_evidence = [
        artifact
        for artifact in control_map.get("evidence_artifacts", [])
        if isinstance(artifact, dict) and artifact.get("availability") == "external"
    ]

    return {
        "agent_bom_seed": build_agent_bom_seed(manifest, policy_pack),
        "assurance_summary": {
            "active_workflow_count": sum(1 for workflow in workflows if workflow.get("status") == "active"),
            "control_count": len(controls),
            "external_evidence_artifact_count": len(external_evidence),
            "failure_count": len(failures),
            "gateway_default_decision": policy_pack.get("decision_contract", {}).get("default_decision"),
            "standards_count": len(control_map.get("standards_alignment", [])),
            "workflow_count": len(workflows),
        },
        "control_objectives": controls,
        "enterprise_adoption_packet": {
            "board_level_claim": "Agentic remediation is governed as a scoped, reviewable, evidence-producing AI system rather than an unmanaged developer assistant.",
            "default_questions_answered": [
                "Which workflows are approved to run?",
                "What tools and MCP namespaces can each workflow access?",
                "Who owns the workflow and who reviews the output?",
                "Which evidence records prove the agent stayed inside scope?",
                "Which runtime signal pauses or kills the session?",
                "What needs to be inventoried in an AI or Agent Bill of Materials?"
            ],
            "recommended_first_use": "Attach this pack to AI platform design review, vendor-risk intake, security architecture review, and auditor evidence requests.",
            "sales_motion": "Lead with open recipes, then sell hosted MCP policy, evidence exports, enterprise integrations, and assurance reporting."
        },
        "failures": failures,
        "generated_at": generated_at or str(control_map.get("last_reviewed", "")),
        "intent": control_map.get("intent"),
        "positioning": control_map.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "External evidence is still enterprise-specific.",
                "treatment": "Runtime gateway logs, source-host review events, and model-provider contracts must be supplied by the deploying organization."
            },
            {
                "risk": "A policy pack does not replace exploit-specific verification.",
                "treatment": "Every workflow still needs scanner, test, or simulator evidence proving the original finding was remediated."
            },
            {
                "risk": "Model behavior changes can invalidate prompt assumptions.",
                "treatment": "Model upgrades should re-run pilot fixtures and update the workflow manifest before broad rollout."
            }
        ],
        "schema_version": "1.0",
        "source_artifacts": {
            "control_map": {
                "path": normalize_path(control_map_ref),
                "sha256": sha256_file(control_map_path),
            },
            "gateway_policy_pack": {
                "path": normalize_path(policy_ref),
                "sha256": sha256_file(policy_path),
            },
            "workflow_control_plane_report": {
                "path": normalize_path(report_ref),
                "sha256": sha256_file(report_path),
            },
            "workflow_manifest": {
                "path": normalize_path(manifest_ref),
                "sha256": sha256_file(manifest_path),
            },
        },
        "standards_alignment": control_map.get("standards_alignment", []),
        "workflow_assurance": workflows,
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--control-map", type=Path, default=DEFAULT_CONTROL_MAP)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in assurance pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    control_map_path = resolve(repo_root, args.control_map)
    manifest_path = resolve(repo_root, args.manifest)
    policy_path = resolve(repo_root, args.policy)
    report_path = resolve(repo_root, args.report)
    output_path = resolve(repo_root, args.output)

    try:
        control_map = load_json(control_map_path)
        manifest = load_json(manifest_path)
        policy_pack = load_json(policy_path)
        report = load_json(report_path)
        failures = validate_control_map(control_map, repo_root)
        failures.extend(validate_manifest_policy(manifest, policy_pack, report, manifest_path, control_map))
        pack = build_pack(
            control_map=control_map,
            manifest=manifest,
            policy_pack=policy_pack,
            report=report,
            control_map_path=control_map_path,
            manifest_path=manifest_path,
            policy_path=policy_path,
            report_path=report_path,
            control_map_ref=args.control_map,
            manifest_ref=args.manifest,
            policy_ref=args.policy,
            report_ref=args.report,
            generated_at=args.generated_at,
            failures=failures,
        )
    except AssurancePackError as exc:
        print(f"agentic assurance pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)

    if args.check:
        if failures:
            print("agentic assurance pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(
                f"{output_path} is stale; run scripts/generate_agentic_assurance_pack.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated agentic assurance pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agentic assurance pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic assurance pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
