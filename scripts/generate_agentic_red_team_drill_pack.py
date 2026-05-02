#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic red-team drill pack.

The workflow manifest tells an agent what it may do. The gateway policy
and connector trust pack tell an enforcer how to constrain it. This
script adds the adversarial layer: deterministic drills that test
whether each approved workflow keeps those controls under hostile or
ambiguous agentic inputs.

The output is deterministic by default so CI can run with --check and
fail when the checked-in red-team pack drifts from source controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_SCENARIO_MAP = Path("data/assurance/agentic-red-team-scenario-map.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_IDENTITY_LEDGER = Path("data/evidence/agent-identity-delegation-ledger.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-red-team-drill-pack.json")

SCENARIO_ID_RE = re.compile(r"^SR-RT-\d{2}$")
CONTROL_ID_RE = re.compile(r"^SR-AI-\d{2}$")
VALID_ACCESS_MODES = {"any", "read", "write_branch", "write_ticket", "approval_required"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class RedTeamPackError(RuntimeError):
    """Raised when the red-team drill pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RedTeamPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise RedTeamPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RedTeamPackError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RedTeamPackError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RedTeamPackError(f"{label} must be an object")
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


def policy_decisions(policy_pack: dict[str, Any]) -> set[str]:
    contract = policy_pack.get("decision_contract") if isinstance(policy_pack.get("decision_contract"), dict) else {}
    return {
        str(item.get("decision"))
        for item in contract.get("decisions", [])
        if isinstance(item, dict) and item.get("decision")
    }


def policy_scope_by_workflow(policy_pack: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    output: dict[str, dict[str, dict[str, Any]]] = {}
    for policy in as_list(policy_pack.get("workflow_policies"), "policy_pack.workflow_policies"):
        item = as_dict(policy, "policy_pack.workflow_policy")
        workflow_id = str(item.get("workflow_id"))
        tool_access = as_dict(item.get("tool_access"), f"{workflow_id}: tool_access")
        output[workflow_id] = {
            str(scope.get("namespace")): scope
            for scope in as_list(tool_access.get("allowed_mcp_scopes"), f"{workflow_id}: allowed_mcp_scopes")
            if isinstance(scope, dict) and scope.get("namespace")
        }
    return output


def connector_by_namespace(connector_trust_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(connector.get("namespace")): connector
        for connector in connector_trust_pack.get("connectors", [])
        if isinstance(connector, dict) and connector.get("namespace")
    }


def identity_classes_by_workflow(identity_ledger: dict[str, Any]) -> dict[str, list[str]]:
    output: dict[str, set[str]] = {}
    for identity in identity_ledger.get("agent_identities", []):
        if not isinstance(identity, dict):
            continue
        workflow_id = str(identity.get("workflow_id", "")).strip()
        agent_class = str(identity.get("agent_class", "")).strip()
        if workflow_id and agent_class:
            output.setdefault(workflow_id, set()).add(agent_class)
    return {workflow_id: sorted(agent_classes) for workflow_id, agent_classes in output.items()}


def validate_scenario_map(
    *,
    scenario_map: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    require(scenario_map.get("schema_version") == "1.0", failures, "scenario map schema_version must be 1.0")
    require(len(str(scenario_map.get("intent", ""))) >= 80, failures, "scenario map intent must explain product goal")

    standards = as_list(scenario_map.get("standards_alignment"), "standards_alignment")
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

    required_phases = set(as_list(manifest.get("required_gate_phases"), "manifest.required_gate_phases"))
    valid_decisions = policy_decisions(policy_pack)
    require(valid_decisions, failures, "gateway policy decision contract must not be empty")

    contract = as_dict(scenario_map.get("scenario_contract"), "scenario_contract")
    contract_phases = {str(item) for item in as_list(contract.get("required_gate_phases"), "scenario_contract.required_gate_phases")}
    require(required_phases.issubset(contract_phases), failures, "scenario contract must include all manifest gate phases")
    contract_decisions = {str(item) for item in as_list(contract.get("required_policy_decisions"), "scenario_contract.required_policy_decisions")}
    require(valid_decisions.issubset(contract_decisions), failures, "scenario contract must include all policy decisions")

    scenarios = as_list(scenario_map.get("scenarios"), "scenarios")
    require(len(scenarios) >= 8, failures, "scenario map must include at least eight adversarial scenarios")
    seen_ids: set[str] = set()
    for idx, scenario in enumerate(scenarios):
        label = f"scenarios[{idx}]"
        if not isinstance(scenario, dict):
            failures.append(f"{label} must be an object")
            continue

        scenario_id = str(scenario.get("id", "")).strip()
        require(bool(SCENARIO_ID_RE.match(scenario_id)), failures, f"{label}.id must match SR-RT-##")
        require(scenario_id not in seen_ids, failures, f"{label}.id duplicates {scenario_id}")
        seen_ids.add(scenario_id)

        require(str(scenario.get("title", "")).strip(), failures, f"{scenario_id}: title is required")
        require(str(scenario.get("attack_family", "")).strip(), failures, f"{scenario_id}: attack_family is required")
        require(scenario.get("severity") in VALID_SEVERITIES, failures, f"{scenario_id}: severity is invalid")

        applies_to = as_dict(scenario.get("applies_to"), f"{scenario_id}: applies_to")
        access_modes = {str(item) for item in as_list(applies_to.get("access_modes"), f"{scenario_id}: applies_to.access_modes")}
        require(bool(access_modes), failures, f"{scenario_id}: applies_to.access_modes must not be empty")
        require(access_modes.issubset(VALID_ACCESS_MODES), failures, f"{scenario_id}: applies_to.access_modes has invalid values")
        if "any" in access_modes:
            require(len(access_modes) == 1, failures, f"{scenario_id}: access mode 'any' must be used alone")

        for standard_id in as_list(scenario.get("standards_refs"), f"{scenario_id}: standards_refs"):
            require(str(standard_id) in standard_ids, failures, f"{scenario_id}: unknown standard ref {standard_id}")

        for control_id in as_list(scenario.get("target_control_ids"), f"{scenario_id}: target_control_ids"):
            require(bool(CONTROL_ID_RE.match(str(control_id))), failures, f"{scenario_id}: target_control_ids must match SR-AI-##")

        scenario_phases = {str(item) for item in as_list(scenario.get("required_gate_phases"), f"{scenario_id}: required_gate_phases")}
        require(bool(scenario_phases), failures, f"{scenario_id}: required_gate_phases must not be empty")
        require(scenario_phases.issubset(required_phases), failures, f"{scenario_id}: unknown required gate phase")

        scenario_decisions = {str(item) for item in as_list(scenario.get("expected_policy_decisions"), f"{scenario_id}: expected_policy_decisions")}
        require(bool(scenario_decisions), failures, f"{scenario_id}: expected_policy_decisions must not be empty")
        require(scenario_decisions.issubset(valid_decisions), failures, f"{scenario_id}: unknown expected policy decision")

        for field in [
            "benign_payloads",
            "test_steps",
            "required_evidence",
            "pass_criteria",
            "fail_signals",
            "reviewer_questions",
        ]:
            values = as_list(scenario.get(field), f"{scenario_id}: {field}")
            require(bool(values), failures, f"{scenario_id}: {field} must not be empty")

        require(len(str(scenario.get("expected_agent_behavior", ""))) >= 40, failures, f"{scenario_id}: expected_agent_behavior must be specific")

    return failures


def validate_source_alignment(
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    workflow_ids = {
        str(workflow.get("id"))
        for workflow in manifest.get("workflows", [])
        if isinstance(workflow, dict) and workflow.get("id")
    }

    policy_source = policy_pack.get("source_manifest") if isinstance(policy_pack.get("source_manifest"), dict) else {}
    require(
        policy_source.get("sha256") == sha256_file(manifest_path),
        failures,
        "gateway policy source_manifest.sha256 does not match workflow manifest",
    )

    connector_source = connector_trust_pack.get("source_artifacts") if isinstance(connector_trust_pack.get("source_artifacts"), dict) else {}
    connector_manifest = connector_source.get("workflow_manifest") if isinstance(connector_source.get("workflow_manifest"), dict) else {}
    require(
        connector_manifest.get("sha256") == sha256_file(manifest_path),
        failures,
        "connector trust pack workflow_manifest.sha256 does not match workflow manifest",
    )

    identity_source = identity_ledger.get("source_artifacts") if isinstance(identity_ledger.get("source_artifacts"), dict) else {}
    identity_manifest = identity_source.get("workflow_manifest") if isinstance(identity_source.get("workflow_manifest"), dict) else {}
    require(
        identity_manifest.get("sha256") == sha256_file(manifest_path),
        failures,
        "identity ledger workflow_manifest.sha256 does not match workflow manifest",
    )

    policy_ids = {
        str(policy.get("workflow_id"))
        for policy in policy_pack.get("workflow_policies", [])
        if isinstance(policy, dict) and policy.get("workflow_id")
    }
    require(policy_ids == workflow_ids, failures, "gateway policy workflow IDs must match manifest workflow IDs")

    identity_workflow_ids = set(identity_classes_by_workflow(identity_ledger))
    missing_identity_workflows = sorted(workflow_ids - identity_workflow_ids)
    require(not missing_identity_workflows, failures, f"identity ledger missing workflow IDs: {missing_identity_workflows}")

    return failures


def scenario_applies_to_workflow(scenario: dict[str, Any], workflow: dict[str, Any]) -> bool:
    applies_to = scenario.get("applies_to") if isinstance(scenario.get("applies_to"), dict) else {}
    statuses = {str(item) for item in applies_to.get("workflow_statuses", [])}
    if statuses and str(workflow.get("status")) not in statuses:
        return False

    wanted_modes = {str(item) for item in applies_to.get("access_modes", [])}
    if "any" in wanted_modes:
        return True

    workflow_modes = {
        str(context.get("access"))
        for context in workflow.get("mcp_context", [])
        if isinstance(context, dict) and context.get("access")
    }
    return bool(wanted_modes.intersection(workflow_modes))


def matched_namespaces(
    *,
    scenario: dict[str, Any],
    workflow: dict[str, Any],
    policy_scopes: dict[str, dict[str, dict[str, Any]]],
    connectors: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    applies_to = scenario.get("applies_to") if isinstance(scenario.get("applies_to"), dict) else {}
    wanted_modes = {str(item) for item in applies_to.get("access_modes", [])}
    workflow_id = str(workflow.get("id"))
    rows: list[dict[str, Any]] = []
    for context in workflow.get("mcp_context", []):
        if not isinstance(context, dict):
            continue
        access = str(context.get("access"))
        if "any" not in wanted_modes and access not in wanted_modes:
            continue
        namespace = str(context.get("namespace"))
        scope = policy_scopes.get(workflow_id, {}).get(namespace, {})
        connector = connectors.get(namespace, {})
        trust_tier = connector.get("trust_tier") if isinstance(connector.get("trust_tier"), dict) else {}
        rows.append(
            {
                "access": access,
                "connector_id": connector.get("connector_id"),
                "connector_status": connector.get("status"),
                "namespace": namespace,
                "policy_decision": scope.get("decision"),
                "purpose": context.get("purpose"),
                "trust_tier": trust_tier.get("id") or connector.get("trust_tier"),
            }
        )
    return rows


def scenario_preview(scenario: dict[str, Any]) -> dict[str, Any]:
    applies_to = scenario.get("applies_to") if isinstance(scenario.get("applies_to"), dict) else {}
    return {
        "applies_to": {
            "access_modes": applies_to.get("access_modes", []),
            "workflow_statuses": applies_to.get("workflow_statuses", []),
        },
        "attack_family": scenario.get("attack_family"),
        "expected_policy_decisions": scenario.get("expected_policy_decisions", []),
        "id": scenario.get("id"),
        "required_gate_phases": scenario.get("required_gate_phases", []),
        "severity": scenario.get("severity"),
        "standards_refs": scenario.get("standards_refs", []),
        "target_control_ids": scenario.get("target_control_ids", []),
        "title": scenario.get("title"),
    }


def build_workflow_drills(
    *,
    manifest: dict[str, Any],
    scenario_map: dict[str, Any],
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
) -> list[dict[str, Any]]:
    policy_scopes = policy_scope_by_workflow(policy_pack)
    connectors = connector_by_namespace(connector_trust_pack)
    identity_classes = identity_classes_by_workflow(identity_ledger)
    rows: list[dict[str, Any]] = []
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        if not isinstance(workflow, dict):
            continue
        workflow_id = str(workflow.get("id"))
        owner = workflow.get("owner") if isinstance(workflow.get("owner"), dict) else {}
        workflow_drills: list[dict[str, Any]] = []
        for scenario in as_list(scenario_map.get("scenarios"), "scenario_map.scenarios"):
            if not isinstance(scenario, dict) or not scenario_applies_to_workflow(scenario, workflow):
                continue
            scenario_id = str(scenario.get("id"))
            workflow_drills.append(
                {
                    "attack_family": scenario.get("attack_family"),
                    "benign_payloads": scenario.get("benign_payloads", []),
                    "drill_id": f"{workflow_id}:{scenario_id.lower()}",
                    "expected_agent_behavior": scenario.get("expected_agent_behavior"),
                    "expected_policy_decisions": scenario.get("expected_policy_decisions", []),
                    "fail_signals": scenario.get("fail_signals", []),
                    "matched_namespaces": matched_namespaces(
                        scenario=scenario,
                        workflow=workflow,
                        policy_scopes=policy_scopes,
                        connectors=connectors,
                    ),
                    "pass_criteria": scenario.get("pass_criteria", []),
                    "required_evidence": scenario.get("required_evidence", []),
                    "required_gate_phases": scenario.get("required_gate_phases", []),
                    "reviewer_questions": scenario.get("reviewer_questions", []),
                    "scenario_id": scenario_id,
                    "scenario_title": scenario.get("title"),
                    "severity": scenario.get("severity"),
                    "standards_refs": scenario.get("standards_refs", []),
                    "target_control_ids": scenario.get("target_control_ids", []),
                    "test_steps": scenario.get("test_steps", []),
                }
            )

        rows.append(
            {
                "agent_identity_classes": identity_classes.get(workflow_id, []),
                "drill_count": len(workflow_drills),
                "drills": workflow_drills,
                "maturity_stage": workflow.get("maturity_stage"),
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
    return rows


def validate_drill_coverage(workflow_drills: list[dict[str, Any]], scenario_map: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    active_workflows = [row for row in workflow_drills if row.get("status") == "active"]
    for row in active_workflows:
        require(int(row.get("drill_count") or 0) >= 5, failures, f"{row.get('workflow_id')}: active workflow must have at least five red-team drills")

    used_scenarios = {
        str(drill.get("scenario_id"))
        for row in workflow_drills
        for drill in row.get("drills", [])
        if isinstance(drill, dict) and drill.get("scenario_id")
    }
    all_scenarios = {
        str(scenario.get("id"))
        for scenario in scenario_map.get("scenarios", [])
        if isinstance(scenario, dict) and scenario.get("id")
    }
    unused = sorted(all_scenarios - used_scenarios)
    require(not unused, failures, f"scenarios do not apply to any workflow: {unused}")
    return failures


def build_pack(
    *,
    scenario_map: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
    scenario_map_path: Path,
    manifest_path: Path,
    policy_path: Path,
    connector_trust_pack_path: Path,
    identity_ledger_path: Path,
    scenario_map_ref: Path,
    manifest_ref: Path,
    policy_ref: Path,
    connector_trust_pack_ref: Path,
    identity_ledger_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    workflow_drills = build_workflow_drills(
        manifest=manifest,
        scenario_map=scenario_map,
        policy_pack=policy_pack,
        connector_trust_pack=connector_trust_pack,
        identity_ledger=identity_ledger,
    )
    failures.extend(validate_drill_coverage(workflow_drills, scenario_map))

    drill_count = sum(int(row.get("drill_count") or 0) for row in workflow_drills)
    workflows_with_drills = sum(1 for row in workflow_drills if int(row.get("drill_count") or 0) > 0)
    workflow_count = len(workflow_drills)
    coverage_percent = round(100.0 * workflows_with_drills / workflow_count, 2) if workflow_count else 100.0
    if float(coverage_percent).is_integer():
        coverage_percent = int(coverage_percent)

    severity_counts = Counter(
        str(drill.get("severity"))
        for row in workflow_drills
        for drill in row.get("drills", [])
        if isinstance(drill, dict) and drill.get("severity")
    )
    family_counts = Counter(
        str(drill.get("attack_family"))
        for row in workflow_drills
        for drill in row.get("drills", [])
        if isinstance(drill, dict) and drill.get("attack_family")
    )

    return {
        "enterprise_adoption_packet": {
            "board_level_claim": "Approved agentic remediation workflows are continuously tested against current agentic AI and MCP attack patterns, not merely documented as safe.",
            "default_questions_answered": [
                "Which adversarial scenarios are run before a workflow is promoted?",
                "Which MCP namespaces and policy decisions are exercised by each drill?",
                "Which evidence proves the agent refused unsafe instructions or stopped cleanly?",
                "Which workflows lack coverage for approval bypass, tool poisoning, identity abuse, or evidence failure?"
            ],
            "recommended_first_use": "Run the pack as a promotion gate before moving a workflow from crawl to walk or walk to run.",
            "sales_motion": "Lead with open red-team scenarios, then sell hosted eval execution, MCP gateway enforcement telemetry, customer-specific scenario packs, and audit-ready eval evidence exports."
        },
        "failures": failures,
        "generated_at": generated_at or str(scenario_map.get("last_reviewed", "")),
        "intent": scenario_map.get("intent"),
        "positioning": scenario_map.get("positioning", {}),
        "red_team_summary": {
            "active_workflow_count": sum(1 for row in workflow_drills if row.get("status") == "active"),
            "attack_family_counts": dict(sorted(family_counts.items())),
            "drill_count": drill_count,
            "failure_count": len(failures),
            "scenario_count": len(scenario_map.get("scenarios", [])),
            "severity_counts": dict(sorted(severity_counts.items())),
            "workflow_count": workflow_count,
            "workflow_coverage_percent": coverage_percent,
            "workflows_with_drills": workflows_with_drills,
        },
        "residual_risks": [
            {
                "risk": "The pack defines red-team drills, but local execution still needs an eval harness, mocked connectors, and runtime gateway logs.",
                "treatment": "Bind each drill to the enterprise agent host, replay with mocked tool payloads, and export transcripts plus policy decisions."
            },
            {
                "risk": "Scenario coverage can lag new model, MCP, or connector behavior.",
                "treatment": "Run --check in CI and review the scenario map during model upgrades, connector promotions, and workflow maturity changes."
            },
            {
                "risk": "Passing a drill does not prove the underlying remediation is correct.",
                "treatment": "Continue to require scanner, test, simulator, and reviewer evidence for the original finding."
            }
        ],
        "scenario_contract": scenario_map.get("scenario_contract", {}),
        "scenario_library": [
            scenario_preview(scenario)
            for scenario in scenario_map.get("scenarios", [])
            if isinstance(scenario, dict)
        ],
        "schema_version": "1.0",
        "source_artifacts": {
            "agent_identity_delegation_ledger": {
                "path": normalize_path(identity_ledger_ref),
                "sha256": sha256_file(identity_ledger_path),
            },
            "connector_trust_pack": {
                "path": normalize_path(connector_trust_pack_ref),
                "sha256": sha256_file(connector_trust_pack_path),
            },
            "gateway_policy_pack": {
                "path": normalize_path(policy_ref),
                "sha256": sha256_file(policy_path),
            },
            "red_team_scenario_map": {
                "path": normalize_path(scenario_map_ref),
                "sha256": sha256_file(scenario_map_path),
            },
            "workflow_manifest": {
                "path": normalize_path(manifest_ref),
                "sha256": sha256_file(manifest_path),
            },
        },
        "standards_alignment": scenario_map.get("standards_alignment", []),
        "workflow_drills": workflow_drills,
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--scenario-map", type=Path, default=DEFAULT_SCENARIO_MAP)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--identity-ledger", type=Path, default=DEFAULT_IDENTITY_LEDGER)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in red-team drill pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    scenario_map_path = resolve(repo_root, args.scenario_map)
    manifest_path = resolve(repo_root, args.manifest)
    policy_path = resolve(repo_root, args.policy)
    connector_trust_pack_path = resolve(repo_root, args.connector_trust_pack)
    identity_ledger_path = resolve(repo_root, args.identity_ledger)
    output_path = resolve(repo_root, args.output)

    try:
        scenario_map = load_json(scenario_map_path)
        manifest = load_json(manifest_path)
        policy_pack = load_json(policy_path)
        connector_trust_pack = load_json(connector_trust_pack_path)
        identity_ledger = load_json(identity_ledger_path)
        failures = validate_scenario_map(
            scenario_map=scenario_map,
            manifest=manifest,
            policy_pack=policy_pack,
        )
        failures.extend(
            validate_source_alignment(
                manifest=manifest,
                manifest_path=manifest_path,
                policy_pack=policy_pack,
                connector_trust_pack=connector_trust_pack,
                identity_ledger=identity_ledger,
            )
        )
        pack = build_pack(
            scenario_map=scenario_map,
            manifest=manifest,
            policy_pack=policy_pack,
            connector_trust_pack=connector_trust_pack,
            identity_ledger=identity_ledger,
            scenario_map_path=scenario_map_path,
            manifest_path=manifest_path,
            policy_path=policy_path,
            connector_trust_pack_path=connector_trust_pack_path,
            identity_ledger_path=identity_ledger_path,
            scenario_map_ref=args.scenario_map,
            manifest_ref=args.manifest,
            policy_ref=args.policy,
            connector_trust_pack_ref=args.connector_trust_pack,
            identity_ledger_ref=args.identity_ledger,
            generated_at=args.generated_at,
            failures=failures,
        )
    except RedTeamPackError as exc:
        print(f"agentic red-team drill pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)

    if args.check:
        if failures:
            print("agentic red-team drill pack validation failed:", file=sys.stderr)
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
                f"{output_path} is stale; run scripts/generate_agentic_red_team_drill_pack.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated agentic red-team drill pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agentic red-team drill pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic red-team drill pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
