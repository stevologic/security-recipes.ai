#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic red-team replay harness.

The harness turns existing red-team drill scenarios into replayable,
evidence-gated fixtures. It does not run a customer's live agent host by
itself; it defines the fixture, expected decision, trace, receipt, and
review evidence shape that a local or hosted runner must produce before
the replay can be counted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-red-team-replay-harness-profile.json")
DEFAULT_RED_TEAM_PACK = Path("data/evidence/agentic-red-team-drill-pack.json")
DEFAULT_TELEMETRY_CONTRACT = Path("data/evidence/agentic-telemetry-contract.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_ACTION_RUNTIME_PACK = Path("data/evidence/agentic-action-runtime-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-red-team-replay-harness.json")

DEFAULT_SOURCE_PACKS: dict[str, Path] = {
    "agentic_action_runtime_pack": DEFAULT_ACTION_RUNTIME_PACK,
    "agentic_red_team_drill_pack": DEFAULT_RED_TEAM_PACK,
    "agentic_run_receipt_pack": DEFAULT_RUN_RECEIPT_PACK,
    "agentic_telemetry_contract": DEFAULT_TELEMETRY_CONTRACT,
}

REQUIRED_EVIDENCE_CLASSES = {
    "mocked_connector_payload",
    "agent_transcript_or_structured_response",
    "mcp_gateway_policy_decision",
    "authorization_or_scope_decision",
    "telemetry_trace_event",
    "run_receipt",
    "verifier_or_replay_assertion",
    "reviewer_outcome",
}
REQUIRED_TRACE_EVENT_CLASSES = {
    "agent.session",
    "mcp.tools.call",
    "policy.decision",
    "verifier.result",
    "run.closed",
}


class ReplayHarnessError(RuntimeError):
    """Raised when the replay harness cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReplayHarnessError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ReplayHarnessError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReplayHarnessError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReplayHarnessError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReplayHarnessError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def rows_by_id(rows: Any, key: str) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        return {}
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and row.get(key):
            output[str(row[key])] = row
    return output


def failure_count(pack: dict[str, Any]) -> int:
    failures = pack.get("failures")
    if isinstance(failures, list):
        return len(failures)
    for value in pack.values():
        if isinstance(value, dict) and isinstance(value.get("failure_count"), int):
            return int(value["failure_count"])
    return 0


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the replay harness goal")

    refs = as_list(profile.get("source_references"), "source_references")
    require(len(refs) >= 8, failures, "source_references must include OWASP, MCP, A2A, OpenAI, OTel, and NIST anchors")
    source_classes: set[str] = set()
    source_ids: set[str] = set()
    for idx, source in enumerate(refs):
        item = as_dict(source, f"source_references[{idx}]")
        source_id = str(item.get("id", "")).strip()
        source_class = str(item.get("source_class", "")).strip()
        require(bool(source_id), failures, f"source_references[{idx}].id is required")
        require(source_id not in source_ids, failures, f"{source_id}: duplicate source id")
        source_ids.add(source_id)
        source_classes.add(source_class)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(len(str(item.get("why_it_matters", ""))) >= 80, failures, f"{source_id}: why_it_matters must be specific")
    for required_class in {
        "government_framework",
        "industry_guidance",
        "industry_standard",
        "protocol_specification",
        "telemetry_standard",
        "vendor_implementation_guidance",
    }:
        require(required_class in source_classes, failures, f"source_references must include {required_class}")

    contract = as_dict(profile.get("harness_contract"), "harness_contract")
    require(
        contract.get("default_state") == "untrusted_until_replay_result_and_runtime_evidence_match",
        failures,
        "harness_contract.default_state must fail closed",
    )
    required_source_keys = {str(item) for item in as_list(contract.get("required_source_pack_keys"), "required_source_pack_keys")}
    require(required_source_keys == set(DEFAULT_SOURCE_PACKS), failures, "required_source_pack_keys must match generator source packs")
    evidence = {str(item) for item in as_list(contract.get("required_evidence_classes"), "required_evidence_classes")}
    trace_events = {str(item) for item in as_list(contract.get("required_trace_event_classes"), "required_trace_event_classes")}
    require(REQUIRED_EVIDENCE_CLASSES.issubset(evidence), failures, "harness is missing required evidence classes")
    require(REQUIRED_TRACE_EVENT_CLASSES.issubset(trace_events), failures, "harness is missing required trace event classes")

    evidence_rows = as_list(profile.get("evidence_classes"), "evidence_classes")
    evidence_ids = {str(row.get("id")) for row in evidence_rows if isinstance(row, dict)}
    require(REQUIRED_EVIDENCE_CLASSES.issubset(evidence_ids), failures, "evidence_classes must define every required class")
    for idx, row in enumerate(evidence_rows):
        item = as_dict(row, f"evidence_classes[{idx}]")
        evidence_id = str(item.get("id", "")).strip()
        require(evidence_id in REQUIRED_EVIDENCE_CLASSES, failures, f"{evidence_id}: unknown evidence class")
        require(len(as_list(item.get("minimum_fields"), f"{evidence_id}.minimum_fields")) >= 5, failures, f"{evidence_id}: minimum_fields are incomplete")
        require(len(str(item.get("why_required", ""))) >= 70, failures, f"{evidence_id}: why_required must be specific")

    modes = as_list(profile.get("replay_modes"), "replay_modes")
    require(len(modes) >= 4, failures, "replay_modes must include mocked, trace-only, host, and private modes")
    gates = as_list(profile.get("replay_pass_gates"), "replay_pass_gates")
    require(len(gates) >= 4, failures, "replay_pass_gates must cover decision, fail-signal, trace, and fixture gates")
    risks = as_list(profile.get("risk_register"), "risk_register")
    require(len(risks) >= 5, failures, "risk_register must include replay-specific residual risks")
    return failures


def validate_sources(source_payloads: dict[str, dict[str, Any]], profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for key, payload in source_payloads.items():
        require(payload.get("schema_version") == PACK_SCHEMA_VERSION, failures, f"{key} schema_version must be 1.0")
        require(failure_count(payload) == 0, failures, f"{key} must have zero validation failures")

    red_team = source_payloads["agentic_red_team_drill_pack"]
    telemetry = source_payloads["agentic_telemetry_contract"]
    receipts = source_payloads["agentic_run_receipt_pack"]
    actions = source_payloads["agentic_action_runtime_pack"]

    workflow_drills = as_list(red_team.get("workflow_drills"), "red_team.workflow_drills")
    require(bool(workflow_drills), failures, "red-team pack must include workflow_drills")
    workflow_ids = {str(row.get("workflow_id")) for row in workflow_drills if isinstance(row, dict) and row.get("workflow_id")}
    require(bool(workflow_ids), failures, "red-team workflow ids are empty")

    telemetry_ids = set(rows_by_id(telemetry.get("workflow_telemetry_contracts"), "workflow_id"))
    receipt_ids = set(rows_by_id(receipts.get("workflow_receipt_templates"), "workflow_id"))
    action_ids = set(rows_by_id(actions.get("workflow_action_matrix"), "workflow_id"))
    require(workflow_ids.issubset(telemetry_ids), failures, "telemetry contract must cover every red-team workflow")
    require(workflow_ids.issubset(receipt_ids), failures, "run receipt pack must cover every red-team workflow")
    require(workflow_ids.issubset(action_ids), failures, "action runtime pack must cover every red-team workflow")

    contract = as_dict(profile.get("harness_contract"), "harness_contract")
    scenario_count = len(red_team.get("scenario_library", []) or [])
    attack_family_count = len({str(row.get("attack_family")) for row in red_team.get("scenario_library", []) or [] if isinstance(row, dict)})
    fixture_count = sum(len(row.get("drills", []) or []) for row in workflow_drills if isinstance(row, dict))
    require(fixture_count >= int(contract.get("minimum_replay_fixtures") or 0), failures, "red-team pack does not provide enough replay fixtures")
    require(attack_family_count >= int(contract.get("minimum_attack_families") or 0), failures, "red-team pack does not cover enough attack families")
    require(scenario_count >= 8, failures, "red-team scenario library must include at least eight scenarios")
    return failures


def source_artifacts(repo_root: Path, refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for key, ref in sorted(refs.items()):
        path = resolve(repo_root, ref)
        output[key] = {
            "path": normalize_path(ref),
            "sha256": sha256_file(path),
        }
    return output


def fixture_id(workflow_id: str, scenario_id: str) -> str:
    normalized_scenario = scenario_id.lower().replace("_", "-")
    return f"{workflow_id}:{normalized_scenario}:fixture"


def replay_id(workflow_id: str, scenario_id: str) -> str:
    normalized_scenario = scenario_id.lower().replace("_", "-")
    return f"{workflow_id}:{normalized_scenario}"


def payload_fixtures(workflow_id: str, drill: dict[str, Any]) -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []
    scenario_id = str(drill.get("scenario_id"))
    namespaces = [
        str(row.get("namespace"))
        for row in drill.get("matched_namespaces", []) or []
        if isinstance(row, dict) and row.get("namespace")
    ]
    default_namespace = namespaces[0] if namespaces else "unregistered.mock"
    for idx, payload in enumerate(drill.get("benign_payloads", []) or [], start=1):
        payload_text = str(payload)
        fixtures.append(
            {
                "fixture_id": f"{fixture_id(workflow_id, scenario_id)}:{idx}",
                "payload_class": str(drill.get("attack_family", "unknown")),
                "payload_hash": sha256_text(payload_text),
                "redaction_state": "safe_benign_fixture_hash_exportable",
                "sample_payload": payload_text,
                "source_namespace": default_namespace,
            }
        )
    return fixtures


def expected_runtime_outcome(drill: dict[str, Any]) -> str:
    expected = {str(item) for item in drill.get("expected_policy_decisions", []) or []}
    severity = str(drill.get("severity", "")).lower()
    if "kill_session" in expected:
        return "deny_or_kill_before_unsafe_side_effect"
    if "deny" in expected and severity == "critical":
        return "deny_before_context_or_authority_expands"
    if "deny" in expected:
        return "deny_or_hold_with_reviewer_evidence"
    return "continue_only_inside_declared_workflow_scope"


def workflow_support(
    workflow_id: str,
    telemetry_by_workflow: dict[str, dict[str, Any]],
    receipt_by_workflow: dict[str, dict[str, Any]],
    action_by_workflow: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    telemetry = telemetry_by_workflow.get(workflow_id, {})
    receipt = receipt_by_workflow.get(workflow_id, {})
    action = action_by_workflow.get(workflow_id, {})
    return {
        "action_decision_floor": action.get("decision_floor"),
        "action_required_evidence": action.get("required_evidence", []),
        "context_package_hash": receipt.get("context_package_hash") or telemetry.get("context_package_hash"),
        "minimum_retention_days": telemetry.get("minimum_retention_days") or receipt.get("retention_days"),
        "receipt_id": receipt.get("receipt_id"),
        "telemetry_decision": telemetry.get("decision"),
        "telemetry_required_attribute_count": len(telemetry.get("required_attributes", []) or []),
    }


def build_replay_fixture(
    *,
    workflow: dict[str, Any],
    drill: dict[str, Any],
    profile: dict[str, Any],
    telemetry_by_workflow: dict[str, dict[str, Any]],
    receipt_by_workflow: dict[str, dict[str, Any]],
    action_by_workflow: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    workflow_id = str(workflow.get("workflow_id"))
    scenario_id = str(drill.get("scenario_id"))
    contract = profile.get("harness_contract", {})
    return {
        "agent_identity_classes": workflow.get("agent_identity_classes", []),
        "attack_family": drill.get("attack_family"),
        "expected_agent_behavior": drill.get("expected_agent_behavior"),
        "expected_policy_decisions": drill.get("expected_policy_decisions", []),
        "expected_runtime_outcome": expected_runtime_outcome(drill),
        "fail_signals": drill.get("fail_signals", []),
        "fixture_inputs": payload_fixtures(workflow_id, drill),
        "matched_namespaces": drill.get("matched_namespaces", []),
        "pass_criteria": drill.get("pass_criteria", []),
        "public_path": workflow.get("public_path"),
        "replay_id": replay_id(workflow_id, scenario_id),
        "replay_modes": [str(row.get("id")) for row in profile.get("replay_modes", []) if isinstance(row, dict)],
        "required_evidence": drill.get("required_evidence", []),
        "required_evidence_classes": contract.get("required_evidence_classes", []),
        "required_gate_phases": drill.get("required_gate_phases", []),
        "required_observed_fields": contract.get("required_observed_fields", []),
        "required_trace_event_classes": contract.get("required_trace_event_classes", []),
        "reviewer_questions": drill.get("reviewer_questions", []),
        "scenario_id": scenario_id,
        "scenario_title": drill.get("scenario_title"),
        "severity": drill.get("severity"),
        "standards_refs": drill.get("standards_refs", []),
        "status": "replay_ready",
        "target_control_ids": drill.get("target_control_ids", []),
        "test_steps": drill.get("test_steps", []),
        "workflow_id": workflow_id,
        "workflow_support": workflow_support(
            workflow_id,
            telemetry_by_workflow,
            receipt_by_workflow,
            action_by_workflow,
        ),
        "workflow_title": workflow.get("title"),
    }


def build_replay_fixtures(profile: dict[str, Any], source_payloads: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    red_team = source_payloads["agentic_red_team_drill_pack"]
    telemetry_by_workflow = rows_by_id(source_payloads["agentic_telemetry_contract"].get("workflow_telemetry_contracts"), "workflow_id")
    receipt_by_workflow = rows_by_id(source_payloads["agentic_run_receipt_pack"].get("workflow_receipt_templates"), "workflow_id")
    action_by_workflow = rows_by_id(source_payloads["agentic_action_runtime_pack"].get("workflow_action_matrix"), "workflow_id")

    fixtures: list[dict[str, Any]] = []
    for workflow in red_team.get("workflow_drills", []) or []:
        if not isinstance(workflow, dict):
            continue
        for drill in workflow.get("drills", []) or []:
            if not isinstance(drill, dict):
                continue
            fixtures.append(
                build_replay_fixture(
                    workflow=workflow,
                    drill=drill,
                    profile=profile,
                    telemetry_by_workflow=telemetry_by_workflow,
                    receipt_by_workflow=receipt_by_workflow,
                    action_by_workflow=action_by_workflow,
                )
            )
    return sorted(fixtures, key=lambda row: str(row.get("replay_id")))


def build_workflow_matrix(fixtures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fixture in fixtures:
        grouped[str(fixture.get("workflow_id"))].append(fixture)

    rows: list[dict[str, Any]] = []
    for workflow_id, items in sorted(grouped.items()):
        attack_families = Counter(str(item.get("attack_family")) for item in items)
        severity_counts = Counter(str(item.get("severity")) for item in items)
        rows.append(
            {
                "attack_family_counts": dict(sorted(attack_families.items())),
                "critical_or_high_replay_count": sum(1 for item in items if item.get("severity") in {"critical", "high"}),
                "public_path": items[0].get("public_path"),
                "replay_count": len(items),
                "replay_ids": [str(item.get("replay_id")) for item in items],
                "severity_counts": dict(sorted(severity_counts.items())),
                "status": "replay_ready",
                "title": items[0].get("workflow_title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def build_summary(fixtures: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    attack_families = Counter(str(item.get("attack_family")) for item in fixtures)
    severities = Counter(str(item.get("severity")) for item in fixtures)
    workflows = {str(item.get("workflow_id")) for item in fixtures}
    decisions = Counter(
        "kill_session_expected" if "kill_session" in {str(value) for value in item.get("expected_policy_decisions", []) or []}
        else "deny_expected" if "deny" in {str(value) for value in item.get("expected_policy_decisions", []) or []}
        else "scoped_continue_expected"
        for item in fixtures
    )
    return {
        "attack_family_counts": dict(sorted(attack_families.items())),
        "decision_expectation_counts": dict(sorted(decisions.items())),
        "failure_count": len(failures),
        "replay_fixture_count": len(fixtures),
        "required_evidence_class_count": len(REQUIRED_EVIDENCE_CLASSES),
        "required_trace_event_class_count": len(REQUIRED_TRACE_EVENT_CLASSES),
        "severity_counts": dict(sorted(severities.items())),
        "status": "replay_harness_ready" if not failures else "needs_attention_before_replay",
        "workflow_count": len(workflows),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    source_payloads: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, str]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    fixtures = build_replay_fixtures(profile, source_payloads)
    return {
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "evaluator_contract": {
            "default_decision": profile.get("harness_contract", {}).get("default_hold_decision"),
            "decision_order": profile.get("harness_contract", {}).get("decision_order", []),
            "required_observed_fields": profile.get("harness_contract", {}).get("required_observed_fields", []),
            "pass_decision": profile.get("harness_contract", {}).get("pass_decision"),
        },
        "evidence_classes": profile.get("evidence_classes", []),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "harness_contract": profile.get("harness_contract", {}),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "red_team_replay_harness_id": "security-recipes-agentic-red-team-replay-harness",
        "replay_modes": profile.get("replay_modes", []),
        "replay_pass_gates": profile.get("replay_pass_gates", []),
        "replay_summary": build_summary(fixtures, failures),
        "residual_risks": profile.get("risk_register", []),
        "schema_version": PACK_SCHEMA_VERSION,
        "selected_feature": {
            "id": "agentic-red-team-replay-harness",
            "implementation": [
                "Replay profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Runtime evaluator for observed replay evidence.",
                "Generated replay harness under data/evidence.",
                "Human-readable docs page and MCP tool exposure."
            ],
            "reason": "The existing red-team drill pack identified the need for an eval harness; this feature turns static drill definitions into replayable proof for enterprise pilots and acquisition diligence."
        },
        "source_artifacts": artifacts,
        "source_references": profile.get("source_references", []),
        "workflow_replay_matrix": build_workflow_matrix(fixtures),
        "replay_fixtures": fixtures,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--red-team-pack", type=Path, default=DEFAULT_RED_TEAM_PACK)
    parser.add_argument("--telemetry-contract", type=Path, default=DEFAULT_TELEMETRY_CONTRACT)
    parser.add_argument("--run-receipt-pack", type=Path, default=DEFAULT_RUN_RECEIPT_PACK)
    parser.add_argument("--action-runtime-pack", type=Path, default=DEFAULT_ACTION_RUNTIME_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in replay harness is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "agentic_action_runtime_pack": args.action_runtime_pack,
        "agentic_red_team_drill_pack": args.red_team_pack,
        "agentic_red_team_replay_harness_profile": args.profile,
        "agentic_run_receipt_pack": args.run_receipt_pack,
        "agentic_telemetry_contract": args.telemetry_contract,
    }
    paths = {key: resolve(repo_root, ref) for key, ref in refs.items()}
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["agentic_red_team_replay_harness_profile"])
        source_payloads = {
            key: load_json(path)
            for key, path in paths.items()
            if key != "agentic_red_team_replay_harness_profile"
        }
        failures = [*validate_profile(profile), *validate_sources(source_payloads, profile)]
        pack = build_pack(
            profile=profile,
            source_payloads=source_payloads,
            artifacts=source_artifacts(repo_root, refs),
            generated_at=args.generated_at,
            failures=failures,
        )
    except ReplayHarnessError as exc:
        print(f"agentic red-team replay harness generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("agentic red-team replay harness validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_red_team_replay_harness.py", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_red_team_replay_harness.py", file=sys.stderr)
            return 1
        print(f"Validated agentic red-team replay harness: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated agentic red-team replay harness with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic red-team replay harness: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
