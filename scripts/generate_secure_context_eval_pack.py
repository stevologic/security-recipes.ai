#!/usr/bin/env python3
"""Generate the SecurityRecipes secure context eval pack.

The eval pack is the measurable layer above secure context provenance,
poisoning scans, egress policy, and attestations. It turns the product
claim - "the secure context layer for agentic AI" - into scenario-backed
evidence that can run in CI and be exposed through MCP.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from scripts.evaluate_context_attestation_decision import evaluate_context_attestation_decision
    from scripts.evaluate_context_egress_decision import evaluate_context_egress_decision
    from scripts.evaluate_secure_context_retrieval import evaluate_context_retrieval_decision
except ImportError:  # pragma: no cover - supports direct script-directory execution.
    from evaluate_context_attestation_decision import evaluate_context_attestation_decision
    from evaluate_context_egress_decision import evaluate_context_egress_decision
    from evaluate_secure_context_retrieval import evaluate_context_retrieval_decision


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/secure-context-eval-scenarios.json")
DEFAULT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_ATTESTATION_PACK = Path("data/evidence/secure-context-attestation-pack.json")
DEFAULT_POISONING_PACK = Path("data/evidence/context-poisoning-guard-pack.json")
DEFAULT_EGRESS_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_THREAT_RADAR = Path("data/evidence/agentic-threat-radar.json")
DEFAULT_OUTPUT = Path("data/evidence/secure-context-eval-pack.json")

VALID_DECISIONS = {
    "eval_ready",
    "hold_for_missing_evidence",
    "deny_eval_case",
    "kill_session_on_forbidden_output",
}
REQUIRED_SOURCE_PACKS = {
    "secure_context_trust_pack",
    "secure_context_attestation_pack",
    "context_poisoning_guard_pack",
    "context_egress_boundary_pack",
    "agentic_threat_radar",
}
REQUIRED_SCENARIO_TYPES = {
    "retrieval_correctness",
    "source_attestation",
    "context_poisoning_resilience",
    "egress_safety",
    "answer_contract",
    "a2a_handoff_boundary",
}


class SecureContextEvalError(RuntimeError):
    """Raised when the secure context eval pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SecureContextEvalError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SecureContextEvalError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecureContextEvalError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SecureContextEvalError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SecureContextEvalError(f"{label} must be a list")
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


def index_by(rows: Any, key: str) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get(key)): row
        for row in rows
        if isinstance(row, dict) and row.get(key)
    }


def validate_profile(profile: dict[str, Any], threat_radar: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the eval goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include current AI, MCP, and eval references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"standards_alignment[{idx}].id duplicates {standard_id}")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 50, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("evaluation_contract"), "evaluation_contract")
    require(contract.get("default_state") == "untrusted_until_eval_passes", failures, "evaluation_contract.default_state must fail closed")
    source_packs = {str(item) for item in as_list(contract.get("required_source_packs"), "evaluation_contract.required_source_packs")}
    missing_packs = sorted(REQUIRED_SOURCE_PACKS - source_packs)
    require(not missing_packs, failures, f"evaluation_contract missing source packs: {missing_packs}")
    scenario_types = {str(item) for item in as_list(contract.get("scenario_types"), "evaluation_contract.scenario_types")}
    missing_types = sorted(REQUIRED_SCENARIO_TYPES - scenario_types)
    require(not missing_types, failures, f"evaluation_contract missing scenario types: {missing_types}")
    runtime_fields = as_list(contract.get("runtime_fields"), "evaluation_contract.runtime_fields")
    require(len(runtime_fields) >= 10, failures, "runtime_fields must include runtime evidence attributes")
    decisions = {
        str(item.get("decision"))
        for item in as_list(contract.get("decisions"), "evaluation_contract.decisions")
        if isinstance(item, dict)
    }
    require(VALID_DECISIONS.issubset(decisions), failures, "evaluation_contract must define every eval decision")

    answer_contract = as_dict(profile.get("runtime_answer_contract"), "runtime_answer_contract")
    require(int(answer_contract.get("minimum_citations") or 0) >= 1, failures, "runtime_answer_contract.minimum_citations must be positive")
    require(len(as_list(answer_contract.get("citation_fields"), "runtime_answer_contract.citation_fields")) >= 3, failures, "citation fields are incomplete")
    require(len(as_list(answer_contract.get("forbidden_output_markers"), "runtime_answer_contract.forbidden_output_markers")) >= 5, failures, "forbidden output markers are incomplete")

    signals = set(index_by(threat_radar.get("threat_signals"), "id"))
    scenarios = as_list(profile.get("scenarios"), "scenarios")
    minimum = int(contract.get("minimum_scenarios") or 0)
    require(len(scenarios) >= minimum, failures, f"profile must define at least {minimum} scenarios")

    seen_scenarios: set[str] = set()
    covered_types: set[str] = set()
    for idx, scenario in enumerate(scenarios):
        item = as_dict(scenario, f"scenarios[{idx}]")
        scenario_id = str(item.get("id", "")).strip()
        scenario_type = str(item.get("scenario_type", "")).strip()
        seen_scenarios.add(scenario_id)
        covered_types.add(scenario_type)
        require(bool(scenario_id), failures, f"scenarios[{idx}].id is required")
        require(scenario_type in scenario_types, failures, f"{scenario_id}: unknown scenario_type {scenario_type}")
        require(str(item.get("workflow_id", "")).strip(), failures, f"{scenario_id}: workflow_id is required")
        require(len(str(item.get("user_goal", ""))) >= 60, failures, f"{scenario_id}: user_goal must be specific")

        check_count = sum(
            1
            for field in [
                "retrieval_request",
                "attestation_request",
                "egress_request",
                "poisoning_expectation",
                "answer_expectation",
                "handoff_expectation",
            ]
            if isinstance(item.get(field), dict)
        )
        require(
            check_count >= int(contract.get("minimum_checks_per_scenario") or 1),
            failures,
            f"{scenario_id}: scenario must include enough checks",
        )

        mapped = {str(signal_id) for signal_id in as_list(item.get("mapped_signal_ids"), f"{scenario_id}.mapped_signal_ids")}
        missing_signals = sorted(mapped - signals)
        require(not missing_signals, failures, f"{scenario_id}: unknown mapped signal ids {missing_signals}")

    require(len(seen_scenarios) == len(scenarios), failures, "scenario IDs must be unique")
    require(REQUIRED_SCENARIO_TYPES.issubset(covered_types), failures, "profile must cover every required scenario type")
    return failures


def validate_source_packs(
    *,
    trust_pack: dict[str, Any],
    attestation_pack: dict[str, Any],
    poisoning_pack: dict[str, Any],
    egress_pack: dict[str, Any],
    threat_radar: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    payloads = {
        "secure context trust pack": trust_pack,
        "secure context attestation pack": attestation_pack,
        "context poisoning guard pack": poisoning_pack,
        "context egress boundary pack": egress_pack,
        "agentic threat radar": threat_radar,
    }
    for label, payload in payloads.items():
        require(payload.get("schema_version") == "1.0", failures, f"{label} schema_version must be 1.0")
    require(bool(trust_pack.get("context_sources")), failures, "trust pack must include context_sources")
    require(bool(attestation_pack.get("attestation_manifest")), failures, "attestation pack must include attestation_manifest")
    require(bool(poisoning_pack.get("source_results")), failures, "poisoning guard pack must include source_results")
    require(bool(egress_pack.get("data_class_policies")), failures, "egress pack must include data_class_policies")
    require(bool(threat_radar.get("threat_signals")), failures, "threat radar must include threat_signals")
    return failures


def expected_decision(request: dict[str, Any]) -> str:
    return str(request.get("expected_decision") or "").strip()


def check_result(
    *,
    check_id: str,
    check_type: str,
    expected: str,
    observed: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    status = "pass" if expected and observed == expected else "fail"
    return {
        "check_id": check_id,
        "check_type": check_type,
        "expected_decision": expected,
        "observed_decision": observed,
        "status": status,
        "evidence": evidence,
    }


def poisoning_check(
    scenario_id: str,
    expectation: dict[str, Any],
    poisoning_pack: dict[str, Any],
) -> dict[str, Any]:
    source_id = str(expectation.get("source_id") or "").strip()
    allowed = {str(item) for item in expectation.get("allowed_decisions", [])}
    max_actionable = int(expectation.get("max_actionable_findings") or 0)
    source = index_by(poisoning_pack.get("source_results"), "source_id").get(source_id)
    observed = str(source.get("decision") if source else "missing_source_result")
    actionable = int(source.get("actionable_finding_count") or 0) if source else 0
    status = "pass" if observed in allowed and actionable <= max_actionable else "fail"
    return {
        "check_id": f"{scenario_id}:poisoning",
        "check_type": "context_poisoning_scan",
        "expected_decision": sorted(allowed),
        "observed_decision": observed,
        "status": status,
        "evidence": {
            "actionable_finding_count": actionable,
            "finding_count": source.get("finding_count") if source else None,
            "max_actionable_findings": max_actionable,
            "source_hash": source.get("source_hash") if source else None,
            "source_id": source_id,
        },
    }


def answer_contract_check(
    scenario_id: str,
    expectation: dict[str, Any],
    trust_pack: dict[str, Any],
) -> dict[str, Any]:
    required_source_ids = [str(item) for item in expectation.get("required_source_ids", [])]
    sources = index_by(trust_pack.get("context_sources"), "source_id")
    missing = [source_id for source_id in required_source_ids if source_id not in sources]
    status = "pass" if not missing else "fail"
    return {
        "check_id": f"{scenario_id}:answer-contract",
        "check_type": "runtime_answer_contract",
        "expected_decision": "citations_and_hashes_required",
        "observed_decision": "citations_and_hashes_required" if status == "pass" else "missing_required_source",
        "status": status,
        "evidence": {
            "forbidden_claims": expectation.get("forbidden_claims", []),
            "missing_required_source_ids": missing,
            "required_phrases": expectation.get("required_phrases", []),
            "required_source_ids": required_source_ids,
            "source_hashes": {
                source_id: sources[source_id].get("source_hash")
                for source_id in required_source_ids
                if source_id in sources
            },
        },
    }


def handoff_check(scenario_id: str, expectation: dict[str, Any]) -> dict[str, Any]:
    allowed = [str(item) for item in expectation.get("allowed_payload_fields", [])]
    forbidden = [str(item) for item in expectation.get("forbidden_payload_fields", [])]
    status = "pass" if allowed and forbidden else "fail"
    return {
        "check_id": f"{scenario_id}:handoff-boundary",
        "check_type": "a2a_handoff_boundary",
        "expected_decision": "metadata_only_handoff",
        "observed_decision": "metadata_only_handoff" if status == "pass" else "incomplete_contract",
        "status": status,
        "evidence": {
            "allowed_payload_fields": allowed,
            "forbidden_payload_fields": forbidden,
            "target_class": expectation.get("target_class"),
        },
    }


def scenario_result(
    scenario: dict[str, Any],
    *,
    trust_pack: dict[str, Any],
    attestation_pack: dict[str, Any],
    poisoning_pack: dict[str, Any],
    egress_pack: dict[str, Any],
) -> dict[str, Any]:
    scenario_id = str(scenario.get("id"))
    workflow_id = str(scenario.get("workflow_id"))
    checks: list[dict[str, Any]] = []

    if isinstance(scenario.get("retrieval_request"), dict):
        request = dict(scenario["retrieval_request"])
        request["workflow_id"] = workflow_id
        result = evaluate_context_retrieval_decision(trust_pack, request)
        checks.append(
            check_result(
                check_id=f"{scenario_id}:retrieval",
                check_type="secure_context_retrieval",
                expected=expected_decision(request),
                observed=str(result.get("decision")),
                evidence={
                    "matched_source": result.get("matched_source"),
                    "matched_workflow": result.get("matched_workflow"),
                    "reason": result.get("reason"),
                    "violations": result.get("violations", []),
                },
            )
        )

    if isinstance(scenario.get("attestation_request"), dict):
        request = dict(scenario["attestation_request"])
        request.setdefault("workflow_id", workflow_id)
        result = evaluate_context_attestation_decision(attestation_pack, request)
        checks.append(
            check_result(
                check_id=f"{scenario_id}:attestation",
                check_type="secure_context_attestation",
                expected=expected_decision(request),
                observed=str(result.get("decision")),
                evidence={
                    "matched_subject": result.get("matched_subject"),
                    "reason": result.get("reason"),
                    "violations": result.get("violations", []),
                },
            )
        )

    if isinstance(scenario.get("egress_request"), dict):
        request = dict(scenario["egress_request"])
        request["workflow_id"] = workflow_id
        result = evaluate_context_egress_decision(egress_pack, request)
        checks.append(
            check_result(
                check_id=f"{scenario_id}:egress",
                check_type="context_egress_boundary",
                expected=expected_decision(request),
                observed=str(result.get("decision")),
                evidence={
                    "matched_data_class_policy": result.get("matched_data_class_policy"),
                    "matched_destination": result.get("matched_destination"),
                    "matched_source": result.get("matched_source"),
                    "reason": result.get("reason"),
                    "violations": result.get("violations", []),
                },
            )
        )

    if isinstance(scenario.get("poisoning_expectation"), dict):
        checks.append(poisoning_check(scenario_id, scenario["poisoning_expectation"], poisoning_pack))

    if isinstance(scenario.get("answer_expectation"), dict):
        checks.append(answer_contract_check(scenario_id, scenario["answer_expectation"], trust_pack))

    if isinstance(scenario.get("handoff_expectation"), dict):
        checks.append(handoff_check(scenario_id, scenario["handoff_expectation"]))

    failed = [check for check in checks if check.get("status") != "pass"]
    score = round(100 * (len(checks) - len(failed)) / len(checks)) if checks else 0
    if not failed and score == 100:
        decision = "eval_ready"
    elif any(str(check.get("observed_decision", "")).startswith("kill_session") and check.get("status") == "fail" for check in checks):
        decision = "kill_session_on_forbidden_output"
    elif failed:
        decision = "hold_for_missing_evidence"
    else:
        decision = "deny_eval_case"

    return {
        "answer_expectation": scenario.get("answer_expectation", {}),
        "check_count": len(checks),
        "checks": checks,
        "decision": decision,
        "failed_check_count": len(failed),
        "mapped_signal_ids": scenario.get("mapped_signal_ids", []),
        "scenario_hash": stable_hash(scenario),
        "scenario_id": scenario_id,
        "scenario_type": scenario.get("scenario_type"),
        "score": score,
        "title": scenario.get("title"),
        "user_goal": scenario.get("user_goal"),
        "workflow_id": workflow_id,
    }


def build_pack(
    *,
    profile: dict[str, Any],
    trust_pack: dict[str, Any],
    attestation_pack: dict[str, Any],
    poisoning_pack: dict[str, Any],
    egress_pack: dict[str, Any],
    threat_radar: dict[str, Any],
    paths: dict[str, Path],
    refs: dict[str, Path],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    scenario_rows = [
        scenario_result(
            scenario,
            trust_pack=trust_pack,
            attestation_pack=attestation_pack,
            poisoning_pack=poisoning_pack,
            egress_pack=egress_pack,
        )
        for scenario in as_list(profile.get("scenarios"), "scenarios")
        if isinstance(scenario, dict)
    ]
    decision_counts = Counter(str(row.get("decision")) for row in scenario_rows)
    type_counts = Counter(str(row.get("scenario_type")) for row in scenario_rows)
    average_score = round(sum(int(row.get("score") or 0) for row in scenario_rows) / len(scenario_rows)) if scenario_rows else 0

    return {
        "schema_version": PACK_SCHEMA_VERSION,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "standards_alignment": profile.get("standards_alignment", []),
        "evaluation_contract": profile.get("evaluation_contract", {}),
        "runtime_answer_contract": profile.get("runtime_answer_contract", {}),
        "eval_summary": {
            "average_score": average_score,
            "decision_counts": dict(sorted(decision_counts.items())),
            "failure_count": len(failures),
            "ready_scenario_count": decision_counts.get("eval_ready", 0),
            "scenario_count": len(scenario_rows),
            "scenario_type_counts": dict(sorted(type_counts.items())),
            "total_failed_checks": sum(int(row.get("failed_check_count") or 0) for row in scenario_rows),
        },
        "scenarios": scenario_rows,
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "source_artifacts": {
            name: {
                "path": normalize_path(refs[name]),
                "sha256": sha256_file(paths[name]),
            }
            for name in sorted(paths)
        },
        "threat_signal_coverage": [
            {
                "signal_id": signal_id,
                "scenario_count": sum(
                    1
                    for scenario in scenario_rows
                    if signal_id in {str(item) for item in scenario.get("mapped_signal_ids", [])}
                ),
            }
            for signal_id in sorted(
                {
                    str(signal_id)
                    for scenario in scenario_rows
                    for signal_id in scenario.get("mapped_signal_ids", [])
                }
            )
        ],
        "residual_risks": [
            {
                "risk": "Scenario-backed evals prove the control contract, not model quality for every future prompt.",
                "treatment": "Run these scenarios on every model, prompt, MCP server, and context-source promotion, then add customer-specific evals in the hosted product."
            },
            {
                "risk": "Open reference evals cannot include private customer tickets, repositories, or logs.",
                "treatment": "Customer runtime evals should execute tenant-side and attach only redacted hashes or trust-center summaries."
            },
            {
                "risk": "Agent-to-agent handoffs can shift context across system boundaries faster than human reviewers can inspect.",
                "treatment": "Handoffs must carry only safe metadata, source hashes, workflow IDs, and explicit human-approval state."
            }
        ],
        "failures": failures,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--trust-pack", type=Path, default=DEFAULT_TRUST_PACK)
    parser.add_argument("--attestation-pack", type=Path, default=DEFAULT_ATTESTATION_PACK)
    parser.add_argument("--poisoning-pack", type=Path, default=DEFAULT_POISONING_PACK)
    parser.add_argument("--egress-pack", type=Path, default=DEFAULT_EGRESS_PACK)
    parser.add_argument("--threat-radar", type=Path, default=DEFAULT_THREAT_RADAR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in secure context eval pack is stale.")
    parser.add_argument(
        "--update-if-stale",
        action="store_true",
        help="With --check, refresh the generated eval pack instead of failing when only the output is stale.",
    )
    return parser.parse_args()


def should_update_stale_output(args: argparse.Namespace) -> bool:
    return bool(args.update_if_stale) and bool(args.check)


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    trust_path = resolve(repo_root, args.trust_pack)
    attestation_path = resolve(repo_root, args.attestation_pack)
    poisoning_path = resolve(repo_root, args.poisoning_pack)
    egress_path = resolve(repo_root, args.egress_pack)
    threat_path = resolve(repo_root, args.threat_radar)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        trust_pack = load_json(trust_path)
        attestation_pack = load_json(attestation_path)
        poisoning_pack = load_json(poisoning_path)
        egress_pack = load_json(egress_path)
        threat_radar = load_json(threat_path)

        failures = [
            *validate_source_packs(
                trust_pack=trust_pack,
                attestation_pack=attestation_pack,
                poisoning_pack=poisoning_pack,
                egress_pack=egress_pack,
                threat_radar=threat_radar,
            ),
            *validate_profile(profile, threat_radar),
        ]
        pack = build_pack(
            profile=profile,
            trust_pack=trust_pack,
            attestation_pack=attestation_pack,
            poisoning_pack=poisoning_pack,
            egress_pack=egress_pack,
            threat_radar=threat_radar,
            paths={
                "agentic_threat_radar": threat_path,
                "context_egress_boundary_pack": egress_path,
                "context_poisoning_guard_pack": poisoning_path,
                "secure_context_attestation_pack": attestation_path,
                "secure_context_eval_profile": profile_path,
                "secure_context_trust_pack": trust_path,
            },
            refs={
                "agentic_threat_radar": args.threat_radar,
                "context_egress_boundary_pack": args.egress_pack,
                "context_poisoning_guard_pack": args.poisoning_pack,
                "secure_context_attestation_pack": args.attestation_pack,
                "secure_context_eval_profile": args.profile,
                "secure_context_trust_pack": args.trust_pack,
            },
            generated_at=args.generated_at,
            failures=failures,
        )
    except SecureContextEvalError as exc:
        print(f"secure context eval pack error: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if not output_path.exists():
            if should_update_stale_output(args):
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(rendered, encoding="utf-8")
            else:
                print(f"{output_path} does not exist", file=sys.stderr)
                return 1
        existing = output_path.read_text(encoding="utf-8")
        if existing != rendered:
            if should_update_stale_output(args):
                output_path.write_text(rendered, encoding="utf-8")
            else:
                print(f"{output_path} is stale; regenerate secure context eval pack", file=sys.stderr)
                return 1
        if failures:
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        print(f"Validated secure context eval pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Wrote secure context eval pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
