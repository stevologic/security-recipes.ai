#!/usr/bin/env python3
"""Evaluate CVE intelligence intake packets against the local policy.

The evaluator is intentionally deterministic and conservative. It does not
fetch advisory data or inspect repositories; it checks whether an intake packet
contains enough evidence to route a CVE/GHSA signal to remediation,
containment, suppression, triage, or rejection.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = REPO_ROOT / "data" / "intelligence" / "cve-intelligence-intake-gates.json"
DEFAULT_FIXTURES = REPO_ROOT / "data" / "intelligence" / "cve-intelligence-intake-fixtures.json"

IDENTIFIER_PATTERN = re.compile(
    r"^(?:"
    r"CVE-\d{4}-\d{4,}|"
    r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|"
    r"OSV-\d{4}-\d+|"
    r"PYSEC-\d{4}-\d+|"
    r"RUSTSEC-\d{4}-\d+|"
    r"GO-\d{4}-\d+|"
    r"USN-\d{4,}-\d+|"
    r"RHSA-\d{4}:\d+|"
    r"ALAS\d*-\d{4}-\d+|"
    r"VMSA-\d{4}-\d+"
    r")$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SourceAudit:
    standalone_primary_source_types: list[str]
    valid_primary_sources: list[dict[str, Any]]
    invalid_or_non_standalone_sources: list[dict[str, Any]]


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def evaluate_packet(
    packet: dict[str, Any],
    policy: dict[str, Any],
    *,
    evaluation_date: str | None = None,
) -> dict[str, Any]:
    contract = policy.get("evaluator_contract", {})
    output_files = contract.get("output_files", {})
    source_audit = audit_sources(packet, policy)
    priority_modifiers = collect_priority_modifiers(packet)
    missing_evidence = collect_missing_evidence(packet, source_audit)

    eval_date = str(packet.get("evaluation_date") or evaluation_date or "").strip()
    follow_up_date = str(packet.get("follow_up_date") or "").strip()
    date_error = validate_dates(eval_date, follow_up_date)
    if date_error:
        missing_evidence.append(date_error)

    canonical_id = str(packet.get("canonical_id") or "").strip()
    stable_identifier = bool(IDENTIFIER_PATTERN.fullmatch(canonical_id))
    sources_disagree = bool(packet.get("sources_disagree"))
    exposure_status = normalize_status(packet.get("exposure_status"))

    if not stable_identifier and not has_meaningful_surface(packet):
        decision = "reject_unverified"
        reason = "no stable identifier or affected surface"
    elif not stable_identifier:
        decision = "triage_needed"
        reason = "canonical identifier is missing or malformed"
    elif not source_audit.valid_primary_sources:
        decision = "triage_needed"
        reason = "no standalone primary source with an absolute URL"
    elif sources_disagree:
        decision = "triage_needed"
        reason = "sources disagree in a way that changes remediation"
    elif missing_evidence:
        decision = "triage_needed"
        reason = "required intake evidence is missing or stale"
    elif exposure_status in suppression_statuses(policy):
        decision = "suppress_not_exposed"
        reason = f"exposure status is {exposure_status}"
    elif is_containment_packet(packet):
        decision = "accept_containment"
        reason = "full remediation is blocked and a temporary control is recorded"
    elif exposure_status in remediation_statuses(policy):
        decision = "accept_remediation"
        reason = "primary-source-backed remediation evidence is complete"
    else:
        decision = "triage_needed"
        reason = "exposure status does not support remediation, containment, or suppression"

    return {
        "decision": decision,
        "output_file": output_files.get(decision),
        "reason": reason,
        "canonical_id_valid": stable_identifier,
        "evaluation_date": eval_date,
        "source_evidence": {
            "standalone_primary_source_types": source_audit.standalone_primary_source_types,
            "valid_primary_sources": source_audit.valid_primary_sources,
            "invalid_or_non_standalone_sources": source_audit.invalid_or_non_standalone_sources,
        },
        "primary_source_backed": bool(source_audit.valid_primary_sources),
        "valid_primary_source_count": len(source_audit.valid_primary_sources),
        "invalid_or_non_standalone_source_count": len(source_audit.invalid_or_non_standalone_sources),
        "priority_modifiers": priority_modifiers,
        "missing_evidence": missing_evidence,
    }


def audit_sources(packet: dict[str, Any], policy: dict[str, Any]) -> SourceAudit:
    standalone = [
        str(item.get("source_type"))
        for item in policy.get("source_priority", [])
        if isinstance(item, dict) and item.get("standalone_primary_source")
    ]
    standalone_set = {item.lower() for item in standalone}
    valid: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []

    sources = packet.get("source_links")
    if not isinstance(sources, list):
        sources = []

    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            invalid.append({"index": index, "reason": "source entry is not an object"})
            continue
        url = str(source.get("url") or "").strip()
        source_type = str(source.get("source_type") or "").strip()
        reasons = []
        if source_type.lower() not in standalone_set:
            reasons.append("source type is not standalone primary evidence")
        if not is_absolute_http_url(url):
            reasons.append("source URL is missing or not absolute http(s)")
        if reasons:
            invalid.append(
                {
                    "index": index,
                    "source_type": source_type,
                    "url": url,
                    "publisher": source.get("publisher"),
                    "reasons": reasons,
                }
            )
            continue
        valid.append(
            {
                "index": index,
                "source_type": source_type,
                "url": url,
                "publisher": source.get("publisher"),
            }
        )

    return SourceAudit(standalone, valid, invalid)


def collect_missing_evidence(packet: dict[str, Any], source_audit: SourceAudit) -> list[str]:
    missing = []
    if not str(packet.get("canonical_id") or "").strip():
        missing.append("canonical_id")
    if not source_audit.valid_primary_sources:
        missing.append("source_links.primary")
    for key in ("affected_surface", "affected_range", "fix_or_containment_path", "owner"):
        if not str(packet.get(key) or "").strip():
            missing.append(key)
    for key in ("repository_evidence", "verification_commands"):
        value = packet.get(key)
        if not isinstance(value, list) or not any(str(item).strip() for item in value):
            missing.append(key)
    return missing


def validate_dates(evaluation_date: str, follow_up_date: str) -> str | None:
    if not evaluation_date:
        return "evaluation_date"
    parsed_evaluation = parse_iso_date(evaluation_date)
    if not parsed_evaluation:
        return "evaluation_date"
    if not follow_up_date:
        return "follow_up_date"
    parsed_follow_up = parse_iso_date(follow_up_date)
    if not parsed_follow_up:
        return "follow_up_date"
    if parsed_follow_up < parsed_evaluation:
        return "follow_up_date_before_evaluation_date"
    return None


def collect_priority_modifiers(packet: dict[str, Any]) -> list[str]:
    checks = {
        "known_exploited": ("known_exploited", "kev", "vendor_confirmed_exploitation", "internal_incident_signal"),
        "internet_reachable": ("internet_reachable", "public_route", "externally_reachable"),
        "agent_or_control_plane": ("agent_or_control_plane", "agent_surface", "mcp_surface", "connector_surface"),
        "no_known_fix": ("no_known_fix",),
    }
    modifiers = []
    for modifier, keys in checks.items():
        if any(bool(packet.get(key)) for key in keys) and modifier not in modifiers:
            modifiers.append(modifier)
    return modifiers


def has_meaningful_surface(packet: dict[str, Any]) -> bool:
    return bool(str(packet.get("affected_surface") or "").strip() or str(packet.get("affected_range") or "").strip())


def is_containment_packet(packet: dict[str, Any]) -> bool:
    return bool(packet.get("full_fix_blocked") or packet.get("temporary_control") or packet.get("no_known_fix"))


def remediation_statuses(policy: dict[str, Any]) -> set[str]:
    contract = policy.get("evaluator_contract", {})
    statuses = contract.get("exposure_statuses", {}).get("remediation", ["plausible", "confirmed"])
    return {normalize_status(item) for item in statuses}


def suppression_statuses(policy: dict[str, Any]) -> set[str]:
    contract = policy.get("evaluator_contract", {})
    statuses = contract.get("exposure_statuses", {}).get(
        "suppression",
        ["absent", "unreachable", "dev_only", "test_only", "below_preconditions"],
    )
    return {normalize_status(item) for item in statuses}


def normalize_status(value: Any) -> str:
    return str(value or "unknown").strip().lower()


def is_absolute_http_url(value: str) -> bool:
    return value.startswith("https://") or value.startswith("http://")


def parse_iso_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def run_fixtures(
    *,
    policy: dict[str, Any],
    fixtures: dict[str, Any],
    case_id: str | None,
    verbose: bool,
) -> int:
    cases = fixtures.get("cases")
    if not isinstance(cases, list):
        raise ValueError("fixture file does not contain a cases array")

    selected = [case for case in cases if isinstance(case, dict) and (not case_id or case.get("id") == case_id)]
    if case_id and not selected:
        raise ValueError(f"fixture case not found: {case_id}")

    failures = 0
    for case in selected:
        packet = case.get("packet")
        if not isinstance(packet, dict):
            print(f"not ok - {case.get('id')} packet is not an object")
            failures += 1
            continue
        result = evaluate_packet(packet, policy, evaluation_date=str(fixtures.get("evaluation_date") or ""))
        expected = str(case.get("expected_decision") or "")
        ok = result["decision"] == expected
        expected_evidence = case.get("expected_evidence")
        if ok and isinstance(expected_evidence, dict):
            ok = evidence_matches(result, expected_evidence)
        status = "ok" if ok else "not ok"
        print(f"{status} - {case.get('id')} => {result['decision']}")
        if verbose or not ok:
            print(json.dumps(result, indent=2, sort_keys=True))
        if not ok:
            failures += 1
    return 1 if failures else 0


def evidence_matches(result: dict[str, Any], expected: dict[str, Any]) -> bool:
    for key, expected_value in expected.items():
        actual = result.get(key)
        if key == "priority_modifiers" and isinstance(expected_value, list):
            if not set(expected_value).issubset(set(actual or [])):
                return False
            continue
        if actual != expected_value:
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--packet", type=Path, help="JSON intake packet to evaluate.")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES, help="Fixture file for --run-fixtures.")
    parser.add_argument("--run-fixtures", action="store_true", help="Evaluate fixture cases instead of a packet.")
    parser.add_argument("--case", help="Only run one fixture case.")
    parser.add_argument("--evaluation-date", help="YYYY-MM-DD evaluation date used when a packet omits it.")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    policy_path = args.policy if args.policy.is_absolute() else REPO_ROOT / args.policy
    policy = load_json(policy_path)
    if args.run_fixtures or args.case:
        fixtures_path = args.fixtures if args.fixtures.is_absolute() else REPO_ROOT / args.fixtures
        return run_fixtures(policy=policy, fixtures=load_json(fixtures_path), case_id=args.case, verbose=args.verbose)

    if not args.packet:
        parser.error("--packet is required unless --run-fixtures or --case is used")

    packet_path = args.packet if args.packet.is_absolute() else REPO_ROOT / args.packet
    packet = load_json(packet_path)
    result = evaluate_packet(packet, policy, evaluation_date=args.evaluation_date)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("decision") else 1


if __name__ == "__main__":
    raise SystemExit(main())
