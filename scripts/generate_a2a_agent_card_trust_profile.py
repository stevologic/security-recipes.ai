#!/usr/bin/env python3
"""Generate the SecurityRecipes A2A Agent Card trust profile.

The generated pack turns a source A2A Agent Card policy model into
machine-readable intake evidence. CI can use --check to prove the
checked-in evidence is current, and MCP tools can expose the same pack
to agent hosts and enterprise reviewers.
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
    from scripts.evaluate_a2a_agent_card_trust_decision import evaluate_a2a_agent_card_trust_decision
except ImportError:  # pragma: no cover - supports direct script-directory execution.
    from evaluate_a2a_agent_card_trust_decision import evaluate_a2a_agent_card_trust_decision


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/a2a-agent-card-trust-profile.json")
DEFAULT_HANDOFF_PACK = Path("data/evidence/agent-handoff-boundary-pack.json")
DEFAULT_THREAT_RADAR = Path("data/evidence/agentic-threat-radar.json")
DEFAULT_OUTPUT = Path("data/evidence/a2a-agent-card-trust-profile.json")

REQUIRED_DECISIONS = {
    "allow_trusted_agent_card",
    "pilot_with_restricted_context",
    "hold_for_agent_card_intake",
    "deny_insecure_agent_card",
    "kill_session_on_agent_card_secret",
}
REQUIRED_PROFILES = {
    "blocked-agent-card",
    "public-discovery-only",
    "restricted-pilot-agent",
    "trusted-production-agent",
}
REQUIRED_CARD_FIELDS = {
    "capabilities",
    "defaultInputModes",
    "defaultOutputModes",
    "description",
    "name",
    "skills",
    "supportedInterfaces",
    "version",
}


class A2AAgentCardTrustProfileError(RuntimeError):
    """Raised when the Agent Card trust profile cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise A2AAgentCardTrustProfileError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise A2AAgentCardTrustProfileError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise A2AAgentCardTrustProfileError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise A2AAgentCardTrustProfileError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise A2AAgentCardTrustProfileError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


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
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the Agent Card trust goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include current A2A, MCP, AI security, and control references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicate standard id")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("trust_contract"), "trust_contract")
    require(contract.get("default_state") == "hold_for_agent_card_intake", failures, "trust_contract.default_state must hold by default")
    decisions = {
        str(decision.get("decision"))
        for decision in as_list(contract.get("decisions"), "trust_contract.decisions")
        if isinstance(decision, dict)
    }
    require(REQUIRED_DECISIONS.issubset(decisions), failures, "trust_contract must declare every Agent Card decision")
    fields = {str(field) for field in as_list(contract.get("required_agent_card_fields"), "trust_contract.required_agent_card_fields")}
    require(REQUIRED_CARD_FIELDS.issubset(fields), failures, "required Agent Card fields are incomplete")
    require(len(as_list(contract.get("required_allow_controls"), "trust_contract.required_allow_controls")) >= 8, failures, "required allow controls are incomplete")
    require(len(as_list(contract.get("prohibited_secret_markers"), "trust_contract.prohibited_secret_markers")) >= 8, failures, "secret markers are incomplete")
    require(len(as_list(contract.get("high_impact_skill_terms"), "trust_contract.high_impact_skill_terms")) >= 10, failures, "high-impact skill terms are incomplete")

    profile_rows = as_list(profile.get("intake_profiles"), "intake_profiles")
    profile_ids = {str(item.get("id")) for item in profile_rows if isinstance(item, dict)}
    require(REQUIRED_PROFILES.issubset(profile_ids), failures, "intake_profiles must include trusted, pilot, discovery, and blocked profiles")
    for idx, row in enumerate(profile_rows):
        item = as_dict(row, f"intake_profiles[{idx}]")
        profile_id = str(item.get("id", "")).strip()
        require(bool(profile_id), failures, f"intake_profiles[{idx}].id is required")
        require(str(item.get("default_decision")) in REQUIRED_DECISIONS, failures, f"{profile_id}: default_decision is invalid")
        require(len(str(item.get("description", ""))) >= 80, failures, f"{profile_id}: description must be specific")
        require(bool(as_list(item.get("required_controls"), f"{profile_id}.required_controls")), failures, f"{profile_id}: required_controls are required")
        if item.get("risk_tier") != "blocked":
            require("https_interface" in {str(control) for control in item.get("required_controls", [])}, failures, f"{profile_id}: https_interface is required")

    taxonomy = as_list(profile.get("skill_risk_taxonomy"), "skill_risk_taxonomy")
    require(len(taxonomy) >= 4, failures, "skill_risk_taxonomy must include low, medium, high, and prohibited tiers")
    for idx, item in enumerate(taxonomy):
        row = as_dict(item, f"skill_risk_taxonomy[{idx}]")
        require(str(row.get("id", "")).strip(), failures, f"skill_risk_taxonomy[{idx}].id is required")
        require(bool(as_list(row.get("required_controls"), f"{row.get('id')}.required_controls")), failures, f"{row.get('id')}: required controls are required")

    cases = as_list(profile.get("sample_agent_cards"), "sample_agent_cards")
    require(len(cases) >= 3, failures, "sample_agent_cards must include allow, pilot, and kill cases")
    for idx, case in enumerate(cases):
        item = as_dict(case, f"sample_agent_cards[{idx}]")
        case_id = str(item.get("id", "")).strip()
        require(bool(case_id), failures, f"sample_agent_cards[{idx}].id is required")
        require(str(item.get("expected_profile_id")) in profile_ids, failures, f"{case_id}: expected_profile_id is unknown")
        require(str(item.get("expected_decision")) in REQUIRED_DECISIONS, failures, f"{case_id}: expected_decision is invalid")
        require(isinstance(item.get("agent_card"), dict), failures, f"{case_id}: agent_card must be an object")

    return failures


def validate_source_packs(handoff_pack: dict[str, Any], threat_radar: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(handoff_pack.get("schema_version") == "1.0", failures, "agent handoff boundary pack schema_version must be 1.0")
    require(threat_radar.get("schema_version") == "1.0", failures, "agentic threat radar schema_version must be 1.0")
    require(bool(handoff_pack.get("handoff_profiles")), failures, "agent handoff boundary pack must include handoff_profiles")
    require(bool(threat_radar.get("threat_signals")), failures, "agentic threat radar must include threat_signals")
    return failures


def evaluate_samples(profile: dict[str, Any], pack_shell: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    for case in profile.get("sample_agent_cards", []) or []:
        if not isinstance(case, dict):
            continue
        request = {
            "agent_card": case.get("agent_card", {}),
            "declared_controls": case.get("declared_controls", []),
            "expected_domain": case.get("expected_domain"),
            "production": bool(case.get("production")),
            "profile_id": case.get("expected_profile_id"),
        }
        decision = evaluate_a2a_agent_card_trust_decision(pack_shell, request)
        expected = str(case.get("expected_decision"))
        if decision.get("decision") != expected:
            failures.append(
                f"{case.get('id')}: expected {expected}, got {decision.get('decision')}"
            )
        rows.append(
            {
                "agent_card_hash": stable_hash(case.get("agent_card", {})),
                "case_id": case.get("id"),
                "decision": decision.get("decision"),
                "expected_decision": expected,
                "expected_profile_id": case.get("expected_profile_id"),
                "production": bool(case.get("production")),
                "reason": decision.get("reason"),
                "violations": decision.get("violations", []),
            }
        )
    return rows, failures


def build_handoff_integration(profile: dict[str, Any], handoff_pack: dict[str, Any]) -> dict[str, Any]:
    handoff_profiles = {
        str(item.get("profile_id")): item
        for item in handoff_pack.get("handoff_profiles", []) or []
        if isinstance(item, dict) and item.get("profile_id")
    }
    rows: list[dict[str, Any]] = []
    for intake in profile.get("intake_profiles", []) or []:
        if not isinstance(intake, dict):
            continue
        allowed_ids = [str(item) for item in intake.get("allowed_handoff_profiles", []) or []]
        rows.append(
            {
                "allowed_handoff_profiles": [
                    {
                        "default_decision": handoff_profiles.get(profile_id, {}).get("default_decision"),
                        "profile_id": profile_id,
                        "risk_tier": handoff_profiles.get(profile_id, {}).get("risk_tier"),
                        "title": handoff_profiles.get(profile_id, {}).get("title"),
                    }
                    for profile_id in allowed_ids
                    if profile_id in handoff_profiles
                ],
                "intake_profile_id": intake.get("id"),
                "risk_tier": intake.get("risk_tier"),
            }
        )
    a2a_surface = next(
        (
            surface
            for surface in handoff_pack.get("protocol_surfaces", []) or []
            if isinstance(surface, dict) and surface.get("protocol_id") == "a2a_task_delegation"
        ),
        {},
    )
    return {
        "a2a_protocol_surface": a2a_surface,
        "profile_handoff_map": rows,
    }


def build_threat_signal_coverage(threat_radar: dict[str, Any]) -> list[dict[str, Any]]:
    related = {
        "agent-handoff-boundary-pack",
        "agent-identity-ledger",
        "context-egress-boundary",
        "mcp-authorization-conformance",
        "secure-context-trust-pack",
    }
    rows: list[dict[str, Any]] = []
    for signal in threat_radar.get("threat_signals", []) or []:
        if not isinstance(signal, dict):
            continue
        mapped = {str(item) for item in signal.get("mapped_capability_ids", []) or []}
        if mapped & related:
            rows.append(
                {
                    "mapped_capability_ids": sorted(mapped & related),
                    "priority": signal.get("priority"),
                    "signal_id": signal.get("id"),
                    "strategic_score": signal.get("strategic_score"),
                    "title": signal.get("title"),
                }
            )
    return sorted(rows, key=lambda row: str(row.get("signal_id")))


def build_summary(
    profile: dict[str, Any],
    sample_evaluations: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    decisions = Counter(str(row.get("decision")) for row in sample_evaluations)
    tiers = Counter(str(row.get("risk_tier")) for row in profile.get("intake_profiles", []) if isinstance(row, dict))
    return {
        "default_state": profile.get("trust_contract", {}).get("default_state"),
        "failure_count": len(failures),
        "intake_profile_count": len(profile.get("intake_profiles", []) or []),
        "required_agent_card_field_count": len(profile.get("trust_contract", {}).get("required_agent_card_fields", []) or []),
        "sample_decision_counts": dict(sorted(decisions.items())),
        "sample_evaluation_count": len(sample_evaluations),
        "skill_risk_tier_counts": dict(sorted(tiers.items())),
        "status": "agent_card_trust_profile_ready" if not failures else "needs_attention",
    }


def build_pack(
    *,
    profile: dict[str, Any],
    handoff_pack: dict[str, Any],
    threat_radar: dict[str, Any],
    paths: dict[str, Path],
    refs: dict[str, Path],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    pack_shell = {
        "intake_profiles": profile.get("intake_profiles", []),
        "trust_contract": profile.get("trust_contract", {}),
    }
    sample_evaluations, sample_failures = evaluate_samples(profile, pack_shell)
    all_failures = [*failures, *sample_failures]
    return {
        "schema_version": PACK_SCHEMA_VERSION,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "standards_alignment": profile.get("standards_alignment", []),
        "trust_contract": profile.get("trust_contract", {}),
        "intake_profiles": profile.get("intake_profiles", []),
        "skill_risk_taxonomy": profile.get("skill_risk_taxonomy", []),
        "sample_agent_card_evaluations": sample_evaluations,
        "handoff_integration": build_handoff_integration(profile, handoff_pack),
        "threat_signal_coverage": build_threat_signal_coverage(threat_radar),
        "agent_card_trust_summary": build_summary(profile, sample_evaluations, all_failures),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "commercialization_path": {
            "open_layer": "Publish Agent Card trust evaluation as open evidence and a local CLI so A2A pilots can start with a shared security vocabulary.",
            "enterprise_layer": "Sell hosted Agent Card monitoring, signature verification, allowlist drift detection, procurement exports, A2A gateway policy, and tenant-specific remote-agent trust tiers.",
            "acquirer_value": "A model lab, AI platform, or security vendor gets a control surface for remote-agent discovery before A2A delegation and MCP tool access become production defaults."
        },
        "source_artifacts": {
            name: {
                "path": normalize_path(refs[name]),
                "sha256": sha256_file(paths[name]),
            }
            for name in sorted(paths)
        },
        "residual_risks": [
            {
                "risk": "The open evaluator checks Agent Card evidence but does not cryptographically verify signatures.",
                "treatment": "Production deployments should verify JWS signatures against tenant or vendor trust roots before promoting an agent to the trusted-production profile."
            },
            {
                "risk": "An Agent Card can describe safe behavior while the remote opaque agent behaves differently at runtime.",
                "treatment": "Bind Agent Card trust to gateway telemetry, handoff receipts, eval replay, output inspection, and per-skill allowlists."
            },
            {
                "risk": "A2A and MCP adoption can compose into multi-hop chains where one trusted card delegates to another untrusted agent.",
                "treatment": "Require a fresh Agent Card trust decision and handoff decision at every hop, with correlation IDs propagated across the chain."
            }
        ],
        "failures": all_failures,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--handoff-pack", type=Path, default=DEFAULT_HANDOFF_PACK)
    parser.add_argument("--threat-radar", type=Path, default=DEFAULT_THREAT_RADAR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in pack is stale.")
    parser.add_argument(
        "--update-if-stale",
        action="store_true",
        help="With --check, refresh the generated pack instead of failing when only the output is stale.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    handoff_path = resolve(repo_root, args.handoff_pack)
    threat_radar_path = resolve(repo_root, args.threat_radar)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        handoff_pack = load_json(handoff_path)
        threat_radar = load_json(threat_radar_path)
        failures = [
            *validate_profile(profile),
            *validate_source_packs(handoff_pack, threat_radar),
        ]
        pack = build_pack(
            profile=profile,
            handoff_pack=handoff_pack,
            threat_radar=threat_radar,
            paths={
                "a2a_agent_card_trust_profile": profile_path,
                "agent_handoff_boundary_pack": handoff_path,
                "agentic_threat_radar": threat_radar_path,
            },
            refs={
                "a2a_agent_card_trust_profile": args.profile,
                "agent_handoff_boundary_pack": args.handoff_pack,
                "agentic_threat_radar": args.threat_radar,
            },
            generated_at=args.generated_at,
            failures=failures,
        )
    except A2AAgentCardTrustProfileError as exc:
        print(f"A2A Agent Card trust profile generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if not output_path.exists():
            if args.update_if_stale:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(rendered, encoding="utf-8")
            else:
                print(f"{output_path} is missing; run scripts/generate_a2a_agent_card_trust_profile.py", file=sys.stderr)
                return 1
        current = output_path.read_text(encoding="utf-8")
        if current != rendered:
            if args.update_if_stale:
                output_path.write_text(rendered, encoding="utf-8")
            else:
                print(f"{output_path} is stale; run scripts/generate_a2a_agent_card_trust_profile.py", file=sys.stderr)
                return 1
        if pack.get("failures"):
            print("A2A Agent Card trust profile validation failed:", file=sys.stderr)
            for failure in pack.get("failures", []):
                print(f"- {failure}", file=sys.stderr)
            return 1
        print(f"Validated A2A Agent Card trust profile: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if pack.get("failures"):
        print("Generated A2A Agent Card trust profile with validation failures:", file=sys.stderr)
        for failure in pack.get("failures", []):
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated A2A Agent Card trust profile: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
