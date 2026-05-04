#!/usr/bin/env python3
"""Generate the SecurityRecipes secure context release pack.

This pack is the release gate above secure-context provenance. It joins
the trust pack, attestation pack, poisoning guard, secure-context evals,
egress policy, and threat radar into versioned context releases for open
reference, production MCP, and trust-center use.
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
DEFAULT_PROFILE = Path("data/context/secure-context-release-profile.json")
DEFAULT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_ATTESTATION_PACK = Path("data/evidence/secure-context-attestation-pack.json")
DEFAULT_POISONING_PACK = Path("data/evidence/context-poisoning-guard-pack.json")
DEFAULT_EVAL_PACK = Path("data/evidence/secure-context-eval-pack.json")
DEFAULT_EGRESS_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_THREAT_RADAR = Path("data/evidence/agentic-threat-radar.json")
DEFAULT_OUTPUT = Path("data/context/secure-context-release-pack.json")

ALLOW_POISONING_DECISIONS = {"pass", "allow_with_adversarial_examples"}
ALLOW_ATTESTATION_DECISIONS = {"allow_attested_context", "allow_attested_workflow_context"}
ALLOW_EVAL_DECISIONS = {"eval_ready"}


class SecureContextReleaseError(RuntimeError):
    """Raised when the release pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SecureContextReleaseError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SecureContextReleaseError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecureContextReleaseError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SecureContextReleaseError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SecureContextReleaseError(f"{label} must be a list")
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


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain release gating")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include current primary references")
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        require(str(item.get("id", "")).strip(), failures, f"standards_alignment[{idx}].id is required")
        require(str(item.get("url", "")).startswith("https://"), failures, f"{item.get('id')}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 50, failures, f"{item.get('id')}: coverage must be specific")

    contract = as_dict(profile.get("release_contract"), "release_contract")
    require(
        contract.get("default_state") == "not_releasable_until_context_is_attested_scanned_evaluated_and_signed_when_required",
        failures,
        "release_contract.default_state must fail closed",
    )
    require(len(as_list(contract.get("required_source_packs"), "release_contract.required_source_packs")) >= 5, failures, "required source packs are incomplete")
    require(len(as_list(contract.get("required_release_fields"), "release_contract.required_release_fields")) >= 10, failures, "required release fields are incomplete")
    require(len(as_list(contract.get("decisions"), "release_contract.decisions")) >= 8, failures, "release decisions are incomplete")

    channels = as_list(profile.get("release_channels"), "release_channels")
    require(len(channels) >= int(contract.get("minimum_release_channels") or 0), failures, "release channel count below minimum")
    channel_ids: set[str] = set()
    for idx, channel in enumerate(channels):
        item = as_dict(channel, f"release_channels[{idx}]")
        channel_id = str(item.get("id", "")).strip()
        require(bool(channel_id), failures, f"release_channels[{idx}].id is required")
        require(channel_id not in channel_ids, failures, f"{channel_id}: duplicate release channel")
        channel_ids.add(channel_id)
        require(str(item.get("target_environment", "")).strip(), failures, f"{channel_id}: target_environment is required")
        require(isinstance(item.get("requires_signature"), bool), failures, f"{channel_id}: requires_signature must be boolean")
        require(len(as_list(item.get("minimum_controls"), f"{channel_id}.minimum_controls")) >= 4, failures, f"{channel_id}: minimum_controls are incomplete")

    bundles = as_list(profile.get("release_bundles"), "release_bundles")
    require(len(bundles) >= int(contract.get("minimum_release_bundles") or 0), failures, "release bundle count below minimum")
    bundle_ids: set[str] = set()
    for idx, bundle in enumerate(bundles):
        item = as_dict(bundle, f"release_bundles[{idx}]")
        bundle_id = str(item.get("id", "")).strip()
        channel_id = str(item.get("channel_id", "")).strip()
        require(bool(bundle_id), failures, f"release_bundles[{idx}].id is required")
        require(bundle_id not in bundle_ids, failures, f"{bundle_id}: duplicate release bundle")
        bundle_ids.add(bundle_id)
        require(channel_id in channel_ids, failures, f"{bundle_id}: unknown channel_id {channel_id}")
        require(str(item.get("workflow_id", "")).strip(), failures, f"{bundle_id}: workflow_id is required")
        require(len(as_list(item.get("source_ids"), f"{bundle_id}.source_ids")) >= 2, failures, f"{bundle_id}: at least two sources are required")
        require(bool(as_list(item.get("required_eval_scenario_ids"), f"{bundle_id}.required_eval_scenario_ids")), failures, f"{bundle_id}: required eval scenarios are required")
        require(len(str(item.get("commercial_value", ""))) >= 60, failures, f"{bundle_id}: commercial_value must be specific")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer views must include platform, procurement, and diligence")
    return failures


def validate_source_packs(packs: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for name, pack in packs.items():
        require(pack.get("schema_version") == PACK_SCHEMA_VERSION, failures, f"{name} schema_version must be 1.0")
    require(bool(packs["secure_context_trust_pack"].get("context_sources")), failures, "trust pack must include context_sources")
    require(bool(packs["secure_context_attestation_pack"].get("attestation_manifest")), failures, "attestation pack must include attestation_manifest")
    require(bool(packs["context_poisoning_guard_pack"].get("source_results")), failures, "poisoning pack must include source_results")
    require(bool(packs["secure_context_eval_pack"].get("scenarios")), failures, "eval pack must include scenarios")
    require(bool(packs["context_egress_boundary_pack"].get("data_class_policies")), failures, "egress pack must include data_class_policies")
    require(bool(packs["agentic_threat_radar"].get("threat_signals")), failures, "threat radar must include threat_signals")
    return failures


def channel_by_id(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(profile.get("release_channels"), "id")


def attestation_sources(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    manifest = pack.get("attestation_manifest")
    if not isinstance(manifest, dict):
        return {}
    return index_by(manifest.get("context_source_attestations"), "source_id")


def workflow_attestations(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    manifest = pack.get("attestation_manifest")
    if not isinstance(manifest, dict):
        return {}
    return index_by(manifest.get("workflow_context_package_attestations"), "workflow_id")


def release_hash(release_id: str, workflow_id: str, source_rows: list[dict[str, Any]]) -> str:
    payload = {
        "release_id": release_id,
        "sources": [
            {
                "source_hash": source.get("source_hash"),
                "source_id": source.get("source_id"),
            }
            for source in sorted(source_rows, key=lambda row: str(row.get("source_id")))
        ],
        "workflow_id": workflow_id,
    }
    return stable_hash(payload)


def release_decision(
    *,
    channel: dict[str, Any],
    missing_sources: list[str],
    source_rows: list[dict[str, Any]],
    source_attestations: list[dict[str, Any]],
    poisoning_results: list[dict[str, Any]],
    eval_results: list[dict[str, Any]],
) -> tuple[str, list[str]]:
    blockers: list[str] = []
    if missing_sources:
        return "deny_unregistered_release_source", [f"missing source: {source_id}" for source_id in missing_sources]

    prohibited = [
        str(source.get("source_id"))
        for source in source_rows
        if str(source.get("decision")) == "kill_session_on_prohibited_context"
        or str(source.get("trust_tier", {}).get("id")) == "tier_4_prohibited_context"
    ]
    if prohibited:
        return "kill_session_on_release_violation", [f"prohibited context source: {source_id}" for source_id in prohibited]

    attestation_blockers = [
        str(item.get("source_id"))
        for item in source_attestations
        if item.get("status") != "active" or str(item.get("decision")) not in ALLOW_ATTESTATION_DECISIONS
    ]
    if attestation_blockers:
        return "hold_for_recertification", [f"source attestation not active: {source_id}" for source_id in attestation_blockers]

    poisoning_blockers = [
        str(item.get("source_id"))
        for item in poisoning_results
        if str(item.get("decision")) not in ALLOW_POISONING_DECISIONS
        or int(item.get("actionable_finding_count") or 0) > 0
    ]
    if poisoning_blockers:
        return "hold_for_poisoning_review", [f"poisoning review required: {source_id}" for source_id in poisoning_blockers]

    eval_blockers = [
        str(item.get("scenario_id"))
        for item in eval_results
        if str(item.get("decision")) not in ALLOW_EVAL_DECISIONS
    ]
    if eval_blockers:
        return "hold_for_eval_replay", [f"eval scenario not ready: {scenario_id}" for scenario_id in eval_blockers]

    if channel.get("requires_signature"):
        blockers.append("signature bundle and transparency proof required for this channel")
        return "hold_for_signature", blockers

    return "allow_open_reference_release", blockers


def build_release_bundle(
    bundle: dict[str, Any],
    profile: dict[str, Any],
    packs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    trust_sources = index_by(packs["secure_context_trust_pack"].get("context_sources"), "source_id")
    source_attestations = attestation_sources(packs["secure_context_attestation_pack"])
    workflow_context = workflow_attestations(packs["secure_context_attestation_pack"]).get(str(bundle.get("workflow_id")))
    poisoning = index_by(packs["context_poisoning_guard_pack"].get("source_results"), "source_id")
    evals = index_by(packs["secure_context_eval_pack"].get("scenarios"), "scenario_id")
    channels = channel_by_id(profile)
    channel = channels[str(bundle.get("channel_id"))]

    source_ids = [str(item) for item in bundle.get("source_ids", [])]
    source_rows = [trust_sources[source_id] for source_id in source_ids if source_id in trust_sources]
    missing_sources = sorted(source_id for source_id in source_ids if source_id not in trust_sources)
    source_attestation_rows = [source_attestations.get(source_id, {"source_id": source_id, "status": "missing"}) for source_id in source_ids]
    poisoning_rows = [poisoning.get(source_id, {"source_id": source_id, "decision": "missing_source_result"}) for source_id in source_ids]
    eval_ids = [str(item) for item in bundle.get("required_eval_scenario_ids", [])]
    eval_rows = [evals.get(scenario_id, {"scenario_id": scenario_id, "decision": "missing_eval_scenario"}) for scenario_id in eval_ids]
    decision, blockers = release_decision(
        channel=channel,
        missing_sources=missing_sources,
        source_rows=source_rows,
        source_attestations=source_attestation_rows,
        poisoning_results=poisoning_rows,
        eval_results=eval_rows,
    )
    source_hashes = {
        str(source.get("source_id")): source.get("source_hash")
        for source in source_rows
    }

    return {
        "allowed_audiences": bundle.get("allowed_audiences", []),
        "blockers": blockers,
        "channel": {
            "id": channel.get("id"),
            "requires_signature": channel.get("requires_signature"),
            "target_environment": channel.get("target_environment"),
            "title": channel.get("title"),
        },
        "commercial_value": bundle.get("commercial_value"),
        "context_package_hash": release_hash(str(bundle.get("id")), str(bundle.get("workflow_id")), source_rows),
        "default_release_decision": decision,
        "egress_policy_state": {
            "pack": "context_egress_boundary_pack",
            "summary": packs["context_egress_boundary_pack"].get("egress_boundary_summary"),
        },
        "eval_state": {
            "required_scenario_ids": eval_ids,
            "scenario_results": [
                {
                    "decision": item.get("decision"),
                    "failed_check_count": item.get("failed_check_count"),
                    "scenario_id": item.get("scenario_id"),
                    "score": item.get("score"),
                    "workflow_id": item.get("workflow_id"),
                }
                for item in eval_rows
            ],
        },
        "missing_source_ids": missing_sources,
        "poisoning_scan_state": {
            "source_results": [
                {
                    "actionable_finding_count": item.get("actionable_finding_count"),
                    "decision": item.get("decision"),
                    "source_id": item.get("source_id"),
                }
                for item in poisoning_rows
            ],
        },
        "release_id": bundle.get("id"),
        "release_manifest_hash": stable_hash(
            {
                "channel_id": bundle.get("channel_id"),
                "release_id": bundle.get("id"),
                "source_hashes": source_hashes,
                "workflow_id": bundle.get("workflow_id"),
            }
        ),
        "rollback_triggers": bundle.get("rollback_triggers", []),
        "signature_policy": {
            "open_reference_state": "unsigned_release_manifest",
            "production_state": "requires_external_keyless_signature_bundle" if channel.get("requires_signature") else "signature_not_required",
            "requires_signature": channel.get("requires_signature"),
            "requires_transparency_log": channel.get("requires_signature"),
        },
        "source_attestation_state": {
            "source_attestations": [
                {
                    "attestation_id": item.get("attestation_id"),
                    "decision": item.get("decision"),
                    "source_id": item.get("source_id"),
                    "status": item.get("status"),
                }
                for item in source_attestation_rows
            ],
            "workflow_context_attestation": {
                "attestation_id": workflow_context.get("attestation_id") if workflow_context else None,
                "decision": workflow_context.get("decision") if workflow_context else None,
                "status": workflow_context.get("status") if workflow_context else "missing",
                "workflow_id": bundle.get("workflow_id"),
            },
        },
        "source_hashes": source_hashes,
        "source_ids": source_ids,
        "title": bundle.get("title"),
        "workflow_id": bundle.get("workflow_id"),
    }


def build_summary(releases: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    decisions = Counter(str(release.get("default_release_decision")) for release in releases)
    channel_ids = Counter(str(release.get("channel", {}).get("id")) for release in releases)
    return {
        "channel_counts": dict(sorted(channel_ids.items())),
        "failure_count": len(failures),
        "release_count": len(releases),
        "release_decision_counts": dict(sorted(decisions.items())),
        "signed_release_count": sum(1 for release in releases if release.get("signature_policy", {}).get("requires_signature")),
        "status": "release_gate_ready" if not failures else "needs_attention",
    }


def source_artifacts(paths: dict[str, Path], refs: dict[str, Path]) -> dict[str, Any]:
    return {
        name: {
            "path": normalize_path(refs[name]),
            "sha256": sha256_file(paths[name]),
        }
        for name in sorted(paths)
    }


def build_pack(
    *,
    profile: dict[str, Any],
    packs: dict[str, dict[str, Any]],
    paths: dict[str, Path],
    refs: dict[str, Path],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    releases = [
        build_release_bundle(bundle, profile, packs)
        for bundle in as_list(profile.get("release_bundles"), "release_bundles")
        if isinstance(bundle, dict)
    ]
    return {
        "buyer_views": profile.get("buyer_views", []),
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "release_channels": profile.get("release_channels", []),
        "release_contract": profile.get("release_contract", {}),
        "release_manifest": releases,
        "release_summary": build_summary(releases, failures),
        "residual_risks": [
            {
                "risk": "Open-reference releases are unsigned and prove source state, not live customer enforcement.",
                "treatment": "Production MCP and trust-center channels require external keyless signatures and transparency-log proof before release promotion."
            },
            {
                "risk": "A release can become stale after context, model, workflow, connector, or eval drift.",
                "treatment": "Regenerate the release pack in CI and use hosted release rollback alerts when source hashes, eval states, or poisoning decisions change."
            },
            {
                "risk": "Customer-private context cannot be stored in this public release manifest.",
                "treatment": "Customer releases should keep private data tenant-side and export only hashes, policy decisions, and redacted trust-center summaries."
            }
        ],
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts(paths, refs),
        "standards_alignment": profile.get("standards_alignment", []),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--trust-pack", type=Path, default=DEFAULT_TRUST_PACK)
    parser.add_argument("--attestation-pack", type=Path, default=DEFAULT_ATTESTATION_PACK)
    parser.add_argument("--poisoning-pack", type=Path, default=DEFAULT_POISONING_PACK)
    parser.add_argument("--eval-pack", type=Path, default=DEFAULT_EVAL_PACK)
    parser.add_argument("--egress-pack", type=Path, default=DEFAULT_EGRESS_PACK)
    parser.add_argument("--threat-radar", type=Path, default=DEFAULT_THREAT_RADAR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in release pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "agentic_threat_radar": args.threat_radar,
        "context_egress_boundary_pack": args.egress_pack,
        "context_poisoning_guard_pack": args.poisoning_pack,
        "secure_context_attestation_pack": args.attestation_pack,
        "secure_context_eval_pack": args.eval_pack,
        "secure_context_release_profile": args.profile,
        "secure_context_trust_pack": args.trust_pack,
    }
    paths = {name: resolve(repo_root, path) for name, path in refs.items()}
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["secure_context_release_profile"])
        packs = {
            "agentic_threat_radar": load_json(paths["agentic_threat_radar"]),
            "context_egress_boundary_pack": load_json(paths["context_egress_boundary_pack"]),
            "context_poisoning_guard_pack": load_json(paths["context_poisoning_guard_pack"]),
            "secure_context_attestation_pack": load_json(paths["secure_context_attestation_pack"]),
            "secure_context_eval_pack": load_json(paths["secure_context_eval_pack"]),
            "secure_context_trust_pack": load_json(paths["secure_context_trust_pack"]),
        }
        failures = [
            *validate_profile(profile),
            *validate_source_packs(packs),
        ]
        pack = build_pack(
            profile=profile,
            packs=packs,
            paths=paths,
            refs=refs,
            generated_at=args.generated_at,
            failures=failures,
        )
    except SecureContextReleaseError as exc:
        print(f"secure context release pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("secure context release pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_secure_context_release_pack.py", file=sys.stderr)
            return 1
        print(f"Validated secure context release pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated secure context release pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated secure context release pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
