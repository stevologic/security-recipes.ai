#!/usr/bin/env python3
"""Generate the SecurityRecipes secure context attestation pack.

The existing secure context trust pack proves source ownership, trust
tiers, retrieval decisions, and workflow context package hashes. This
generator turns that evidence into an attestation-shaped artifact that
can be fed to CI, MCP gateways, procurement review, and a future hosted
keyless signing path.

The generated pack is deliberately unsigned. It is an open reference
attestation seed with enough structure to sign later through Sigstore,
in-toto, or an enterprise signing service without inventing a different
control model.
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
DEFAULT_PROFILE = Path("data/assurance/secure-context-attestation-profile.json")
DEFAULT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/secure-context-attestation-pack.json")


class SecureContextAttestationError(RuntimeError):
    """Raised when the attestation pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SecureContextAttestationError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SecureContextAttestationError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecureContextAttestationError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SecureContextAttestationError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SecureContextAttestationError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def trust_tier_id(source: dict[str, Any]) -> str:
    trust_tier = source.get("trust_tier")
    if isinstance(trust_tier, dict):
        return str(trust_tier.get("id") or "")
    return str(trust_tier or "")


def owner_label(source: dict[str, Any]) -> str:
    owner = source.get("owner")
    if not isinstance(owner, dict):
        return ""
    return str(owner.get("accountable_team") or owner.get("evidence_owner") or "")


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the attestation goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 8, failures, "standards_alignment must include current primary references")
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        require(str(item.get("id", "")).strip(), failures, f"standards_alignment[{idx}].id is required")
        require(str(item.get("url", "")).startswith("https://"), failures, f"{item.get('id')}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 50, failures, f"{item.get('id')}: coverage must be specific")

    contract = as_dict(profile.get("attestation_contract"), "attestation_contract")
    require(
        contract.get("default_state") == "untrusted_until_attested_and_recertified",
        failures,
        "attestation_contract.default_state must fail closed",
    )
    require(str(contract.get("predicate_type", "")).startswith("https://"), failures, "predicate_type must be an HTTPS URI")
    require(contract.get("statement_type") == "https://in-toto.io/Statement/v1", failures, "statement_type must use in-toto Statement v1")
    require(contract.get("hash_algorithm") == "sha256", failures, "hash_algorithm must be sha256")
    require(len(as_list(contract.get("required_subject_fields"), "attestation_contract.required_subject_fields")) >= 8, failures, "required subject fields are incomplete")
    require(len(as_list(contract.get("signed_environments"), "attestation_contract.signed_environments")) >= 2, failures, "signed environments are required")
    recert = as_dict(contract.get("trust_tier_recertification_days"), "attestation_contract.trust_tier_recertification_days")
    for tier in ("tier_1_curated_guidance", "tier_2_policy_context", "tier_3_customer_runtime_context"):
        require(isinstance(recert.get(tier), int), failures, f"{tier} recertification days are required")

    policy = as_dict(profile.get("verification_policy"), "verification_policy")
    require(str(policy.get("default_decision")) == "deny_unregistered_attestation", failures, "verification policy must deny by default")
    decisions = {str(item.get("decision")) for item in as_list(policy.get("decisions"), "verification_policy.decisions") if isinstance(item, dict)}
    expected = {
        "allow_attested_context",
        "allow_attested_workflow_context",
        "hold_for_signature",
        "hold_for_recertification",
        "deny_attestation_mismatch",
        "deny_unregistered_attestation",
        "kill_session_on_forbidden_attestation",
    }
    require(expected.issubset(decisions), failures, "verification policy is missing required decisions")
    require(len(as_list(policy.get("production_signature_requirements"), "verification_policy.production_signature_requirements")) >= 5, failures, "production signature requirements are incomplete")

    return failures


def validate_trust_pack(trust_pack: dict[str, Any], profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    sources = as_list(trust_pack.get("context_sources"), "context_sources")
    workflows = as_list(trust_pack.get("workflow_context_map"), "workflow_context_map")
    contract = as_dict(profile.get("attestation_contract"), "attestation_contract")
    minimum_sources = int(contract.get("minimum_context_source_subjects") or 0)
    minimum_workflows = int(contract.get("minimum_workflow_package_subjects") or 0)

    require(len(sources) >= minimum_sources, failures, "trust pack has too few context source subjects")
    require(len(workflows) >= minimum_workflows, failures, "trust pack has too few workflow package subjects")
    require(isinstance(trust_pack.get("source_artifacts"), dict), failures, "trust pack is missing source_artifacts")

    source_ids: set[str] = set()
    for idx, source in enumerate(sources):
        if not isinstance(source, dict):
            failures.append(f"context_sources[{idx}] must be an object")
            continue
        source_id = str(source.get("source_id") or "")
        source_ids.add(source_id)
        require(bool(source_id), failures, f"context_sources[{idx}].source_id is required")
        require(bool(source.get("source_hash")), failures, f"{source_id}: source_hash is required")
        require(bool(owner_label(source)), failures, f"{source_id}: accountable owner is required")
        require(bool(trust_tier_id(source)), failures, f"{source_id}: trust_tier is required")
        require(source.get("citation_required") is True, failures, f"{source_id}: citation_required must be true")
        require("instruction_demoted" in {str(item) for item in source.get("required_controls", [])}, failures, f"{source_id}: instruction_demoted control is required")

    for idx, workflow in enumerate(workflows):
        if not isinstance(workflow, dict):
            failures.append(f"workflow_context_map[{idx}] must be an object")
            continue
        workflow_id = str(workflow.get("workflow_id") or "")
        require(bool(workflow_id), failures, f"workflow_context_map[{idx}].workflow_id is required")
        require(bool(workflow.get("context_package_hash")), failures, f"{workflow_id}: context_package_hash is required")
        missing = sorted({str(item) for item in workflow.get("source_ids", [])} - source_ids)
        require(not missing, failures, f"{workflow_id}: workflow references unattested source ids {missing}")

    return failures


def source_attestation(source: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    contract = as_dict(profile.get("attestation_contract"), "attestation_contract")
    recert = as_dict(contract.get("trust_tier_recertification_days"), "trust_tier_recertification_days")
    tier = trust_tier_id(source)
    policy_decision = str(source.get("decision") or "")
    status = "active"
    if source.get("freshness_state") != "declared_current":
        status = "needs_recertification"
    if not source.get("source_hash"):
        status = "invalid_missing_hash"
    if policy_decision == "kill_session_on_prohibited_context":
        status = "forbidden_context"

    subject = {
        "digest": {
            "sha256": source.get("source_hash")
        },
        "name": f"secure-context-source:{source.get('source_id')}",
    }
    return {
        "attestation_id": f"ctxsrc-{source.get('source_id')}",
        "controls": source.get("required_controls", []),
        "decision": "allow_attested_context" if status == "active" else "hold_for_recertification",
        "freshness_state": source.get("freshness_state"),
        "owner": source.get("owner"),
        "policy_decision": policy_decision,
        "recertification": {
            "due_days": int(recert.get(tier, 30) or 0),
            "owner": owner_label(source),
            "trigger_events": [
                "source_hash_change",
                "retrieval_mode_change",
                "trust_tier_change",
                "owner_change",
                "poisoning_control_change",
                "generator_or_mcp_runtime_change"
            ]
        },
        "root": source.get("root"),
        "source_hash": source.get("source_hash"),
        "source_id": source.get("source_id"),
        "status": status,
        "subject": subject,
        "subject_type": "context_source",
        "title": source.get("title"),
        "trust_tier": tier,
    }


def workflow_attestation(workflow: dict[str, Any], context_subjects: dict[str, dict[str, Any]]) -> dict[str, Any]:
    source_ids = [str(item) for item in workflow.get("source_ids", [])]
    missing = sorted(source_id for source_id in source_ids if source_id not in context_subjects)
    status = "active"
    if workflow.get("freshness_state") != "declared_current":
        status = "needs_recertification"
    if workflow.get("status") != "active":
        status = "not_active"
    if missing:
        status = "invalid_missing_source_attestation"

    subject = {
        "digest": {
            "sha256": workflow.get("context_package_hash")
        },
        "name": f"workflow-context-package:{workflow.get('workflow_id')}",
    }
    return {
        "attestation_id": f"wfctx-{workflow.get('workflow_id')}",
        "context_package_hash": workflow.get("context_package_hash"),
        "decision": "allow_attested_workflow_context" if status == "active" else "hold_for_recertification",
        "freshness_state": workflow.get("freshness_state"),
        "missing_source_attestation_ids": missing,
        "mcp_namespaces": workflow.get("mcp_namespaces", []),
        "public_path": workflow.get("public_path"),
        "source_ids": source_ids,
        "status": status,
        "subject": subject,
        "subject_type": "workflow_context_package",
        "title": workflow.get("title"),
        "workflow_id": workflow.get("workflow_id"),
    }


def artifact_attestations(trust_pack: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    source_artifacts = trust_pack.get("source_artifacts")
    if not isinstance(source_artifacts, dict):
        return rows
    for artifact_id in sorted(source_artifacts):
        artifact = source_artifacts.get(artifact_id)
        if not isinstance(artifact, dict):
            continue
        rows.append(
            {
                "attestation_id": f"artifact-{artifact_id}",
                "path": artifact.get("path"),
                "sha256": artifact.get("sha256"),
                "status": "active" if artifact.get("sha256") else "invalid_missing_hash",
                "subject": {
                    "digest": {
                        "sha256": artifact.get("sha256")
                    },
                    "name": f"source-artifact:{artifact_id}",
                },
                "subject_type": "source_artifact",
            }
        )
    return rows


def build_in_toto_statement(
    *,
    profile: dict[str, Any],
    trust_pack: dict[str, Any],
    context_attestations: list[dict[str, Any]],
    workflow_attestations: list[dict[str, Any]],
    source_artifacts: list[dict[str, Any]],
    generated_at: str,
) -> dict[str, Any]:
    contract = as_dict(profile.get("attestation_contract"), "attestation_contract")
    subjects = [
        row.get("subject")
        for row in [*context_attestations, *workflow_attestations, *source_artifacts]
        if isinstance(row.get("subject"), dict)
    ]
    return {
        "_type": contract.get("statement_type"),
        "predicate": {
            "context_trust_summary": trust_pack.get("context_trust_summary"),
            "generated_at": generated_at,
            "policy": profile.get("verification_policy"),
            "positioning": profile.get("positioning"),
            "source_contract": trust_pack.get("source_contract"),
            "trust_pack_generated_at": trust_pack.get("generated_at"),
        },
        "predicateType": contract.get("predicate_type"),
        "subject": subjects,
    }


def build_summary(
    context_attestations: list[dict[str, Any]],
    workflow_attestations: list[dict[str, Any]],
    source_artifacts: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    all_rows = [*context_attestations, *workflow_attestations, *source_artifacts]
    status_counts = Counter(str(row.get("status")) for row in all_rows)
    decision_counts = Counter(str(row.get("decision")) for row in all_rows if row.get("decision"))
    return {
        "active_subject_count": status_counts.get("active", 0),
        "context_source_subject_count": len(context_attestations),
        "decision_counts": dict(sorted(decision_counts.items())),
        "failure_count": len(failures),
        "source_artifact_subject_count": len(source_artifacts),
        "status": "ready_for_open_reference_use" if not failures else "needs_attention",
        "status_counts": dict(sorted(status_counts.items())),
        "total_subject_count": len(all_rows),
        "workflow_package_subject_count": len(workflow_attestations),
    }


def recertification_queue(
    context_attestations: list[dict[str, Any]],
    workflow_attestations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in context_attestations:
        if item.get("status") != "active":
            rows.append(
                {
                    "attestation_id": item.get("attestation_id"),
                    "owner": item.get("recertification", {}).get("owner") if isinstance(item.get("recertification"), dict) else None,
                    "reason": item.get("status"),
                    "subject_type": item.get("subject_type"),
                }
            )
    for item in workflow_attestations:
        if item.get("status") != "active":
            rows.append(
                {
                    "attestation_id": item.get("attestation_id"),
                    "owner": "workflow-owner",
                    "reason": item.get("status"),
                    "subject_type": item.get("subject_type"),
                }
            )
    return rows


def build_pack(
    *,
    profile: dict[str, Any],
    trust_pack: dict[str, Any],
    profile_path: Path,
    profile_ref: Path,
    trust_pack_path: Path,
    trust_pack_ref: Path,
    generated_at: str,
    failures: list[str],
) -> dict[str, Any]:
    context_attestations = [
        source_attestation(source, profile)
        for source in as_list(trust_pack.get("context_sources"), "context_sources")
        if isinstance(source, dict)
    ]
    context_subjects = {str(item.get("source_id")): item for item in context_attestations}
    workflow_attestations = [
        workflow_attestation(workflow, context_subjects)
        for workflow in as_list(trust_pack.get("workflow_context_map"), "workflow_context_map")
        if isinstance(workflow, dict)
    ]
    artifacts = artifact_attestations(trust_pack)
    statement = build_in_toto_statement(
        profile=profile,
        trust_pack=trust_pack,
        context_attestations=context_attestations,
        workflow_attestations=workflow_attestations,
        source_artifacts=artifacts,
        generated_at=generated_at,
    )
    statement_hash = stable_hash(statement)

    return {
        "attestation_contract": profile.get("attestation_contract"),
        "attestation_manifest": {
            "context_source_attestations": context_attestations,
            "source_artifact_attestations": artifacts,
            "workflow_context_package_attestations": workflow_attestations,
        },
        "attestation_summary": build_summary(context_attestations, workflow_attestations, artifacts, failures),
        "commercialization_path": profile.get("commercialization_path"),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet"),
        "failures": failures,
        "generated_at": generated_at,
        "in_toto_statement": statement,
        "in_toto_statement_sha256": statement_hash,
        "positioning": profile.get("positioning"),
        "recertification_queue": recertification_queue(context_attestations, workflow_attestations),
        "schema_version": PACK_SCHEMA_VERSION,
        "signature_readiness": {
            "open_reference_state": "unsigned_attestation_seed",
            "production_state": "requires_external_keyless_signature_bundle",
            "required_before_production_mcp": profile.get("verification_policy", {}).get("production_signature_requirements", []),
            "statement_sha256": statement_hash,
        },
        "source_artifacts": {
            "secure_context_attestation_profile": {
                "path": normalize_path(profile_ref),
                "sha256": sha256_file(profile_path),
            },
            "secure_context_trust_pack": {
                "path": normalize_path(trust_pack_ref),
                "sha256": sha256_file(trust_pack_path),
            },
        },
        "standards_alignment": profile.get("standards_alignment", []),
        "verification_policy": profile.get("verification_policy"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--trust-pack", type=Path, default=DEFAULT_TRUST_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in attestation pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    trust_pack_path = resolve(repo_root, args.trust_pack)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        trust_pack = load_json(trust_pack_path)
        failures = []
        failures.extend(validate_profile(profile))
        failures.extend(validate_trust_pack(trust_pack, profile))
        pack = build_pack(
            profile=profile,
            trust_pack=trust_pack,
            profile_path=profile_path,
            profile_ref=args.profile,
            trust_pack_path=trust_pack_path,
            trust_pack_ref=args.trust_pack,
            generated_at=args.generated_at or str(profile.get("last_reviewed", "")),
            failures=failures,
        )
    except SecureContextAttestationError as exc:
        print(f"secure context attestation generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("secure context attestation validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(f"{output_path} is stale; run scripts/generate_secure_context_attestation_pack.py", file=sys.stderr)
            return 1
        print(f"Validated secure context attestation pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")
    if failures:
        print("Generated secure context attestation pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated secure context attestation pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
