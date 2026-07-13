#!/usr/bin/env python3
"""Evaluate one secure-context attestation decision.

This evaluator is the runtime companion to
generate_secure_context_attestation_pack.py. It answers whether a context
source, workflow context package, or source artifact has a current
attestation and whether the requested environment requires a production
signature bundle before MCP retrieval can continue.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_ATTESTATION_PACK = Path("data/evidence/secure-context-attestation-pack.json")
VALID_DECISIONS = {
    "allow_attested_context",
    "allow_attested_workflow_context",
    "deny_attestation_mismatch",
    "deny_unregistered_attestation",
    "hold_for_recertification",
    "hold_for_signature",
    "kill_session_on_forbidden_attestation",
}


class ContextAttestationDecisionError(RuntimeError):
    """Raised when the attestation pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContextAttestationDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ContextAttestationDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContextAttestationDecisionError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def manifest(pack: dict[str, Any]) -> dict[str, Any]:
    data = pack.get("attestation_manifest")
    if not isinstance(data, dict):
        raise ContextAttestationDecisionError("attestation pack is missing attestation_manifest")
    return data


def by_source_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest(pack).get("context_source_attestations")
    if not isinstance(rows, list):
        raise ContextAttestationDecisionError("attestation pack is missing context_source_attestations")
    return {
        str(row.get("source_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("source_id")
    }


def by_workflow_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest(pack).get("workflow_context_package_attestations")
    if not isinstance(rows, list):
        raise ContextAttestationDecisionError("attestation pack is missing workflow_context_package_attestations")
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def by_artifact_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest(pack).get("source_artifact_attestations")
    if not isinstance(rows, list):
        raise ContextAttestationDecisionError("attestation pack is missing source_artifact_attestations")
    return {
        str(row.get("attestation_id")).removeprefix("artifact-"): row
        for row in rows
        if isinstance(row, dict) and row.get("attestation_id")
    }


def expected_hash(subject: dict[str, Any] | None) -> str:
    if not subject:
        return ""
    if subject.get("source_hash"):
        return str(subject.get("source_hash"))
    if subject.get("context_package_hash"):
        return str(subject.get("context_package_hash"))
    if subject.get("sha256"):
        return str(subject.get("sha256"))
    digest = as_dict(subject.get("subject")).get("digest")
    if isinstance(digest, dict):
        return str(digest.get("sha256") or "")
    return ""


def signed_environment(pack: dict[str, Any], environment: str) -> bool:
    contract = as_dict(pack.get("attestation_contract"))
    return environment in {str(item) for item in as_list(contract.get("signed_environments"))}


def open_environment(pack: dict[str, Any], environment: str) -> bool:
    contract = as_dict(pack.get("attestation_contract"))
    return environment in {str(item) for item in as_list(contract.get("open_reference_environments"))}


def forbidden_data_class(pack: dict[str, Any], data_class: str) -> bool:
    policy = as_dict(pack.get("verification_policy"))
    return bool(data_class) and data_class in {str(item) for item in as_list(policy.get("forbidden_data_classes"))}


def subject_preview(subject: dict[str, Any] | None) -> dict[str, Any] | None:
    if subject is None:
        return None
    return {
        "attestation_id": subject.get("attestation_id"),
        "decision": subject.get("decision"),
        "freshness_state": subject.get("freshness_state"),
        "hash": expected_hash(subject),
        "source_id": subject.get("source_id"),
        "status": subject.get("status"),
        "subject_type": subject.get("subject_type"),
        "title": subject.get("title"),
        "trust_tier": subject.get("trust_tier"),
        "workflow_id": subject.get("workflow_id"),
    }


def decision_result(
    *,
    decision: str,
    reason: str,
    request: dict[str, Any],
    pack: dict[str, Any],
    subject: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise ContextAttestationDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in {"allow_attested_context", "allow_attested_workflow_context"},
        "decision": decision,
        "evidence": {
            "expected_hash": expected_hash(subject),
            "in_toto_statement_sha256": pack.get("in_toto_statement_sha256"),
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {})),
            "signature_readiness": pack.get("signature_readiness"),
            "source_artifacts": pack.get("source_artifacts"),
        },
        "matched_subject": subject_preview(subject),
        "reason": reason,
        "request": {
            "artifact_id": request.get("artifact_id"),
            "data_class": request.get("data_class"),
            "environment": request.get("environment"),
            "signature_bundle_present": request.get("signature_bundle_present"),
            "source_id": request.get("source_id"),
            "subject_hash": request.get("subject_hash"),
            "subject_type": request.get("subject_type"),
            "transparency_log_verified": request.get("transparency_log_verified"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_context_attestation_decision(
    attestation_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured attestation decision for one requested subject."""
    if not isinstance(attestation_pack, dict):
        raise ContextAttestationDecisionError("attestation_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise ContextAttestationDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    request["subject_type"] = str(request.get("subject_type") or "").strip()
    request["source_id"] = str(request.get("source_id") or "").strip()
    request["workflow_id"] = str(request.get("workflow_id") or "").strip()
    request["artifact_id"] = str(request.get("artifact_id") or "").strip()
    request["subject_hash"] = str(request.get("subject_hash") or "").strip()
    request["environment"] = str(request.get("environment") or "open_reference").strip()
    request["data_class"] = str(request.get("data_class") or "").strip()
    request["signature_bundle_present"] = as_bool(request.get("signature_bundle_present"))
    request["transparency_log_verified"] = as_bool(request.get("transparency_log_verified"))

    if forbidden_data_class(attestation_pack, request["data_class"]):
        return decision_result(
            decision="kill_session_on_forbidden_attestation",
            reason="request attempts to attest or retrieve forbidden context data",
            request=request,
            pack=attestation_pack,
            violations=[f"forbidden data_class: {request['data_class']}"],
        )

    if not (open_environment(attestation_pack, request["environment"]) or signed_environment(attestation_pack, request["environment"])):
        return decision_result(
            decision="deny_unregistered_attestation",
            reason="environment is not declared in the attestation contract",
            request=request,
            pack=attestation_pack,
            violations=[f"unknown environment: {request['environment']}"],
        )

    subject: dict[str, Any] | None = None
    if request["subject_type"] == "context_source":
        subject = by_source_id(attestation_pack).get(request["source_id"])
        missing_reason = f"source_id is not attested: {request['source_id']}"
        allow_decision = "allow_attested_context"
    elif request["subject_type"] == "workflow_context_package":
        subject = by_workflow_id(attestation_pack).get(request["workflow_id"])
        missing_reason = f"workflow_id is not attested: {request['workflow_id']}"
        allow_decision = "allow_attested_workflow_context"
    elif request["subject_type"] == "source_artifact":
        subject = by_artifact_id(attestation_pack).get(request["artifact_id"])
        missing_reason = f"artifact_id is not attested: {request['artifact_id']}"
        allow_decision = "allow_attested_context"
    else:
        return decision_result(
            decision="deny_unregistered_attestation",
            reason="subject_type must be context_source, workflow_context_package, or source_artifact",
            request=request,
            pack=attestation_pack,
            violations=["invalid or missing subject_type"],
        )

    if subject is None:
        return decision_result(
            decision="deny_unregistered_attestation",
            reason=missing_reason,
            request=request,
            pack=attestation_pack,
            violations=[missing_reason],
        )

    if subject.get("status") != "active":
        return decision_result(
            decision="hold_for_recertification",
            reason="attestation subject is registered but not active",
            request=request,
            pack=attestation_pack,
            subject=subject,
            violations=[f"subject status is {subject.get('status')!r}"],
        )

    expected = expected_hash(subject)
    if request["subject_hash"] and request["subject_hash"] != expected:
        return decision_result(
            decision="deny_attestation_mismatch",
            reason="supplied subject_hash does not match the attested digest",
            request=request,
            pack=attestation_pack,
            subject=subject,
            violations=["subject_hash mismatch"],
        )

    if signed_environment(attestation_pack, request["environment"]):
        missing: list[str] = []
        if not request["signature_bundle_present"]:
            missing.append("signature_bundle_present")
        if not request["transparency_log_verified"]:
            missing.append("transparency_log_verified")
        if missing:
            return decision_result(
                decision="hold_for_signature",
                reason="production or diligence environment requires keyless signature and transparency-log proof",
                request=request,
                pack=attestation_pack,
                subject=subject,
                violations=missing,
            )

    return decision_result(
        decision=allow_decision,
        reason="attestation subject is registered, active, hash-matched, and acceptable for the requested environment",
        request=request,
        pack=attestation_pack,
        subject=subject,
    )


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}
    overrides = {
        "artifact_id": args.artifact_id,
        "data_class": args.data_class,
        "environment": args.environment,
        "signature_bundle_present": args.signature_bundle_present,
        "source_id": args.source_id,
        "subject_hash": args.subject_hash,
        "subject_type": args.subject_type,
        "transparency_log_verified": args.transparency_log_verified,
        "workflow_id": args.workflow_id,
    }
    for key, value in overrides.items():
        if value not in (None, ""):
            payload[key] = value
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation-pack", type=Path, default=DEFAULT_ATTESTATION_PACK)
    parser.add_argument("--request", type=Path, help="JSON file containing runtime request attributes")
    parser.add_argument("--subject-type", choices=["context_source", "workflow_context_package", "source_artifact"])
    parser.add_argument("--source-id")
    parser.add_argument("--workflow-id")
    parser.add_argument("--artifact-id")
    parser.add_argument("--subject-hash", default="")
    parser.add_argument("--environment", default="open_reference")
    parser.add_argument("--data-class", default="")
    parser.add_argument("--signature-bundle-present", action="store_true")
    parser.add_argument("--transparency-log-verified", action="store_true")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    pack = load_json(args.attestation_pack)
    request = request_from_args(args)
    decision = evaluate_context_attestation_decision(pack, request)
    print(json.dumps(decision, indent=2, sort_keys=True))
    if args.expect_decision and decision.get("decision") != args.expect_decision:
        print(
            f"expected decision {args.expect_decision!r}, got {decision.get('decision')!r}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
