#!/usr/bin/env python3
"""Evaluate one secure context evidence release request.

This deterministic evaluator is the product-facing guard between open
reference artifacts, hosted MCP evidence, customer-private proof, and
trust-center or acquirer exports. It fails closed when evidence is not
redacted, source-hash-bound, tenant-bound where required, signed where
required, or free of secrets and raw customer payloads.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/secure-context-evidence-contract.json")
ALLOW_DECISIONS = {"allow_publish_evidence_release"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_redaction_or_signature",
    "hold_for_customer_runtime_evidence",
    "deny_sensitive_payload_release",
    "kill_session_on_secret_or_token_release",
}


class EvidenceReleaseDecisionError(RuntimeError):
    """Raised when the pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise EvidenceReleaseDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceReleaseDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise EvidenceReleaseDecisionError(f"{path} root must be a JSON object")
    return payload


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def channels_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(channel.get("id")): channel
        for channel in as_list(pack.get("release_channels"))
        if isinstance(channel, dict) and channel.get("id")
    }


def artifacts_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(artifact.get("id")): artifact
        for artifact in as_list(pack.get("source_pack_index"))
        if isinstance(artifact, dict) and artifact.get("id")
    }


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "release_id",
        "release_channel",
        "tenant_id",
        "correlation_id",
        "approval_receipt_id",
        "retention_policy_id",
        "dpa_state",
        "zero_data_retention_state",
        "redaction_manifest_id",
        "signature_id",
    ]:
        request[key] = str(request.get(key) or "").strip()
    for key in [
        "contains_api_key",
        "contains_customer_data",
        "contains_private_key",
        "contains_raw_prompt",
        "contains_secret",
        "contains_session_cookie",
        "contains_source_code",
        "contains_token",
        "dpa_in_place",
        "redaction_verified",
        "signature_present",
        "source_hashes_present",
        "tenant_bound",
        "zero_data_retention_committed",
    ]:
        request[key] = as_bool(request.get(key))
    request["artifact_ids"] = [str(item).strip() for item in as_list(request.get("artifact_ids")) if str(item).strip()]
    request["payload_classes"] = [str(item).strip() for item in as_list(request.get("payload_classes")) if str(item).strip()]
    return request


def decision_result(
    *,
    decision: str,
    reason: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    channel: dict[str, Any] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise EvidenceReleaseDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "evidence_contract_generated_at": pack.get("generated_at"),
            "evidence_contract_summary": pack.get("evidence_contract_summary"),
            "source_artifacts": pack.get("source_artifacts"),
        },
        "matched_artifacts": artifacts or [],
        "matched_channel": {
            "id": channel.get("id") if channel else request.get("release_channel"),
            "requires_customer_runtime_evidence": channel.get("requires_customer_runtime_evidence") if channel else None,
            "requires_signature": channel.get("requires_signature") if channel else None,
            "requires_tenant_binding": channel.get("requires_tenant_binding") if channel else None,
            "status": channel.get("status") if channel else None,
            "title": channel.get("title") if channel else None,
        },
        "reason": reason,
        "runtime_request": {
            "artifact_ids": request.get("artifact_ids", []),
            "correlation_id": request.get("correlation_id"),
            "payload_classes": request.get("payload_classes", []),
            "release_channel": request.get("release_channel"),
            "release_id": request.get("release_id"),
            "tenant_id": request.get("tenant_id"),
        },
        "violations": violations or [],
    }


def evaluate_secure_context_evidence_release(
    evidence_contract: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured release decision for one evidence export."""
    if not isinstance(evidence_contract, dict):
        raise EvidenceReleaseDecisionError("evidence_contract must be an object")
    if not isinstance(runtime_request, dict):
        raise EvidenceReleaseDecisionError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    contract = evidence_contract.get("release_contract") if isinstance(evidence_contract.get("release_contract"), dict) else {}
    prohibited_payload_classes = {str(item) for item in contract.get("prohibited_payload_classes", []) or []}

    secret_flags = [
        "contains_api_key",
        "contains_private_key",
        "contains_secret",
        "contains_session_cookie",
        "contains_token",
    ]
    if any(request.get(flag) for flag in secret_flags):
        return decision_result(
            decision="kill_session_on_secret_or_token_release",
            reason="release payload contains a secret, token, key, cookie, or signing material",
            pack=evidence_contract,
            request=request,
            violations=[flag for flag in secret_flags if request.get(flag)],
        )

    prohibited_payloads = sorted(set(request["payload_classes"]) & prohibited_payload_classes)
    if prohibited_payloads:
        return decision_result(
            decision="kill_session_on_secret_or_token_release",
            reason="release payload declares prohibited payload classes",
            pack=evidence_contract,
            request=request,
            violations=[f"prohibited payload class: {item}" for item in prohibited_payloads],
        )

    channels = channels_by_id(evidence_contract)
    channel = channels.get(request["release_channel"])
    if channel is None:
        return decision_result(
            decision="hold_for_redaction_or_signature",
            reason="release channel is not registered in the evidence contract",
            pack=evidence_contract,
            request=request,
            violations=[f"unknown release_channel: {request['release_channel'] or '<missing>'}"],
        )

    all_artifacts = artifacts_by_id(evidence_contract)
    artifacts = [all_artifacts[artifact_id] for artifact_id in request["artifact_ids"] if artifact_id in all_artifacts]
    missing_artifacts = sorted(set(request["artifact_ids"]) - set(all_artifacts))
    if missing_artifacts:
        return decision_result(
            decision="hold_for_redaction_or_signature",
            reason="release references source packs that are not registered in the evidence contract",
            pack=evidence_contract,
            request=request,
            channel=channel,
            artifacts=artifacts,
            violations=[f"unknown artifact_id: {artifact_id}" for artifact_id in missing_artifacts],
        )

    if not request["artifact_ids"]:
        return decision_result(
            decision="hold_for_redaction_or_signature",
            reason="release must identify at least one source artifact",
            pack=evidence_contract,
            request=request,
            channel=channel,
            artifacts=artifacts,
            violations=["artifact_ids is empty"],
        )

    not_ready = [artifact for artifact in artifacts if artifact.get("status") != "ready"]
    if not_ready:
        return decision_result(
            decision="hold_for_redaction_or_signature",
            reason="one or more referenced source packs is not ready",
            pack=evidence_contract,
            request=request,
            channel=channel,
            artifacts=artifacts,
            violations=[f"{artifact.get('id')}: {artifact.get('status')}" for artifact in not_ready],
        )

    raw_sensitive_flags = [
        "contains_raw_prompt",
        "contains_source_code",
        "contains_customer_data",
    ]
    if any(request.get(flag) for flag in raw_sensitive_flags) and not request["redaction_verified"]:
        return decision_result(
            decision="deny_sensitive_payload_release",
            reason="raw prompt, source code, or customer data requires a verified redaction manifest before release",
            pack=evidence_contract,
            request=request,
            channel=channel,
            artifacts=artifacts,
            violations=[flag for flag in raw_sensitive_flags if request.get(flag)],
        )

    if request["release_channel"] == "open_reference" and any(request.get(flag) for flag in raw_sensitive_flags):
        return decision_result(
            decision="deny_sensitive_payload_release",
            reason="open reference releases cannot contain customer data, raw prompts, or source code even when redacted",
            pack=evidence_contract,
            request=request,
            channel=channel,
            artifacts=artifacts,
            violations=[f"{flag}=true" for flag in raw_sensitive_flags if request.get(flag)],
        )

    required_controls = {str(control) for control in channel.get("required_controls", []) or []}
    violations: list[str] = []
    if "source_hashes" in required_controls and not request["source_hashes_present"]:
        violations.append("source_hashes_present=false")
    if "redaction_manifest" in required_controls and not request["redaction_verified"]:
        violations.append("redaction_verified=false")
    if "tenant_binding" in required_controls and not request["tenant_bound"]:
        violations.append("tenant_bound=false")
    if "approval_receipt" in required_controls and not request["approval_receipt_id"]:
        violations.append("approval_receipt_id missing")
    if "retention_policy" in required_controls and not request["retention_policy_id"]:
        violations.append("retention_policy_id missing")
    if "dpa_or_processor_record" in required_controls and not (request["dpa_in_place"] or request["dpa_state"] in {"in_place", "not_required"}):
        violations.append("dpa_or_processor_record missing")
    if "zero_data_retention_state" in required_controls and not (request["zero_data_retention_committed"] or request["zero_data_retention_state"] in {"committed", "not_required"}):
        violations.append("zero_data_retention_state missing")
    if bool(channel.get("requires_signature")) and not request["signature_present"]:
        violations.append("signature_present=false")

    if violations:
        return decision_result(
            decision="hold_for_redaction_or_signature",
            reason="release is missing redaction, source hash, tenant, approval, retention, DPA, ZDR, or signature evidence",
            pack=evidence_contract,
            request=request,
            channel=channel,
            artifacts=artifacts,
            violations=violations,
        )

    if bool(channel.get("requires_customer_runtime_evidence")):
        customer_runtime_artifacts = {
            "secure_context_customer_proof_pack",
            "agentic_run_receipt_pack",
            "agentic_telemetry_contract",
        }
        if not (set(request["artifact_ids"]) & customer_runtime_artifacts):
            return decision_result(
                decision="hold_for_customer_runtime_evidence",
                reason="release channel requires customer runtime proof, receipts, or telemetry evidence",
                pack=evidence_contract,
                request=request,
                channel=channel,
                artifacts=artifacts,
                violations=["customer runtime evidence artifact missing"],
            )

    return decision_result(
        decision="allow_publish_evidence_release",
        reason="release satisfies channel, redaction, source hash, artifact readiness, tenant, approval, retention, and signature requirements",
        pack=evidence_contract,
        request=request,
        channel=channel,
        artifacts=artifacts,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-channel", required=True)
    parser.add_argument("--artifact-id", action="append", dest="artifact_ids", default=[])
    parser.add_argument("--payload-class", action="append", dest="payload_classes", default=[])
    parser.add_argument("--tenant-id")
    parser.add_argument("--correlation-id")
    parser.add_argument("--approval-receipt-id")
    parser.add_argument("--retention-policy-id")
    parser.add_argument("--dpa-state")
    parser.add_argument("--zero-data-retention-state")
    parser.add_argument("--redaction-manifest-id")
    parser.add_argument("--signature-id")
    parser.add_argument("--source-hashes-present", action="store_true")
    parser.add_argument("--redaction-verified", action="store_true")
    parser.add_argument("--tenant-bound", action="store_true")
    parser.add_argument("--signature-present", action="store_true")
    parser.add_argument("--dpa-in-place", action="store_true")
    parser.add_argument("--zero-data-retention-committed", action="store_true")
    parser.add_argument("--contains-api-key", action="store_true")
    parser.add_argument("--contains-customer-data", action="store_true")
    parser.add_argument("--contains-private-key", action="store_true")
    parser.add_argument("--contains-raw-prompt", action="store_true")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--contains-session-cookie", action="store_true")
    parser.add_argument("--contains-source-code", action="store_true")
    parser.add_argument("--contains-token", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        payload = {
            "approval_receipt_id": args.approval_receipt_id,
            "artifact_ids": args.artifact_ids,
            "contains_api_key": args.contains_api_key,
            "contains_customer_data": args.contains_customer_data,
            "contains_private_key": args.contains_private_key,
            "contains_raw_prompt": args.contains_raw_prompt,
            "contains_secret": args.contains_secret,
            "contains_session_cookie": args.contains_session_cookie,
            "contains_source_code": args.contains_source_code,
            "contains_token": args.contains_token,
            "correlation_id": args.correlation_id,
            "dpa_in_place": args.dpa_in_place,
            "dpa_state": args.dpa_state,
            "payload_classes": args.payload_classes,
            "redaction_manifest_id": args.redaction_manifest_id,
            "redaction_verified": args.redaction_verified,
            "release_channel": args.release_channel,
            "release_id": args.release_id,
            "retention_policy_id": args.retention_policy_id,
            "signature_id": args.signature_id,
            "signature_present": args.signature_present,
            "source_hashes_present": args.source_hashes_present,
            "tenant_bound": args.tenant_bound,
            "tenant_id": args.tenant_id,
            "zero_data_retention_committed": args.zero_data_retention_committed,
            "zero_data_retention_state": args.zero_data_retention_state,
        }
        result = evaluate_secure_context_evidence_release(pack, payload)
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.expect_decision and result.get("decision") != args.expect_decision:
            print(f"expected {args.expect_decision}, got {result.get('decision')}", file=sys.stderr)
            return 1
        return 0
    except EvidenceReleaseDecisionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
