#!/usr/bin/env python3
"""Evaluate one agent-memory boundary decision.

The agent memory boundary pack declares which memories agents may read,
write, delete, replay, or reindex. This evaluator is the deterministic
policy function an MCP gateway, memory middleware, CI admission check,
or audit replay can call before persistent state is stored or reused.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_MEMORY_PACK = Path("data/evidence/agent-memory-boundary-pack.json")
VALID_DECISIONS = {
    "allow_ephemeral_memory",
    "allow_append_only_evidence_memory",
    "allow_readonly_policy_memory",
    "hold_for_tenant_memory_boundary",
    "hold_for_memory_admission_review",
    "deny_runtime_memory_write",
    "deny_cross_tenant_memory",
    "kill_session_on_prohibited_memory",
}
ALLOW_DECISIONS = {
    "allow_ephemeral_memory",
    "allow_append_only_evidence_memory",
    "allow_readonly_policy_memory",
}


class AgentMemoryDecisionError(RuntimeError):
    """Raised when the memory pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgentMemoryDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AgentMemoryDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AgentMemoryDecisionError(f"{path} root must be a JSON object")
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


def memory_classes_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    classes = pack.get("memory_classes")
    if not isinstance(classes, list):
        raise AgentMemoryDecisionError("memory pack is missing memory_classes")
    return {
        str(memory_class.get("id")): memory_class
        for memory_class in classes
        if isinstance(memory_class, dict) and memory_class.get("id")
    }


def workflows_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    profiles = pack.get("workflow_memory_profiles")
    if not isinstance(profiles, list):
        raise AgentMemoryDecisionError("memory pack is missing workflow_memory_profiles")
    return {
        str(profile.get("workflow_id")): profile
        for profile in profiles
        if isinstance(profile, dict) and profile.get("workflow_id")
    }


def approval_present(value: Any) -> bool:
    return isinstance(value, dict) and bool(value.get("id") or value.get("approval_id") or value.get("approved_at"))


def class_preview(memory_class: dict[str, Any] | None) -> dict[str, Any] | None:
    if memory_class is None:
        return None
    return {
        "allowed_operations": memory_class.get("allowed_operations", []),
        "default_decision": memory_class.get("default_decision"),
        "human_approval_required": memory_class.get("human_approval_required"),
        "id": memory_class.get("id"),
        "max_ttl_days": memory_class.get("max_ttl_days"),
        "persistent": memory_class.get("persistent"),
        "provenance_hash_required": memory_class.get("provenance_hash_required"),
        "runtime_writes_allowed": memory_class.get("runtime_writes_allowed"),
        "tenant_id_required": memory_class.get("tenant_id_required"),
        "title": memory_class.get("title"),
    }


def workflow_preview(workflow: dict[str, Any] | None) -> dict[str, Any] | None:
    if workflow is None:
        return None
    return {
        "allowed_memory_class_ids": workflow.get("allowed_memory_class_ids", []),
        "hold_memory_class_ids": workflow.get("hold_memory_class_ids", []),
        "kill_memory_class_ids": workflow.get("kill_memory_class_ids", []),
        "memory_profile_hash": workflow.get("memory_profile_hash"),
        "status": workflow.get("status"),
        "title": workflow.get("title"),
        "workflow_id": workflow.get("workflow_id"),
    }


def decision_result(
    *,
    decision: str,
    reason: str,
    request: dict[str, Any],
    pack: dict[str, Any],
    memory_class: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise AgentMemoryDecisionError(f"unknown decision {decision!r}")

    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "memory_pack_generated_at": pack.get("generated_at"),
            "memory_profile_hash": workflow.get("memory_profile_hash") if workflow else None,
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {})),
            "required_controls": memory_class.get("required_controls", []) if memory_class else [],
            "source_artifacts": pack.get("source_artifacts"),
            "write_controls": memory_class.get("write_controls", []) if memory_class else [],
        },
        "matched_memory_class": class_preview(memory_class),
        "matched_workflow": workflow_preview(workflow),
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "contains_secret": request.get("contains_secret"),
            "contains_unredacted_pii": request.get("contains_unredacted_pii"),
            "memory_class_id": request.get("memory_class_id"),
            "operation": request.get("operation"),
            "provenance_hash": request.get("provenance_hash"),
            "requested_ttl_days": request.get("requested_ttl_days"),
            "run_id": request.get("run_id"),
            "source_id": request.get("source_id"),
            "tenant_id": request.get("tenant_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_agent_memory_boundary_decision(
    memory_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured runtime decision for one memory operation."""
    if not isinstance(memory_pack, dict):
        raise AgentMemoryDecisionError("memory_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise AgentMemoryDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    request["contains_secret"] = as_bool(request.get("contains_secret"))
    request["contains_unredacted_pii"] = as_bool(request.get("contains_unredacted_pii"))
    request["memory_class_id"] = str(request.get("memory_class_id") or "").strip()
    request["operation"] = str(request.get("operation") or "").strip().lower()
    request["provenance_hash"] = str(request.get("provenance_hash") or "").strip()
    request["source_id"] = str(request.get("source_id") or "").strip()
    request["tenant_id"] = str(request.get("tenant_id") or "").strip()
    request["workflow_id"] = str(request.get("workflow_id") or "").strip()
    request["runtime_kill_signal"] = str(request.get("runtime_kill_signal") or "").strip()

    try:
        request["requested_ttl_days"] = int(request.get("requested_ttl_days") or 0)
    except (TypeError, ValueError):
        request["requested_ttl_days"] = 0

    if request["runtime_kill_signal"]:
        return decision_result(
            decision="kill_session_on_prohibited_memory",
            reason="runtime kill signal is present",
            request=request,
            pack=memory_pack,
            violations=[f"runtime_kill_signal: {request['runtime_kill_signal']}"],
        )

    prohibited = {
        str(item)
        for item in memory_pack.get("memory_decision_contract", {}).get("prohibited_data_classes", [])
        if item
    }
    requested_data_classes = {str(item) for item in as_list(request.get("data_classes")) if item}
    if request.get("data_class"):
        requested_data_classes.add(str(request.get("data_class")))
    if request["contains_secret"] or requested_data_classes.intersection(prohibited):
        return decision_result(
            decision="kill_session_on_prohibited_memory",
            reason="request contains secret or prohibited memory data class",
            request=request,
            pack=memory_pack,
            violations=sorted(requested_data_classes.intersection(prohibited) or {"contains_secret"}),
        )

    classes = memory_classes_by_id(memory_pack)
    workflows = workflows_by_id(memory_pack)
    memory_class = classes.get(request["memory_class_id"]) if request["memory_class_id"] else None
    workflow = workflows.get(request["workflow_id"]) if request["workflow_id"] else None

    violations: list[str] = []
    if not request["workflow_id"]:
        violations.append("workflow_id is required")
    if not request["memory_class_id"]:
        violations.append("memory_class_id is required")
    if not request["operation"]:
        violations.append("operation is required")
    if memory_class is None and request["memory_class_id"]:
        violations.append(f"memory_class_id is not registered: {request['memory_class_id']}")
    if workflow is None and request["workflow_id"]:
        violations.append(f"workflow_id is not registered: {request['workflow_id']}")
    if violations:
        return decision_result(
            decision="hold_for_memory_admission_review",
            reason="runtime request references missing or undeclared memory boundary",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=violations,
        )

    assert memory_class is not None
    assert workflow is not None

    if workflow.get("status") != "active":
        return decision_result(
            decision="hold_for_memory_admission_review",
            reason="workflow is not active for memory operations",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=[f"workflow status is {workflow.get('status')!r}, not active"],
        )

    workflow_class_ids = {
        str(item)
        for item in (
            workflow.get("default_memory_class_ids", [])
            or workflow.get("allowed_memory_class_ids", [])
            or []
        )
    }
    if request["memory_class_id"] not in workflow_class_ids:
        return decision_result(
            decision="hold_for_memory_admission_review",
            reason="memory class is registered but not approved for this workflow profile",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=[f"memory_class_id {request['memory_class_id']!r} is not in workflow memory profile"],
        )

    if request["operation"] not in {str(item) for item in as_list(memory_class.get("allowed_operations"))}:
        return decision_result(
            decision="deny_runtime_memory_write",
            reason="operation is not allowed for this memory class",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=[f"operation {request['operation']!r} is not declared for memory class"],
        )

    decision = str(memory_class.get("default_decision") or "")
    if decision == "kill_session_on_prohibited_memory":
        return decision_result(
            decision="kill_session_on_prohibited_memory",
            reason="memory class is prohibited",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
        )

    write_like = request["operation"] in {"write", "delete", "reindex", "replay", "export"}
    if write_like and memory_class.get("runtime_writes_allowed") is False:
        return decision_result(
            decision="deny_runtime_memory_write",
            reason="runtime writes are denied for this memory class",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
        )

    if memory_class.get("tenant_id_required") and not request["tenant_id"]:
        return decision_result(
            decision="deny_cross_tenant_memory",
            reason="tenant-bound memory request is missing tenant_id",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=["tenant_id is required"],
        )

    if memory_class.get("provenance_hash_required") and write_like and not request["provenance_hash"]:
        return decision_result(
            decision="hold_for_memory_admission_review",
            reason="persistent memory write is missing provenance_hash",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=["provenance_hash is required for write-like operation"],
        )

    if request["requested_ttl_days"] and request["requested_ttl_days"] > int(memory_class.get("max_ttl_days") or 0):
        return decision_result(
            decision="hold_for_memory_admission_review",
            reason="requested TTL exceeds the memory class maximum",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=[f"requested_ttl_days {request['requested_ttl_days']} exceeds max_ttl_days {memory_class.get('max_ttl_days')}"],
        )

    if request["contains_unredacted_pii"]:
        return decision_result(
            decision="hold_for_tenant_memory_boundary",
            reason="unredacted PII requires tenant-side redaction and approval before memory persistence",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=["contains_unredacted_pii is true"],
        )

    if memory_class.get("human_approval_required") and write_like and not approval_present(request.get("human_approval_record")):
        return decision_result(
            decision="hold_for_tenant_memory_boundary",
            reason="memory class requires human approval before write-like operation",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=["human_approval_record is required"],
        )

    if decision not in VALID_DECISIONS:
        return decision_result(
            decision="hold_for_memory_admission_review",
            reason="memory class has an unknown default decision",
            request=request,
            pack=memory_pack,
            memory_class=memory_class,
            workflow=workflow,
            violations=[f"unknown decision: {decision}"],
        )

    return decision_result(
        decision=decision,
        reason="runtime request satisfies agent memory boundary policy",
        request=request,
        pack=memory_pack,
        memory_class=memory_class,
        workflow=workflow,
    )


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}

    overrides = {
        "agent_id": args.agent_id,
        "contains_secret": args.contains_secret,
        "contains_unredacted_pii": args.contains_unredacted_pii,
        "data_class": args.data_class,
        "memory_class_id": args.memory_class_id,
        "operation": args.operation,
        "provenance_hash": args.provenance_hash,
        "requested_ttl_days": args.requested_ttl_days,
        "run_id": args.run_id,
        "runtime_kill_signal": args.runtime_kill_signal,
        "source_id": args.source_id,
        "tenant_id": args.tenant_id,
        "workflow_id": args.workflow_id,
    }
    for key, value in overrides.items():
        if value not in (None, ""):
            payload[key] = value
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-pack", type=Path, default=DEFAULT_MEMORY_PACK, help="Path to agent-memory-boundary-pack.json")
    parser.add_argument("--request", type=Path, help="JSON file containing runtime request attributes")
    parser.add_argument("--workflow-id")
    parser.add_argument("--memory-class-id")
    parser.add_argument("--operation")
    parser.add_argument("--agent-id")
    parser.add_argument("--run-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--source-id")
    parser.add_argument("--provenance-hash")
    parser.add_argument("--requested-ttl-days", type=int)
    parser.add_argument("--data-class")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--contains-unredacted-pii", action="store_true")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    memory_pack = load_json(args.memory_pack)
    request = request_from_args(args)
    decision = evaluate_agent_memory_boundary_decision(memory_pack, request)
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
