#!/usr/bin/env python3
"""Evaluate one secure-context retrieval decision.

The secure context trust pack declares approved context roots, source
hashes, retrieval modes, workflow context packages, and prohibited data
classes. This evaluator is the deterministic policy function an MCP
gateway, agent host, CI admission check, or audit replay can call before
retrieved context is returned to an agent.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
VALID_DECISIONS = {
    "allow_policy_context_with_citation",
    "allow_public_context",
    "deny_unapproved_workflow_context",
    "deny_unregistered_context",
    "hold_for_context_recertification",
    "hold_for_customer_context",
    "kill_session_on_prohibited_context",
}


class ContextRetrievalDecisionError(RuntimeError):
    """Raised when the trust pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContextRetrievalDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ContextRetrievalDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContextRetrievalDecisionError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_path(path: Any) -> str:
    value = str(path or "").replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    return value.lstrip("/")


def matches_pattern(path: str, pattern: str) -> bool:
    path = normalize_path(path)
    pattern = normalize_path(pattern)
    if not path or not pattern:
        return False

    if fnmatch.fnmatchcase(path, pattern):
        return True

    if pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]):
        return True

    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        return path == prefix or path.startswith(prefix + "/")

    return False


def matches_any(path: str, patterns: list[Any]) -> bool:
    name = Path(path).name
    return any(matches_pattern(path, str(pattern)) or matches_pattern(name, str(pattern)) for pattern in patterns)


def sources_by_id(trust_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sources = trust_pack.get("context_sources")
    if not isinstance(sources, list):
        raise ContextRetrievalDecisionError("trust pack is missing context_sources")
    return {
        str(source.get("source_id")): source
        for source in sources
        if isinstance(source, dict) and source.get("source_id")
    }


def workflows_by_id(trust_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    workflows = trust_pack.get("workflow_context_map")
    if not isinstance(workflows, list):
        raise ContextRetrievalDecisionError("trust pack is missing workflow_context_map")
    return {
        str(workflow.get("workflow_id")): workflow
        for workflow in workflows
        if isinstance(workflow, dict) and workflow.get("workflow_id")
    }


def source_path_allowed(source: dict[str, Any], requested_path: str) -> tuple[bool, list[str]]:
    path = normalize_path(requested_path)
    if not path:
        return True, []

    root = normalize_path(source.get("root"))
    root_type = str(source.get("root_type") or "")
    violations: list[str] = []

    if root_type == "file":
        if path != root:
            violations.append(f"requested_path {path!r} does not match source file {root!r}")
    elif root:
        if path != root and not path.startswith(root.rstrip("/") + "/"):
            violations.append(f"requested_path {path!r} is outside source root {root!r}")

    excluded = as_list(source.get("exclude_file_globs"))
    if excluded and matches_any(path, excluded):
        violations.append(f"requested_path {path!r} matches excluded source glob")

    allowed = as_list(source.get("allowed_file_globs"))
    if allowed and not matches_any(path, allowed):
        violations.append(f"requested_path {path!r} does not match allowed source globs")

    return not violations, violations


def source_preview(source: dict[str, Any] | None) -> dict[str, Any] | None:
    if source is None:
        return None
    trust_tier = source.get("trust_tier") if isinstance(source.get("trust_tier"), dict) else {}
    return {
        "citation_required": source.get("citation_required"),
        "decision": source.get("decision"),
        "exposure": source.get("exposure"),
        "freshness_state": source.get("freshness_state"),
        "retrieval_modes": source.get("retrieval_modes", []),
        "root": source.get("root"),
        "source_hash": source.get("source_hash"),
        "source_id": source.get("source_id"),
        "title": source.get("title"),
        "trust_tier": trust_tier.get("id"),
    }


def workflow_preview(workflow: dict[str, Any] | None) -> dict[str, Any] | None:
    if workflow is None:
        return None
    return {
        "context_package_hash": workflow.get("context_package_hash"),
        "source_ids": workflow.get("source_ids", []),
        "status": workflow.get("status"),
        "title": workflow.get("title"),
        "workflow_id": workflow.get("workflow_id"),
    }


def decision_result(
    *,
    decision: str,
    reason: str,
    request: dict[str, Any],
    trust_pack: dict[str, Any],
    source: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise ContextRetrievalDecisionError(f"unknown decision {decision!r}")

    return {
        "allowed": decision in {"allow_public_context", "allow_policy_context_with_citation"},
        "decision": decision,
        "evidence": {
            "citation_required": source.get("citation_required") if source else None,
            "context_package_hash": workflow.get("context_package_hash") if workflow else None,
            "instruction_handling": source.get("instruction_handling") if source else None,
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {})),
            "source_artifacts": trust_pack.get("source_artifacts"),
            "source_hash": source.get("source_hash") if source else None,
            "trust_pack_generated_at": trust_pack.get("generated_at"),
        },
        "matched_source": source_preview(source),
        "matched_workflow": workflow_preview(workflow),
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "context_hash": request.get("context_hash"),
            "data_class": request.get("data_class"),
            "requested_path": request.get("requested_path"),
            "retrieval_mode": request.get("retrieval_mode"),
            "run_id": request.get("run_id"),
            "source_id": request.get("source_id"),
            "tenant_id": request.get("tenant_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_context_retrieval_decision(
    trust_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured runtime decision for one requested context retrieval."""
    if not isinstance(trust_pack, dict):
        raise ContextRetrievalDecisionError("trust_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise ContextRetrievalDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    request["requested_path"] = normalize_path(request.get("requested_path"))
    request["source_id"] = str(request.get("source_id") or "").strip()
    request["workflow_id"] = str(request.get("workflow_id") or "").strip()
    request["retrieval_mode"] = str(request.get("retrieval_mode") or "").strip()
    request["data_class"] = str(request.get("data_class") or "").strip()

    prohibited = {
        str(item)
        for item in (
            trust_pack.get("retrieval_decision_contract", {}).get("prohibited_data_classes", [])
            if isinstance(trust_pack.get("retrieval_decision_contract"), dict)
            else []
        )
    }
    if request["data_class"] and request["data_class"] in prohibited:
        return decision_result(
            decision="kill_session_on_prohibited_context",
            reason="requested data_class is prohibited context",
            request=request,
            trust_pack=trust_pack,
            violations=[f"prohibited data_class: {request['data_class']}"],
        )

    violations: list[str] = []
    if not request["workflow_id"]:
        violations.append("workflow_id is required")
    if not request["source_id"]:
        violations.append("source_id is required")
    if not request["retrieval_mode"]:
        violations.append("retrieval_mode is required")

    sources = sources_by_id(trust_pack)
    workflows = workflows_by_id(trust_pack)
    source = sources.get(request["source_id"]) if request["source_id"] else None
    workflow = workflows.get(request["workflow_id"]) if request["workflow_id"] else None

    if source is None and request["source_id"]:
        violations.append(f"source_id is not registered: {request['source_id']}")
    if workflow is None and request["workflow_id"]:
        violations.append(f"workflow_id is not registered: {request['workflow_id']}")
    if violations:
        return decision_result(
            decision="deny_unregistered_context",
            reason="runtime request references missing or undeclared context",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
            violations=violations,
        )

    assert source is not None
    assert workflow is not None

    workflow_source_ids = {str(source_id) for source_id in as_list(workflow.get("source_ids"))}
    if request["source_id"] not in workflow_source_ids:
        return decision_result(
            decision="deny_unapproved_workflow_context",
            reason="source is registered but not approved for this workflow context package",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
            violations=[f"source_id {request['source_id']!r} is not in workflow source_ids"],
        )

    if workflow.get("status") != "active":
        return decision_result(
            decision="deny_unapproved_workflow_context",
            reason="workflow is not active for runtime context retrieval",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
            violations=[f"workflow status is {workflow.get('status')!r}, not active"],
        )

    if request["retrieval_mode"] not in {str(mode) for mode in as_list(source.get("retrieval_modes"))}:
        return decision_result(
            decision="deny_unapproved_workflow_context",
            reason="retrieval mode is not approved for the requested context source",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
            violations=[f"retrieval_mode {request['retrieval_mode']!r} is not declared for source"],
        )

    _, path_violations = source_path_allowed(source, request["requested_path"])
    if path_violations:
        return decision_result(
            decision="deny_unapproved_workflow_context",
            reason="requested path is outside the approved context source boundary",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
            violations=path_violations,
        )

    if source.get("freshness_state") != "declared_current":
        return decision_result(
            decision="hold_for_context_recertification",
            reason="source freshness is not currently declared",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
            violations=[f"freshness_state is {source.get('freshness_state')!r}"],
        )

    expected_hash = str(source.get("source_hash") or "")
    supplied_hash = str(request.get("context_hash") or "").strip()
    if supplied_hash and supplied_hash != expected_hash:
        return decision_result(
            decision="hold_for_context_recertification",
            reason="supplied context_hash does not match the registered source hash",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
            violations=["context_hash mismatch"],
        )

    source_decision = str(source.get("decision") or "")
    if source_decision == "hold_for_customer_context":
        return decision_result(
            decision="hold_for_customer_context",
            reason="customer runtime context must be retrieved inside a tenant-controlled MCP gateway",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
        )

    if source_decision == "kill_session_on_prohibited_context":
        return decision_result(
            decision="kill_session_on_prohibited_context",
            reason="source trust tier is prohibited for retrieval",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
        )

    if source_decision not in {"allow_public_context", "allow_policy_context_with_citation"}:
        return decision_result(
            decision="deny_unregistered_context",
            reason="source has an unknown retrieval decision",
            request=request,
            trust_pack=trust_pack,
            source=source,
            workflow=workflow,
            violations=[f"unknown source decision: {source_decision}"],
        )

    return decision_result(
        decision=source_decision,
        reason="runtime request satisfies secure context retrieval policy",
        request=request,
        trust_pack=trust_pack,
        source=source,
        workflow=workflow,
    )


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}

    overrides = {
        "agent_id": args.agent_id,
        "context_hash": args.context_hash,
        "data_class": args.data_class,
        "requested_path": args.requested_path,
        "retrieval_mode": args.retrieval_mode,
        "run_id": args.run_id,
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
    parser.add_argument("--trust-pack", type=Path, default=DEFAULT_TRUST_PACK, help="Path to secure-context-trust-pack.json")
    parser.add_argument("--request", type=Path, help="JSON file containing runtime request attributes")
    parser.add_argument("--workflow-id")
    parser.add_argument("--source-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--run-id")
    parser.add_argument("--retrieval-mode")
    parser.add_argument("--requested-path", default="")
    parser.add_argument("--context-hash", default="")
    parser.add_argument("--tenant-id", default="")
    parser.add_argument("--data-class", default="")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    trust_pack = load_json(args.trust_pack)
    request = request_from_args(args)
    decision = evaluate_context_retrieval_decision(trust_pack, request)
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
