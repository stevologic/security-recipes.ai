#!/usr/bin/env python3
"""Evaluate one model-provider routing decision.

The model-provider routing pack declares approved providers, model
routes, workflow route preferences, data classes, and required proof.
This evaluator is the deterministic function an agent host, MCP gateway,
or audit replay can call before secure context is sent to a model.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_PACK = Path("data/evidence/model-provider-routing-pack.json")
VALID_DECISIONS = {
    "allow_approved_route",
    "allow_guarded_route",
    "hold_for_model_provider_review",
    "deny_unapproved_route",
    "kill_session_on_provider_signal",
}
ALLOW_DECISIONS = {"allow_approved_route", "allow_guarded_route"}
PUBLIC_DATA_CLASSES = {
    "public_reference",
    "curated_security_guidance",
    "generated_policy_evidence",
    "public_vulnerability_intelligence",
}
SECRET_DATA_CLASSES = {
    "secret_or_signer_material",
    "raw_access_token",
    "private_key",
    "seed_phrase",
    "browser_password",
}
REGULATED_DATA_CLASSES = {
    "regulated_customer_data",
    "customer_pii",
    "tenant_private_data",
    "support_ticket_history",
}


class ModelProviderRoutingDecisionError(RuntimeError):
    """Raised when the routing pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ModelProviderRoutingDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ModelProviderRoutingDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ModelProviderRoutingDecisionError(f"{path} root must be an object")
    return payload


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def providers_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    providers = pack.get("provider_profiles")
    if not isinstance(providers, list):
        raise ModelProviderRoutingDecisionError("routing pack is missing provider_profiles")
    return {
        str(provider.get("provider_id")): provider
        for provider in providers
        if isinstance(provider, dict) and provider.get("provider_id")
    }


def routes_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    routes = pack.get("model_route_profiles")
    if not isinstance(routes, list):
        raise ModelProviderRoutingDecisionError("routing pack is missing model_route_profiles")
    return {
        str(route.get("route_id")): route
        for route in routes
        if isinstance(route, dict) and route.get("route_id")
    }


def workflow_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    workflows = pack.get("workflow_route_matrix")
    if not isinstance(workflows, list):
        raise ModelProviderRoutingDecisionError("routing pack is missing workflow_route_matrix")
    return {
        str(workflow.get("workflow_id")): workflow
        for workflow in workflows
        if isinstance(workflow, dict) and workflow.get("workflow_id")
    }


def autonomy_rank(pack: dict[str, Any], level: str | None) -> int:
    rank = (
        pack.get("scoring_model", {})
        .get("autonomy_rank", {})
    )
    if isinstance(rank, dict):
        return int(rank.get(str(level or "assisted"), 1) or 1)
    fallback = {"assisted": 1, "bounded_agent": 2, "autonomous": 3, "multi_agent_coordinator": 4}
    return fallback.get(str(level or "assisted"), 1)


def request_from_input(runtime_request: dict[str, Any]) -> dict[str, Any]:
    data_classes = [str(item) for item in as_list(runtime_request.get("data_classes")) if str(item).strip()]
    return {
        "autonomy_level": str(runtime_request.get("autonomy_level") or "assisted"),
        "contains_secret": as_bool(runtime_request.get("contains_secret")),
        "contains_unredacted_pii": as_bool(runtime_request.get("contains_unredacted_pii")),
        "cross_tenant_context": as_bool(runtime_request.get("cross_tenant_context")),
        "data_classes": data_classes,
        "dpa_in_place": as_bool(runtime_request.get("dpa_in_place")),
        "egress_decision": str(runtime_request.get("egress_decision") or ""),
        "endpoint_url": str(runtime_request.get("endpoint_url") or ""),
        "enterprise_contract": as_bool(runtime_request.get("enterprise_contract")),
        "external_side_effect": as_bool(runtime_request.get("external_side_effect")),
        "high_impact_action": as_bool(runtime_request.get("high_impact_action")),
        "human_approval_record": runtime_request.get("human_approval_record") or {},
        "mcp_gateway_enforced": as_bool(runtime_request.get("mcp_gateway_enforced")),
        "model_id": str(runtime_request.get("model_id") or ""),
        "output_guardrails_enforced": as_bool(runtime_request.get("output_guardrails_enforced")),
        "provider_id": str(runtime_request.get("provider_id") or ""),
        "provider_region": str(runtime_request.get("provider_region") or ""),
        "route_class": str(runtime_request.get("route_class") or ""),
        "route_id": str(runtime_request.get("route_id") or ""),
        "run_receipt_attached": as_bool(runtime_request.get("run_receipt_attached")),
        "runtime_kill_signal": str(runtime_request.get("runtime_kill_signal") or ""),
        "telemetry_redacted": as_bool(runtime_request.get("telemetry_redacted")),
        "tenant_id": str(runtime_request.get("tenant_id") or ""),
        "tenant_region": str(runtime_request.get("tenant_region") or ""),
        "tool_call_started": as_bool(runtime_request.get("tool_call_started")),
        "tool_guardrails_enforced": as_bool(runtime_request.get("tool_guardrails_enforced")),
        "training_opt_out": as_bool(runtime_request.get("training_opt_out")),
        "untrusted_input": as_bool(runtime_request.get("untrusted_input")),
        "workflow_id": str(runtime_request.get("workflow_id") or ""),
        "zero_data_retention": as_bool(runtime_request.get("zero_data_retention")),
    }


def match_route(pack: dict[str, Any], request: dict[str, Any]) -> dict[str, Any] | None:
    routes = routes_by_id(pack)
    route_id = request.get("route_id")
    if route_id:
        return routes.get(str(route_id))
    provider_id = str(request.get("provider_id") or "")
    model_id = str(request.get("model_id") or "")
    route_class = str(request.get("route_class") or "")
    for route in routes.values():
        if provider_id and str(route.get("provider_id")) != provider_id:
            continue
        if model_id and str(route.get("model_id")) != model_id:
            continue
        if route_class and str(route.get("route_class")) != route_class:
            continue
        return route
    return None


def human_approval_present(request: dict[str, Any]) -> bool:
    approval = request.get("human_approval_record")
    if isinstance(approval, dict):
        return bool(approval.get("approval_id") or approval.get("approved_by") or approval.get("approver"))
    return bool(approval)


def endpoint_is_https(endpoint_url: str) -> bool:
    if not endpoint_url:
        return True
    return urlparse(endpoint_url).scheme == "https"


def missing_controls(
    *,
    request: dict[str, Any],
    route: dict[str, Any],
    provider: dict[str, Any],
) -> list[str]:
    missing: list[str] = []
    provider_type = str(provider.get("provider_type") or "")
    if str(provider.get("status")) not in {"approved_with_contract", "approved_private_runtime", "guarded_pilot"}:
        missing.append("approved_provider_profile")
    if provider_type == "external_processor" and not request["enterprise_contract"]:
        missing.append("enterprise_contract")
    if provider_type == "external_processor" and not request["training_opt_out"]:
        missing.append("training_opt_out")
    if route.get("zero_data_retention_required") and not request["zero_data_retention"]:
        missing.append("zero_data_retention")
    if route.get("dpa_required") and not request["dpa_in_place"]:
        missing.append("dpa_in_place")
    if route.get("residency_match_required") and request["tenant_region"] and request["provider_region"]:
        if request["tenant_region"] != request["provider_region"]:
            missing.append("residency_match")
    elif route.get("residency_match_required") and not (request["tenant_region"] and request["provider_region"]):
        missing.append("residency_match")
    if not request["mcp_gateway_enforced"]:
        missing.append("mcp_gateway_enforced")
    if not request["tool_guardrails_enforced"]:
        missing.append("tool_guardrails_enforced")
    if not request["output_guardrails_enforced"] and route.get("route_class") != "public_reference_reasoning":
        missing.append("output_guardrails_enforced")
    if not request["telemetry_redacted"]:
        missing.append("telemetry_redacted")
    if not request["run_receipt_attached"] and route.get("route_class") != "public_reference_reasoning":
        missing.append("run_receipt_attached")
    if not request["egress_decision"].startswith("allow_"):
        missing.append("egress_decision_allow")
    if route.get("human_approval_required") and not human_approval_present(request):
        missing.append("human_approval_record")
    return sorted(set(missing))


def risk_score(
    *,
    pack: dict[str, Any],
    request: dict[str, Any],
    provider: dict[str, Any],
    missing: list[str],
) -> int:
    scoring = pack.get("scoring_model", {})
    weights = scoring.get("risk_weights", {}) if isinstance(scoring, dict) else {}
    credits = scoring.get("control_credits", {}) if isinstance(scoring, dict) else {}
    score = 0
    if provider.get("provider_type") == "external_processor":
        score += int(weights.get("external_processor", 0) or 0)
    if provider.get("provider_type") == "unsanctioned_external_processor":
        score += int(weights.get("shadow_ai_provider", 0) or 0)
    for data_class in request["data_classes"]:
        if data_class in SECRET_DATA_CLASSES:
            score += int(weights.get("secret_or_signer_data", 0) or 0)
        elif data_class in REGULATED_DATA_CLASSES:
            score += int(weights.get("regulated_data", 0) or 0)
        elif data_class == "customer_source_code":
            score += int(weights.get("customer_source_code", 0) or 0)
        elif data_class not in PUBLIC_DATA_CLASSES:
            score += int(weights.get("tenant_sensitive_data", 0) or 0)
    score += int(weights.get(f"autonomy_{request['autonomy_level']}", 0) or 0)
    if request["untrusted_input"]:
        score += int(weights.get("untrusted_input", 0) or 0)
    if request["high_impact_action"]:
        score += int(weights.get("high_impact_action", 0) or 0)
    missing_weight_map = {
        "dpa_in_place": "missing_dpa",
        "egress_decision_allow": "missing_egress_decision",
        "enterprise_contract": "unknown_provider",
        "human_approval_record": "missing_human_approval",
        "mcp_gateway_enforced": "missing_mcp_gateway",
        "output_guardrails_enforced": "missing_output_guardrails",
        "residency_match": "missing_residency_match",
        "run_receipt_attached": "missing_run_receipt",
        "telemetry_redacted": "missing_redacted_telemetry",
        "tool_guardrails_enforced": "missing_tool_guardrails",
        "training_opt_out": "missing_training_opt_out",
        "zero_data_retention": "missing_zdr",
    }
    for control in missing:
        score += int(weights.get(missing_weight_map.get(control, ""), 0) or 0)
    for control in [
        "enterprise_contract",
        "zero_data_retention",
        "training_opt_out",
        "dpa_in_place",
        "mcp_gateway_enforced",
        "tool_guardrails_enforced",
        "output_guardrails_enforced",
        "telemetry_redacted",
        "run_receipt_attached",
    ]:
        if request.get(control):
            score -= int(credits.get(control, 0) or 0)
    if request["egress_decision"].startswith("allow_"):
        score -= int(credits.get("egress_decision_allow", 0) or 0)
    if human_approval_present(request):
        score -= int(credits.get("human_approval_record", 0) or 0)
    if provider.get("provider_type") == "tenant_controlled_runtime":
        score -= int(credits.get("private_runtime", 0) or 0)
    return max(score, 0)


def decision_result(
    *,
    decision: str,
    reason: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    provider: dict[str, Any] | None = None,
    route: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
    missing: list[str] | None = None,
    violations: list[str] | None = None,
    score: int | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise ModelProviderRoutingDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "generated_at": pack.get("generated_at"),
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {})),
            "route_hash": route.get("route_hash") if route else None,
            "source_artifacts": pack.get("source_artifacts", []),
            "workflow_route_hash": workflow.get("workflow_route_hash") if workflow else None,
        },
        "matched_provider": {
            "default_decision": provider.get("default_decision"),
            "provider_id": provider.get("provider_id"),
            "provider_type": provider.get("provider_type"),
            "risk_tier": provider.get("risk_tier"),
            "status": provider.get("status"),
            "title": provider.get("title"),
        } if provider else None,
        "matched_route": {
            "allowed_data_classes": route.get("allowed_data_classes", []),
            "default_decision": route.get("default_decision"),
            "max_autonomy_level": route.get("max_autonomy_level"),
            "model_id": route.get("model_id"),
            "provider_id": route.get("provider_id"),
            "risk_tier": route.get("risk_tier"),
            "route_class": route.get("route_class"),
            "route_id": route.get("route_id"),
            "title": route.get("title"),
        } if route else None,
        "matched_workflow": {
            "default_decision": workflow.get("default_decision"),
            "preferred_route_ids": workflow.get("preferred_route_ids", []),
            "title": workflow.get("title"),
            "workflow_id": workflow.get("workflow_id"),
        } if workflow else None,
        "missing_controls": missing or [],
        "reason": reason,
        "request": {
            "autonomy_level": request.get("autonomy_level"),
            "data_classes": request.get("data_classes"),
            "egress_decision": request.get("egress_decision"),
            "model_id": request.get("model_id"),
            "provider_id": request.get("provider_id"),
            "route_class": request.get("route_class"),
            "route_id": request.get("route_id"),
            "tenant_region": request.get("tenant_region"),
            "provider_region": request.get("provider_region"),
            "workflow_id": request.get("workflow_id"),
        },
        "risk_score": score,
        "schema_version": pack.get("schema_version"),
        "violations": violations or [],
    }


def evaluate_model_provider_routing_decision(
    routing_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured model-provider routing decision."""
    if not isinstance(routing_pack, dict):
        raise ModelProviderRoutingDecisionError("routing_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise ModelProviderRoutingDecisionError("runtime_request must be an object")

    request = request_from_input(runtime_request)
    kill_signals = set(routing_pack.get("decision_contract", {}).get("runtime_kill_signals", []))
    if request["runtime_kill_signal"]:
        decision = "kill_session_on_provider_signal" if request["runtime_kill_signal"] in kill_signals else "hold_for_model_provider_review"
        return decision_result(
            decision=decision,
            reason="runtime provider kill signal was supplied",
            pack=routing_pack,
            request=request,
            violations=[request["runtime_kill_signal"]],
        )
    if request["endpoint_url"] and not endpoint_is_https(request["endpoint_url"]):
        return decision_result(
            decision="kill_session_on_provider_signal",
            reason="provider endpoint is not HTTPS",
            pack=routing_pack,
            request=request,
            violations=["provider_endpoint_not_https"],
        )
    if request["cross_tenant_context"]:
        return decision_result(
            decision="kill_session_on_provider_signal",
            reason="cross-tenant context was observed in the model request",
            pack=routing_pack,
            request=request,
            violations=["cross_tenant_context_in_model_request"],
        )
    if request["egress_decision"].startswith(("deny_", "kill_")):
        return decision_result(
            decision="kill_session_on_provider_signal",
            reason="context egress decision already denied or killed the route",
            pack=routing_pack,
            request=request,
            violations=["egress_decision_denied_or_killed"],
        )

    route = match_route(routing_pack, request)
    if route is None:
        return decision_result(
            decision="deny_unapproved_route",
            reason="no approved model route matched provider/model/route_class",
            pack=routing_pack,
            request=request,
            violations=["unknown_model_route"],
        )
    provider = providers_by_id(routing_pack).get(str(route.get("provider_id")))
    if provider is None:
        return decision_result(
            decision="deny_unapproved_route",
            reason="matched route references an unknown provider",
            pack=routing_pack,
            request=request,
            route=route,
            violations=["unknown_provider"],
        )
    workflow = workflow_by_id(routing_pack).get(request["workflow_id"])
    if workflow is None:
        return decision_result(
            decision="hold_for_model_provider_review",
            reason="workflow is not registered in the routing matrix",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            violations=["unregistered_workflow"],
        )

    if str(provider.get("status")) == "prohibited" or str(provider.get("provider_type")) == "unsanctioned_external_processor":
        return decision_result(
            decision="deny_unapproved_route",
            reason="provider profile is prohibited or unsanctioned",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            workflow=workflow,
            violations=["unsanctioned_provider_detected"],
        )

    route_id = str(route.get("route_id"))
    if route_id not in {str(item) for item in workflow.get("preferred_route_ids", [])}:
        return decision_result(
            decision="hold_for_model_provider_review",
            reason="route is approved globally but not preferred for this workflow",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            workflow=workflow,
            violations=["workflow_route_exception_required"],
        )

    prohibited = {str(item) for item in route.get("prohibited_data_classes", [])}
    allowed = {str(item) for item in route.get("allowed_data_classes", [])}
    request_data = set(request["data_classes"])
    if "*" in prohibited or request_data & prohibited:
        decision = "kill_session_on_provider_signal" if request_data & SECRET_DATA_CLASSES else "deny_unapproved_route"
        return decision_result(
            decision=decision,
            reason="request contains a data class prohibited for the matched route",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            workflow=workflow,
            violations=sorted(request_data & prohibited) or ["all_data_classes_prohibited"],
        )
    if request_data and not request_data.issubset(allowed):
        return decision_result(
            decision="deny_unapproved_route",
            reason="request contains a data class not allowed for the matched route",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            workflow=workflow,
            violations=sorted(request_data - allowed),
        )
    if request["contains_secret"] and provider.get("provider_type") == "external_processor":
        return decision_result(
            decision="kill_session_on_provider_signal",
            reason="secret or signer material cannot be sent to an external model route",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            workflow=workflow,
            violations=["secret_or_signer_material_to_external_model"],
        )
    if request["contains_unredacted_pii"] and not human_approval_present(request):
        return decision_result(
            decision="hold_for_model_provider_review",
            reason="unredacted PII requires explicit review before model-provider routing",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            workflow=workflow,
            violations=["unredacted_pii_without_approval"],
        )
    if autonomy_rank(routing_pack, request["autonomy_level"]) > autonomy_rank(routing_pack, str(route.get("max_autonomy_level"))):
        return decision_result(
            decision="deny_unapproved_route",
            reason="requested autonomy exceeds the matched route maximum",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            workflow=workflow,
            violations=["autonomy_exceeds_route_limit"],
        )
    if request["tool_call_started"] and route.get("route_class") == "untrusted_content_guardrail":
        return decision_result(
            decision="kill_session_on_provider_signal",
            reason="tool execution started before the blocking untrusted-content guardrail completed",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            workflow=workflow,
            violations=["tool_call_started_before_blocking_guardrail"],
        )

    missing = missing_controls(request=request, route=route, provider=provider)
    score = risk_score(pack=routing_pack, request=request, provider=provider, missing=missing)
    thresholds = routing_pack.get("scoring_model", {}).get("decision_thresholds", {})
    if missing:
        return decision_result(
            decision="hold_for_model_provider_review",
            reason="matched route is plausible but required provider-routing evidence is missing",
            pack=routing_pack,
            request=request,
            provider=provider,
            route=route,
            workflow=workflow,
            missing=missing,
            score=score,
        )

    if score <= int(thresholds.get("allow_approved_route_max", 24) or 24) and route.get("default_decision") == "allow_approved_route":
        decision = "allow_approved_route"
    elif score <= int(thresholds.get("allow_guarded_route_max", 44) or 44):
        decision = "allow_guarded_route"
    else:
        decision = "hold_for_model_provider_review"
    return decision_result(
        decision=decision,
        reason="matched route, data classes, autonomy, egress, and provider evidence satisfied the routing contract",
        pack=routing_pack,
        request=request,
        provider=provider,
        route=route,
        workflow=workflow,
        score=score,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--provider-id", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--route-class", required=True)
    parser.add_argument("--route-id")
    parser.add_argument("--data-class", dest="data_classes", action="append", default=[])
    parser.add_argument("--autonomy-level", default="assisted")
    parser.add_argument("--tenant-id", default="")
    parser.add_argument("--tenant-region", default="")
    parser.add_argument("--provider-region", default="")
    parser.add_argument("--endpoint-url", default="")
    parser.add_argument("--egress-decision", default="")
    parser.add_argument("--runtime-kill-signal", default="")
    parser.add_argument("--zero-data-retention", action="store_true")
    parser.add_argument("--training-opt-out", action="store_true")
    parser.add_argument("--dpa-in-place", action="store_true")
    parser.add_argument("--enterprise-contract", action="store_true")
    parser.add_argument("--mcp-gateway-enforced", action="store_true")
    parser.add_argument("--tool-guardrails-enforced", action="store_true")
    parser.add_argument("--output-guardrails-enforced", action="store_true")
    parser.add_argument("--telemetry-redacted", action="store_true")
    parser.add_argument("--run-receipt-attached", action="store_true")
    parser.add_argument("--human-approval-id", default="")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--contains-unredacted-pii", action="store_true")
    parser.add_argument("--cross-tenant-context", action="store_true")
    parser.add_argument("--untrusted-input", action="store_true")
    parser.add_argument("--tool-call-started", action="store_true")
    parser.add_argument("--high-impact-action", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    pack = load_json(args.pack)
    request = {
        "autonomy_level": args.autonomy_level,
        "contains_secret": args.contains_secret,
        "contains_unredacted_pii": args.contains_unredacted_pii,
        "cross_tenant_context": args.cross_tenant_context,
        "data_classes": args.data_classes,
        "dpa_in_place": args.dpa_in_place,
        "egress_decision": args.egress_decision,
        "endpoint_url": args.endpoint_url,
        "enterprise_contract": args.enterprise_contract,
        "high_impact_action": args.high_impact_action,
        "human_approval_record": {"approval_id": args.human_approval_id} if args.human_approval_id else {},
        "mcp_gateway_enforced": args.mcp_gateway_enforced,
        "model_id": args.model_id,
        "output_guardrails_enforced": args.output_guardrails_enforced,
        "provider_id": args.provider_id,
        "provider_region": args.provider_region,
        "route_class": args.route_class,
        "route_id": args.route_id,
        "run_receipt_attached": args.run_receipt_attached,
        "runtime_kill_signal": args.runtime_kill_signal,
        "telemetry_redacted": args.telemetry_redacted,
        "tenant_id": args.tenant_id,
        "tenant_region": args.tenant_region,
        "tool_call_started": args.tool_call_started,
        "tool_guardrails_enforced": args.tool_guardrails_enforced,
        "training_opt_out": args.training_opt_out,
        "untrusted_input": args.untrusted_input,
        "workflow_id": args.workflow_id,
        "zero_data_retention": args.zero_data_retention,
    }
    decision = evaluate_model_provider_routing_decision(pack, request)
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
