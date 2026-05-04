#!/usr/bin/env python3
"""Evaluate one A2A Agent Card trust decision.

The evaluator is deterministic. It treats A2A discovery as a security
intake event: a remote agent must prove enough structure, transport,
authentication, signature, provider, scope, and skill evidence before it
can receive secure context or join an agent-to-agent workflow.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_AGENT_CARD_PACK = Path("data/evidence/a2a-agent-card-trust-profile.json")

ALLOW_DECISIONS = {
    "allow_trusted_agent_card",
    "pilot_with_restricted_context",
}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_agent_card_intake",
    "deny_insecure_agent_card",
    "kill_session_on_agent_card_secret",
}
SECURITY_SCHEME_KEYS = {
    "apiKeySecurityScheme",
    "httpAuthSecurityScheme",
    "mtlsSecurityScheme",
    "oauth2SecurityScheme",
    "openIdConnectSecurityScheme",
}
PREFERRED_SECURITY_SCHEME_KEYS = {
    "mtlsSecurityScheme",
    "oauth2SecurityScheme",
    "openIdConnectSecurityScheme",
}


class A2AAgentCardTrustError(RuntimeError):
    """Raised when the Agent Card pack or runtime request is invalid."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise A2AAgentCardTrustError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise A2AAgentCardTrustError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise A2AAgentCardTrustError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def lower_set(values: Any) -> set[str]:
    return {str(item).strip().lower() for item in as_list(values) if str(item).strip()}


def profile_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(profile.get("id")): profile
        for profile in as_list(pack.get("intake_profiles"))
        if isinstance(profile, dict) and profile.get("id")
    }


def contract(pack: dict[str, Any]) -> dict[str, Any]:
    return as_dict(pack.get("trust_contract") or pack.get("decision_contract"))


def decision_result(
    *,
    decision: str,
    reason: str,
    runtime_request: dict[str, Any],
    violations: list[str] | None = None,
    matched_profile: dict[str, Any] | None = None,
    card_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise A2AAgentCardTrustError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "card_facts": card_facts or {},
        "decision": decision,
        "matched_profile": {
            "profile_id": matched_profile.get("id") if matched_profile else runtime_request.get("profile_id"),
            "risk_tier": matched_profile.get("risk_tier") if matched_profile else None,
            "title": matched_profile.get("title") if matched_profile else None,
        },
        "reason": reason,
        "runtime_request": {
            "approved_skill_ids": as_list(runtime_request.get("approved_skill_ids")),
            "correlation_id": runtime_request.get("correlation_id"),
            "declared_controls": as_list(runtime_request.get("declared_controls")),
            "expected_domain": runtime_request.get("expected_domain"),
            "production": bool(runtime_request.get("production")),
            "profile_id": runtime_request.get("profile_id"),
            "run_id": runtime_request.get("run_id"),
            "tenant_id": runtime_request.get("tenant_id"),
        },
        "violations": violations or [],
    }


def walk_strings(value: Any) -> list[str]:
    output: list[str] = []
    if isinstance(value, str):
        output.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            output.extend(walk_strings(item))
    elif isinstance(value, list):
        for item in value:
            output.extend(walk_strings(item))
    return output


def has_secret_or_injection(card: dict[str, Any], pack: dict[str, Any]) -> list[str]:
    cfg = contract(pack)
    markers = [
        *[str(item).lower() for item in cfg.get("prohibited_secret_markers", [])],
        *[str(item).lower() for item in cfg.get("prompt_injection_markers", [])],
    ]
    violations: list[str] = []
    for text in walk_strings(card):
        lowered = text.lower()
        for marker in markers:
            if marker and marker in lowered:
                violations.append(f"agent card contains prohibited marker: {marker}")
    return sorted(set(violations))


def required_field_violations(card: dict[str, Any], pack: dict[str, Any]) -> list[str]:
    required = [str(item) for item in contract(pack).get("required_agent_card_fields", [])]
    violations = []
    for field in required:
        if field not in card:
            violations.append(f"missing required Agent Card field: {field}")
        elif isinstance(card.get(field), (list, dict)) and not card.get(field):
            violations.append(f"required Agent Card field is empty: {field}")
        elif isinstance(card.get(field), str) and not str(card.get(field)).strip():
            violations.append(f"required Agent Card field is empty: {field}")
    return violations


def interface_facts(card: dict[str, Any]) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    violations: list[str] = []
    for idx, interface in enumerate(as_list(card.get("supportedInterfaces"))):
        item = as_dict(interface)
        raw_url = str(item.get("url") or "").strip()
        if not raw_url:
            violations.append(f"supportedInterfaces[{idx}].url is required")
            continue
        urls.append(raw_url)
        parsed = urlparse(raw_url)
        if parsed.scheme != "https":
            violations.append(f"supportedInterfaces[{idx}].url must use https")
        if not parsed.hostname:
            violations.append(f"supportedInterfaces[{idx}].url must include a host")
    return urls, violations


def url_host(value: str) -> str:
    return (urlparse(value).hostname or "").lower()


def provider_violations(card: dict[str, Any], expected_domain: str | None) -> list[str]:
    violations: list[str] = []
    provider = as_dict(card.get("provider"))
    if not provider:
        violations.append("provider is required for trusted or pilot Agent Cards")
        return violations
    provider_url = str(provider.get("url") or "").strip()
    organization = str(provider.get("organization") or "").strip()
    if not organization:
        violations.append("provider.organization is required")
    if not provider_url:
        violations.append("provider.url is required")
    elif urlparse(provider_url).scheme != "https":
        violations.append("provider.url must use https")
    if expected_domain:
        expected = expected_domain.lower().lstrip(".")
        hosts = {url_host(provider_url)}
        for interface in as_list(card.get("supportedInterfaces")):
            hosts.add(url_host(str(as_dict(interface).get("url") or "")))
        matching = any(host == expected or host.endswith(f".{expected}") for host in hosts if host)
        if not matching:
            violations.append(f"no provider or interface host matches expected_domain={expected}")
    return violations


def security_scheme_entries(card: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    entries: list[tuple[str, str, dict[str, Any]]] = []
    schemes = as_dict(card.get("securitySchemes"))
    for scheme_name, raw_scheme in schemes.items():
        scheme = as_dict(raw_scheme)
        present = [key for key in SECURITY_SCHEME_KEYS if key in scheme]
        for key in present:
            entries.append((str(scheme_name), key, as_dict(scheme.get(key))))
    return entries


def security_violations(card: dict[str, Any], production: bool) -> tuple[list[str], dict[str, Any]]:
    violations: list[str] = []
    entries = security_scheme_entries(card)
    scheme_types = sorted({entry[1] for entry in entries})
    facts = {
        "preferred_security_scheme_present": bool(set(scheme_types) & PREFERRED_SECURITY_SCHEME_KEYS),
        "security_requirement_count": len(as_list(card.get("securityRequirements"))),
        "security_scheme_count": len(entries),
        "security_scheme_types": scheme_types,
    }
    if production and not entries:
        violations.append("production Agent Card must declare securitySchemes")
    if production and not as_list(card.get("securityRequirements")):
        violations.append("production Agent Card must declare securityRequirements")

    for name, scheme_type, scheme in entries:
        if scheme_type == "apiKeySecurityScheme":
            location = str(scheme.get("location") or "").lower()
            if location in {"query", "cookie"}:
                violations.append(f"{name}: API key location {location} is prohibited")
        if scheme_type == "oauth2SecurityScheme":
            flows = as_dict(scheme.get("flows"))
            auth_code = as_dict(flows.get("authorizationCode"))
            if auth_code and auth_code.get("pkceRequired") is False:
                violations.append(f"{name}: OAuth authorizationCode flow must require PKCE")
    return violations, facts


def signature_facts(card: dict[str, Any]) -> dict[str, Any]:
    signatures = [as_dict(item) for item in as_list(card.get("signatures")) if isinstance(item, dict)]
    complete = [
        signature
        for signature in signatures
        if str(signature.get("protected") or "").strip() and str(signature.get("signature") or "").strip()
    ]
    return {
        "complete_signature_count": len(complete),
        "signature_present": bool(complete),
    }


def skills_text(card: dict[str, Any]) -> dict[str, Any]:
    skills = [as_dict(item) for item in as_list(card.get("skills")) if isinstance(item, dict)]
    return {
        "skill_count": len(skills),
        "skill_ids": [str(skill.get("id") or skill.get("name") or f"skill-{idx}") for idx, skill in enumerate(skills)],
        "text": " ".join(walk_strings(skills)).lower(),
    }


def high_impact_skill_violations(card: dict[str, Any], pack: dict[str, Any], runtime_request: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    cfg = contract(pack)
    terms = [str(item).lower() for item in cfg.get("high_impact_skill_terms", [])]
    skill_facts = skills_text(card)
    hits = sorted({term for term in terms if term and term in skill_facts["text"]})
    declared = lower_set(runtime_request.get("declared_controls"))
    violations: list[str] = []
    if hits:
        if "human_approval_for_high_impact" not in declared:
            violations.append("high-impact skill terms require human_approval_for_high_impact")
        if "gateway_enforced" not in declared:
            violations.append("high-impact skill terms require gateway_enforced")
    return violations, {
        "high_impact_skill_terms": hits,
        "skill_count": skill_facts["skill_count"],
        "skill_ids": skill_facts["skill_ids"],
    }


def extended_card_violations(card: dict[str, Any]) -> list[str]:
    capabilities = as_dict(card.get("capabilities"))
    if capabilities.get("extendedAgentCard") and not security_scheme_entries(card):
        return ["extendedAgentCard=true requires authentication before extended card retrieval"]
    return []


def evaluate_a2a_agent_card_trust_decision(
    agent_card_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured A2A Agent Card trust decision."""
    if not isinstance(agent_card_pack, dict):
        raise A2AAgentCardTrustError("agent_card_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise A2AAgentCardTrustError("runtime_request must be an object")

    profile_id = str(runtime_request.get("profile_id") or "").strip()
    profiles = profile_by_id(agent_card_pack)
    profile = profiles.get(profile_id)
    if not profile:
        return decision_result(
            decision="hold_for_agent_card_intake",
            reason="Agent Card intake profile is not registered",
            runtime_request=runtime_request,
            violations=[f"unknown profile_id: {profile_id}"],
        )

    card = as_dict(runtime_request.get("agent_card"))
    if not card:
        return decision_result(
            decision="hold_for_agent_card_intake",
            reason="runtime request did not include an Agent Card object",
            runtime_request=runtime_request,
            matched_profile=profile,
            violations=["agent_card is required"],
        )

    secret_violations = has_secret_or_injection(card, agent_card_pack)
    card_facts: dict[str, Any] = {}
    if secret_violations:
        return decision_result(
            decision="kill_session_on_agent_card_secret",
            reason="Agent Card contains credential, hidden-instruction, or exfiltration markers",
            runtime_request=runtime_request,
            matched_profile=profile,
            violations=secret_violations,
            card_facts=card_facts,
        )

    production = bool(runtime_request.get("production"))
    violations: list[str] = []
    holds: list[str] = []
    violations.extend(required_field_violations(card, agent_card_pack))
    interface_urls, interface_violations = interface_facts(card)
    provider_gaps = provider_violations(card, runtime_request.get("expected_domain"))
    security_gaps, security_facts = security_violations(card, production)
    skill_gaps, skill_facts = high_impact_skill_violations(card, agent_card_pack, runtime_request)
    signature = signature_facts(card)
    extended_gaps = extended_card_violations(card)

    card_facts.update(
        {
            "agent_name": card.get("name"),
            "default_input_mode_count": len(as_list(card.get("defaultInputModes"))),
            "default_output_mode_count": len(as_list(card.get("defaultOutputModes"))),
            "interface_urls": interface_urls,
            "provider": as_dict(card.get("provider")),
            **security_facts,
            **signature,
            **skill_facts,
        }
    )

    declared_controls = lower_set(runtime_request.get("declared_controls"))
    required_controls = lower_set(profile.get("required_controls"))
    missing_controls = sorted(required_controls - declared_controls)

    if interface_violations:
        return decision_result(
            decision="deny_insecure_agent_card",
            reason="Agent Card advertises insecure or invalid A2A interfaces",
            runtime_request=runtime_request,
            matched_profile=profile,
            violations=interface_violations,
            card_facts=card_facts,
        )
    if security_gaps:
        violations.extend(security_gaps)
    if extended_gaps:
        violations.extend(extended_gaps)
    if skill_gaps:
        holds.extend(skill_gaps)
    if provider_gaps and profile_id in {"trusted-production-agent", "restricted-pilot-agent"}:
        holds.extend(provider_gaps)

    if profile_id == "trusted-production-agent":
        if not signature["signature_present"]:
            holds.append("trusted production profile requires a complete Agent Card signature")
        if missing_controls:
            holds.extend(f"missing declared control: {control}" for control in missing_controls)
        if violations:
            return decision_result(
                decision="deny_insecure_agent_card",
                reason="trusted production Agent Card failed security requirements",
                runtime_request=runtime_request,
                matched_profile=profile,
                violations=violations,
                card_facts=card_facts,
            )
        if holds:
            return decision_result(
                decision="hold_for_agent_card_intake",
                reason="trusted production Agent Card is missing review or control evidence",
                runtime_request=runtime_request,
                matched_profile=profile,
                violations=holds,
                card_facts=card_facts,
            )
        return decision_result(
            decision="allow_trusted_agent_card",
            reason="Agent Card satisfies production profile requirements",
            runtime_request=runtime_request,
            matched_profile=profile,
            card_facts=card_facts,
        )

    if profile_id == "restricted-pilot-agent":
        if violations:
            return decision_result(
                decision="deny_insecure_agent_card",
                reason="restricted pilot Agent Card failed baseline security requirements",
                runtime_request=runtime_request,
                matched_profile=profile,
                violations=violations,
                card_facts=card_facts,
            )
        severe_holds = [
            item
            for item in holds
            if "provider." in item or "high-impact" in item or "gateway_enforced" in item
        ]
        if severe_holds:
            return decision_result(
                decision="hold_for_agent_card_intake",
                reason="restricted pilot Agent Card needs owner review before metadata-only use",
                runtime_request=runtime_request,
                matched_profile=profile,
                violations=severe_holds,
                card_facts=card_facts,
            )
        return decision_result(
            decision="pilot_with_restricted_context",
            reason="Agent Card is eligible only for restricted metadata-context pilot use",
            runtime_request=runtime_request,
            matched_profile=profile,
            violations=holds,
            card_facts=card_facts,
        )

    if profile_id == "public-discovery-only":
        if violations:
            return decision_result(
                decision="deny_insecure_agent_card",
                reason="public discovery Agent Card failed baseline security requirements",
                runtime_request=runtime_request,
                matched_profile=profile,
                violations=violations,
                card_facts=card_facts,
            )
        return decision_result(
            decision="hold_for_agent_card_intake",
            reason="public discovery card may be indexed but not trusted for context handoff",
            runtime_request=runtime_request,
            matched_profile=profile,
            violations=holds,
            card_facts=card_facts,
        )

    return decision_result(
        decision="deny_insecure_agent_card",
        reason="blocked profile prevents the Agent Card from being trusted",
        runtime_request=runtime_request,
        matched_profile=profile,
        violations=violations or holds or ["blocked-agent-card profile selected"],
        card_facts=card_facts,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_AGENT_CARD_PACK)
    parser.add_argument("--agent-card", type=Path, required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--production", action="store_true")
    parser.add_argument("--expected-domain", default=None)
    parser.add_argument("--declared-control", action="append", default=[])
    parser.add_argument("--approved-skill-id", action="append", default=[])
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--correlation-id", default=None)
    parser.add_argument("--expect-decision", default=None)
    parser.add_argument("--json", action="store_true", help="Print full JSON decision.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        card = load_json(args.agent_card)
        request = {
            "agent_card": card,
            "approved_skill_ids": args.approved_skill_id,
            "correlation_id": args.correlation_id,
            "declared_controls": args.declared_control,
            "expected_domain": args.expected_domain,
            "production": args.production,
            "profile_id": args.profile_id,
            "run_id": args.run_id,
            "tenant_id": args.tenant_id,
        }
        decision = evaluate_a2a_agent_card_trust_decision(pack, request)
    except A2AAgentCardTrustError as exc:
        print(f"A2A Agent Card trust error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(decision, indent=2, sort_keys=True))
    else:
        print(decision["decision"])
        for violation in decision.get("violations", []):
            print(f"- {violation}")

    if args.expect_decision:
        if decision["decision"] != args.expect_decision:
            print(
                f"expected decision {args.expect_decision!r}, got {decision['decision']!r}",
                file=sys.stderr,
            )
            return 1
        return 0
    return 0 if decision["decision"] in ALLOW_DECISIONS or decision["decision"].startswith("hold_") else 2


if __name__ == "__main__":
    raise SystemExit(main())
