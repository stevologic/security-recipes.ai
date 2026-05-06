#!/usr/bin/env python3
"""Evaluate one runtime event against the Agentic AIVSS Risk Scoring Pack."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/agentic-aivss-risk-scoring-pack.json")
ALLOW_DECISION = "allow_with_monitoring"
GUARDED_DECISION = "allow_guarded_with_receipt"
HOLD_DECISION = "hold_for_human_security_review"
DENY_DECISION = "deny_pending_remediation"
KILL_DECISION = "kill_session_on_agentic_aivss_signal"


class AivssEvaluationError(RuntimeError):
    """Raised when AIVSS risk evaluation cannot run."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AivssEvaluationError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AivssEvaluationError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AivssEvaluationError(f"{path} root must be an object")
    return payload


def normalize(value: Any) -> str:
    return str(value or "").strip()


def scenario_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = pack.get("risk_scores", [])
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("scenario_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("scenario_id")
    }


def score_band(pack: dict[str, Any], score: float) -> dict[str, Any]:
    bands = pack.get("decision_contract", {}).get("score_bands", [])
    if not isinstance(bands, list):
        return {"band": "high", "runtime_default_decision": HOLD_DECISION}
    sorted_bands = sorted(
        [band for band in bands if isinstance(band, dict)],
        key=lambda band: float(band.get("minimum_score") or 0),
        reverse=True,
    )
    for band in sorted_bands:
        if score >= float(band.get("minimum_score") or 0):
            return band
    return sorted_bands[-1] if sorted_bands else {"band": "low", "runtime_default_decision": ALLOW_DECISION}


def evaluate_agentic_aivss_risk_decision(pack: dict[str, Any], runtime_event: dict[str, Any]) -> dict[str, Any]:
    scenario_id = normalize(runtime_event.get("scenario_id"))
    scenarios = scenario_by_id(pack)
    scenario = scenarios.get(scenario_id) if scenario_id else None
    provided_score = runtime_event.get("aivss_score")
    score = float(provided_score) if provided_score is not None else float((scenario or {}).get("aivss_score") or 0)
    band = score_band(pack, score)
    severity = normalize((scenario or {}).get("severity") or band.get("band"))
    default_decision = normalize((scenario or {}).get("runtime_default_decision") or band.get("runtime_default_decision") or HOLD_DECISION)

    contains_secret = bool(runtime_event.get("contains_secret"))
    unregistered_agent = bool(runtime_event.get("unregistered_agent"))
    shadow_mcp_server = bool(runtime_event.get("shadow_mcp_server"))
    external_write = bool(runtime_event.get("external_write"))
    exfiltration_capable_tool = bool(runtime_event.get("exfiltration_capable_tool"))
    untrusted_context = bool(runtime_event.get("untrusted_context"))
    high_autonomy = normalize(runtime_event.get("autonomy_level")) in {"high", "autonomous"}
    human_approval_present = bool(runtime_event.get("human_approval_present"))
    malicious_or_unpinned_skill = bool(runtime_event.get("malicious_or_unpinned_skill"))

    notes: list[str] = []
    if not scenario and scenario_id:
        notes.append("Scenario id is not present in the generated Agentic AIVSS pack.")

    if contains_secret:
        return {
            "aivss_score": score,
            "decision": KILL_DECISION,
            "notes": ["Secret, token, or prohibited credential material appeared in the runtime event."],
            "scenario_id": scenario_id,
            "severity": severity or "critical",
        }

    if unregistered_agent or shadow_mcp_server:
        return {
            "aivss_score": max(score, 8.6),
            "decision": KILL_DECISION,
            "notes": ["Unregistered agent or shadow MCP server attempted to cross a governed boundary."],
            "scenario_id": scenario_id or "rogue_agent_shadow_mcp",
            "severity": "critical",
        }

    if malicious_or_unpinned_skill and (external_write or exfiltration_capable_tool):
        return {
            "aivss_score": max(score, 8.6),
            "decision": KILL_DECISION,
            "notes": ["Malicious or unpinned skill requested write, network, shell, credential, or exfiltration-capable authority."],
            "scenario_id": scenario_id or "agentic_supply_chain_skill_compromise",
            "severity": "critical",
        }

    if high_autonomy and untrusted_context and external_write and not human_approval_present:
        return {
            "aivss_score": max(score, 8.6),
            "decision": KILL_DECISION if exfiltration_capable_tool else DENY_DECISION,
            "notes": ["High-autonomy agent combined untrusted context with external write authority without human approval."],
            "scenario_id": scenario_id,
            "severity": "critical",
        }

    if score >= 8.6 or severity == "critical":
        return {
            "aivss_score": score,
            "decision": DENY_DECISION if human_approval_present else HOLD_DECISION,
            "notes": notes + ["Critical Agentic AIVSS risk requires remediation or explicit risk acceptance before production expansion."],
            "remediation_sla": (scenario or {}).get("remediation_sla") or band.get("remediation_sla"),
            "scenario_id": scenario_id,
            "severity": "critical",
        }

    if score >= 7.0 or severity == "high":
        return {
            "aivss_score": score,
            "decision": HOLD_DECISION,
            "notes": notes + ["High Agentic AIVSS risk requires human security review, receipt binding, and a remediation owner."],
            "remediation_sla": (scenario or {}).get("remediation_sla") or band.get("remediation_sla"),
            "scenario_id": scenario_id,
            "severity": "high",
        }

    if default_decision == GUARDED_DECISION or score >= 4.0 or severity == "medium":
        return {
            "aivss_score": score,
            "decision": GUARDED_DECISION,
            "notes": notes + ["Medium Agentic AIVSS risk can proceed only with generated evidence, telemetry, and run receipt binding."],
            "remediation_sla": (scenario or {}).get("remediation_sla") or band.get("remediation_sla"),
            "scenario_id": scenario_id,
            "severity": "medium",
        }

    return {
        "aivss_score": score,
        "decision": ALLOW_DECISION,
        "notes": notes + ["Low Agentic AIVSS risk can proceed with normal monitoring and posture drift review."],
        "remediation_sla": (scenario or {}).get("remediation_sla") or band.get("remediation_sla"),
        "scenario_id": scenario_id,
        "severity": severity or "low",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--scenario-id")
    parser.add_argument("--workflow-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--aivss-score", type=float)
    parser.add_argument("--autonomy-level", choices=["bounded", "assisted", "high", "autonomous"], default="bounded")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--unregistered-agent", action="store_true")
    parser.add_argument("--shadow-mcp-server", action="store_true")
    parser.add_argument("--external-write", action="store_true")
    parser.add_argument("--exfiltration-capable-tool", action="store_true")
    parser.add_argument("--untrusted-context", action="store_true")
    parser.add_argument("--human-approval-present", action="store_true")
    parser.add_argument("--malicious-or-unpinned-skill", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        decision = evaluate_agentic_aivss_risk_decision(
            pack,
            {
                "agent_id": args.agent_id,
                "aivss_score": args.aivss_score,
                "autonomy_level": args.autonomy_level,
                "contains_secret": args.contains_secret,
                "exfiltration_capable_tool": args.exfiltration_capable_tool,
                "external_write": args.external_write,
                "human_approval_present": args.human_approval_present,
                "malicious_or_unpinned_skill": args.malicious_or_unpinned_skill,
                "scenario_id": args.scenario_id,
                "shadow_mcp_server": args.shadow_mcp_server,
                "unregistered_agent": args.unregistered_agent,
                "untrusted_context": args.untrusted_context,
                "workflow_id": args.workflow_id,
            },
        )
    except AivssEvaluationError as exc:
        print(f"agentic AIVSS risk evaluation failed: {exc}", file=sys.stderr)
        return 1

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
