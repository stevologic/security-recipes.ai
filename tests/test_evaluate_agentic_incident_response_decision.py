from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_incident_response_decision import (
    evaluate_agentic_incident_response_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-incident-response-pack.json"


def _minimal_pack() -> dict[str, object]:
    return {
        "incident_classes": [
            {
                "id": "mcp-authorization-confused-deputy",
                "title": "MCP authorization confused deputy or token passthrough",
                "default_severity": "sev0",
                "default_decision": "kill_session_and_escalate_board",
            },
            {
                "id": "uninstructed-control-compromise",
                "title": "Uninstructed control-compromise or monitor interference",
                "default_severity": "sev0",
                "default_decision": "kill_session_and_escalate_board",
            },
            {
                "id": "evidence-integrity-gap",
                "title": "Evidence integrity, receipt, or replay gap",
                "default_severity": "sev2",
                "default_decision": "hold_for_forensics",
            },
            {
                "id": "context-poisoning",
                "title": "Context poisoning or prompt-injection intake",
                "default_severity": "sev3",
                "default_decision": "triage_and_monitor",
            },
        ],
        "workflow_response_matrix": [
            {
                "workflow_id": "vulnerable-dependency-remediation",
                "title": "Vulnerable dependency remediation",
                "default_response_decision": "contain_and_open_war_room",
                "readiness_decision": "hold",
                "risk_tier": "medium",
                "severity_floor": "sev1",
            }
        ],
        "response_phases": [{"id": "detect-and-classify"}],
        "incident_contract": {
            "required_runtime_fields": [
                "incident_id",
                "workflow_id",
                "run_id",
                "agent_id",
                "identity_id",
                "tenant_id",
                "correlation_id",
                "incident_class_id",
                "receipt_id",
            ]
        },
    }


def _request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "incident_id": "inc-ci",
        "workflow_id": "vulnerable-dependency-remediation",
        "run_id": "run-ci",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "tenant_id": "tenant-demo",
        "correlation_id": "corr-ci",
        "incident_class_id": "evidence-integrity-gap",
        "severity_signal": "sev2",
        "source_event_ids": ["event-1"],
        "receipt_id": "receipt-ci",
        "context_source_ids": ["workflow-manifest"],
        "context_source_hashes": ["hash-ci"],
        "mcp_namespaces": ["repo.contents"],
        "authorization_decisions": ["allow_authorized_mcp_request"],
        "containment_action_ids": ["pause_agent_run"],
        "replay_case_ids": ["replay-ci"],
    }
    request.update(overrides)
    return request


class MonitorIsolationDecisionTests(unittest.TestCase):
    def test_unspecified_monitor_evidence_keeps_token_passthrough_kill(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(
                incident_class_id="mcp-authorization-confused-deputy",
                severity_signal="sev1",
                token_passthrough=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertIn("raw MCP or provider token passthrough was observed", result["violations"])

    def test_unspecified_monitor_flags_do_not_kill_or_hold(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(incident_class_id="context-poisoning", severity_signal="sev3"),
        )
        self.assertEqual(result["decision"], "monitor_no_incident")
        self.assertTrue(result["allowed"])

    def test_agent_can_access_monitors_kills_the_session(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(
                incident_class_id="uninstructed-control-compromise",
                severity_signal="sev1",
                agent_can_access_monitors=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertFalse(result["allowed"])
        self.assertIn(
            "agent can access or interfere with monitoring processes and logs",
            result["violations"],
        )

    def test_monitor_tampering_or_outage_kills_the_session(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(
                incident_class_id="uninstructed-control-compromise",
                severity_signal="sev1",
                monitor_tampering_or_outage=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertIn("monitor tampering or outage was observed", result["violations"])

    def test_resume_without_verified_containment_holds_for_forensics(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(resume_without_verified_containment=True),
        )
        self.assertEqual(result["decision"], "hold_for_forensics")
        self.assertFalse(result["allowed"])
        self.assertIn("resume attempted without verified containment", result["violations"])

    def test_sev0_still_kills_when_resume_is_attempted(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(
                incident_class_id="uninstructed-control-compromise",
                severity_signal="sev0",
                resume_without_verified_containment=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")


class GeneratedPackMonitorIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_generated_pack_registers_uninstructed_control_compromise(self) -> None:
        classes = {row["id"] for row in self.pack.get("incident_classes", [])}
        self.assertIn("uninstructed-control-compromise", classes)
        source_ids = {row["id"] for row in self.pack.get("standards_alignment", [])}
        self.assertIn("nist-caissi-si-incident-readiness-2026", source_ids)

    def test_generated_pack_assigns_control_compromise_and_containment_actions(self) -> None:
        matrix = self.pack.get("workflow_response_matrix", [])
        self.assertTrue(matrix)
        self.assertTrue(
            all("uninstructed-control-compromise" in row.get("assigned_incident_class_ids", []) for row in matrix)
        )
        self.assertTrue(
            all(
                "isolate_monitors_from_agent_access" in row.get("containment_actions", [])
                and "verify_monitors_logging_egress_and_shutdown_before_resume" in row.get("containment_actions", [])
                for row in matrix
            )
        )


if __name__ == "__main__":
    unittest.main()
