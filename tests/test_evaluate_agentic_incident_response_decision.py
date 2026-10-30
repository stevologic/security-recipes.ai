from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_incident_response_decision import (
    evaluate_agentic_incident_response_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-incident-response-pack.json"


def _complete_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "incident_id": "inc-ir-monitors",
        "workflow_id": "vulnerable-dependency-remediation",
        "run_id": "run-ir-monitors",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "tenant_id": "tenant-demo",
        "correlation_id": "corr-ir-monitors",
        "incident_class_id": "uninstructed-control-compromise",
        "severity_signal": "sev3",
        "source_event_ids": ["event-ir-1"],
        "receipt_id": "receipt-ir-monitors",
        "context_source_ids": ["workflow-manifest"],
        "context_source_hashes": ["hash-ir"],
        "mcp_namespaces": ["repo.contents"],
        "authorization_decisions": ["allow_authorized_mcp_request"],
        "containment_action_ids": [
            "isolate_agent_from_monitors_and_verify_containment_before_resume"
        ],
        "replay_case_ids": ["replay-ir-1"],
    }
    request.update(overrides)
    return request


class AgenticIncidentResponseControlIncidentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_unspecified_monitor_evidence_stays_on_the_prior_monitor_path(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            self.pack,
            _complete_request(),
        )
        self.assertEqual(result["decision"], "monitor_no_incident")
        self.assertTrue(result["allowed"])

    def test_agent_access_to_monitors_kills_the_session(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            self.pack,
            _complete_request(agent_can_access_monitors=True),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("monitoring processes or logs" in item for item in result["violations"])
        )

    def test_monitor_tampering_indicator_kills_the_session(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            self.pack,
            _complete_request(indicators=["monitor_tampering"]),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("monitor_tampering" in item for item in result["violations"]))

    def test_monitor_outage_kills_the_session(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            self.pack,
            _complete_request(monitor_outage=True),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("monitor outage" in item for item in result["violations"]))

    def test_resume_without_verified_containment_is_held(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            self.pack,
            _complete_request(resume_without_verified_containment=True),
        )
        self.assertEqual(result["decision"], "hold_for_forensics")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("verified containment" in item for item in result["violations"])
        )

    def test_si_incident_readiness_source_is_present(self) -> None:
        source_ids = {
            str(row.get("id"))
            for row in self.pack.get("standards_alignment", [])
            if isinstance(row, dict)
        }
        self.assertIn("nist-caisi-si-incident-readiness-2026", source_ids)
        class_ids = {
            str(row.get("id"))
            for row in self.pack.get("incident_classes", [])
            if isinstance(row, dict)
        }
        self.assertIn("uninstructed-control-compromise", class_ids)


if __name__ == "__main__":
    unittest.main()
