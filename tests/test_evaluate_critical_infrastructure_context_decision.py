from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_critical_infrastructure_context_decision import (
    evaluate_critical_infrastructure_context_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "critical-infrastructure-secure-context-pack.json"


def _read_only_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "sector_id": "energy-ot-ics",
        "workflow_id": "vulnerable-dependency-remediation",
        "action_class": "read_only_context",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "run_id": "ci-readonly",
        "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "tenant_id": "ci-tenant",
        "context_package_hash": "sha256:context",
        "authorization_decision": "allow_authorized_mcp_request",
        "egress_decision": "allow_internal_context",
    }
    request.update(overrides)
    return request


class CriticalInfrastructureFiveEyesPrivilegeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_bounded_read_only_context_is_allowed(self) -> None:
        result = evaluate_critical_infrastructure_context_decision(
            self.pack, _read_only_request()
        )
        self.assertEqual(result["decision"], "allow_ci_read_only_context")
        self.assertTrue(result["allowed"])

    def test_unrestricted_critical_system_access_kills_the_session(self) -> None:
        result = evaluate_critical_infrastructure_context_decision(
            self.pack,
            _read_only_request(unrestricted_critical_system_access=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_ci_hazard_signal")
        self.assertFalse(result["allowed"])
        self.assertIn("unrestricted_critical_system_access", result["violations"])

    def test_shared_agent_credentials_kill_the_session(self) -> None:
        result = evaluate_critical_infrastructure_context_decision(
            self.pack,
            _read_only_request(shared_agent_credentials=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_ci_hazard_signal")
        self.assertFalse(result["allowed"])
        self.assertIn("shared_agent_credentials", result["violations"])

    def test_regulated_pii_holds_even_read_only_context(self) -> None:
        result = evaluate_critical_infrastructure_context_decision(
            self.pack,
            _read_only_request(handles_regulated_pii=True),
        )
        self.assertEqual(result["decision"], "hold_for_ci_safety_case")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("ci_safety_case_id" in item for item in result["violations"])
        )


if __name__ == "__main__":
    unittest.main()
