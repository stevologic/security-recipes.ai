from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_model_provider_routing_decision import (
    evaluate_model_provider_routing_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "model-provider-routing-pack.json"


def _guarded_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "provider_id": "frontier-enterprise-provider",
        "model_id": "frontier-code-and-security-reasoning",
        "route_class": "tenant_sensitive_remediation",
        "data_classes": ["customer_source_code", "customer_finding_metadata"],
        "autonomy_level": "bounded_agent",
        "tenant_id": "tenant-123",
        "tenant_region": "us",
        "provider_region": "us",
        "enterprise_contract": True,
        "dpa_in_place": True,
        "zero_data_retention": True,
        "training_opt_out": True,
        "mcp_gateway_enforced": True,
        "tool_guardrails_enforced": True,
        "output_guardrails_enforced": True,
        "telemetry_redacted": True,
        "run_receipt_attached": True,
        "egress_decision": "allow_tenant_bound_egress",
        "human_approval_record": {"approval_id": "approval-123"},
    }
    request.update(overrides)
    return request


class ModelProviderRoutingConsumptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_guarded_route_is_allowed_when_consumption_evidence_is_unspecified(self) -> None:
        result = evaluate_model_provider_routing_decision(self.pack, _guarded_request())
        self.assertEqual(result["decision"], "allow_guarded_route")
        self.assertTrue(result["allowed"])

    def test_unbounded_consumption_kills_the_session(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack,
            _guarded_request(unbounded_consumption_observed=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_provider_signal")
        self.assertFalse(result["allowed"])
        self.assertIn("unbounded_consumption_observed", result["violations"])

    def test_agentic_loop_without_circuit_breaker_kills_the_session(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack,
            _guarded_request(agentic_loop_without_circuit_breaker=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_provider_signal")
        self.assertFalse(result["allowed"])
        self.assertIn("agentic_loop_without_circuit_breaker", result["violations"])

    def test_alert_only_spending_cap_denies_the_route(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack,
            _guarded_request(spending_cap_alert_only=True),
        )
        self.assertEqual(result["decision"], "deny_unapproved_route")
        self.assertFalse(result["allowed"])
        self.assertIn("spending_cap_does_not_halt_inference", result["violations"])


if __name__ == "__main__":
    unittest.main()
