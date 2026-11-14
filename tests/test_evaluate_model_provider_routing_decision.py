from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_model_provider_routing_decision import (
    evaluate_model_provider_routing_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "model-provider-routing-pack.json"
CONSUMPTION_CONTROLS = (
    "token_aware_rate_limit",
    "spending_cap_halts_inference",
    "agentic_circuit_breaker",
)


def _tenant_sensitive_request(**overrides: object) -> dict[str, object]:
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
        "token_aware_rate_limit": True,
        "spending_cap_halts_inference": True,
        "agentic_circuit_breaker": True,
    }
    request.update(overrides)
    return request


class ModelProviderRoutingLlm06ConsumptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_complete_tenant_route_with_consumption_halt_is_guarded(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack, _tenant_sensitive_request()
        )
        self.assertEqual(result["decision"], "allow_guarded_route")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["missing_controls"], [])

    def test_missing_consumption_evidence_holds_a_production_looking_route(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack,
            _tenant_sensitive_request(
                token_aware_rate_limit=False,
                spending_cap_halts_inference=False,
                agentic_circuit_breaker=False,
            ),
        )
        self.assertEqual(result["decision"], "hold_for_model_provider_review")
        self.assertFalse(result["allowed"])
        for control in CONSUMPTION_CONTROLS:
            self.assertIn(control, result["missing_controls"])

    def test_alert_only_spending_cap_does_not_count_as_a_hard_halt(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack,
            _tenant_sensitive_request(spending_cap_halts_inference=False),
        )
        self.assertEqual(result["decision"], "hold_for_model_provider_review")
        self.assertFalse(result["allowed"])
        self.assertIn("spending_cap_halts_inference", result["missing_controls"])
        self.assertNotIn("token_aware_rate_limit", result["missing_controls"])
        self.assertNotIn("agentic_circuit_breaker", result["missing_controls"])

    def test_missing_circuit_breaker_holds(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack, _tenant_sensitive_request(agentic_circuit_breaker=False)
        )
        self.assertEqual(result["decision"], "hold_for_model_provider_review")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["missing_controls"], ["agentic_circuit_breaker"])

    def test_unparseable_consumption_flags_fail_closed_to_hold(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack,
            _tenant_sensitive_request(
                token_aware_rate_limit="maybe",
                spending_cap_halts_inference="not-a-bool",
                agentic_circuit_breaker="unknown",
            ),
        )
        self.assertEqual(result["decision"], "hold_for_model_provider_review")
        self.assertFalse(result["allowed"])
        for control in CONSUMPTION_CONTROLS:
            self.assertIn(control, result["missing_controls"])

    def test_omitted_consumption_flags_fail_closed_to_hold(self) -> None:
        request = _tenant_sensitive_request()
        for control in CONSUMPTION_CONTROLS:
            request.pop(control)
        result = evaluate_model_provider_routing_decision(self.pack, request)
        self.assertEqual(result["decision"], "hold_for_model_provider_review")
        self.assertFalse(result["allowed"])
        for control in CONSUMPTION_CONTROLS:
            self.assertIn(control, result["missing_controls"])

    def test_detected_unbounded_loop_kills_the_session(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack,
            _tenant_sensitive_request(recursive_tool_or_reasoning_loop=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_provider_signal")
        self.assertFalse(result["allowed"])
        self.assertIn("unbounded_consumption_loop_detected", result["violations"])

    def test_runtime_kill_signal_for_unbounded_consumption_kills(self) -> None:
        result = evaluate_model_provider_routing_decision(
            self.pack,
            _tenant_sensitive_request(
                runtime_kill_signal="unbounded_consumption_loop_detected"
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_provider_signal")
        self.assertFalse(result["allowed"])
        self.assertIn("unbounded_consumption_loop_detected", result["violations"])


if __name__ == "__main__":
    unittest.main()
