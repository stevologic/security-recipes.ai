from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_protocol_conformance_decision import (
    evaluate_agentic_protocol_conformance_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-protocol-conformance-pack.json"


def _authorization_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "protocol_id": "mcp-authorization-2025-11-25",
        "workflow_id": "vulnerable-dependency-remediation",
        "agent_id": "sec-auto-remediator",
        "run_id": "run-2026-09-27-001",
        "session_id": "sess-001",
        "correlation_id": "corr-001",
        "transport": "streamable-http",
        "resource_indicator_present": True,
        "token_audience_bound": True,
        "pkce_verified": True,
        "client_metadata_reviewed": True,
    }
    request.update(overrides)
    return request


def _tooling_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "protocol_id": "mcp-tooling-safety",
        "workflow_id": "vulnerable-dependency-remediation",
        "agent_id": "sec-auto-remediator",
        "run_id": "run-2026-09-27-002",
        "session_id": "sess-002",
        "correlation_id": "corr-002",
        "transport": "streamable-http",
        "tool_surface_pinned": True,
        "tool_annotations_trusted": True,
    }
    request.update(overrides)
    return request


class AgenticProtocolConformanceSubscriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_unspecified_subscription_evidence_still_allows_authorization(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack, _authorization_request()
        )
        self.assertEqual(result["decision"], "allow_with_protocol_receipt")
        self.assertTrue(result["allowed"])

    def test_matching_listen_stream_is_allowed(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_id="1",
                subscription_acknowledged=True,
                requested_notification_types=["toolsListChanged"],
                observed_notification_types=["toolsListChanged"],
            ),
        )
        self.assertEqual(result["decision"], "allow_with_protocol_receipt")
        self.assertTrue(result["allowed"])

    def test_legacy_resources_subscribe_is_held_for_drift_review(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _authorization_request(subscription_method="resources/subscribe"),
        )
        self.assertEqual(result["decision"], "hold_for_protocol_drift_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("legacy MCP notification subscription method" in item for item in result["violations"])
        )

    def test_legacy_http_get_notifications_are_held_for_drift_review(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _authorization_request(legacy_http_get_notifications=True),
        )
        self.assertEqual(result["decision"], "hold_for_protocol_drift_review")
        self.assertFalse(result["allowed"])

    def test_missing_listen_acknowledgment_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_id="1",
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("notifications/subscriptions/acknowledged" in item for item in result["violations"])
        )

    def test_missing_subscription_id_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_acknowledged=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("io.modelcontextprotocol/subscriptionId" in item for item in result["violations"])
        )

    def test_unsolicited_notification_type_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_id="1",
                subscription_acknowledged=True,
                requested_notification_types=["toolsListChanged"],
                observed_notification_types=["toolsListChanged", "resourcesListChanged"],
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("unsolicited notification type" in item for item in result["violations"])
        )

    def test_request_scoped_progress_on_listen_stream_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_id="1",
                subscription_acknowledged=True,
                subscription_request_scoped_on_listen_stream=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("notifications/progress" in item for item in result["violations"])
        )

    def test_stdio_subscription_reuse_after_reconnect_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_id="1",
                subscription_acknowledged=True,
                stdio_subscription_state_reused_after_reconnect=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("stdio subscription state reused" in item for item in result["violations"])
        )

    def test_subscriptions_source_is_present(self) -> None:
        source_ids = {
            str(row.get("id"))
            for row in self.pack.get("source_references", [])
            if isinstance(row, dict)
        }
        self.assertIn("mcp-subscriptions-listen-2026-07-28", source_ids)
        self.assertIn("mcp-spec-changelog-2026-07-28", source_ids)


if __name__ == "__main__":
    unittest.main()
