from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_protocol_conformance_decision import (
    evaluate_agentic_protocol_conformance_decision,
    subscription_listen_violations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-protocol-conformance-pack.json"


def _tooling_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "protocol_id": "mcp-tooling-safety",
        "workflow_id": "vulnerable-dependency-remediation",
        "agent_id": "sec-auto-remediator",
        "run_id": "ci-listen",
        "session_id": "sess-listen",
        "correlation_id": "corr-listen",
        "transport": "streamable-http",
        "protocol_version_observed": "2026-07-28",
        "tool_surface_pinned": True,
        "tool_annotations_trusted": True,
    }
    request.update(overrides)
    return request


class SubscriptionListenBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_unspecified_subscription_evidence_stays_on_allow_path(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(self.pack, _tooling_request())
        self.assertEqual(result["decision"], "allow_with_protocol_receipt")
        self.assertTrue(result["allowed"])

    def test_matching_listen_stream_allows_with_receipt(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_acknowledged=True,
                subscription_id_present=True,
                requested_notification_types=["toolsListChanged"],
                observed_notification_types=["toolsListChanged"],
            ),
        )
        self.assertEqual(result["decision"], "allow_with_protocol_receipt")
        self.assertTrue(result["allowed"])

    def test_unsolicited_notification_type_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_acknowledged=True,
                subscription_id_present=True,
                requested_notification_types=["toolsListChanged"],
                observed_notification_types=["toolsListChanged", "resourcesListChanged"],
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("resourcesListChanged" in item for item in result["violations"])
        )

    def test_missing_acknowledgment_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_id_present=True,
                requested_notification_types=["toolsListChanged"],
                observed_notification_types=["toolsListChanged"],
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertTrue(any("acknowledged" in item for item in result["violations"]))

    def test_missing_subscription_id_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_acknowledged=True,
                requested_notification_types=["toolsListChanged"],
                observed_notification_types=["toolsListChanged"],
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertTrue(any("subscriptionId" in item for item in result["violations"]))

    def test_request_scoped_notification_on_listen_stream_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                subscription_method="subscriptions/listen",
                subscription_acknowledged=True,
                subscription_id_present=True,
                requested_notification_types=["toolsListChanged"],
                observed_notification_types=["toolsListChanged"],
                request_scoped_notification_on_listen_stream=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertTrue(any("request-scoped" in item for item in result["violations"]))

    def test_stdio_reconnect_without_relissen_is_denied(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                transport="stdio",
                subscription_method="subscriptions/listen",
                subscription_acknowledged=True,
                subscription_id_present=True,
                requested_notification_types=["toolsListChanged"],
                observed_notification_types=["toolsListChanged"],
                stdio_reconnect_without_relissen=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_protocol_surface")
        self.assertTrue(any("stdio reconnect" in item for item in result["violations"]))

    def test_legacy_resources_subscribe_holds_on_current_protocol(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(subscription_method="resources/subscribe"),
        )
        self.assertEqual(result["decision"], "hold_for_protocol_drift_review")
        self.assertFalse(result["allowed"])

    def test_legacy_http_get_holds_on_current_protocol(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(subscription_method="GET"),
        )
        self.assertEqual(result["decision"], "hold_for_protocol_drift_review")

    def test_legacy_subscribe_may_proceed_on_prior_protocol_revision(self) -> None:
        result = evaluate_agentic_protocol_conformance_decision(
            self.pack,
            _tooling_request(
                protocol_version_observed="2025-11-25",
                subscription_method="resources/subscribe",
            ),
        )
        self.assertEqual(result["decision"], "allow_with_protocol_receipt")

    def test_helper_encodes_listen_musts(self) -> None:
        self.assertEqual(
            subscription_listen_violations(
                {
                    "subscription_method": "subscriptions/listen",
                    "subscription_acknowledged": True,
                    "subscription_id_present": True,
                    "requested_notification_types": ["toolsListChanged"],
                    "observed_notification_types": ["toolsListChanged"],
                }
            ),
            [],
        )
        self.assertTrue(
            subscription_listen_violations(
                {
                    "subscription_method": "subscriptions/listen",
                    "subscription_acknowledged": True,
                    "subscription_id_present": True,
                    "requested_notification_types": ["toolsListChanged"],
                    "observed_notification_types": ["promptsListChanged"],
                }
            )
        )
        self.assertEqual(
            subscription_listen_violations({"subscription_method": "resources/subscribe"}),
            [],
        )
