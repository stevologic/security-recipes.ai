from __future__ import annotations

import json
import unittest
from io import BytesIO
from urllib.error import HTTPError

from scripts import diagnose_xai_credentials as diagnostic


class FakeResponse:
    status = 200

    def __init__(self, payload: object) -> None:
        self.raw = json.dumps(payload).encode()

    def read(self, size: int = -1) -> bytes:
        return self.raw[:size] if size >= 0 else self.raw

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class XAICredentialDiagnosticsTests(unittest.TestCase):
    def test_reports_only_safe_metadata_and_checks_model_aliases(self) -> None:
        key = "xai-private-example"
        requests = []

        def opener(request: object, *, timeout: int) -> FakeResponse:
            requests.append(request)
            self.assertEqual(timeout, 30)
            if len(requests) == 1:
                return FakeResponse({
                    "redacted_api_key": "xai-...private-fragment",
                    "team_id": "private-team-id",
                    "name": "private-key-name",
                    "api_key_disabled": False,
                    "api_key_blocked": False,
                    "team_blocked": False,
                    "acls": ["api-key:model:*", "api-key:endpoint:*"],
                })
            if len(requests) == 2:
                return FakeResponse({
                    "models": [{"id": "versioned-model", "aliases": ["grok-test"]}]
                })
            return FakeResponse({"id": "private-response-id"})

        report = diagnostic.diagnose(key, model="grok-test", opener=opener)
        encoded = json.dumps(report)
        self.assertNotIn("private", encoded)
        self.assertNotIn("grok-test", encoded)
        self.assertEqual(len(requests), 3)
        self.assertTrue(report["key_metadata"]["all_endpoints_allowed"])
        self.assertTrue(report["model_metadata"]["configured_model_listed"])
        self.assertTrue(report["responses_probe"]["usable"])
        self.assertEqual(report["responses_probe"]["reason"], "ready")

    def test_authentication_success_does_not_imply_inference_permission(self) -> None:
        calls = []

        def opener(request: object, *, timeout: int) -> FakeResponse:
            calls.append(request)
            if len(calls) == 1:
                return FakeResponse({"acls": ["api-key:endpoint:models"]})
            if len(calls) == 2:
                return FakeResponse({"models": []})
            raise HTTPError(
                "https://api.x.ai/v1/responses", 403, "private-error", {},
                BytesIO(b'{"error":"private-key-value ::error::injected"}'),
            )

        report = diagnostic.diagnose("xai-private-key-value", opener=opener)
        self.assertEqual(report["key_metadata"]["result"], "ready")
        self.assertFalse(report["key_metadata"]["all_endpoints_allowed"])
        self.assertFalse(report["responses_probe"]["usable"])
        self.assertEqual(report["responses_probe"]["reason"], "permission_denied")
        self.assertEqual(report["responses_probe"]["http_status"], 403)
        self.assertNotIn("private", json.dumps(report))
        self.assertNotIn("::error::", json.dumps(report))

    def test_missing_or_malformed_keys_make_no_network_requests(self) -> None:
        def opener(*_: object, **__: object) -> FakeResponse:
            self.fail("A malformed key must not be sent")

        for key in ("", "Bearer xai-private", '"xai-private"', "xai-\nprivate"):
            with self.subTest(key=key):
                report = diagnostic.diagnose(key, opener=opener)
                self.assertIn(report["result"], ("missing", "invalid_format"))
                self.assertNotIn("private", json.dumps(report))

    def test_metadata_failures_remain_unknown_and_hide_payloads(self) -> None:
        calls = []

        def opener(request: object, *, timeout: int) -> FakeResponse:
            calls.append(request)
            if len(calls) < 3:
                raise HTTPError(
                    "https://api.x.ai/v1/api-key", 403, "private", {},
                    BytesIO(b'{"error":"private-data"}'),
                )
            return FakeResponse({"id": "private-id"})

        report = diagnostic.diagnose("xai-test", opener=opener)
        self.assertEqual(report["key_metadata"]["result"], "permission_denied")
        self.assertNotIn("all_endpoints_allowed", report["key_metadata"])
        self.assertNotIn("configured_model_listed", report["model_metadata"])
        self.assertTrue(report["responses_probe"]["usable"])
        self.assertNotIn("private", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
