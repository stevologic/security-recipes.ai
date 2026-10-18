from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_context_egress_decision import evaluate_context_egress_decision


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "context-egress-boundary-pack.json"


def _public_guidance_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "destination_class": "approved_model_provider",
        "source_id": "recipes",
        "data_class": "curated_security_guidance",
        "dpa_in_place": True,
        "zero_data_retention": True,
        "residency_region": "us",
        "required_region": "us",
    }
    request.update(overrides)
    return request


class ContextEgressHiddenContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_public_guidance_to_approved_model_is_allowed(self) -> None:
        result = evaluate_context_egress_decision(self.pack, _public_guidance_request())
        self.assertEqual(result["decision"], "allow_public_egress_with_citation")
        self.assertTrue(result["allowed"])

    def test_hidden_operational_context_on_public_corpus_is_denied(self) -> None:
        result = evaluate_context_egress_decision(
            self.pack,
            _public_guidance_request(
                destination_class="securityrecipes_public_corpus",
                contains_hidden_operational_context=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_destination")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("hidden operational context" in item for item in result["violations"])
        )

    def test_hidden_operational_data_class_on_public_corpus_is_denied(self) -> None:
        result = evaluate_context_egress_decision(
            self.pack,
            _public_guidance_request(
                destination_class="securityrecipes_public_corpus",
                data_class="hidden_operational_context",
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_destination")
        self.assertFalse(result["allowed"])

    def test_tool_schema_alias_on_public_corpus_is_denied(self) -> None:
        result = evaluate_context_egress_decision(
            self.pack,
            _public_guidance_request(
                destination_class="securityrecipes_public_corpus",
                data_class="tool_function_schema",
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_destination")
        self.assertFalse(result["allowed"])
        self.assertEqual(
            result["request"]["data_class"], "hidden_operational_context"
        )

    def test_hidden_operational_context_may_reach_an_approved_model(self) -> None:
        result = evaluate_context_egress_decision(
            self.pack,
            _public_guidance_request(
                data_class="hidden_operational_context",
                contains_hidden_operational_context=True,
            ),
        )
        self.assertEqual(result["decision"], "allow_tenant_bound_egress")
        self.assertTrue(result["allowed"])

    def test_secret_egress_still_kills_the_session(self) -> None:
        result = evaluate_context_egress_decision(
            self.pack,
            _public_guidance_request(contains_secret=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_secret_egress")
        self.assertFalse(result["allowed"])
