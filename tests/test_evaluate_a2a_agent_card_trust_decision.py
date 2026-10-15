from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.evaluate_a2a_agent_card_trust_decision import (
    evaluate_a2a_agent_card_trust_decision,
)
from scripts.generate_a2a_agent_card_trust_profile import validate_profile


REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = REPO_ROOT / "data" / "assurance" / "a2a-agent-card-trust-profile.json"
WORKFLOW_PAGE = REPO_ROOT / "content" / "security-remediation" / "a2a-agent-card-trust" / "_index.md"


def _sample(profile: dict, sample_id: str) -> dict:
    for sample in profile.get("sample_agent_cards", []):
        if isinstance(sample, dict) and sample.get("id") == sample_id:
            return sample
    raise AssertionError(f"missing sample {sample_id}")


def _request_from_sample(sample: dict, **overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "agent_card": copy.deepcopy(sample["agent_card"]),
        "declared_controls": list(sample.get("declared_controls") or []),
        "production": bool(sample.get("production")),
        "profile_id": sample.get("expected_profile_id"),
    }
    request.update(overrides)
    return request


def _oauth_card(base_card: dict, flows: dict) -> dict:
    card = copy.deepcopy(base_card)
    card["securitySchemes"] = {
        "oauth": {
            "oauth2SecurityScheme": {
                "flows": flows,
            }
        }
    }
    card["securityRequirements"] = [{"oauth": ["a2a.task:read"]}]
    return card


class A2AAgentCardOAuthFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        cls.page = WORKFLOW_PAGE.read_text(encoding="utf-8")
        cls.trusted = _sample(cls.profile, "trusted-security-recipes-delegated-agent")
        cls.implicit = _sample(cls.profile, "implicit-oauth-production-agent")

    def test_profile_and_page_record_deprecated_oauth_without_claiming_human_review(self) -> None:
        alignment = {
            str(item.get("id")): item
            for item in self.profile.get("standards_alignment", [])
            if isinstance(item, dict)
        }
        spec = alignment["a2a-specification-latest"]
        self.assertEqual(spec["url"], "https://a2a-protocol.org/latest/specification/")
        self.assertIn("implicit", spec["coverage"])
        self.assertIn("password", spec["coverage"])
        self.assertIn("pkceRequired", spec["coverage"])
        self.assertIn("deviceCode", spec["coverage"])

        whats_new = alignment["a2a-whats-new-v1"]
        self.assertEqual(whats_new["url"], "https://a2a-protocol.org/latest/whats-new-v1/")
        self.assertIn("RFC 8628", whats_new["coverage"])

        contract = self.profile["trust_contract"]
        self.assertEqual(contract["deprecated_oauth_flows"], ["implicit", "password"])
        self.assertEqual(
            contract["current_oauth_flows"],
            ["authorizationCode", "clientCredentials", "deviceCode"],
        )
        self.assertTrue(contract["production_authorization_code_requires_pkce"])
        self.assertEqual(self.profile["last_reviewed"], "2026-10-15")
        self.assertEqual(validate_profile(self.profile), [])

        self.assertIn("https://a2a-protocol.org/latest/specification/", self.page)
        self.assertIn("https://a2a-protocol.org/latest/whats-new-v1/", self.page)
        self.assertIn("pkceRequired", self.page)
        self.assertIn("does not claim human review", self.page)
        self.assertIn("lastmod: 2026-10-15", self.page)

    def test_trusted_oidc_sample_still_allows(self) -> None:
        result = evaluate_a2a_agent_card_trust_decision(
            self.profile, _request_from_sample(self.trusted)
        )
        self.assertEqual(result["decision"], "allow_trusted_agent_card")
        self.assertTrue(result["allowed"])

    def test_implicit_oauth_sample_is_denied(self) -> None:
        result = evaluate_a2a_agent_card_trust_decision(
            self.profile, _request_from_sample(self.implicit)
        )
        self.assertEqual(result["decision"], "deny_insecure_agent_card")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("implicit" in item for item in result["violations"]))

    def test_password_oauth_flow_is_denied(self) -> None:
        card = _oauth_card(
            self.trusted["agent_card"],
            {
                "password": {
                    "tokenUrl": "https://auth.legacy.example.com/token",
                    "scopes": {"a2a.task:read": "Read delegated tasks"},
                }
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.profile, _request_from_sample(self.trusted, agent_card=card)
        )
        self.assertEqual(result["decision"], "deny_insecure_agent_card")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("password" in item for item in result["violations"]))

    def test_authorization_code_with_pkce_false_is_denied(self) -> None:
        card = _oauth_card(
            self.trusted["agent_card"],
            {
                "authorizationCode": {
                    "authorizationUrl": "https://auth.security-recipes.ai/authorize",
                    "tokenUrl": "https://auth.security-recipes.ai/token",
                    "pkceRequired": False,
                    "scopes": {"a2a.task:read": "Read delegated tasks"},
                }
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.profile, _request_from_sample(self.trusted, agent_card=card)
        )
        self.assertEqual(result["decision"], "deny_insecure_agent_card")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("PKCE" in item for item in result["violations"]))

    def test_production_authorization_code_without_pkce_flag_is_held(self) -> None:
        card = _oauth_card(
            self.trusted["agent_card"],
            {
                "authorizationCode": {
                    "authorizationUrl": "https://auth.security-recipes.ai/authorize",
                    "tokenUrl": "https://auth.security-recipes.ai/token",
                    "scopes": {"a2a.task:read": "Read delegated tasks"},
                }
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.profile, _request_from_sample(self.trusted, agent_card=card)
        )
        self.assertEqual(result["decision"], "hold_for_agent_card_intake")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("pkceRequired=true" in item for item in result["violations"]))

    def test_authorization_code_with_pkce_true_is_allowed(self) -> None:
        card = _oauth_card(
            self.trusted["agent_card"],
            {
                "authorizationCode": {
                    "authorizationUrl": "https://auth.security-recipes.ai/authorize",
                    "tokenUrl": "https://auth.security-recipes.ai/token",
                    "pkceRequired": True,
                    "scopes": {"a2a.task:read": "Read delegated tasks"},
                }
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.profile, _request_from_sample(self.trusted, agent_card=card)
        )
        self.assertEqual(result["decision"], "allow_trusted_agent_card")
        self.assertTrue(result["allowed"])
        self.assertIn("authorizationCode", result["card_facts"]["oauth_flow_types"])

    def test_device_code_flow_is_allowed(self) -> None:
        card = _oauth_card(
            self.trusted["agent_card"],
            {
                "deviceCode": {
                    "deviceAuthorizationUrl": "https://auth.security-recipes.ai/device",
                    "tokenUrl": "https://auth.security-recipes.ai/token",
                    "scopes": {"a2a.task:read": "Read delegated tasks"},
                }
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.profile, _request_from_sample(self.trusted, agent_card=card)
        )
        self.assertEqual(result["decision"], "allow_trusted_agent_card")
        self.assertTrue(result["allowed"])
        self.assertIn("deviceCode", result["card_facts"]["oauth_flow_types"])


if __name__ == "__main__":
    unittest.main()
