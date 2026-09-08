from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.evaluate_a2a_agent_card_trust_decision import (
    evaluate_a2a_agent_card_trust_decision,
    sample_card_by_id,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = REPO_ROOT / "data" / "assurance" / "a2a-agent-card-trust-profile.json"


def _request_from_sample(pack: dict, sample_id: str, **overrides: object) -> dict:
    sample = sample_card_by_id(pack, sample_id)
    request = {
        "agent_card": copy.deepcopy(sample["agent_card"]),
        "declared_controls": list(sample.get("declared_controls") or []),
        "production": bool(sample.get("production")),
        "profile_id": sample.get("expected_profile_id"),
    }
    request.update(overrides)
    return request


def _with_oauth_flow(card: dict, flow_name: str, flow: dict) -> dict:
    mutated = copy.deepcopy(card)
    mutated["securitySchemes"] = {
        "oauth": {
            "oauth2SecurityScheme": {
                "flows": {
                    flow_name: flow,
                }
            }
        }
    }
    mutated["securityRequirements"] = [{"oauth": ["a2a.task:delegate"]}]
    return mutated


class A2AAgentCardOAuthFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        cls.trusted = sample_card_by_id(cls.pack, "trusted-security-recipes-delegated-agent")

    def test_named_samples_match_expected_decisions(self) -> None:
        expected = {
            "trusted-security-recipes-delegated-agent": "allow_trusted_agent_card",
            "unsigned-public-research-agent": "pilot_with_restricted_context",
            "implicit-oauth-production-agent": "deny_insecure_agent_card",
            "malicious-secret-leaking-card": "kill_session_on_agent_card_secret",
        }
        for sample_id, decision in expected.items():
            with self.subTest(sample_id=sample_id):
                result = evaluate_a2a_agent_card_trust_decision(
                    self.pack, _request_from_sample(self.pack, sample_id)
                )
                self.assertEqual(result["decision"], decision)

    def test_implicit_oauth_is_denied_even_with_production_controls(self) -> None:
        result = evaluate_a2a_agent_card_trust_decision(
            self.pack, _request_from_sample(self.pack, "implicit-oauth-production-agent")
        )
        self.assertEqual(result["decision"], "deny_insecure_agent_card")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("implicit" in item for item in result["violations"]))

    def test_password_oauth_is_denied(self) -> None:
        card = _with_oauth_flow(
            self.trusted["agent_card"],
            "password",
            {
                "tokenUrl": "https://auth.legacy.example.com/token",
                "scopes": {"a2a.task:delegate": "Delegate A2A tasks"},
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.pack,
            _request_from_sample(self.pack, "trusted-security-recipes-delegated-agent", agent_card=card),
        )
        self.assertEqual(result["decision"], "deny_insecure_agent_card")
        self.assertTrue(any("password" in item for item in result["violations"]))

    def test_authorization_code_with_pkce_allows_production(self) -> None:
        card = _with_oauth_flow(
            self.trusted["agent_card"],
            "authorizationCode",
            {
                "authorizationUrl": "https://auth.security-recipes.ai/authorize",
                "tokenUrl": "https://auth.security-recipes.ai/token",
                "pkceRequired": True,
                "scopes": {"a2a.task:delegate": "Delegate A2A tasks"},
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.pack,
            _request_from_sample(self.pack, "trusted-security-recipes-delegated-agent", agent_card=card),
        )
        self.assertEqual(result["decision"], "allow_trusted_agent_card")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["card_facts"].get("oauth_flow_names"), ["authorizationCode"])

    def test_authorization_code_without_pkce_flag_holds_production(self) -> None:
        card = _with_oauth_flow(
            self.trusted["agent_card"],
            "authorizationCode",
            {
                "authorizationUrl": "https://auth.security-recipes.ai/authorize",
                "tokenUrl": "https://auth.security-recipes.ai/token",
                "scopes": {"a2a.task:delegate": "Delegate A2A tasks"},
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.pack,
            _request_from_sample(self.pack, "trusted-security-recipes-delegated-agent", agent_card=card),
        )
        self.assertEqual(result["decision"], "hold_for_agent_card_intake")
        self.assertTrue(any("pkceRequired=true" in item for item in result["violations"]))

    def test_authorization_code_pkce_false_is_denied(self) -> None:
        card = _with_oauth_flow(
            self.trusted["agent_card"],
            "authorizationCode",
            {
                "authorizationUrl": "https://auth.security-recipes.ai/authorize",
                "tokenUrl": "https://auth.security-recipes.ai/token",
                "pkceRequired": False,
                "scopes": {"a2a.task:delegate": "Delegate A2A tasks"},
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.pack,
            _request_from_sample(self.pack, "trusted-security-recipes-delegated-agent", agent_card=card),
        )
        self.assertEqual(result["decision"], "deny_insecure_agent_card")
        self.assertTrue(any("must require PKCE" in item for item in result["violations"]))

    def test_device_code_allows_production(self) -> None:
        card = _with_oauth_flow(
            self.trusted["agent_card"],
            "deviceCode",
            {
                "deviceAuthorizationUrl": "https://auth.security-recipes.ai/device",
                "tokenUrl": "https://auth.security-recipes.ai/token",
                "scopes": {"a2a.task:delegate": "Delegate A2A tasks"},
            },
        )
        result = evaluate_a2a_agent_card_trust_decision(
            self.pack,
            _request_from_sample(self.pack, "trusted-security-recipes-delegated-agent", agent_card=card),
        )
        self.assertEqual(result["decision"], "allow_trusted_agent_card")
        self.assertEqual(result["card_facts"].get("oauth_flow_names"), ["deviceCode"])


if __name__ == "__main__":
    unittest.main()
