from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_authorization_decision import (
    evaluate_mcp_authorization_decision,
    oauth_metadata_ssrf_violations,
    rfc9207_issuer_violations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "mcp-authorization-conformance-pack.json"


def _http_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "connector_id": "repository-contents",
        "namespace": "repo.contents",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "run_id": "ci-allow",
        "client_id": "https://agent.security-recipes.ai/client-metadata/codex.json",
        "client_metadata_document_url": "https://agent.security-recipes.ai/client-metadata/codex.json",
        "client_metadata_document_validated": True,
        "authorization_server_discovery_method": "www_authenticate",
        "protected_resource_metadata_url": "https://mcp.security-recipes.ai/.well-known/oauth-protected-resource",
        "requested_access_mode": "write_branch",
        "resource_indicator": "https://mcp.security-recipes.ai/mcp",
        "token_audience": "https://mcp.security-recipes.ai/mcp",
        "token_issuer": "https://auth.security-recipes.ai",
        "expected_authorization_issuer": "https://auth.security-recipes.ai",
        "authorization_response_iss": "https://auth.security-recipes.ai",
        "authorization_response_iss_parameter_supported": True,
        "token_expires_at": "2099-01-01T00:15:00Z",
        "token_scopes": ["repo.contents:write_branch"],
        "scope_challenge": ["repo.contents:write_branch"],
        "consent_record_id": "consent-ci",
        "session_id": "session-ci",
        "correlation_id": "corr-ci",
        "gateway_policy_hash": "sha256:ci-policy",
    }
    request.update(overrides)
    return request


class RFC9207IssuerValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_matching_iss_allows_authorized_request(self) -> None:
        result = evaluate_mcp_authorization_decision(self.pack, _http_request())
        self.assertEqual(result["decision"], "allow_authorized_mcp_request")
        self.assertTrue(result["allowed"])

    def test_mismatched_iss_is_denied_with_simple_string_comparison(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(authorization_response_iss="https://attacker.example/as"),
        )
        self.assertEqual(result["decision"], "deny_authorization_issuer_mismatch")
        self.assertFalse(result["allowed"])
        self.assertIn(
            "authorization_response_iss does not match expected_authorization_issuer",
            result["violations"],
        )

    def test_trailing_slash_is_not_normalized(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(authorization_response_iss="https://auth.security-recipes.ai/"),
        )
        self.assertEqual(result["decision"], "deny_authorization_issuer_mismatch")

    def test_supported_metadata_without_iss_is_rejected(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(authorization_response_iss=""),
        )
        self.assertEqual(result["decision"], "deny_authorization_issuer_mismatch")
        self.assertTrue(
            any("authorization_response_iss is required" in item for item in result["violations"])
        )

    def test_unsupported_metadata_without_iss_may_proceed(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(
                authorization_response_iss="",
                authorization_response_iss_parameter_supported=False,
            ),
        )
        self.assertEqual(result["decision"], "allow_authorized_mcp_request")

    def test_unsupported_metadata_with_present_iss_still_compares(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(
                authorization_response_iss="https://attacker.example/as",
                authorization_response_iss_parameter_supported=False,
            ),
        )
        self.assertEqual(result["decision"], "deny_authorization_issuer_mismatch")

    def test_token_issuer_must_match_recorded_authorization_server(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(token_issuer="https://other-as.example"),
        )
        self.assertEqual(result["decision"], "deny_authorization_issuer_mismatch")
        self.assertIn(
            "token_issuer does not match expected_authorization_issuer",
            result["violations"],
        )

    def test_missing_recorded_issuer_holds_for_evidence(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(expected_authorization_issuer=""),
        )
        self.assertEqual(result["decision"], "hold_for_authorization_evidence")

    def test_helper_encodes_rfc9207_table(self) -> None:
        expected = "https://auth.example"
        self.assertEqual(
            rfc9207_issuer_violations(
                {
                    "expected_authorization_issuer": expected,
                    "authorization_response_iss": expected,
                    "authorization_response_iss_parameter_supported": True,
                    "token_issuer": expected,
                }
            ),
            [],
        )
        self.assertTrue(
            rfc9207_issuer_violations(
                {
                    "expected_authorization_issuer": expected,
                    "authorization_response_iss": "",
                    "authorization_response_iss_parameter_supported": True,
                    "token_issuer": expected,
                }
            )
        )
        self.assertEqual(
            rfc9207_issuer_violations(
                {
                    "expected_authorization_issuer": expected,
                    "authorization_response_iss": "",
                    "authorization_response_iss_parameter_supported": False,
                    "token_issuer": expected,
                }
            ),
            [],
        )


class OAuthMetadataSSRFTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_https_public_metadata_urls_remain_allowed(self) -> None:
        result = evaluate_mcp_authorization_decision(self.pack, _http_request())
        self.assertEqual(result["decision"], "allow_authorized_mcp_request")
        self.assertTrue(result["allowed"])

    def test_link_local_http_metadata_url_is_denied(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(
                protected_resource_metadata_url="http://169.254.169.254/latest/meta-data/"
            ),
        )
        self.assertEqual(result["decision"], "deny_oauth_metadata_ssrf")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("must use https" in item for item in result["violations"])
        )

    def test_https_link_local_metadata_url_is_denied(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(
                protected_resource_metadata_url="https://169.254.169.254/latest/meta-data/"
            ),
        )
        self.assertEqual(result["decision"], "deny_oauth_metadata_ssrf")
        self.assertTrue(
            any("blocked private, loopback, link-local" in item for item in result["violations"])
        )

    def test_private_rfc1918_metadata_url_is_denied(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(
                protected_resource_metadata_url="https://10.0.0.1/.well-known/oauth-protected-resource"
            ),
        )
        self.assertEqual(result["decision"], "deny_oauth_metadata_ssrf")

    def test_ipv4_mapped_loopback_metadata_url_is_denied(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(
                protected_resource_metadata_url="https://[::ffff:127.0.0.1]/.well-known/oauth-protected-resource"
            ),
        )
        self.assertEqual(result["decision"], "deny_oauth_metadata_ssrf")

    def test_localhost_metadata_hostname_is_denied(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(
                protected_resource_metadata_url="https://localhost/.well-known/oauth-protected-resource"
            ),
        )
        self.assertEqual(result["decision"], "deny_oauth_metadata_ssrf")
        self.assertTrue(any("localhost" in item for item in result["violations"]))

    def test_client_metadata_document_ssrf_is_denied(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(
                client_id="https://169.254.169.254/client-metadata/codex.json",
                client_metadata_document_url="https://169.254.169.254/client-metadata/codex.json",
                client_metadata_document_validated=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_oauth_metadata_ssrf")

    def test_optional_authorization_server_metadata_ssrf_is_denied(self) -> None:
        result = evaluate_mcp_authorization_decision(
            self.pack,
            _http_request(
                authorization_server_metadata_url="https://192.168.1.1/.well-known/oauth-authorization-server"
            ),
        )
        self.assertEqual(result["decision"], "deny_oauth_metadata_ssrf")

    def test_helper_accepts_https_public_hosts_and_rejects_blocked_literals(self) -> None:
        self.assertEqual(
            oauth_metadata_ssrf_violations(
                {
                    "protected_resource_metadata_url": (
                        "https://mcp.security-recipes.ai/.well-known/oauth-protected-resource"
                    ),
                    "client_metadata_document_url": (
                        "https://agent.security-recipes.ai/client-metadata/codex.json"
                    ),
                }
            ),
            [],
        )
        self.assertTrue(
            oauth_metadata_ssrf_violations(
                {
                    "protected_resource_metadata_url": "http://169.254.169.254/latest/meta-data/",
                }
            )
        )
        self.assertTrue(
            oauth_metadata_ssrf_violations(
                {
                    "protected_resource_metadata_url": "https://[fe80::1]/metadata",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
