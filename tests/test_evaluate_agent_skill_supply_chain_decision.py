from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agent_skill_supply_chain_decision import (
    evaluate_agent_skill_supply_chain_decision,
    permission_subset_violations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agent-skill-supply-chain-pack.json"
READONLY_SKILL = "sr-secure-context-retrieval-skill"


def _readonly_run(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "skill_id": READONLY_SKILL,
        "operation": "run",
        "workflow_id": "vulnerable-dependency-remediation",
        "platform": "codex",
    }
    request.update(overrides)
    return request


class AST03RuntimePermissionEnforcementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_pinned_readonly_skill_still_allows_without_extra_permissions(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(self.pack, _readonly_run())
        self.assertEqual(result["decision"], "allow_pinned_readonly_skill")
        self.assertTrue(result["allowed"])

    def test_subset_filesystem_read_stays_on_the_allow_path(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_run(requested_permissions={"filesystem_read": ["content/security-remediation"]}),
        )
        self.assertEqual(result["decision"], "allow_pinned_readonly_skill")
        self.assertTrue(result["allowed"])

    def test_shell_beyond_reviewed_manifest_is_denied(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_run(requested_permissions={"shell": True}),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertFalse(result["allowed"])
        self.assertIn("requested shell exceeds reviewed permission manifest", result["violations"])

    def test_identity_file_write_beyond_reviewed_manifest_is_denied(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_run(requested_permissions={"identity_file_write": True}),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("identity_file_write" in item for item in result["violations"]))

    def test_extra_filesystem_path_is_denied(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_run(requested_permissions={"filesystem_read": ["/etc/passwd"]}),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("/etc/passwd" in item for item in result["violations"]))

    def test_extra_egress_domain_is_denied(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_run(network_egress_domains=["attacker.example"]),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("attacker.example" in item for item in result["violations"]))

    def test_binary_network_true_is_denied_when_manifest_is_allowlisted(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_run(requested_permissions={"network_egress": True}),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("network_egress" in item for item in result["violations"]))

    def test_extra_mcp_namespace_is_denied(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_run(
                requested_permissions={
                    "mcp_namespaces": [{"namespace": "repo.contents", "access": "write"}],
                }
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("repo.contents:write" in item for item in result["violations"]))

    def test_reviewed_mcp_namespace_stays_on_the_allow_path(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_run(
                requested_permissions={
                    "mcp_namespaces": [{"namespace": "recipes.context", "access": "read"}],
                }
            ),
        )
        self.assertEqual(result["decision"], "allow_pinned_readonly_skill")
        self.assertTrue(result["allowed"])

    def test_permission_subset_helper_treats_unrestricted_path_as_extra(self) -> None:
        violations = permission_subset_violations(
            {},
            {"filesystem_read": ["~/**"]},
            {"filesystem_read": ["content/**"], "shell": False},
        )
        self.assertTrue(any("~/**" in item for item in violations))


if __name__ == "__main__":
    unittest.main()
