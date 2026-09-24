from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agent_skill_supply_chain_decision import (
    evaluate_agent_skill_supply_chain_decision,
    overprivileged_permission_violations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agent-skill-supply-chain-pack.json"


def _readonly_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "skill_id": "sr-secure-context-retrieval-skill",
        "operation": "run",
        "workflow_id": "vulnerable-dependency-remediation",
        "platform": "codex",
    }
    request.update(overrides)
    return request


class AST03PermissionManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_unspecified_permissions_keep_pinned_readonly_allow_path(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(self.pack, _readonly_request())
        self.assertEqual(result["decision"], "allow_pinned_readonly_skill")
        self.assertTrue(result["allowed"])

    def test_declared_filesystem_subset_remains_allowed(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_request(
                requested_permissions={"filesystem_read": ["content/recipes/general/base-image-bump.md"]}
            ),
        )
        self.assertEqual(result["decision"], "allow_pinned_readonly_skill")
        self.assertTrue(result["allowed"])

    def test_undeclared_shell_is_denied(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_request(requested_permissions={"shell": True}),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("shell=true" in item for item in result["violations"]),
        )

    def test_undeclared_identity_file_write_is_denied(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_request(requested_permissions={"identity_file_write": True}),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertTrue(
            any("identity_file_write=true" in item for item in result["violations"]),
        )

    def test_extra_egress_domain_is_denied(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_request(network_egress_domains=["attacker.example"]),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertTrue(
            any("attacker.example" in item for item in result["violations"]),
        )

    def test_declared_egress_domain_remains_allowed(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_request(network_egress_domains=["security-recipes.ai"]),
        )
        self.assertEqual(result["decision"], "allow_pinned_readonly_skill")

    def test_extra_mcp_namespace_is_denied(self) -> None:
        result = evaluate_agent_skill_supply_chain_decision(
            self.pack,
            _readonly_request(
                requested_permissions={
                    "mcp_namespaces": [{"namespace": "repo.contents", "access": "write_branch"}]
                }
            ),
        )
        self.assertEqual(result["decision"], "deny_untrusted_skill")
        self.assertTrue(any("repo.contents" in item for item in result["violations"]))

    def test_helper_keeps_unspecified_permissions_on_allow_path(self) -> None:
        skill = {"permissions": {"shell": False, "network_egress": ["security-recipes.ai"]}}
        self.assertEqual(overprivileged_permission_violations(skill, {}), [])
        self.assertEqual(
            overprivileged_permission_violations(skill, {"shell": True})[0],
            "requested shell=true is outside the declared permission manifest",
        )


if __name__ == "__main__":
    unittest.main()
