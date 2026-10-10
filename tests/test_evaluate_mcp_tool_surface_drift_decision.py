from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_tool_surface_drift_decision import (
    evaluate_mcp_tool_surface_drift_decision,
    header_deny_violations,
    header_drift_kill_violations,
    header_sensitive_violations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "mcp-tool-surface-drift-pack.json"


def _pinned_repo(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "namespace": "repo.contents",
        "tool_name": "repo.contents.patch_scoped_branch",
        "workflow_id": "vulnerable-dependency-remediation",
        "requested_access_mode": "write_branch",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "run_id": "run-ci",
        "session_id": "session-ci",
        "correlation_id": "corr-ci",
    }
    request.update(overrides)
    return request


class MCPHeaderAnnotationTests(unittest.TestCase):
    def test_empty_header_is_denied(self) -> None:
        violations = header_deny_violations(
            {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": ""}}}
        )
        self.assertTrue(any("empty" in item for item in violations))

    def test_non_token_header_is_denied(self) -> None:
        violations = header_deny_violations(
            {
                "type": "object",
                "properties": {"region": {"type": "string", "x-mcp-header": "Not Valid"}},
            }
        )
        self.assertTrue(any("field-name token" in item for item in violations))

    def test_number_type_header_is_denied(self) -> None:
        violations = header_deny_violations(
            {
                "type": "object",
                "properties": {"count": {"type": "number", "x-mcp-header": "Count"}},
            }
        )
        self.assertTrue(any("not string, integer, or boolean" in item for item in violations))

    def test_duplicate_headers_are_denied(self) -> None:
        violations = header_deny_violations(
            {
                "type": "object",
                "properties": {
                    "region": {"type": "string", "x-mcp-header": "Region"},
                    "zone": {"type": "string", "x-mcp-header": "region"},
                },
            }
        )
        self.assertTrue(any("duplicate" in item for item in violations))

    def test_header_under_items_is_not_statically_reachable(self) -> None:
        violations = header_deny_violations(
            {
                "type": "object",
                "properties": {
                    "tags": {
                        "type": "array",
                        "items": {"type": "string", "x-mcp-header": "Tag"},
                    }
                },
            }
        )
        self.assertTrue(any("statically reachable" in item for item in violations))

    def test_valid_primitive_header_has_no_deny_violations(self) -> None:
        violations = header_deny_violations(
            {
                "type": "object",
                "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
            }
        )
        self.assertEqual(violations, [])

    def test_sensitive_parameter_name_is_a_kill(self) -> None:
        violations = header_sensitive_violations(
            {
                "type": "object",
                "properties": {"api_key": {"type": "string", "x-mcp-header": "ApiKey"}},
            }
        )
        self.assertTrue(any("sensitive parameter" in item for item in violations))

    def test_added_header_is_a_kill(self) -> None:
        baseline = {"type": "object", "properties": {"region": {"type": "string"}}}
        live = {
            "type": "object",
            "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
        }
        violations = header_drift_kill_violations(live, baseline)
        self.assertTrue(any("added after approval" in item for item in violations))

    def test_renamed_header_is_a_kill(self) -> None:
        baseline = {
            "type": "object",
            "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
        }
        live = {
            "type": "object",
            "properties": {"region": {"type": "string", "x-mcp-header": "Zone"}},
        }
        violations = header_drift_kill_violations(live, baseline)
        self.assertTrue(any("renamed after approval" in item for item in violations))


class MCPToolSurfaceHeaderDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
        surfaces = {
            (str(surface.get("namespace")), str(surface.get("tool_name"))): surface
            for surface in cls.pack.get("tool_surfaces", [])
        }
        cls.repo = surfaces[("repo.contents", "repo.contents.patch_scoped_branch")]

    def _with_baseline_hashes(self, **overrides: object) -> dict[str, object]:
        request = _pinned_repo(
            description_sha256=self.repo["description_sha256"],
            input_schema_sha256=self.repo["input_schema_sha256"],
            output_schema_sha256=self.repo["output_schema_sha256"],
            annotations_sha256=self.repo["annotations_sha256"],
            surface_hash=self.repo["surface_hash"],
            **overrides,
        )
        return request

    def test_pinned_surface_without_headers_still_allows(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(self.pack, self._with_baseline_hashes())
        self.assertEqual(result["decision"], "allow_pinned_tool_surface")
        self.assertTrue(result["allowed"])

    def test_matching_live_schema_without_headers_still_allows(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            self._with_baseline_hashes(input_schema=self.repo["input_schema"]),
        )
        self.assertEqual(result["decision"], "allow_pinned_tool_surface")
        self.assertTrue(result["allowed"])

    def test_invalid_header_token_is_denied(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            self._with_baseline_hashes(
                input_schema={
                    "type": "object",
                    "properties": {
                        "workflow_id": {"type": "string", "x-mcp-header": "Not Valid"}
                    },
                }
            ),
        )
        self.assertEqual(result["decision"], "deny_tool_surface_regression")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("field-name token" in item for item in result["violations"]))

    def test_header_added_after_approval_kills(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            self._with_baseline_hashes(
                input_schema={
                    "type": "object",
                    "properties": {
                        "workflow_id": {"type": "string", "x-mcp-header": "Workflow"}
                    },
                }
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_tool_surface_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("added after approval" in item for item in result["violations"]))

    def test_sensitive_header_kills(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            self._with_baseline_hashes(
                input_schema={
                    "type": "object",
                    "properties": {
                        "api_key": {"type": "string", "x-mcp-header": "ApiKey"}
                    },
                }
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_tool_surface_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("sensitive parameter" in item for item in result["violations"]))


if __name__ == "__main__":
    unittest.main()
