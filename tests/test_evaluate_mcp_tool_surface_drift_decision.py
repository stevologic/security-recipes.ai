from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_tool_surface_drift_decision import (
    collect_x_mcp_headers,
    evaluate_mcp_tool_surface_drift_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "mcp-tool-surface-drift-pack.json"


def _pinned_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "namespace": "repo.contents",
        "tool_name": "repo.contents.patch_scoped_branch",
        "workflow_id": "vulnerable-dependency-remediation",
        "requested_access_mode": "write_branch",
        "run_id": "ci-allow",
        "correlation_id": "corr-ci",
    }
    request.update(overrides)
    return request


class XMCPHeaderDriftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
        surfaces = {
            (str(surface.get("namespace")), str(surface.get("tool_name"))): surface
            for surface in cls.pack.get("tool_surfaces", [])
        }
        cls.repo = surfaces[("repo.contents", "repo.contents.patch_scoped_branch")]

    def test_pinned_baseline_still_allows(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            _pinned_request(
                description_sha256=self.repo["description_sha256"],
                input_schema_sha256=self.repo["input_schema_sha256"],
                output_schema_sha256=self.repo["output_schema_sha256"],
                annotations_sha256=self.repo["annotations_sha256"],
                surface_hash=self.repo["surface_hash"],
            ),
        )
        self.assertEqual(result["decision"], "allow_pinned_tool_surface")
        self.assertTrue(result["allowed"])

    def test_added_x_mcp_header_is_a_kill_session_event(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            _pinned_request(
                input_schema={
                    "type": "object",
                    "properties": {
                        "repository": {
                            "type": "string",
                            "x-mcp-header": "Repository",
                        }
                    },
                }
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_tool_surface_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("x-mcp-header" in item and "added" in item for item in result["violations"])
        )

    def test_invalid_header_token_is_denied(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            _pinned_request(
                input_schema={
                    "type": "object",
                    "properties": {
                        "repository": {
                            "type": "string",
                            "x-mcp-header": "Repo Name",
                        }
                    },
                }
            ),
        )
        self.assertEqual(result["decision"], "deny_tool_surface_regression")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("HTTP field-name token" in item for item in result["violations"]))

    def test_header_on_nested_items_is_not_statically_reachable(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            _pinned_request(
                input_schema={
                    "type": "object",
                    "properties": {
                        "patches": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "x-mcp-header": "Path",
                                    }
                                },
                            },
                        }
                    },
                }
            ),
        )
        self.assertEqual(result["decision"], "deny_tool_surface_regression")
        self.assertTrue(any("statically reachable" in item for item in result["violations"]))

    def test_sensitive_parameter_header_is_killed(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            _pinned_request(
                input_schema={
                    "type": "object",
                    "properties": {
                        "api_key": {
                            "type": "string",
                            "x-mcp-header": "ApiKey",
                        }
                    },
                }
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_tool_surface_signal")
        self.assertTrue(any("sensitive parameter" in item for item in result["violations"]))

    def test_number_type_header_is_denied(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            _pinned_request(
                input_schema={
                    "type": "object",
                    "properties": {
                        "region": {
                            "type": "number",
                            "x-mcp-header": "Region",
                        }
                    },
                }
            ),
        )
        self.assertEqual(result["decision"], "deny_tool_surface_regression")
        self.assertTrue(any("string, integer, or boolean" in item for item in result["violations"]))

    def test_duplicate_header_names_are_denied(self) -> None:
        result = evaluate_mcp_tool_surface_drift_decision(
            self.pack,
            _pinned_request(
                input_schema={
                    "type": "object",
                    "properties": {
                        "region": {"type": "string", "x-mcp-header": "Region"},
                        "zone": {"type": "string", "x-mcp-header": "region"},
                    },
                }
            ),
        )
        self.assertEqual(result["decision"], "deny_tool_surface_regression")
        self.assertTrue(any("duplicates" in item for item in result["violations"]))

    def test_collect_accepts_nested_object_properties(self) -> None:
        records, violations = collect_x_mcp_headers(
            {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "object",
                        "properties": {
                            "region": {
                                "type": "string",
                                "x-mcp-header": "Region",
                            }
                        },
                    }
                },
            }
        )
        self.assertEqual(violations, [])
        self.assertEqual(
            records,
            [
                {
                    "header": "Region",
                    "property_path": "target.region",
                    "type": "string",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
