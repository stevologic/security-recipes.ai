from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.generate_mcp_connector_intake_pack import (
    intake_decision,
    mcp_apps_ui_findings,
    recommend_tier,
    risk_findings,
    risk_score,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CANDIDATES_PATH = REPO_ROOT / "data" / "mcp" / "connector-intake-candidates.json"
WORKFLOW_PAGE = (
    REPO_ROOT / "content" / "security-remediation" / "mcp-connector-intake-scanner" / "_index.md"
)


def _read_candidates() -> dict[str, object]:
    return json.loads(CANDIDATES_PATH.read_text(encoding="utf-8"))


def _read_candidate(candidate_id: str) -> dict[str, object]:
    payload = _read_candidates()
    for row in payload["candidates"]:
        if row["id"] == candidate_id:
            return row
    raise AssertionError(f"missing candidate {candidate_id}")


def _sandboxed_ui(**overrides: object) -> dict[str, object]:
    ui: dict[str, object] = {
        "resource_uri": "ui://tenant-analytics/dashboard",
        "mime_type": "text/html;profile=mcp-app",
        "sandbox_iframe": True,
        "host_enforces_csp": True,
        "auditable_postmessage": True,
        "csp": {
            "connect_domains": ["https://metrics.internal.example"],
            "resource_domains": ["https://cdn.example"],
        },
        "permissions": {},
    }
    ui.update(overrides)
    return ui


class MCPAppsConnectorIntakeTests(unittest.TestCase):
    def test_candidates_record_mcp_apps_and_current_mcp_revision(self) -> None:
        payload = _read_candidates()
        alignment = {
            str(item.get("id")): item
            for item in payload["standards_alignment"]
            if isinstance(item, dict)
        }
        apps = alignment["mcp-apps-ui-2026-01-26"]
        self.assertEqual(
            apps["url"],
            "https://modelcontextprotocol.io/extensions/apps/overview",
        )
        self.assertIn("ui://", apps["coverage"])
        self.assertIn("MUST NOT allow undeclared origins", apps["coverage"])
        self.assertEqual(
            alignment["mcp-authorization-2026-07-28"]["url"],
            "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization",
        )
        self.assertEqual(payload["last_reviewed"], "2026-10-06")

    def test_workflow_page_records_mcp_apps_without_claiming_human_review(self) -> None:
        page = WORKFLOW_PAGE.read_text(encoding="utf-8")
        self.assertIn("https://modelcontextprotocol.io/extensions/apps/overview", page)
        self.assertIn("io.modelcontextprotocol/ui", page)
        self.assertIn("Tenant Analytics MCP App Dashboard", page)
        self.assertIn("does not claim human review of the pack", page)
        self.assertIn("lastmod: 2026-10-06", page)

    def test_unspecified_ui_keeps_github_writer_on_prior_path(self) -> None:
        candidate = _read_candidate("github-remediation-writer")
        findings = risk_findings(candidate, set())
        self.assertFalse(any(str(row["id"]).startswith("mcp-apps-") for row in findings))
        tier = recommend_tier(candidate)
        gaps = sorted(
            {
                "per_client_consent",
                "short_lived_workload_identity",
                "token_audience_validation",
                "deny_token_passthrough",
                "pin_tool_descriptions",
                "inspect_tool_results",
                "deny_private_network_egress",
                "audit_every_tool_call",
                "session_binding",
                "write_scope_enforcement",
                "human_review_before_merge",
            }
            - set(candidate["declared_controls"])
        )
        self.assertEqual(
            intake_decision(tier, risk_score(findings), gaps, findings),
            "approve_for_registry_candidate",
        )

    def test_tenant_analytics_mcp_app_is_held_for_unbounded_ui(self) -> None:
        candidate = _read_candidate("tenant-analytics-mcp-app")
        findings = risk_findings(candidate, set())
        finding_ids = {row["id"] for row in findings}
        self.assertIn("mcp-apps-unbounded-csp", finding_ids)
        self.assertIn("mcp-apps-missing-sandbox", finding_ids)
        self.assertIn("mcp-apps-device-permissions", finding_ids)
        self.assertIn("mcp-apps-deprecated-meta-key", finding_ids)
        self.assertEqual(
            intake_decision(recommend_tier(candidate), risk_score(findings), [], findings),
            "hold_for_controls",
        )

    def test_sandboxed_restrictive_ui_does_not_create_critical_findings(self) -> None:
        findings = mcp_apps_ui_findings(
            "show_tenant_dashboard",
            _sandboxed_ui(),
            {"typed_human_approval", "two_key_review", "audit_every_tool_call"},
        )
        self.assertEqual(findings, [])

    def test_wildcard_subdomain_is_not_treated_as_unbounded(self) -> None:
        findings = mcp_apps_ui_findings(
            "show_tenant_dashboard",
            _sandboxed_ui(
                csp={"connectDomains": ["https://*.metrics.example"], "resourceDomains": []}
            ),
            set(),
        )
        self.assertFalse(any(row["id"] == "mcp-apps-unbounded-csp" for row in findings))

    def test_spec_camelcase_wildcard_connect_domains_are_unbounded(self) -> None:
        findings = mcp_apps_ui_findings(
            "show_tenant_dashboard",
            _sandboxed_ui(csp={"connectDomains": ["*"], "frameDomains": ["https://*"]}),
            set(),
        )
        self.assertTrue(any(row["id"] == "mcp-apps-unbounded-csp" for row in findings))

    def test_invalid_ui_scheme_is_critical(self) -> None:
        findings = mcp_apps_ui_findings(
            "show_tenant_dashboard",
            _sandboxed_ui(resource_uri="https://attacker.example/dashboard.html"),
            set(),
        )
        self.assertTrue(any(row["id"] == "mcp-apps-invalid-uri-scheme" for row in findings))

    def test_empty_permission_object_counts_as_requested(self) -> None:
        findings = mcp_apps_ui_findings(
            "show_tenant_dashboard",
            _sandboxed_ui(permissions={"camera": {}}),
            set(),
        )
        self.assertTrue(any(row["id"] == "mcp-apps-device-permissions" for row in findings))


if __name__ == "__main__":
    unittest.main()
