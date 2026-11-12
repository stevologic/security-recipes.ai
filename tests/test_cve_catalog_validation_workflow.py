from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
REQUEST_WORKFLOW = (
    ROOT / ".github" / "workflows" / "cve-catalog-validate-request.yml"
)
VALIDATION_WORKFLOW = ROOT / ".github" / "workflows" / "cve-catalog-validate.yml"


class CveCatalogValidationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.request = REQUEST_WORKFLOW.read_text(encoding="utf-8")
        cls.validation = VALIDATION_WORKFLOW.read_text(encoding="utf-8")

    def test_dispatch_gateway_only_authorizes_an_exact_pr_head(self) -> None:
        self.assertRegex(self.request, r"(?m)^on:\s*\n\s+workflow_dispatch:")
        self.assertNotRegex(
            self.request,
            r"(?m)^\s+(push|pull_request|pull_request_target|workflow_run|schedule):",
        )
        for input_name in (
            "expected_sha:",
            "request_id:",
            "pr_number:",
            "expected_branch:",
        ):
            self.assertIn(input_name, self.request)
        self.assertIn(
            "run-name: CVE catalog validation request ${{ inputs.request_id }} "
            "PR-${{ inputs.pr_number }} @ ${{ inputs.expected_sha }}",
            self.request,
        )
        self.assertIn('[[ ! "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]', self.request)
        self.assertIn('[[ ! "$PR_NUMBER" =~ ^[0-9]+$ ]]', self.request)
        self.assertIn('[ "$HEAD_REPOSITORY" != "$GITHUB_REPOSITORY" ]', self.request)
        self.assertIn('[ "$HEAD_BRANCH" != "$EXPECTED_BRANCH" ]', self.request)
        self.assertIn('[ "$HEAD_SHA" != "$EXPECTED_SHA" ]', self.request)
        self.assertIn('[ "$BASE_BRANCH" != "$DEFAULT_BRANCH" ]', self.request)

    def test_dispatch_gateway_never_executes_pr_code(self) -> None:
        forbidden = (
            "actions/checkout",
            "setup-python",
            "setup-node",
            "pip install",
            "npm ci",
            "npm run",
            "docker ",
            "scripts/",
            "statuses: write",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, self.request)

    def test_validator_uses_read_only_cache_workflow_dispatch_boundary(self) -> None:
        self.assertRegex(self.validation, r"(?m)^on:\s*\n\s+workflow_dispatch:")
        self.assertNotRegex(
            self.validation,
            r"(?m)^\s+(push|pull_request|pull_request_target|workflow_run|schedule):",
        )
        for input_name in (
            "expected_sha:",
            "request_id:",
            "pr_number:",
            "expected_branch:",
        ):
            self.assertIn(input_name, self.validation)
        self.assertRegex(
            self.validation,
            r"(?m)^run-name: CVE catalog validation .+ @ .+$",
        )
        self.assertNotIn("SOURCE_CONCLUSION", self.validation)
        self.assertNotIn("cve-catalog-validate-request.yml", self.validation)
        self.assertNotIn("cache:", self.validation)

    def test_validator_rechecks_live_pr_before_checkout(self) -> None:
        self.assertIn("ref: ${{ inputs.expected_sha }}", self.validation)
        self.assertIn(
            '[[ ! "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]', self.validation
        )
        self.assertIn("Reject a missing or invalid exact SHA", self.validation)
        self.assertIn("Checkout exact catalog PR revision", self.validation)
        self.assertIn("Prove validation is attached to the requested revision", self.validation)
        self.assertNotIn("authorize-exact-pr-head", self.validation)
        self.assertNotIn("needs: authorize", self.validation)
        self.assertNotIn("submodules: recursive", self.validation)
        self.assertNotIn("cache:", self.validation)
        self.assertNotIn("\n  publish:\n", self.validation)
        self.assertLess(
            self.validation.index("Reject a missing or invalid exact SHA"),
            self.validation.index("Checkout exact catalog PR revision"),
        )
        self.assertLess(
            self.validation.index("Checkout exact catalog PR revision"),
            self.validation.index("Prove validation is attached to the requested revision"),
        )

    def test_validate_job_stays_read_only_and_is_not_named_build(self) -> None:
        validate = self.validation.split("\n  validate:\n", 1)[1]
        validate = validate.split("\n  publish-build-status:\n", 1)[0]
        self.assertIn("contents: read", validate)
        self.assertNotIn("statuses: write", validate)
        self.assertNotIn("checks: write", validate)
        self.assertNotIn("contents: write", validate)
        self.assertIn("persist-credentials: false", validate)
        self.assertNotRegex(validate, r"(?m)^\s{4}name: build\s*$")
        self.assertIn("Never emit `karen-qa`", validate)

    def test_publishes_build_status_on_the_exact_head_sha(self) -> None:
        self.assertIn("\n  publish-build-status:\n", self.validation)
        publish = self.validation.split("\n  publish-build-status:\n", 1)[1]
        publish = publish.split("\n  kick-shepherd:\n", 1)[0]
        self.assertIn("if: always() && github.event_name == 'workflow_dispatch'", publish)
        self.assertIn("statuses: write", publish)
        self.assertIn("pull-requests: read", publish)
        self.assertNotIn("contents: write", publish)
        self.assertNotIn("pull-requests: write", publish)
        self.assertNotIn("actions/checkout", publish)
        self.assertNotIn("scripts/", publish)
        self.assertIn("statuses/${EXPECTED_SHA}", publish)
        self.assertNotIn("statuses/${GITHUB_SHA}", publish)
        self.assertIn('--raw-field "context=build"', publish)
        self.assertNotIn("context=karen-qa", publish)
        self.assertNotIn("publish-required-status", self.validation)
        self.assertIn("gh_api_with_retry", publish)
        self.assertIn('[ "$HEAD_SHA" != "$EXPECTED_SHA" ]', publish)
        self.assertIn('SYNC_BRANCH="automation/cve-catalog-sync"', publish)
        self.assertIn('[ "$EXPECTED_BRANCH" != "$SYNC_BRANCH" ]', publish)
        self.assertIn("catalog-sync only", publish)
        self.assertIn("5ea57357", publish)
        self.assertIn("held for Stephen's ack", publish)
        self.assertIn("DISPATCH_REF: ${{ github.ref }}", publish)
        self.assertIn("DISPATCH_ACTOR: ${{ github.actor }}", publish)
        self.assertIn('TRUSTED_REF="refs/heads/main"', publish)
        self.assertIn('TRUSTED_ACTOR="github-actions[bot]"', publish)
        self.assertIn('[ "$DISPATCH_REF" != "$TRUSTED_REF" ]', publish)
        self.assertIn('[ "$DISPATCH_ACTOR" != "$TRUSTED_ACTOR" ]', publish)
        self.assertIn(
            '[[ ! "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]',
            publish,
        )

    def test_validation_is_build_equivalent(self) -> None:
        expected_commands = (
            "python3 scripts/run_checks.py",
            "python3 scripts/validate_cve_catalog.py",
            "npm run build",
            "npm run check:performance",
            "docker compose --profile caddy config",
            "sudo bash tests/smoke_caddy_404_ban.sh",
            "/opt/security-recipes/generate-traffic-report.sh --once",
            "docker compose build",
        )
        for command in expected_commands:
            with self.subTest(command=command):
                self.assertIn(command, self.validation)

    def test_dispatch_completion_kicks_the_shepherd(self) -> None:
        self.assertIn("kick-shepherd:", self.validation)
        self.assertIn(
            "if: always() && github.event_name == 'workflow_dispatch'",
            self.validation,
        )
        self.assertIn("gh workflow run automation-shepherd.yml --ref main", self.validation)
        kick = self.validation.split("\n  kick-shepherd:\n", 1)[1]
        self.assertIn("actions: write", kick)
        self.assertNotIn("actions/checkout", kick)
        self.assertNotIn("cache:", kick)
        self.assertNotIn("gh workflow run automation-shepherd.yml", kick.split("run:", 1)[0])
        self.assertIn("- publish-build-status", kick.split("steps:", 1)[0])
        self.assertLess(
            self.validation.index("\n  validate:\n"),
            self.validation.index("publish-build-status:"),
        )
        self.assertLess(
            self.validation.index("publish-build-status:"),
            self.validation.index("kick-shepherd:"),
        )

    def test_publish_job_wiring_is_structural(self) -> None:
        document = yaml.safe_load(self.validation)
        jobs = document["jobs"]
        publish = jobs["publish-build-status"]
        kick = jobs["kick-shepherd"]
        self.assertEqual(
            publish["if"],
            "always() && github.event_name == 'workflow_dispatch'",
        )
        self.assertEqual(publish["needs"], ["validate"])
        self.assertEqual(publish["permissions"]["statuses"], "write")
        self.assertNotEqual(publish["permissions"].get("statuses"), "read")
        self.assertIn("publish-build-status", kick["needs"])

    def test_actions_are_pinned_to_full_commit_shas(self) -> None:
        request_references = re.findall(
            r"(?m)^\s*uses:\s*([^#\s]+)", self.request
        )
        validation_references = re.findall(
            r"(?m)^\s*uses:\s*([^#\s]+)", self.validation
        )

        self.assertEqual(request_references, [])
        self.assertEqual(len(validation_references), 3)
        for reference in validation_references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
