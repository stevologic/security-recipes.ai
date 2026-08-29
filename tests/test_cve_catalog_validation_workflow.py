from __future__ import annotations

import re
import unittest
from pathlib import Path


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

    def test_validator_uses_read_only_cache_workflow_run_boundary(self) -> None:
        self.assertRegex(self.validation, r"(?m)^on:\s*\n\s+workflow_run:")
        self.assertIn("- CVE catalog validation request", self.validation)
        self.assertIn("- completed", self.validation)
        self.assertNotIn("workflow_dispatch:", self.validation)
        self.assertIn("SOURCE_CONCLUSION", self.validation)
        self.assertIn('[ "$SOURCE_CONCLUSION" != "success" ]', self.validation)
        self.assertIn(
            '[ "$SOURCE_PATH" != ".github/workflows/cve-catalog-validate-request.yml" ]',
            self.validation,
        )
        self.assertIn('[ "$SOURCE_BRANCH" != "$DEFAULT_BRANCH" ]', self.validation)
        self.assertIn(
            '[ "$SOURCE_REPOSITORY" != "$GITHUB_REPOSITORY" ]', self.validation
        )

    def test_validator_rechecks_live_pr_before_checkout(self) -> None:
        authorize, validate = self.validation.split("\n  validate:\n", 1)
        self.assertIn(
            'PR_JSON="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"',
            authorize,
        )
        self.assertIn('[ "$HEAD_REPOSITORY" != "$GITHUB_REPOSITORY" ]', authorize)
        self.assertIn('[ "$HEAD_SHA" != "$EXPECTED_SHA" ]', authorize)
        self.assertIn('[ "$BASE_BRANCH" != "$DEFAULT_BRANCH" ]', authorize)
        self.assertIn("validated_revision=${EXPECTED_SHA}", authorize)
        self.assertIn("needs: authorize", validate)
        self.assertIn(
            "ref: ${{ needs.authorize.outputs.validated_revision }}", validate
        )
        self.assertLess(
            self.validation.index("authorize-exact-pr-head"),
            self.validation.index("Checkout exact catalog PR revision"),
        )
        self.assertNotIn("submodules: recursive", self.validation)
        self.assertNotIn("cache: npm", self.validation)

    def test_emits_the_existing_required_build_context(self) -> None:
        self.assertRegex(
            self.validation,
            r"(?ms)^\s{2}validate:\s*.*?^\s{4}name: build\s*$",
        )
        self.assertIn(
            "matches the required context emitted by build.yml", self.validation
        )

    def test_publishes_required_status_only_after_exact_sha_validation(self) -> None:
        validate_job, publish_job = self.validation.split("\n  publish:\n", 1)

        self.assertNotIn("statuses: write", validate_job)
        self.assertIn("- validate", publish_job)
        self.assertRegex(publish_job, r"(?m)^\s{6}statuses: write\s*$")
        self.assertIn("pull-requests: read", publish_job)
        self.assertNotIn("actions/checkout", publish_job)
        self.assertNotIn("npm ", publish_job)
        self.assertNotIn("python", publish_job)
        self.assertNotIn("docker ", publish_job)
        self.assertIn("HEAD_REPOSITORY", publish_job)
        self.assertIn("HEAD_BRANCH", publish_job)
        self.assertIn("HEAD_SHA", publish_job)
        self.assertIn("BASE_BRANCH", publish_job)
        self.assertIn(
            '"repos/${GITHUB_REPOSITORY}/statuses/${EXPECTED_SHA}"', publish_job
        )
        self.assertIn("--raw-field state=success", publish_job)
        self.assertIn("--raw-field context=build", publish_job)
        self.assertIn("GH_TOKEN: ${{ github.token }}", publish_job)
        self.assertLess(
            self.validation.index("run: docker compose build"),
            self.validation.index("publish-required-status"),
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
