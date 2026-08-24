from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"


class BuildDispatchWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = BUILD_WORKFLOW.read_text(encoding="utf-8")

    def test_automation_dispatch_can_bind_build_to_an_exact_main_sha(self) -> None:
        self.assertIn(
            "format('CVE catalog Build {0} {1}', inputs.expected_sha, inputs.request_id)",
            self.workflow,
        )
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("expected_sha:", self.workflow)
        self.assertIn("request_id:", self.workflow)
        verify_step = self.workflow.split("- name: Verify dispatched revision", 1)[1]
        self.assertIn("if: github.event_name == 'workflow_dispatch'", verify_step)
        self.assertIn('[[ ! "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]', verify_step)
        self.assertIn('[ "$GITHUB_SHA" != "$EXPECTED_SHA" ]', verify_step)

    def test_dispatches_do_not_cancel_each_other_or_push_ci(self) -> None:
        self.assertIn("format('build-dispatch-{0}', github.run_id)", self.workflow)
        self.assertIn("format('build-{0}', github.ref)", self.workflow)

    def test_dispatched_build_still_publishes_immutable_images(self) -> None:
        publish_job = self.workflow.split("\n  publish:\n", 1)[1]
        self.assertIn("if: github.event_name != 'pull_request'", publish_job)
        self.assertIn('IMAGE_TAG="${GITHUB_SHA}-development"', publish_job)
        self.assertIn('IMAGE_TAG="${GITHUB_SHA}"', publish_job)
        self.assertIn('docker push "${IMAGE_PREFIX}-site:${IMAGE_TAG}"', publish_job)
        self.assertIn('docker push "${IMAGE_PREFIX}-mcp:${IMAGE_TAG}"', publish_job)
        self.assertIn("branches: [main, development]", self.workflow)
        self.assertIn('BASE_URL="https://dev.security-recipes.ai/"', self.workflow)


if __name__ == "__main__":
    unittest.main()
