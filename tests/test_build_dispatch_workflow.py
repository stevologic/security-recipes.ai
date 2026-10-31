from __future__ import annotations

import re
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
        self.assertNotIn("fetch-depth: 0", self.workflow)
        self.assertNotIn("submodules: recursive", self.workflow)
        build_job = self.workflow.split("\n  build:\n", 1)[1].split("\n  publish:\n", 1)[0]
        self.assertIn("timeout-minutes: 30", build_job)
        self.assertIn("fetch-depth: 1", build_job)
        publish_job = self.workflow.split("\n  publish:\n", 1)[1]
        self.assertIn("if: github.event_name != 'pull_request'", publish_job)
        self.assertIn("timeout-minutes: 30", publish_job)
        self.assertNotIn("actions/checkout", publish_job)
        self.assertIn('IMAGE_TAG="${GITHUB_SHA}-development"', publish_job)
        self.assertIn('IMAGE_TAG="${GITHUB_SHA}"', publish_job)
        self.assertIn('SITE_TARGET_IMAGE="${IMAGE_PREFIX}-site:${IMAGE_TAG}"', publish_job)
        self.assertIn('MCP_TARGET_IMAGE="${IMAGE_PREFIX}-mcp:${IMAGE_TAG}"', publish_job)
        self.assertIn('docker push "${SITE_TARGET_IMAGE}"', publish_job)
        self.assertIn('docker push "${MCP_TARGET_IMAGE}"', publish_job)
        self.assertIn("branches: [main, development]", self.workflow)
        self.assertNotIn('BASE_URL="https://dev.security-recipes.ai/"', self.workflow)

    def test_does_not_emit_karen_qa(self) -> None:
        self.assertNotIn("\n  karen-qa:\n", self.workflow)
        self.assertNotIn("name: karen-qa", self.workflow)
        self.assertNotIn("required karen-qa context", self.workflow)

    def test_dispatch_completion_kicks_shepherd_and_search_indexing(self) -> None:
        self.assertIn("kick-automation:", self.workflow)
        self.assertIn(
            "if: always() && github.event_name == 'workflow_dispatch'",
            self.workflow,
        )
        kick = self.workflow.split("\n  kick-automation:\n", 1)[1]
        self.assertIn("actions: write", kick)
        self.assertIn("gh workflow run automation-shepherd.yml --ref main", kick)
        self.assertIn("gh workflow run search-indexing.yml --ref main", kick)
        self.assertNotIn("actions/checkout", kick)
        self.assertNotIn("cache: npm", kick)
        self.assertLess(
            self.workflow.index("\n  publish:\n"),
            self.workflow.index("\n  kick-automation:\n"),
        )

    def test_publish_promotes_the_exact_images_verified_by_the_build_job(self) -> None:
        build_job = self.workflow.split("\n  build:\n", 1)[1].split("\n  publish:\n", 1)[0]
        publish_job = self.workflow.split("\n  publish:\n", 1)[1]
        for scope in ("security-recipes-site", "security-recipes-mcp"):
            self.assertIn(f'type=gha,scope={scope},mode=max', build_job)
        self.assertIn("docker buildx build --load", build_job)
        self.assertNotIn("docker build", publish_job)
        self.assertNotIn("packages: write", build_job)
        self.assertIn("packages: write", publish_job)

        package_step = build_job.split("- name: Package verified deployment images", 1)[1]
        upload_step = build_job.split("- name: Upload verified deployment images", 1)[1]
        self.assertIn("if: github.event_name != 'pull_request'", package_step)
        self.assertIn("if: github.event_name != 'pull_request'", upload_step)
        self.assertIn('docker save "${SITE_IMAGE}" "${MCP_IMAGE}"', package_step)
        self.assertIn("sha256sum images.tar.gz", package_step)
        self.assertIn("image-identities.env", package_step)
        self.assertIn("actions/upload-artifact@", upload_step)
        self.assertIn("retention-days: 1", upload_step)
        self.assertEqual(
            self.workflow.count(
                "name: verified-deployment-images-${{ github.sha }}-"
                "${{ github.run_attempt }}"
            ),
            2,
        )

        self.assertIn("actions/download-artifact@", publish_job)
        self.assertIn("sha256sum --check --strict images.tar.gz.sha256", publish_job)
        self.assertIn("gzip --decompress --stdout images.tar.gz | docker load", publish_job)
        self.assertIn("loaded_site_id=", publish_job)
        self.assertIn("loaded_mcp_id=", publish_job)
        self.assertIn('"${loaded_site_id}" != "${recorded_site_id}"', publish_job)
        self.assertIn('"${loaded_mcp_id}" != "${recorded_mcp_id}"', publish_job)
        self.assertIn('docker tag "${SITE_SOURCE_IMAGE}" "${SITE_TARGET_IMAGE}"', publish_job)
        self.assertIn('docker tag "${MCP_SOURCE_IMAGE}" "${MCP_TARGET_IMAGE}"', publish_job)

        final_smoke_assertion = build_job.index(
            'grep -Fqi "location: ${expected_canonical}" "${lowercase_headers}"'
        )
        package_verified = build_job.index("- name: Package verified deployment images")
        self.assertLess(final_smoke_assertion, package_verified)

    def test_publish_deletes_verified_images_artifact_after_successful_push(self) -> None:
        publish_job = self.workflow.split("\n  publish:\n", 1)[1].split(
            "\n  kick-automation:\n", 1
        )[0]
        permissions = publish_job.split("steps:", 1)[0]
        self.assertIn("actions: write", permissions)
        self.assertEqual(permissions.count("actions: write"), 1)
        self.assertNotIn("issues: write", permissions)
        self.assertNotIn("pull-requests: write", permissions)
        self.assertNotIn("contents: write", permissions)

        push_idx = publish_job.index("- name: Publish immutable deployment images")
        delete_idx = publish_job.index(
            "- name: Delete verified deployment images artifact"
        )
        self.assertLess(push_idx, delete_idx)

        delete_step = re.search(
            r"(?ms)^\s{6}- name: Delete verified deployment images artifact\s*$"
            r"(.*?)(?=^\s{6}- name: |\Z)",
            publish_job,
        )
        self.assertIsNotNone(delete_step, "workflow step not found: Delete verified deployment images artifact")
        delete_text = delete_step.group(0)
        self.assertRegex(delete_text, r"(?m)^\s+if:\s+success\(\)\s*$")
        self.assertRegex(delete_text, r"(?m)^\s+continue-on-error:\s+true\s*$")
        self.assertIn(
            "gh api repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/artifacts",
            delete_text,
        )
        self.assertIn(
            "gh api -X DELETE repos/${GITHUB_REPOSITORY}/actions/artifacts/",
            delete_text,
        )
        self.assertNotIn("${{ github.repository }}", delete_text)
        self.assertNotIn("${{ github.run_id }}", delete_text)
        self.assertIn("verified-deployment-images-", delete_text)
        self.assertNotIn("uses:", delete_text)


if __name__ == "__main__":
    unittest.main()
