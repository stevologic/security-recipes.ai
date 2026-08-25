from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# GitHub rejects `secrets` inside `if:` while validating workflow files on
# push, even when the workflow is not a push workflow. The resulting
# zero-job failure is named after the file path and deploy.sh treats any
# failed push run as a release blocker.
SECRETS_IN_IF_RE = re.compile(
    r"(?m)^\s*if:\s*(?:\$\{\{\s*)?secrets\.",
)


class GitHubWorkflowExpressionTests(unittest.TestCase):
    def test_no_workflow_uses_secrets_in_if(self) -> None:
        offenders: list[str] = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            if SECRETS_IN_IF_RE.search(text):
                offenders.append(path.name)
        self.assertEqual(
            offenders,
            [],
            "secrets in if: records an invalid workflow-file failure on every "
            "push and strands deploy.sh; detect credentials in env + bash "
            f"instead: {offenders}",
        )

    def test_no_first_party_workflow_uses_openai_or_codex(self) -> None:
        offenders: list[str] = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            if "openai/codex-action" in text or "OPENAI_API_KEY" in text:
                offenders.append(path.name)
        self.assertEqual(
            offenders,
            [],
            "first-party automation must use XAI_API_KEY / Grok, not Codex: "
            f"{offenders}",
        )

    def test_security_health_detects_xai_key_without_secrets_if(self) -> None:
        workflow = (WORKFLOWS / "security-health.yml").read_text(encoding="utf-8")
        self.assertIn("id: auth", workflow)
        self.assertIn("XAI_API_KEY: ${{ secrets.XAI_API_KEY }}", workflow)
        self.assertIn("if: steps.auth.outputs.configured == 'true'", workflow)
        self.assertNotIn("if: ${{ secrets.XAI_API_KEY", workflow)
        self.assertNotIn("if: secrets.XAI_API_KEY", workflow)

    def test_dev_dns_workflow_runs_on_pull_request_without_push(self) -> None:
        workflow = (WORKFLOWS / "dev-dns-record.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("pull_request:", workflow)
        self.assertIn("workflow_run:", workflow)
        self.assertIn("workflows: [Build]", workflow)
        self.assertIn(
            "github.event_name != 'workflow_run' || github.event.workflow_run.conclusion == 'success'",
            workflow,
        )
        self.assertNotIn("push:", workflow)
        self.assertIn("python scripts/upsert_dev_dns_record.py", workflow)
        self.assertIn("scripts/upsert_dev_dns_from_host.py", workflow)
        self.assertIn("if: steps.auth.outputs.configured == 'true'", workflow)
        self.assertIn("id: ssh", workflow)
        self.assertNotIn("if: ${{ secrets.DIGITALOCEAN_ACCESS_TOKEN", workflow)
        self.assertIn("DIGITALOCEAN_TOKEN: ${{ secrets.DIGITALOCEAN_TOKEN }}", workflow)
        self.assertIn("DROPLET_SSH_KEY: ${{ secrets.DROPLET_SSH_KEY }}", workflow)
        self.assertIn("No DigitalOcean API token secret is configured", workflow)
        self.assertIn("No droplet SSH private-key secret is configured", workflow)


if __name__ == "__main__":
    unittest.main()
