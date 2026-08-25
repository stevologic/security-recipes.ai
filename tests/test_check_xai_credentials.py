from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import check_xai_credentials as check
from scripts import cve_ai_enrichment as enrichment
from scripts import run_grok_agent as grok_agent


class CheckXAICredentialsTests(unittest.TestCase):
    def test_cli_writes_unusable_github_output_for_exhausted_credits(self) -> None:
        status = enrichment.ProviderCredentialStatus("insufficient_quota", usable=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "github-output.txt"
            with patch.object(check, "probe_xai_credentials", return_value=status):
                result = check.main(["--github-output", str(output)])

            self.assertEqual(result, 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "usable=false\nreason=insufficient_quota\n",
            )

    def test_cli_treats_a_missing_key_as_an_inactive_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "github-output.txt"
            env = {key: value for key, value in os.environ.items() if key != "XAI_API_KEY"}
            with patch.dict(os.environ, env, clear=True):
                result = check.main(["--github-output", str(output)])

            self.assertEqual(result, 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "usable=false\nreason=missing\n",
            )


class RunGrokAgentTests(unittest.TestCase):
    def test_requires_an_xai_key_and_a_nonempty_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            prompt = Path(tmpdir) / "prompt.md"
            prompt.write_text("Review leftover-gold pages.\n", encoding="utf-8")
            env = {key: value for key, value in os.environ.items() if key != "XAI_API_KEY"}
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(
                    grok_agent.main(["--prompt-file", str(prompt)]),
                    2,
                )

            prompt.write_text("   \n", encoding="utf-8")
            with patch.dict(os.environ, {"XAI_API_KEY": "xai-test"}, clear=False):
                self.assertEqual(
                    grok_agent.main(["--prompt-file", str(prompt)]),
                    2,
                )

    def test_builds_a_headless_always_approve_command(self) -> None:
        command = grok_agent.build_command(
            "Fix the failed workflow.",
            model="grok-4.6",
            grok_bin="/usr/bin/grok",
        )
        self.assertEqual(
            command[:7],
            [
                "/usr/bin/grok",
                "--no-auto-update",
                "--no-alt-screen",
                "--always-approve",
                "--output-format",
                "plain",
                "-m",
            ],
        )
        self.assertIn("grok-4.6", command)
        self.assertIn("Fix the failed workflow.", command)


if __name__ == "__main__":
    unittest.main()
