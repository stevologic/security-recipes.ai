from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

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

    def test_cli_reports_safe_http_diagnostics_without_provider_payloads(self) -> None:
        secret = "xai-private-credential-value"
        injected = "\n::error::forged-provider-annotation\nusable=true"
        cases = (
            (401, "Rejected", "invalid_key", "authentication", False),
            (403, "Your team doesn't have any credits yet", "insufficient_quota", "billing", False),
            (403, "Forbidden", "permission_denied", "permissions", False),
            (429, "Too many requests", "rate_limited", "rate_limit", True),
            (503, "Unavailable", "http_error", "provider_error", True),
        )
        for code, message, reason, category, usable in cases:
            with self.subTest(code=code, reason=reason), tempfile.TemporaryDirectory() as tmpdir:
                output = Path(tmpdir) / "github-output.txt"
                stdout = StringIO()
                error = HTTPError(
                    f"https://api.x.ai/?key={secret}",
                    code,
                    secret + injected,
                    {"X-Request-Id": secret},
                    BytesIO(
                        json.dumps({"error": {"code": secret + injected, "message": message + secret}}).encode()
                    ),
                )
                with (
                    patch.dict(os.environ, {"XAI_API_KEY": secret}, clear=True),
                    patch.object(enrichment, "urlopen", side_effect=error),
                    redirect_stdout(stdout),
                ):
                    result = check.main(["--github-output", str(output)])

                self.assertEqual(result, 0)
                self.assertEqual(
                    output.read_text(encoding="utf-8"),
                    f"usable={'true' if usable else 'false'}\nreason={reason}\n"
                    f"http_status={code}\nerror_category={category}\n",
                )
                self.assertIn(f"HTTP {code}; category={category}.", stdout.getvalue())
                for value in (output.read_text(encoding="utf-8"), stdout.getvalue()):
                    self.assertNotIn(secret, value)
                    self.assertNotIn("::error::", value)
                    self.assertNotIn("forged-provider-annotation", value)
                if usable:
                    self.assertIn("readiness is unconfirmed", stdout.getvalue())
                    self.assertNotIn("credentials are usable", stdout.getvalue())
                if code == 403:
                    self.assertNotIn("secret is replaced", stdout.getvalue())


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
