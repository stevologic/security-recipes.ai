from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import check_openai_credentials as check
from scripts import cve_ai_enrichment as enrichment


class CheckOpenAICredentialsTests(unittest.TestCase):
    def test_cli_writes_unusable_github_output_for_exhausted_credits(self) -> None:
        status = enrichment.OpenAICredentialStatus("insufficient_quota", usable=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "github-output.txt"
            with patch.object(check, "probe_openai_credentials", return_value=status):
                result = check.main(["--github-output", str(output)])

            self.assertEqual(result, 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "usable=false\nreason=insufficient_quota\n",
            )

    def test_cli_treats_a_missing_key_as_an_inactive_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "github-output.txt"
            env = {key: value for key, value in os.environ.items() if key != "OPENAI_API_KEY"}
            with patch.dict(os.environ, env, clear=True):
                result = check.main(["--github-output", str(output)])

            self.assertEqual(result, 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "usable=false\nreason=missing\n",
            )


if __name__ == "__main__":
    unittest.main()
