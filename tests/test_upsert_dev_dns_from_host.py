from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.upsert_dev_dns_from_host import first_token


class UpsertDevDnsFromHostTests(unittest.TestCase):
    def test_prefers_environment_token(self) -> None:
        with patch.dict("os.environ", {"DIGITALOCEAN_ACCESS_TOKEN": "from-env"}, clear=False):
            self.assertEqual(first_token(), "from-env")

    def test_reads_doctl_config_without_printing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "config.yaml"
            path.write_text("access-token: dop_v1_test\n", encoding="utf-8")
            with patch.dict("os.environ", {}, clear=False):
                with patch("os.environ.get", return_value=""):
                    with patch(
                        "scripts.upsert_dev_dns_from_host.SEARCH_PATHS",
                        (path,),
                    ):
                        self.assertEqual(first_token(), "dop_v1_test")

    def test_missing_token_is_empty(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with patch("scripts.upsert_dev_dns_from_host.SEARCH_PATHS", ()):
                self.assertEqual(first_token(), "")


if __name__ == "__main__":
    unittest.main()
