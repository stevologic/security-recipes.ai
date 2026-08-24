from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.upsert_dev_dns_from_host import (
    first_token,
    token_from_docker_config,
    token_from_text,
)


class UpsertDevDnsFromHostTests(unittest.TestCase):
    def test_prefers_environment_token(self) -> None:
        with patch.dict("os.environ", {"DIGITALOCEAN_ACCESS_TOKEN": "from-env"}, clear=False):
            self.assertEqual(first_token(), "from-env")

    def test_reads_doctl_config_without_printing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "config.yaml"
            path.write_text("access-token: dop_v1_test\n", encoding="utf-8")
            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "scripts.upsert_dev_dns_from_host.iter_search_paths",
                    return_value=(path,),
                ):
                    self.assertEqual(first_token(), "dop_v1_test")

    def test_missing_token_is_empty(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with patch("scripts.upsert_dev_dns_from_host.iter_search_paths", return_value=()):
                self.assertEqual(first_token(), "")

    def test_token_from_text_accepts_bare_dop_v1(self) -> None:
        hex64 = "ab" * 32
        self.assertEqual(token_from_text(f"notes {hex64} ignored"), "")
        self.assertEqual(
            token_from_text(f"export TOKEN=dop_v1_{hex64} # comment"),
            f"dop_v1_{hex64}",
        )

    def test_reads_digitalocean_docker_auth(self) -> None:
        hex64 = "cd" * 32
        token = f"dop_v1_{hex64}"
        auth = base64.b64encode(f"unused:{token}".encode("utf-8")).decode("ascii")
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "auths": {
                            "ghcr.io": {"auth": base64.b64encode(b"user:ghp_not_do").decode("ascii")},
                            "registry.digitalocean.com": {"auth": auth},
                        }
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(token_from_docker_config(path), token)
            with patch.dict("os.environ", {}, clear=True):
                with patch(
                    "scripts.upsert_dev_dns_from_host.iter_search_paths",
                    return_value=(path,),
                ):
                    self.assertEqual(first_token(), token)

    def test_ignores_non_digitalocean_docker_auth(self) -> None:
        hex64 = "ef" * 32
        auth = base64.b64encode(f"user:dop_v1_{hex64}".encode("utf-8")).decode("ascii")
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "config.json"
            path.write_text(
                json.dumps({"auths": {"ghcr.io": {"auth": auth}}}),
                encoding="utf-8",
            )
            self.assertEqual(token_from_docker_config(path), "")


if __name__ == "__main__":
    unittest.main()
