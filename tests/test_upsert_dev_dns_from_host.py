from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from scripts.upsert_dev_dns_from_host import (
    first_token,
    main,
    token_from_docker_config,
    token_from_docker_inspect_payload,
    token_from_text,
    upsert_with_doctl,
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
                with patch(
                    "scripts.upsert_dev_dns_from_host.token_from_docker_inspect",
                    return_value="",
                ):
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

    def test_reads_token_from_container_env(self) -> None:
        hex64 = "aa" * 32
        token = f"dop_v1_{hex64}"
        self.assertEqual(
            token_from_docker_inspect_payload(
                [{"Config": {"Env": ["PATH=/usr/bin", f"DIGITALOCEAN_ACCESS_TOKEN={token}"]}}]
            ),
            token,
        )
        self.assertEqual(token_from_docker_inspect_payload([{"Config": {"Env": ["PATH=/bin"]}}]), "")

    def test_doctl_creates_missing_record(self) -> None:
        calls: list[list[str]] = []

        def runner(cmd, **_kwargs):
            calls.append(cmd)
            if cmd[-2:] == ["--output", "json"] and "list" in cmd:
                return CompletedProcess(cmd, 0, stdout="[]\n", stderr="")
            return CompletedProcess(cmd, 0, stdout='{"ID": 99, "Type": "A"}\n', stderr="")

        with patch("scripts.upsert_dev_dns_from_host.doctl_commands", return_value=(["doctl"],)):
            self.assertEqual(upsert_with_doctl(runner=runner), 0)
        self.assertTrue(any("create" in cmd for cmd in calls))

    def test_doctl_leaves_matching_record_unchanged(self) -> None:
        payload = json.dumps(
            [{"ID": 7, "Type": "A", "Name": "dev", "Data": "64.227.98.210", "TTL": 300}]
        )

        def runner(cmd, **_kwargs):
            return CompletedProcess(cmd, 0, stdout=payload, stderr="")

        with patch("scripts.upsert_dev_dns_from_host.doctl_commands", return_value=(["doctl"],)):
            self.assertEqual(upsert_with_doctl(runner=runner), 0)

    def test_doctl_auth_error_is_skipped(self) -> None:
        def runner(cmd, **_kwargs):
            return CompletedProcess(
                cmd,
                1,
                stdout="",
                stderr="Unable to initialize digitalocean api client: access token is required. (hint: run 'doctl auth init')",
            )

        with patch("scripts.upsert_dev_dns_from_host.doctl_commands", return_value=(["doctl"],)):
            self.assertEqual(upsert_with_doctl(runner=runner), 2)

    def test_doctl_missing_is_skipped(self) -> None:
        with patch("scripts.upsert_dev_dns_from_host.doctl_commands", return_value=()):
            self.assertEqual(upsert_with_doctl(), 2)

    def test_main_uses_doctl_when_no_token(self) -> None:
        with patch("scripts.upsert_dev_dns_from_host.first_token", return_value=""):
            with patch("scripts.upsert_dev_dns_from_host.upsert_with_doctl", return_value=0):
                self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
